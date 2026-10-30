#include "secret_vault_storage.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_set.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/common/serializer/binary_deserializer.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/serializer/buffered_file_reader.hpp"
#include "duckdb/common/serializer/buffered_file_writer.hpp"
#include "duckdb/common/serializer/memory_stream.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/main/config.hpp"

#include <atomic>
#include <cstring>

namespace duckdb {

const string LOCAL_ENCRYPTED_STORAGE_NAME = "local_encrypted";

//===--------------------------------------------------------------------===//
// VaultBuf RAII 守卫(全面 review CR-H1/H2 修复)
// 析构 = zeroize + 按契约释放:正常与异常(含反序列化抛出、写盘 IO 失败)路径
// 均不泄漏、明文不留残留。storage 与 functions 两个翻译单元共用。
//===--------------------------------------------------------------------===//

VaultBufGuard::~VaultBufGuard() {
	vault_zeroize_buf(buf.ptr, buf.len);
	vault_free_buf(buf);
}

static VaultSecretStorage *g_vault_storage = nullptr;

VaultSecretStorage *GetVaultStorage() {
	return g_vault_storage;
}

void SetVaultStorage(VaultSecretStorage *storage) {
	g_vault_storage = storage;
}

//===--------------------------------------------------------------------===//
// 公共 seal/open 助手(P3-L2 去重:storage 与 functions 共用)
//===--------------------------------------------------------------------===//

void VaultWriteEncryptedFile(FileSystem &fs, const string &dir, const string &name, const void *plaintext,
                             size_t plain_len) {
	fs.CreateDirectoriesRecursive(dir);
	string file_path = fs.JoinPath(dir, name + VAULT_FILE_SUFFIX);
	string temp_path = file_path + ".tmp-" + UUID::ToString(UUID::GenerateRandomUUID());
	fs.TryRemoveFile(file_path);
	fs.TryRemoveFile(temp_path);
	{
		auto flags = FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_PRIVATE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW;
		VaultBufGuard cipher;
		if (vault_seal(VaultProviderId(), name.c_str(), static_cast<const_data_ptr_t>(plaintext), plain_len,
		               &cipher.buf) != 0) {
			throw InvalidInputException("secret_vault: encrypt failed for secret '%s' (provider %s): %s", name,
			                            VaultProviderName(VaultProviderId()), VaultLastError());
		}
		auto writer = BufferedFileWriter(fs, temp_path, flags);
		writer.WriteData(cipher.buf.ptr, cipher.buf.len);
		writer.Flush();
	}
	fs.MoveFile(temp_path, file_path);
}

string VaultReadDecryptedFile(FileSystem &fs, const string &path, const string &name) {
	auto reader = BufferedFileReader(fs, path.c_str());
	idx_t size = reader.FileSize();
	auto cipher = make_unsafe_uniq_array<data_t>(size);
	reader.ReadData(cipher.get(), size);
	VaultBufGuard plain;
	if (vault_open(VaultProviderId(), name.c_str(), cipher.get(), size, &plain.buf) != 0) {
		throw SerializationException("secret_vault: decrypt failed for secret '%s' (provider %s): %s", name,
		                             VaultProviderName(VaultProviderId()), VaultLastError());
	}
	return string(reinterpret_cast<const char *>(plain.buf.ptr), plain.buf.len);
}

//===--------------------------------------------------------------------===//
// 全局配置
//===--------------------------------------------------------------------===//

static std::atomic<uint8_t> g_provider_id {PROVIDER_KEYRING};

uint8_t VaultProviderId() {
	return g_provider_id.load();
}

void SetVaultProviderGlobal(uint8_t id) {
	g_provider_id.store(id);
}

const char *VaultProviderName(uint8_t id) {
	switch (id) {
	case PROVIDER_KEYRING:
		return "keyring";
	case PROVIDER_PASSPHRASE:
		return "passphrase";
	case PROVIDER_ENV:
		return "env";
	default:
		return "unknown";
	}
}

bool TryParseProviderName(const string &name, uint8_t &out) {
	string lowered = StringUtil::Lower(name);
	if (lowered == "keyring") {
		out = PROVIDER_KEYRING;
	} else if (lowered == "passphrase") {
		out = PROVIDER_PASSPHRASE;
	} else if (lowered == "env") {
		out = PROVIDER_ENV;
	} else {
		return false;
	}
	return true;
}

string VaultLastError() {
	const char *err = vault_last_error();
	return err ? string(err) : string("unknown error");
}

//===--------------------------------------------------------------------===//
// VaultSecretGenerator
//===--------------------------------------------------------------------===//

VaultSecretGenerator::VaultSecretGenerator(Catalog &catalog, SecretManager &secret_manager,
                                           identifier_set_t &persistent_secrets,
                                           identifier_map_t<string> &file_names, string vault_path_p)
    : DefaultGenerator(catalog), secret_manager(secret_manager), persistent_secrets(persistent_secrets),
      file_names(file_names), vault_path(std::move(vault_path_p)) {
}

unique_ptr<CatalogEntry> VaultSecretGenerator::CreateDefaultEntryInternal(const Identifier &entry_name) {
	lock_guard<mutex> guard(lock);
	auto secret_lu = persistent_secrets.find(Identifier(entry_name));
	if (secret_lu == persistent_secrets.end()) {
		return nullptr;
	}
	auto name_lu = file_names.find(Identifier(entry_name));
	if (name_lu == file_names.end()) {
		return nullptr;
	}
	// AAD 与路径都使用原始文件名(与 WriteSecret 的文件名基一致)
	const string &orig_name = name_lu->second;

	auto &fs = FileSystem::GetLocal(catalog.GetDatabase());
	string secret_path = fs.JoinPath(vault_path, orig_name + VAULT_FILE_SUFFIX);

	// 权限校验(不包装:让"incorrect permissions"原样可见,避免误导性外壳)
	if (!LocalFileSystem::IsPrivateFile(secret_path, nullptr)) {
		throw IOException("The vault secret file '%s' has incorrect permissions! Please set correct permissions or "
		                  "remove the file",
		                  secret_path);
	}

	// 整读 + 解密(公共助手,P3-L2 去重)
	string plaintext = VaultReadDecryptedFile(fs, secret_path, orig_name);

	unique_ptr<BaseSecret> deserialized_secret;
	try {
		MemoryStream plain_stream(reinterpret_cast<data_ptr_t>(plaintext.data()), plaintext.size());
		BinaryDeserializer deserializer(plain_stream);
		deserializer.Begin();
		deserialized_secret = secret_manager.DeserializeSecret(deserializer, secret_path);
		deserializer.End();
	} catch (std::exception &ex) {
		ErrorData error(ex);
		throw SerializationException("Failed to deserialize the vault secret file: '%s'. The file may be corrupt, "
		                             "please remove the file, restart and try again. (error message: '%s')",
		                             secret_path, error.RawMessage());
	}
	// 卫生:明文副本即用即清
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(plaintext.data()), plaintext.size());

	auto entry = make_uniq<SecretCatalogEntry>(std::move(deserialized_secret), catalog);
	entry->secret->storage_mode = LOCAL_ENCRYPTED_STORAGE_NAME;
	entry->secret->persist_type = SecretPersistType::PERSISTENT;

	persistent_secrets.erase(secret_lu);
	file_names.erase(name_lu);
	return std::move(entry);
}

unique_ptr<CatalogEntry> VaultSecretGenerator::CreateDefaultEntry(CatalogTransaction transaction,
                                                                  const Identifier &entry_name) {
	return CreateDefaultEntryInternal(entry_name);
}

unique_ptr<CatalogEntry> VaultSecretGenerator::CreateDefaultEntry(ClientContext &context,
                                                                  const Identifier &entry_name) {
	return CreateDefaultEntryInternal(entry_name);
}

vector<Identifier> VaultSecretGenerator::GetDefaultEntries() {
	return vector<Identifier>(persistent_secrets.begin(), persistent_secrets.end());
}

//===--------------------------------------------------------------------===//
// VaultSecretStorage
//===--------------------------------------------------------------------===//

VaultSecretStorage::VaultSecretStorage(SecretManager &manager, DatabaseInstance &db_p, const string &name_p,
                                       const string &vault_path_p)
    : CatalogSetSecretStorage(db_p, name_p, LOCAL_ENCRYPTED_STORAGE_OFFSET), manager(manager),
      vault_path(FileSystem::ExpandPath(vault_path_p, nullptr)) {
	persistent = true;

	try {
		ScanDirectory();
	} catch (PermissionException &ex) {
		if (!DBConfig::GetConfig(db).file_system->SubSystemIsDisabled("LocalFileSystem")) {
			throw;
		}
	}

	auto &catalog = Catalog::GetSystemCatalog(db);
	secrets = make_uniq<CatalogSet>(catalog,
	                                make_uniq<VaultSecretGenerator>(catalog, manager, persistent_secrets, file_names,
	                                                                vault_path));
}

void VaultSecretStorage::ScanDirectory() {
	persistent_secrets.clear();
	file_names.clear();
	auto &fs = FileSystem::GetLocal(db);
	if (!fs.DirectoryExists(vault_path)) {
		return;
	}
	fs.ListFiles(vault_path, [&](const string &fname, bool is_dir) {
		if (StringUtil::EndsWith(fname, VAULT_FILE_SUFFIX)) {
			string suffix(VAULT_FILE_SUFFIX);
			string secret_name = fname.substr(0, fname.size() - suffix.size());
			Identifier id(secret_name);
			persistent_secrets.insert(id);
			file_names.emplace(std::move(id), secret_name);
		}
	});
}

string VaultSecretStorage::DefaultVaultPath(DatabaseInstance &db) {
	auto &fs = FileSystem::GetLocal(db);
	auto home = fs.GetHomeDirectory(nullptr);
	return fs.JoinPath(fs.JoinPath(home, ".duckdb"), "stored_secrets_vault");
}

void VaultSecretStorage::RebindDirectory(const string &new_path) {
	lock_guard<mutex> guard(rebind_lock);
	if (has_written || !persistent_secrets.empty()) {
		throw InvalidInputException(
		    "secret_vault: cannot change secret_vault_directory after secrets exist in '%s'; restart with the new "
		    "directory instead",
		    vault_path);
	}
	vault_path = FileSystem::ExpandPath(new_path, nullptr);
	ScanDirectory();
	// 生成器持有扫描集的副本:目录变更后必须重建,否则同会话看不到
	// 新目录中的既有文件(诚实审查 HIGH-1 修复;空状态下重建 CatalogSet 安全)
	auto &catalog = Catalog::GetSystemCatalog(db);
	secrets = make_uniq<CatalogSet>(catalog,
	                                make_uniq<VaultSecretGenerator>(catalog, manager, persistent_secrets, file_names,
	                                                                vault_path));
}

idx_t VaultSecretStorage::CountFilesOnDisk() {
	auto &fs = FileSystem::GetLocal(db);
	idx_t count = 0;
	if (!fs.DirectoryExists(vault_path)) {
		return 0;
	}
	fs.ListFiles(vault_path, [&](const string &fname, bool is_dir) {
		if (StringUtil::EndsWith(fname, VAULT_FILE_SUFFIX)) {
			count++;
		}
	});
	return count;
}

void VaultSecretStorage::WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) {
	auto &fs = FileSystem::GetLocal(db);

	if (!fs.DirectoryExists(vault_path)) {
		try {
			fs.CreateDirectoriesRecursive(vault_path);
		} catch (std::exception &ex) {
			ErrorData error(ex);
			if (error.Type() == ExceptionType::IO) {
				throw IOException("Failed to initialize vault storage directory '%s'. (original error: '%s')",
				                  vault_path, error.RawMessage());
			}
			throw;
		}
	}

	// 1. 序列化到内存(DuckDB 原生二进制格式,类型无关)
	MemoryStream plain_stream;
	{
		BinarySerializer serializer(plain_stream);
		serializer.Begin();
		secret.Serialize(serializer);
		serializer.End();
	}
	data_ptr_t plain = plain_stream.GetData();
	idx_t plain_len = plain_stream.GetPosition();

	// 2. 加密落盘(公共助手:seal + 私有权限 + 原子 rename;P3-L2 去重)
	string file_name = secret.GetName() + VAULT_FILE_SUFFIX;
	string name = file_name.substr(0, file_name.size() - string(VAULT_FILE_SUFFIX).size());
	VaultWriteEncryptedFile(fs, vault_path, name, plain, plain_len);

	// 卫生:序列化明文缓冲即用即清(清整个 capacity,CR-H3 缓解;
	// 设计债:扩容中间缓冲未清零,彻底方案需清零型 WriteStream)
	vault_zeroize_buf(plain, plain_stream.GetCapacity());
	// 写入成功后才锁定目录变更(诚实审查 LOW-3:失败不锁定)
	has_written = true;
}

void VaultSecretStorage::RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) {
	auto &fs = FileSystem::GetLocal(db);
	string file = fs.JoinPath(vault_path, name + VAULT_FILE_SUFFIX);
	persistent_secrets.erase(Identifier(name));
	file_names.erase(Identifier(name));
	try {
		fs.RemoveFile(file);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		if (error.Type() == ExceptionType::IO) {
			throw IOException("Failed to remove vault secret file '%s', the file may have been removed by another "
			                  "duckdb instance. (original error: '%s')",
			                  file, error.RawMessage());
		}
		throw;
	}
}

} // namespace duckdb
