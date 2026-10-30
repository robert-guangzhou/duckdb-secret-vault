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
	// AAD 与路径都使用原始文件名(与 WriteSecret 的 secret.GetName() 一致)
	const string &orig_name = name_lu->second;

	auto &fs = FileSystem::GetLocal(catalog.GetDatabase());
	string secret_path = fs.JoinPath(vault_path, orig_name + VAULT_FILE_SUFFIX);

	try {
		if (!LocalFileSystem::IsPrivateFile(secret_path, nullptr)) {
			throw IOException("The vault secret file '%s' has incorrect permissions! Please set correct "
			                  "permissions or remove the file",
			                  secret_path);
		}

		auto file_reader = BufferedFileReader(fs, secret_path.c_str());
		idx_t file_size = file_reader.FileSize();
		auto cipher = make_unsafe_uniq_array<data_t>(file_size);
		file_reader.ReadData(cipher.get(), file_size);

		VaultBuf plain {
			nullptr, 0, 0};
		int rc = vault_open(VaultProviderId(), orig_name.c_str(), cipher.get(), file_size, &plain);
		if (rc != 0) {
			throw SerializationException(
			    "secret_vault: decrypt failed for secret '%s' (%s): %s — wrong provider/key, renamed file, or "
			    "tampered file",
			    orig_name, VaultProviderName(VaultProviderId()), VaultLastError());
		}

		MemoryStream plain_stream(plain.ptr, plain.len);
		BinaryDeserializer deserializer(plain_stream);
		deserializer.Begin();
		auto deserialized_secret = secret_manager.DeserializeSecret(deserializer, secret_path);
		deserializer.End();

		// 卫生:明文缓冲用后清零,再按契约释放
		vault_zeroize_buf(plain.ptr, plain.len);
		vault_free_buf(plain);

		auto entry = make_uniq<SecretCatalogEntry>(std::move(deserialized_secret), catalog);
		entry->secret->storage_mode = LOCAL_ENCRYPTED_STORAGE_NAME;
		entry->secret->persist_type = SecretPersistType::PERSISTENT;

		persistent_secrets.erase(secret_lu);
		file_names.erase(name_lu);
		return std::move(entry);
	} catch (std::exception &ex) {
		ErrorData error(ex);
		switch (error.Type()) {
		case ExceptionType::SERIALIZATION:
			throw SerializationException(
			    "Failed to load the vault secret file: '%s'. (error message: '%s')", secret_path,
			    error.RawMessage());
		case ExceptionType::IO:
			throw IOException(
			    "Failed to open the vault secret file: '%s'. Some other process may have removed it, please "
			    "restart and try again. (error message: '%s')",
			    secret_path, error.RawMessage());
		default:
			throw;
		}
	}
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
    : CatalogSetSecretStorage(db_p, name_p, LOCAL_ENCRYPTED_STORAGE_OFFSET),
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

	// 2. 加密(AAD 绑定 secret 名)
	string name = secret.GetName();
	VaultBuf cipher {
		nullptr, 0, 0};
	int rc = vault_seal(VaultProviderId(), name.c_str(), plain, plain_len, &cipher);

	// 卫生:序列化明文缓冲立即清零(加密失败也清)
	vault_zeroize_buf(plain, plain_len);

	if (rc != 0) {
		throw InvalidInputException("secret_vault: encrypt failed for secret '%s' (provider %s): %s", name,
		                            VaultProviderName(VaultProviderId()), VaultLastError());
	}

	// 3. 密文原子落盘(临时文件 + rename,私有权限)
	has_written = true;
	string file_path = fs.JoinPath(vault_path, name + VAULT_FILE_SUFFIX);
	string temp_path = file_path + ".tmp-" + UUID::ToString(UUID::GenerateRandomUUID());

	fs.TryRemoveFile(file_path);
	fs.TryRemoveFile(temp_path);

	{
		auto open_flags = FileFlags::FILE_FLAGS_WRITE;
		open_flags |= FileFlags::FILE_FLAGS_PRIVATE;
		open_flags |= FileFlags::FILE_FLAGS_FILE_CREATE_NEW;

		auto file_writer = BufferedFileWriter(fs, temp_path, open_flags);
		file_writer.WriteData(const_data_ptr_t(cipher.ptr), cipher.len);
		file_writer.Flush();
	}

	vault_free_buf(cipher);
	fs.MoveFile(temp_path, file_path);
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
