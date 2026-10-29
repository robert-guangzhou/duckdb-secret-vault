#include "secret_vault_storage.hpp"

#include "duckdb/catalog/catalog.hpp"
#include "duckdb/catalog/catalog_set.hpp"
#include "duckdb/common/buffer/buffered_file_reader.hpp"
#include "duckdb/common/buffer/buffered_file_writer.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/common/serializer/binary_serializer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/uuid.hpp"

namespace duckdb {

const string LOCAL_ENCRYPTED_STORAGE_NAME = "local_encrypted";

//===--------------------------------------------------------------------===//
// VaultSecretGenerator(镜像 DefaultSecretGenerator;vault 路径/后缀/存储名)
//===--------------------------------------------------------------------===//

VaultSecretGenerator::VaultSecretGenerator(Catalog &catalog, SecretManager &secret_manager,
                                           identifier_set_t &persistent_secrets, string vault_path_p)
    : DefaultGenerator(catalog), secret_manager(secret_manager), persistent_secrets(persistent_secrets),
      vault_path(std::move(vault_path_p)) {
}

unique_ptr<CatalogEntry> VaultSecretGenerator::CreateDefaultEntryInternal(const Identifier &entry_name) {
	lock_guard<mutex> guard(lock);
	auto secret_lu = persistent_secrets.find(Identifier(entry_name));
	if (secret_lu == persistent_secrets.end()) {
		return nullptr;
	}

	auto &fs = FileSystem::GetLocal(catalog.GetDatabase());
	string secret_path = fs.JoinPath(vault_path, entry_name + VAULT_FILE_SUFFIX);

	// SPIKE 阶段:直接读取 DuckDB 原生序列化(明文);
	// 阶段二替换为:读密文 → Rust FFI 解密 → 内存反序列化。
	try {
		auto file_reader = BufferedFileReader(fs, secret_path.c_str());

		if (!LocalFileSystem::IsPrivateFile(secret_path, nullptr)) {
			throw IOException("The vault secret file '%s' has incorrect permissions! Please set correct "
			                  "permissions or remove the file",
			                  secret_path);
		}

		if (!file_reader.Finished()) {
			BinaryDeserializer deserializer(file_reader);

			deserializer.Begin();
			auto deserialized_secret = secret_manager.DeserializeSecret(deserializer, secret_path);
			deserializer.End();

			auto entry = make_uniq<SecretCatalogEntry>(std::move(deserialized_secret), catalog);
			entry->secret->storage_mode = LOCAL_ENCRYPTED_STORAGE_NAME;
			entry->secret->persist_type = SecretPersistType::PERSISTENT;

			persistent_secrets.erase(secret_lu);
			return std::move(entry);
		}
	} catch (std::exception &ex) {
		ErrorData error(ex);
		switch (error.Type()) {
		case ExceptionType::SERIALIZATION:
			throw SerializationException(
			    "Failed to deserialize the vault secret file: '%s'. The file may be corrupt, please remove the "
			    "file, restart and try again. (error message: '%s')",
			    secret_path, error.RawMessage());
		case ExceptionType::IO:
			throw IOException(
			    "Failed to open the vault secret file: '%s'. Some other process may have removed it, please "
			    "restart and try again. (error message: '%s')",
			    secret_path, error.RawMessage());
		default:
			throw;
		}
	}

	throw SerializationException("Failed to deserialize vault secret '%s' from '%s': file appears empty! Please "
	                             "remove the file, restart and try again",
	                             entry_name, secret_path);
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
		auto &fs = FileSystem::GetLocal(db);
		if (fs.DirectoryExists(vault_path)) {
			fs.ListFiles(vault_path, [&](const string &fname, bool is_dir) {
				string full_path = fs.JoinPath(vault_path, fname);
				if (StringUtil::EndsWith(full_path, VAULT_FILE_SUFFIX)) {
					string suffix(VAULT_FILE_SUFFIX);
					string secret_name = fname.substr(0, fname.size() - suffix.size());
					persistent_secrets.insert(Identifier(secret_name));
				}
			});
		}
	} catch (PermissionException &ex) {
		if (!DBConfig::GetConfig(db).file_system->SubSystemIsDisabled("LocalFileSystem")) {
			throw;
		}
	}

	auto &catalog = Catalog::GetSystemCatalog(db);
	secrets = make_uniq<CatalogSet>(catalog, make_uniq<VaultSecretGenerator>(catalog, manager, persistent_secrets,
	                                                                         vault_path));
}

string VaultSecretStorage::DefaultVaultPath(DatabaseInstance &db) {
	auto &fs = FileSystem::GetLocal(db);
	auto home = fs.GetHomeDirectory(nullptr);
	return fs.JoinPath(fs.JoinPath(home, ".duckdb"), "stored_secrets_vault");
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

	string file_path = fs.JoinPath(vault_path, secret.GetName() + VAULT_FILE_SUFFIX);
	string temp_path = file_path + ".tmp-" + UUID::ToString(UUID::GenerateRandomUUID());

	fs.TryRemoveFile(file_path);
	fs.TryRemoveFile(temp_path);

	// SPIKE 阶段:与 local_file 相同的明文序列化落盘;
	// 阶段二替换为:序列化到内存 → Rust FFI 加密 → 密文落盘(DSVLT 头)。
	{
		auto open_flags = FileFlags::FILE_FLAGS_WRITE;
		open_flags |= FileFlags::FILE_FLAGS_PRIVATE;
		open_flags |= FileFlags::FILE_FLAGS_FILE_CREATE_NEW;

		auto file_writer = BufferedFileWriter(fs, temp_path, open_flags);
		auto serializer = BinarySerializer(file_writer);
		serializer.Begin();
		secret.Serialize(serializer);
		serializer.End();
		file_writer.Flush();
	}

	fs.MoveFile(temp_path, file_path);
}

void VaultSecretStorage::RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) {
	auto &fs = FileSystem::GetLocal(db);
	string file = fs.JoinPath(vault_path, name + VAULT_FILE_SUFFIX);
	persistent_secrets.erase(Identifier(name));
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
