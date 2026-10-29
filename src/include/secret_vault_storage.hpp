#pragma once

#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"

namespace duckdb {

//! 对外存储名:CREATE PERSISTENT SECRET ... IN local_encrypted / duckdb_secrets().storage
extern const string LOCAL_ENCRYPTED_STORAGE_NAME;

//! tie-break 偏移:紧邻 local_file(LOCAL_FILE_STORAGE_OFFSET=20)之后
constexpr int64_t LOCAL_ENCRYPTED_STORAGE_OFFSET = 21;

//! 文件名:<name>.duckdb_secret.vault
constexpr const char *VAULT_FILE_SUFFIX = ".duckdb_secret.vault";

//! VaultSecretStorage 的懒加载生成器(镜像 DefaultSecretGenerator;
//! 路径/扩展名/存储名替换为 vault 侧)。SPIKE 阶段文件为 DuckDB 原生
//! 序列化明文;阶段二替换为「解密 → 内存反序列化」。
class VaultSecretGenerator : public DefaultGenerator {
public:
	VaultSecretGenerator(Catalog &catalog, SecretManager &secret_manager, identifier_set_t &persistent_secrets,
	                     string vault_path_p);

public:
	unique_ptr<CatalogEntry> CreateDefaultEntry(CatalogTransaction transaction, const Identifier &entry_name) override;
	unique_ptr<CatalogEntry> CreateDefaultEntry(ClientContext &context, const Identifier &entry_name) override;
	vector<Identifier> GetDefaultEntries() override;
	bool LockDuringCreate() const override {
		return true;
	}

private:
	unique_ptr<CatalogEntry> CreateDefaultEntryInternal(const Identifier &entry_name);

	SecretManager &secret_manager;
	mutex lock;
	identifier_set_t persistent_secrets;
	string vault_path;
};

//! 持久化 secret 存储(镜像 LocalFileSecretStorage 的目录扫描/懒加载/
//! 临时文件+原子 rename/私有权限行为)。SPIKE:落盘为明文序列化;
//! 阶段二起 WriteSecret/生成器走 Rust 加解密 FFI(Dev Plan 3.2/3.3)。
class VaultSecretStorage : public CatalogSetSecretStorage {
public:
	VaultSecretStorage(SecretManager &manager, DatabaseInstance &db, const string &name, const string &vault_path);

	//! 默认目录:~/.duckdb/stored_secrets_vault(阶段二加 secret_vault_directory 设置)
	static string DefaultVaultPath(DatabaseInstance &db);

protected:
	void WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) override;
	void RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) override;

private:
	identifier_set_t persistent_secrets;
	string vault_path;
};

} // namespace duckdb
