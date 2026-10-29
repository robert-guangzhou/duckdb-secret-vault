#define DUCKDB_EXTENSION_MAIN

#include "secret_vault_extension.hpp"
#include "secret_vault_rust.h" // cbindgen 生成；变更后运行 rust/regen-header.sh
#include "secret_vault_storage.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

namespace duckdb {

static string SecretVaultCoreVersion() {
	const char *version = secret_vault_core_version();
	if (version == nullptr) {
		return "unknown";
	}
	return string(version);
}

static void SecretVaultVersionFun(DataChunk &args, ExpressionState &state, Vector &result) {
	result.SetValue(0, Value(SecretVaultCoreVersion()));
}

// ---- spike 专用测试 secret 类型（自包含，测试不依赖 httpfs/mysql 等扩展）----
// 阶段二起由真实类型（s3/mysql/pg/nats_rw 等）经 local_encrypted 存储覆盖，
// 本类型保留用于存储层自身的快速回归。
static constexpr const char *VAULT_TEST_TYPE = "vault_test";
static const char *const VAULT_TEST_OPTIONS[] = {"url", "user", "password"};

static unique_ptr<BaseSecret> CreateVaultTestSecret(ClientContext &context, CreateSecretInput &input) {
	auto secret = make_uniq<KeyValueSecret>(input.scope, input.type, input.provider, input.name);
	for (auto option : VAULT_TEST_OPTIONS) {
		secret->TrySetValue(option, input);
	}
	secret->redact_keys = {"password"};
	return std::move(secret);
}

static void RegisterVaultTestSecretType(ExtensionLoader &loader) {
	SecretType secret_type;
	secret_type.name = VAULT_TEST_TYPE;
	secret_type.deserializer = KeyValueSecret::Deserialize<KeyValueSecret>;
	secret_type.default_provider = "config";
	secret_type.extension = "secret_vault";
	loader.RegisterSecretType(secret_type);

	CreateSecretFunction function;
	function.secret_type = VAULT_TEST_TYPE;
	function.provider = "config";
	function.function = CreateVaultTestSecret;
	for (auto option : VAULT_TEST_OPTIONS) {
		function.named_parameters[option] = LogicalType(LogicalTypeId::VARCHAR);
	}
	loader.RegisterFunction(function);
}

static void LoadInternal(ExtensionLoader &loader) {
	// 版本函数（Rust core 版本，验证 corrosion+cbindgen+staticlib 全链路）
	auto version_function = ScalarFunction("secret_vault_version", {}, LogicalType::VARCHAR, SecretVaultVersionFun);
	loader.RegisterFunction(version_function);

	RegisterVaultTestSecretType(loader);

	// 核心 spike：注册 local_encrypted SecretStorage
	// （SecretManager::LoadSecretStorage 为 DUCKDB_API 公开扩展点）
	auto &db = loader.GetDatabaseInstance();
	auto &secret_manager = *DBConfig::GetConfig(db).secret_manager;
	auto vault_path = VaultSecretStorage::DefaultVaultPath(db);
	secret_manager.LoadSecretStorage(make_uniq<VaultSecretStorage>(secret_manager, db, LOCAL_ENCRYPTED_STORAGE_NAME,
	                                                               vault_path));
}

void SecretVaultExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string SecretVaultExtension::Name() {
	return "secret_vault";
}

std::string SecretVaultExtension::Version() const {
#ifdef EXT_VERSION_SECRET_VAULT
	return EXT_VERSION_SECRET_VAULT;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(secret_vault, loader) {
	duckdb::LoadInternal(loader);
}

} // extern "C"
