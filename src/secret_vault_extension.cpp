#define DUCKDB_EXTENSION_MAIN

#include "secret_vault_extension.hpp"
#include "secret_vault_rust.h" // cbindgen 生成；变更后运行 rust/regen-header.sh
#include "secret_vault_storage.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/secret/secret.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include <duckdb/parser/parsed_data/create_scalar_function_info.hpp>

#include <atomic>
#include <cstdlib>

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

// ---- 全局存储实例指针（单 DB 假设；供 settings 回调触达）----
static VaultSecretStorage *g_storage = nullptr;

// ---- settings ----

static void SecretVaultProviderSetting(ClientContext &context, SetScope scope, Value &parameter) {
	uint8_t id;
	if (!TryParseProviderName(parameter.ToString(), id)) {
		throw InvalidInputException(
		    "secret_vault: secret_vault_provider must be one of 'keyring', 'passphrase', 'env' (got '%s')",
		    parameter.ToString());
	}
	SetVaultProviderGlobal(id);
	parameter = Value(VaultProviderName(id));
}

static void SecretVaultDirectorySetting(ClientContext &context, SetScope scope, Value &parameter) {
	if (!g_storage) {
		throw InvalidInputException("secret_vault: storage not initialized");
	}
	g_storage->RebindDirectory(parameter.ToString());
	parameter = Value("ok");
}

// ---- secret_vault_status() 表函数 ----

struct VaultStatusData : public TableFunctionData {
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		names.emplace_back("storage");
		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("directory");
		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("provider");
		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("files");
		return_types.emplace_back(LogicalType::UBIGINT);
		return nullptr;
	}
};

struct VaultStatusGlobal : public GlobalTableFunctionState {
	bool done = false;
	static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input) {
		return make_uniq<VaultStatusGlobal>();
	}
};

static void VaultStatusExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global = data.global_state->Cast<VaultStatusGlobal>();
	// 表函数协议:发过一行后必须发空块终止,否则查询永不结束
	if (global.done) {
		output.SetCardinality(0);
		return;
	}
	global.done = true;
	output.SetCardinality(1);
	if (g_storage) {
		output.SetValue(0, 0, Value(LOCAL_ENCRYPTED_STORAGE_NAME));
		output.SetValue(1, 0, Value(g_storage->PublicDirectory()));
		output.SetValue(2, 0, Value(string(VaultProviderName(VaultProviderId()))));
		output.SetValue(3, 0, Value::UBIGINT(g_storage->CountFilesOnDisk()));
	} else {
		output.SetValue(0, 0, Value("not-initialized"));
		output.SetValue(1, 0, Value());
		output.SetValue(2, 0, Value());
		output.SetValue(3, 0, Value());
	}
}

static void LoadInternal(ExtensionLoader &loader) {
	// 版本函数（Rust core 版本，验证 corrosion+cbindgen+staticlib 全链路）
	auto version_function = ScalarFunction("secret_vault_version", {}, LogicalType::VARCHAR, SecretVaultVersionFun);
	loader.RegisterFunction(version_function);

	RegisterVaultTestSecretType(loader);

	auto &db = loader.GetDatabaseInstance();
	auto &secret_manager = *DBConfig::GetConfig(db).secret_manager;

	// 核心:注册 local_encrypted SecretStorage(SecretManager::LoadSecretStorage 为公开扩展点)
	auto &config = DBConfig::GetConfig(db);
	const char *dir_env = std::getenv("SECRET_VAULT_DIRECTORY");
	string vault_path = dir_env ? string(dir_env) : VaultSecretStorage::DefaultVaultPath(db);
	auto storage = make_uniq<VaultSecretStorage>(secret_manager, db, LOCAL_ENCRYPTED_STORAGE_NAME, vault_path);
	g_storage = storage.get();
	secret_manager.LoadSecretStorage(std::move(storage));

	// settings(经 DBConfig::AddExtensionOption;SET/RESET/duckdb_settings 可见)
	config.AddExtensionOption("secret_vault_provider",
	                          "Key provider for the local_encrypted secret storage: keyring | passphrase | env",
	                          LogicalType::VARCHAR, Value("keyring"), SecretVaultProviderSetting, SetScope::SESSION);
	config.AddExtensionOption("secret_vault_directory",
	                          "Directory for local_encrypted secret files (changeable only while storage is empty)",
	                          LogicalType::VARCHAR, Value(), SecretVaultDirectorySetting, SetScope::SESSION);

	// secret_vault_status()
	TableFunction status_fn("secret_vault_status", {}, VaultStatusExecute, VaultStatusData::Create,
	                        VaultStatusGlobal::Init);
	loader.RegisterFunction(status_fn);
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
