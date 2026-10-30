#include "secret_vault_functions.hpp"

#include "secret_vault_storage.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/local_file_system.hpp"
#include "duckdb/common/serializer/buffered_file_reader.hpp"
#include "duckdb/common/serializer/buffered_file_writer.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/common/types/uuid.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"
#include "duckdb/main/client_context.hpp"
#include "duckdb/main/config.hpp"
#include "duckdb/main/secret/secret_manager.hpp"

#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace duckdb {

//===--------------------------------------------------------------------===//
// 本地小工具
//===--------------------------------------------------------------------===//

static FileSystem &LocalFS() {
	static LocalFileSystem fs;
	return fs;
}

// 读整个文件(不存在返回 false)
static bool ReadWholeFile(FileSystem &fs, const string &path, string &out) {
	if (!fs.FileExists(path)) {
		return false;
	}
	auto reader = BufferedFileReader(fs, path.c_str());
	idx_t size = reader.FileSize();
	out.resize(size);
	if (size > 0) {
		reader.ReadData(reinterpret_cast<data_ptr_t>(out.data()), size);
	}
	return true;
}

// 加密写盘:seal(当前 provider) → 临时文件 + 原子 rename,私有权限
static void WriteEncryptedFile(FileSystem &fs, const string &dir, const string &name, const string &plaintext) {
	fs.CreateDirectoriesRecursive(dir);
	string file_path = fs.JoinPath(dir, name + VAULT_FILE_SUFFIX);
	string temp_path = file_path + ".tmp-" + UUID::ToString(UUID::GenerateRandomUUID());
	fs.TryRemoveFile(file_path);
	fs.TryRemoveFile(temp_path);
	{
		auto flags = FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_PRIVATE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW;
		VaultBufGuard cipher;
		if (vault_seal(VaultProviderId(), name.c_str(),
		               reinterpret_cast<const_data_ptr_t>(plaintext.data()), plaintext.size(), &cipher.buf) != 0) {
			throw InvalidInputException("secret_vault: encrypt failed for secret '%s' (provider %s): %s", name,
			                            VaultProviderName(VaultProviderId()), VaultLastError());
		}
		auto writer = BufferedFileWriter(fs, temp_path, flags);
		writer.WriteData(cipher.buf.ptr, cipher.buf.len);
		writer.Flush();
	}
	fs.MoveFile(temp_path, file_path);
}

// 解密读盘:整读 + vault_open(AAD 绑定文件名)
static string ReadDecryptedFile(FileSystem &fs, const string &path, const string &name) {
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

// 解密读盘:整读 + vault_open(AAD 绑定文件名)

// 列出目录中后缀匹配的文件基名(排序稳定)
static vector<string> ListBaseNames(FileSystem &fs, const string &dir, const char *suffix) {
	vector<string> names;
	if (!fs.DirectoryExists(dir)) {
		return names;
	}
	fs.ListFiles(dir, [&](const string &fname, bool is_dir) {
		if (is_dir || !StringUtil::EndsWith(fname, suffix)) {
			return;
		}
		names.push_back(fname.substr(0, fname.size() - string(suffix).size()));
	});
	std::sort(names.begin(), names.end());
	return names;
}

//===--------------------------------------------------------------------===//
// 封套 payload 编解码:count | { name_len u32 | name | pt_len u32 | pt }
//===--------------------------------------------------------------------===//

static void AppendU32(string &buf, uint32_t v) {
	for (int i = 3; i >= 0; i--) {
		buf.push_back(static_cast<char>((v >> (8 * i)) & 0xff));
	}
}

static uint32_t ReadU32(const char *&p, const char *end) {
	if (p + 4 > end) {
		throw SerializationException("secret_vault: malformed envelope payload (truncated u32)");
	}
	uint32_t v = 0;
	for (int i = 0; i < 4; i++) {
		v = (v << 8) | static_cast<uint8_t>(*p++);
	}
	return v;
}

struct EnvelopeEntry {
	string name;
	string plaintext;
};

static string EncodePayload(const vector<EnvelopeEntry> &entries) {
	string buf;
	AppendU32(buf, static_cast<uint32_t>(entries.size()));
	for (auto &e : entries) {
		AppendU32(buf, static_cast<uint32_t>(e.name.size()));
		buf.append(e.name);
		AppendU32(buf, static_cast<uint32_t>(e.plaintext.size()));
		buf.append(e.plaintext);
	}
	return buf;
}

static vector<EnvelopeEntry> DecodePayload(const string &payload) {
	const char *p = payload.data();
	const char *end = p + payload.size();
	uint32_t count = ReadU32(p, end);
	vector<EnvelopeEntry> entries;
	entries.reserve(count);
	for (uint32_t i = 0; i < count; i++) {
		EnvelopeEntry e;
		uint32_t nlen = ReadU32(p, end);
		if (p + nlen > end) {
			throw SerializationException("secret_vault: malformed envelope payload (truncated name)");
		}
		e.name.assign(p, nlen);
		p += nlen;
		uint32_t plen = ReadU32(p, end);
		if (p + plen > end) {
			throw SerializationException("secret_vault: malformed envelope payload (truncated plaintext)");
		}
		e.plaintext.assign(p, plen);
		p += plen;
		entries.push_back(std::move(e));
	}
	if (p != end) {
		throw SerializationException("secret_vault: malformed envelope payload (trailing bytes)");
	}
	return entries;
}

//===--------------------------------------------------------------------===//
// secret_vault_migrate():local_file 明文 → 加密存储(文件级,新连接生效)
//===--------------------------------------------------------------------===//

struct MigrateBind : TableFunctionData {
	bool delete_source = false;
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		auto bind = make_uniq<MigrateBind>();
		for (auto &kv : input.named_parameters) {
			if (kv.first == "delete_source") {
				bind->delete_source = kv.second.GetValue<bool>();
			}
		}
		names.emplace_back("migrated");
		return_types.emplace_back(LogicalType::UBIGINT);
		return std::move(bind);
	}
};

struct OnceGlobal : GlobalTableFunctionState {
	bool done = false;
	static unique_ptr<GlobalTableFunctionState> Init(ClientContext &context, TableFunctionInitInput &input) {
		return make_uniq<OnceGlobal>();
	}
};

static void MigrateExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global = data.global_state->Cast<OnceGlobal>();
	if (global.done) {
		output.SetCardinality(0);
		return;
	}
	global.done = true;

	auto storage = GetVaultStorage();
	if (!storage) {
		throw InvalidInputException("secret_vault: storage not initialized");
	}
	auto &fs = LocalFS();
	string source_dir = SecretManager::Get(context).PersistentSecretPath();
	auto sources = ListBaseNames(fs, source_dir, ".duckdb_secret");
	idx_t migrated = 0;
	for (auto &name : sources) {
		string plaintext;
		if (!ReadWholeFile(fs, fs.JoinPath(source_dir, name + ".duckdb_secret"), plaintext)) {
			continue;
		}
		WriteEncryptedFile(fs, storage->PublicDirectory(), name, plaintext);
		if (data.bind_data->Cast<MigrateBind>().delete_source) {
			fs.RemoveFile(fs.JoinPath(source_dir, name + ".duckdb_secret"));
		}
		migrated++;
	}
	output.SetCardinality(1);
	output.SetValue(0, 0, Value::UBIGINT(migrated));
}

//===--------------------------------------------------------------------===//
// secret_vault_rotate():新 provider/密钥 重加密全部 vault 文件
//===--------------------------------------------------------------------===//

struct RotateBind : TableFunctionData {
	uint8_t new_provider = 0;
	string new_passphrase; // 空则不动 env
	string new_key;
	bool have_passphrase = false;
	bool have_key = false;
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		auto bind = make_uniq<RotateBind>();
		for (auto &kv : input.named_parameters) {
			if (kv.first == "new_provider") {
				if (!TryParseProviderName(kv.second.ToString(), bind->new_provider)) {
					throw InvalidInputException(
					    "secret_vault: new_provider must be keyring|passphrase|env (got '%s')",
					    kv.second.ToString());
				}
			} else if (kv.first == "new_passphrase") {
				bind->new_passphrase = kv.second.ToString();
				bind->have_passphrase = true;
			} else if (kv.first == "new_key") {
				bind->new_key = kv.second.ToString();
				bind->have_key = true;
			}
		}
		if (bind->new_provider == 0) {
			throw InvalidInputException("secret_vault_rotate: new_provider is required");
		}
		names.emplace_back("rotated");
		return_types.emplace_back(LogicalType::UBIGINT);
		return std::move(bind);
	}
};

static void RotateExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global = data.global_state->Cast<OnceGlobal>();
	if (global.done) {
		output.SetCardinality(0);
		return;
	}
	global.done = true;

	auto storage = GetVaultStorage();
	if (!storage) {
		throw InvalidInputException("secret_vault: storage not initialized");
	}
	auto &bind = data.bind_data->Cast<RotateBind>();
	auto &fs = LocalFS();
	auto dir = storage->PublicDirectory();
	auto names = ListBaseNames(fs, dir, VAULT_FILE_SUFFIX);
	if (names.empty()) {
		output.SetCardinality(1);
		output.SetValue(0, 0, Value::UBIGINT(0));
		return;
	}

	// 第一遍:全部用旧 provider 解密(任何失败即中止,不写任何文件)
	vector<string> plaintexts;
	plaintexts.reserve(names.size());
	for (auto &n : names) {
		plaintexts.push_back(ReadDecryptedFile(fs, fs.JoinPath(dir, n + VAULT_FILE_SUFFIX), n));
	}

	// 切换到新 provider/新密钥材料
	uint8_t old_provider = VaultProviderId();
	if (bind.have_passphrase) {
#ifdef _WIN32
		_putenv_s("SECRET_VAULT_PASSPHRASE", bind.new_passphrase.c_str());
#else
		setenv("SECRET_VAULT_PASSPHRASE", bind.new_passphrase.c_str(), 1);
#endif
	}
	if (bind.have_key) {
#ifdef _WIN32
		_putenv_s("SECRET_VAULT_KEY", bind.new_key.c_str());
#else
		setenv("SECRET_VAULT_KEY", bind.new_key.c_str(), 1);
#endif
	}
	SetVaultProviderGlobal(bind.new_provider);

	// 第二遍:重加密写回
	idx_t rotated = 0;
	try {
		for (idx_t i = 0; i < names.size(); i++) {
			WriteEncryptedFile(fs, dir, names[i], plaintexts[i]);
			// 卫生:明文副本即用即清
			auto *p = reinterpret_cast<data_ptr_t>(plaintexts[i].data());
			vault_zeroize_buf(p, plaintexts[i].size());
			rotated++;
		}
	} catch (std::exception &) {
		SetVaultProviderGlobal(old_provider);
		throw;
	}

	output.SetCardinality(1);
	output.SetValue(0, 0, Value::UBIGINT(rotated));
}

//===--------------------------------------------------------------------===//
// secret_vault_export():vault 文件 → 一次性加密封套 + 长密钥码(结果列显示一次)
//===--------------------------------------------------------------------===//

struct ExportBind : TableFunctionData {
	string file;
	string code; // 空 = 现场生成
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		auto bind = make_uniq<ExportBind>();
		bind->file = input.inputs[0].ToString();
		for (auto &kv : input.named_parameters) {
			if (kv.first == "code") {
				bind->code = kv.second.ToString();
			}
		}
		names.emplace_back("file");
		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("transport_code"); // 一次性,仅此结果行可见
		return_types.emplace_back(LogicalType::VARCHAR);
		names.emplace_back("secrets");
		return_types.emplace_back(LogicalType::UBIGINT);
		return std::move(bind);
	}
};

static void ExportExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global = data.global_state->Cast<OnceGlobal>();
	if (global.done) {
		output.SetCardinality(0);
		return;
	}
	global.done = true;

	auto storage = GetVaultStorage();
	if (!storage) {
		throw InvalidInputException("secret_vault: storage not initialized");
	}
	auto &bind = data.bind_data->Cast<ExportBind>();
	auto &fs = LocalFS();
	auto dir = storage->PublicDirectory();
	auto names = ListBaseNames(fs, dir, VAULT_FILE_SUFFIX);
	if (names.empty()) {
		throw InvalidInputException("secret_vault_export: no secrets to export in '%s'", dir);
	}

	// 解密全部 → payload
	vector<EnvelopeEntry> entries;
	entries.reserve(names.size());
	for (auto &n : names) {
		entries.push_back(EnvelopeEntry {n, ReadDecryptedFile(fs, fs.JoinPath(dir, n + VAULT_FILE_SUFFIX), n)});
	}
	string payload = EncodePayload(entries);

	// transport key:参数提供(自动化)或现场生成;封套加密写文件
	uint8_t transport[32];
	if (!bind.code.empty()) {
		if (vault_base32_to_key(bind.code.c_str(), transport) != 0) {
			throw InvalidInputException("secret_vault_export: %s", VaultLastError());
		}
	} else {
		vault_transport_key_generate(transport);
	}
	VaultBufGuard envelope;
	if (vault_envelope_seal(transport, reinterpret_cast<const_data_ptr_t>(payload.data()), payload.size(),
	                        &envelope.buf) != 0) {
		throw InvalidInputException("secret_vault_export: %s", VaultLastError());
	}
	{
		auto flags = FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW;
		auto writer = BufferedFileWriter(fs, bind.file, flags);
		writer.WriteData(envelope.buf.ptr, envelope.buf.len);
		writer.Flush();
	}
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(payload.data()), payload.size());

	// 一次性码仅在结果行出现(查询输出即"显示一次")
	char code_buf[64];
	vault_key_to_base32(transport, code_buf, sizeof(code_buf));
	output.SetCardinality(1);
	output.SetValue(0, 0, Value(bind.file));
	output.SetValue(1, 0, Value(string(code_buf)));
	output.SetValue(2, 0, Value::UBIGINT(names.size()));
}

//===--------------------------------------------------------------------===//
// secret_vault_import():封套 + 码(stdin 默认/参数) → 本机密钥重加密落盘
//===--------------------------------------------------------------------===//

struct ImportBind : TableFunctionData {
	string file;
	string code; // 空 = stdin 读一行
	string on_conflict = "error";
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		auto bind = make_uniq<ImportBind>();
		bind->file = input.inputs[0].ToString();
		for (auto &kv : input.named_parameters) {
			if (kv.first == "code") {
				bind->code = kv.second.ToString();
			} else if (kv.first == "on_conflict") {
				bind->on_conflict = StringUtil::Lower(kv.second.ToString());
				if (bind->on_conflict != "error" && bind->on_conflict != "overwrite" && bind->on_conflict != "skip") {
					throw InvalidInputException("secret_vault_import: on_conflict must be error|overwrite|skip");
				}
			}
		}
		names.emplace_back("imported");
		return_types.emplace_back(LogicalType::UBIGINT);
		names.emplace_back("skipped");
		return_types.emplace_back(LogicalType::UBIGINT);
		return std::move(bind);
	}
};

static void ImportExecute(ClientContext &context, TableFunctionInput &data, DataChunk &output) {
	auto &global = data.global_state->Cast<OnceGlobal>();
	if (global.done) {
		output.SetCardinality(0);
		return;
	}
	global.done = true;

	auto storage = GetVaultStorage();
	if (!storage) {
		throw InvalidInputException("secret_vault: storage not initialized");
	}
	auto &bind = data.bind_data->Cast<ImportBind>();
	auto &fs = LocalFS();

	// 码:参数优先;否则 stderr 提示 + stdin 读一行(管道/重定向均可)
	uint8_t transport[32];
	if (!bind.code.empty()) {
		if (vault_base32_to_key(bind.code.c_str(), transport) != 0) {
			throw InvalidInputException("secret_vault_import: %s", VaultLastError());
		}
	} else {
		fprintf(stderr, "secret_vault: enter transport code: ");
		fflush(stderr);
		char line[256];
		if (!fgets(line, sizeof(line), stdin) || line[0] == '\n' || line[0] == '\0') {
			throw InvalidInputException(
			    "secret_vault_import: no code on stdin; pipe it or pass code := '...' (automation, 会入 SQL 历史)");
		}
		string code(line);
		code.erase(code.find_last_not_of(" \r\n\t") + 1);
		if (vault_base32_to_key(code.c_str(), transport) != 0) {
			throw InvalidInputException("secret_vault_import: %s", VaultLastError());
		}
	}

	string envelope;
	if (!ReadWholeFile(fs, bind.file, envelope) || envelope.empty()) {
		throw InvalidInputException("secret_vault_import: cannot read envelope file '%s'", bind.file);
	}
	VaultBufGuard payload;
	if (vault_envelope_open(transport, reinterpret_cast<const_data_ptr_t>(envelope.data()), envelope.size(),
	                        &payload.buf) != 0) {
		throw InvalidInputException("secret_vault_import: %s", VaultLastError());
	}
	string payload_str(reinterpret_cast<const char *>(payload.buf.ptr), payload.buf.len);
	auto entries = DecodePayload(payload_str);
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(payload_str.data()), payload_str.size());

	auto dir = storage->PublicDirectory();
	idx_t imported = 0, skipped = 0;
	for (auto &e : entries) {
		string target = fs.JoinPath(dir, e.name + VAULT_FILE_SUFFIX);
		bool exists = fs.FileExists(target);
		if (exists && bind.on_conflict == "skip") {
			skipped++;
			continue;
		}
		if (exists && bind.on_conflict == "error") {
			throw InvalidInputException(
			    "secret_vault_import: secret '%s' already exists in '%s' (use on_conflict := 'overwrite' or 'skip')",
			    e.name, dir);
		}
		WriteEncryptedFile(fs, dir, e.name, e.plaintext);
		imported++;
	}
	output.SetCardinality(1);
	output.SetValue(0, 0, Value::UBIGINT(imported));
	output.SetValue(1, 0, Value::UBIGINT(skipped));
}

//===--------------------------------------------------------------------===//
// 注册
//===--------------------------------------------------------------------===//

void RegisterVaultFunctions(ExtensionLoader &loader) {
	// 注意:v2.0 表函数签名 API——位置参数经 FunctionSignature,具名参数经
	// GetSignature().WithTypedKkwargs(nats_rw 同款);bind 侧仍读 input.named_parameters。
	TableFunction migrate_fn(Identifier("secret_vault_migrate"), FunctionSignature(), MigrateExecute,
	                         MigrateBind::Create, OnceGlobal::Init);
	migrate_fn.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("delete_source", LogicalType(LogicalTypeId::BOOLEAN));
	});
	loader.RegisterFunction(migrate_fn);

	TableFunction rotate_fn(Identifier("secret_vault_rotate"), FunctionSignature(), RotateExecute,
	                        RotateBind::Create, OnceGlobal::Init);
	rotate_fn.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("new_provider", LogicalType(LogicalTypeId::VARCHAR));
		options.Add("new_passphrase", LogicalType(LogicalTypeId::VARCHAR));
		options.Add("new_key", LogicalType(LogicalTypeId::VARCHAR));
	});
	loader.RegisterFunction(rotate_fn);

	TableFunction export_fn(Identifier("secret_vault_export"),
	                        FunctionSignature().AddPositionalOnly("file", LogicalType(LogicalTypeId::VARCHAR)),
	                        ExportExecute, ExportBind::Create, OnceGlobal::Init);
	export_fn.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("code", LogicalType(LogicalTypeId::VARCHAR));
	});
	loader.RegisterFunction(export_fn);

	TableFunction import_fn(Identifier("secret_vault_import"),
	                        FunctionSignature().AddPositionalOnly("file", LogicalType(LogicalTypeId::VARCHAR)),
	                        ImportExecute, ImportBind::Create, OnceGlobal::Init);
	import_fn.GetSignature().WithTypedKwargs("options", [](TypedKwargs &options) {
		options.Add("code", LogicalType(LogicalTypeId::VARCHAR));
		options.Add("on_conflict", LogicalType(LogicalTypeId::VARCHAR));
	});
	loader.RegisterFunction(import_fn);
}

} // namespace duckdb
