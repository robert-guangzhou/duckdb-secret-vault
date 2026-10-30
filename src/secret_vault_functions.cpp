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
	string on_conflict = "error"; // P3-M2:消除静默覆盖;与 import 一致
	static unique_ptr<FunctionData> Create(ClientContext &context, TableFunctionBindInput &input,
	                                       vector<LogicalType> &return_types, vector<Identifier> &names) {
		auto bind = make_uniq<MigrateBind>();
		for (auto &kv : input.named_parameters) {
			if (kv.first == "delete_source") {
				bind->delete_source = kv.second.GetValue<bool>();
			} else if (kv.first == "on_conflict") {
				bind->on_conflict = StringUtil::Lower(kv.second.ToString());
				if (bind->on_conflict != "error" && bind->on_conflict != "overwrite" && bind->on_conflict != "skip") {
					throw InvalidInputException("secret_vault_migrate: on_conflict must be error|overwrite|skip");
				}
			}
		}
		names.emplace_back("migrated");
		return_types.emplace_back(LogicalType::UBIGINT);
		names.emplace_back("skipped");
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
	auto &bind = data.bind_data->Cast<MigrateBind>();
	idx_t migrated = 0, skipped = 0;
	for (auto &name : sources) {
		string src_path = fs.JoinPath(source_dir, name + ".duckdb_secret");
		// P3-L1:源明文文件权限校验(对齐 local_file 读取语义)
		if (!LocalFileSystem::IsPrivateFile(src_path, nullptr)) {
			throw IOException("The source secret file '%s' has incorrect permissions! Fix with chmod 600 and retry",
			                  src_path);
		}
		string target = fs.JoinPath(storage->PublicDirectory(), name + VAULT_FILE_SUFFIX);
		if (fs.FileExists(target)) {
			if (bind.on_conflict == "skip") {
				skipped++;
				continue;
			}
			if (bind.on_conflict == "error") {
				throw InvalidInputException(
				    "secret_vault_migrate: secret '%s' already exists in '%s' (use on_conflict := 'overwrite' or "
				    "'skip')",
				    name, storage->PublicDirectory());
			}
		}
		string plaintext;
		if (!ReadWholeFile(fs, src_path, plaintext)) {
			continue;
		}
		VaultWriteEncryptedFile(fs, storage->PublicDirectory(), name, plaintext.data(), plaintext.size());
		vault_zeroize_buf(reinterpret_cast<data_ptr_t>(plaintext.data()), plaintext.size());
		if (bind.delete_source) {
			fs.RemoveFile(src_path);
		}
		migrated++;
	}
	output.SetCardinality(1);
	output.SetValue(0, 0, Value::UBIGINT(migrated));
	output.SetValue(1, 0, Value::UBIGINT(skipped));
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
		plaintexts.push_back(VaultReadDecryptedFile(fs, fs.JoinPath(dir, n + VAULT_FILE_SUFFIX), n));
	}

	// 切换到新 provider/新密钥材料。
	// P3-M1:保留旧 env 值,写阶段失败时恢复——否则旧钥文件将无法解密
	// (半失败恢复步骤见 README:重设旧口令 → 重新 rotate)
	uint8_t old_provider = VaultProviderId();
	// HC2-M1:记录旧值是否"原本存在"——不存在者恢复时必须 unsetenv,
	// 否则恢复成空串会让 passphrase 派生退化为"空口令→AEAD 失败"的误导形态
	const char *old_pass_env = std::getenv("SECRET_VAULT_PASSPHRASE");
	bool had_pass = old_pass_env != nullptr;
	string old_pass = had_pass ? string(old_pass_env) : string();
	const char *old_key_env = std::getenv("SECRET_VAULT_KEY");
	bool had_key = old_key_env != nullptr;
	string old_key = had_key ? string(old_key_env) : string();
	auto restore_env = [&]() {
#ifdef _WIN32
		if (had_pass) {
			_putenv_s("SECRET_VAULT_PASSPHRASE", old_pass.c_str());
		} else {
			_putenv_s("SECRET_VAULT_PASSPHRASE", "");
		}
		if (had_key) {
			_putenv_s("SECRET_VAULT_KEY", old_key.c_str());
		} else {
			_putenv_s("SECRET_VAULT_KEY", "");
		}
#else
		if (had_pass) {
			setenv("SECRET_VAULT_PASSPHRASE", old_pass.c_str(), 1);
		} else {
			unsetenv("SECRET_VAULT_PASSPHRASE");
		}
		if (had_key) {
			setenv("SECRET_VAULT_KEY", old_key.c_str(), 1);
		} else {
			unsetenv("SECRET_VAULT_KEY");
		}
#endif
	};
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
			VaultWriteEncryptedFile(fs, dir, names[i], plaintexts[i].data(), plaintexts[i].size());
			// 卫生:明文副本即用即清
			auto *p = reinterpret_cast<data_ptr_t>(plaintexts[i].data());
			vault_zeroize_buf(p, plaintexts[i].size());
			rotated++;
		}
	} catch (std::exception &) {
		SetVaultProviderGlobal(old_provider);
		restore_env();
		// 卫生:失败路径剩余明文与新密钥材料也清零(P3-M3/HC2-M2)
		for (auto &pt : plaintexts) {
			vault_zeroize_buf(reinterpret_cast<data_ptr_t>(pt.data()), pt.size());
		}
		vault_zeroize_buf(reinterpret_cast<data_ptr_t>(const_cast<char *>(bind.new_passphrase.data())),
		                  bind.new_passphrase.size());
		vault_zeroize_buf(reinterpret_cast<data_ptr_t>(const_cast<char *>(bind.new_key.data())), bind.new_key.size());
		throw;
	}
	// 卫生:rotate 参数中的新口令/新密钥用后清零(不入残余内存)
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(const_cast<char *>(bind.new_passphrase.data())), bind.new_passphrase.size());
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(const_cast<char *>(bind.new_key.data())), bind.new_key.size());

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
		entries.push_back(EnvelopeEntry {n, VaultReadDecryptedFile(fs, fs.JoinPath(dir, n + VAULT_FILE_SUFFIX), n)});
	}
	string payload = EncodePayload(entries);

	// transport key:参数提供(自动化)或现场生成;封套加密写文件
	uint8_t transport[32];
	if (!bind.code.empty()) {
		if (vault_base32_to_key(bind.code.c_str(), transport) != 0) {
			throw InvalidInputException("secret_vault_export: %s", VaultLastError());
		}
		// 卫生:码等价于信封密钥,用后即清(P3-M3)
		vault_zeroize_buf(reinterpret_cast<data_ptr_t>(const_cast<char *>(bind.code.data())), bind.code.size());
	} else {
		vault_transport_key_generate(transport);
	}
	VaultBufGuard envelope;
	if (vault_envelope_seal(transport, reinterpret_cast<const_data_ptr_t>(payload.data()), payload.size(),
	                        &envelope.buf) != 0) {
		throw InvalidInputException("secret_vault_export: %s", VaultLastError());
	}
	{
		// P3-H2:信封承载全部 secret 明文(仅一次性码保护),权限不得弱于单文件密文。
		// 幂等仅对"安全可覆盖"目标放行:不存在 / 空文件 / 有效信封(magic 前 8 字节,
		// 对齐 Rust 侧 ENV_MAGIC=b"DSVLTENV"——若格式演进须同步此常量)。
		// HC2-H1:其余既有文件一律拒绝,杜绝误删任意路径内容。
		if (fs.FileExists(bind.file)) {
			char head[8] = {0};
			idx_t got = 0;
			auto reader = BufferedFileReader(fs, bind.file.c_str());
			got = MinValue<idx_t>(reader.FileSize(), 8);
			if (got > 0) {
				reader.ReadData(reinterpret_cast<data_ptr_t>(head), got);
			}
			bool empty = (got == 0);
			bool is_envelope = (got == 8 && std::memcmp(head, "DSVLTENV", 8) == 0);
			if (!empty && !is_envelope) {
				throw InvalidInputException(
				    "secret_vault_export: refusing to overwrite '%s': existing file is not a vault envelope (empty "
				    "file or DSVLTENV magic required)",
				    bind.file);
			}
			fs.TryRemoveFile(bind.file);
		}
		auto flags = FileFlags::FILE_FLAGS_WRITE | FileFlags::FILE_FLAGS_PRIVATE | FileFlags::FILE_FLAGS_FILE_CREATE_NEW;
		auto writer = BufferedFileWriter(fs, bind.file, flags);
		writer.WriteData(envelope.buf.ptr, envelope.buf.len);
		writer.Flush();
	}
	vault_zeroize_buf(reinterpret_cast<data_ptr_t>(payload.data()), payload.size());
	for (auto &e : entries) {
		vault_zeroize_buf(reinterpret_cast<data_ptr_t>(e.plaintext.data()), e.plaintext.size());
	}

	// 一次性码仅在结果行出现(查询输出即"显示一次");生成码之后才清 transport
	char code_buf[64] = {0};
	vault_key_to_base32(transport, code_buf, sizeof(code_buf));
	vault_zeroize_buf(transport, sizeof(transport));
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
	vault_zeroize_buf(transport, sizeof(transport));

	auto dir = storage->PublicDirectory();
	idx_t imported = 0, skipped = 0;
	try {
		for (auto &e : entries) {
			string target = fs.JoinPath(dir, e.name + VAULT_FILE_SUFFIX);
			bool exists = fs.FileExists(target);
			if (exists && bind.on_conflict == "skip") {
				skipped++;
				vault_zeroize_buf(reinterpret_cast<data_ptr_t>(e.plaintext.data()), e.plaintext.size());
				continue;
			}
			if (exists && bind.on_conflict == "error") {
				throw InvalidInputException(
				    "secret_vault_import: secret '%s' already exists in '%s' (use on_conflict := 'overwrite' or "
				    "'skip')",
				    e.name, dir);
			}
			VaultWriteEncryptedFile(fs, dir, e.name, e.plaintext.data(), e.plaintext.size());
			vault_zeroize_buf(reinterpret_cast<data_ptr_t>(e.plaintext.data()), e.plaintext.size());
			imported++;
		}
	} catch (std::exception &) {
		// 卫生:异常路径清零全部条目明文(HC2-M2;已清条目重复清零无害)
		for (auto &e : entries) {
			vault_zeroize_buf(reinterpret_cast<data_ptr_t>(e.plaintext.data()), e.plaintext.size());
		}
		throw;
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
		options.Add("on_conflict", LogicalType(LogicalTypeId::VARCHAR));
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
