#pragma once

#include "duckdb/catalog/default/default_generator.hpp"
#include "duckdb/main/secret/secret_manager.hpp"
#include "duckdb/main/secret/secret_storage.hpp"
#include "duckdb/common/serializer/write_stream.hpp"

#include "secret_vault_rust.h" // PROVIDER_* / VaultBuf / vault_* C ABI

#include <atomic>
#include <mutex>
#include <cstring>
#include <unordered_map>
#include <utility>

namespace duckdb {

//! 对外存储名:CREATE PERSISTENT SECRET ... IN local_encrypted / duckdb_secrets().storage
extern const string LOCAL_ENCRYPTED_STORAGE_NAME;

//! tie-break 偏移:紧邻 local_file(LOCAL_FILE_STORAGE_OFFSET=20)之后
constexpr int64_t LOCAL_ENCRYPTED_STORAGE_OFFSET = 21;

//! 文件名:<name>.duckdb_secret.vault
constexpr const char *VAULT_FILE_SUFFIX = ".duckdb_secret.vault";

//! reload 统计(TP-F1;v1.1 fleet 阶段A/r14)
struct VaultReloadStats {
	idx_t added = 0;
	idx_t changed = 0;
	idx_t removed = 0;
	idx_t invalid = 0;
};

//===--------------------------------------------------------------------===//
// 全局配置(经 DuckDB settings 暴露,见 secret_vault_extension.cpp)
//===--------------------------------------------------------------------===//

//! 当前密钥来源 id(PROVIDER_KEYRING/PASSPHRASE/ENV);SET secret_vault_provider 更新
uint8_t VaultProviderId();
void SetVaultProviderGlobal(uint8_t id);
const char *VaultProviderName(uint8_t id);
//! 密钥来源合法名 → id;非法名返回 false
bool TryParseProviderName(const string &name, uint8_t &out);
//! 拷贝 Rust 侧最近一次错误(线程本地,须立即拷贝——见 secret_vault_rust.h 契约)
string VaultLastError();

//! VaultBuf RAII 守卫(全面 review CR-H1/H2 修复):析构 = zeroize + 按契约释放,
//! 正常与异常路径均不泄漏、明文不留残留。storage 与 functions 共用。
struct VaultBufGuard {
	VaultBuf buf {nullptr, 0, 0};
	~VaultBufGuard();
};

//! CR-H3(r13)彻底方案:清零型内存写流。扩容时旧缓冲先清零再释放,
//! 析构清零——序列化明文不因容器扩容残留在已释放堆内存。
class ZeroizingMemoryStream final : public WriteStream {
public:
	ZeroizingMemoryStream() : capacity_(4096), data_(new data_t[capacity_]) {
	}
	~ZeroizingMemoryStream() override {
		if (data_) {
			std::memset(data_, 0, capacity_);
			delete[] data_;
		}
	}
	ZeroizingMemoryStream(const ZeroizingMemoryStream &) = delete;
	ZeroizingMemoryStream &operator=(const ZeroizingMemoryStream &) = delete;

	void WriteData(const_data_ptr_t buffer, idx_t write_size) override {
		if (pos_ + write_size > capacity_) {
			idx_t new_cap = capacity_ * 2;
			while (pos_ + write_size > new_cap) {
				new_cap *= 2;
			}
			data_t *fresh = new data_t[new_cap];
			std::memcpy(fresh, data_, pos_);
			std::memset(data_, 0, capacity_); // 旧缓冲清零后释放(核心)
			delete[] data_;
			data_ = fresh;
			capacity_ = new_cap;
		}
		std::memcpy(data_ + pos_, buffer, write_size);
		pos_ += write_size;
	}
	idx_t GetPosition() const {
		return pos_;
	}
	data_t *GetData() {
		return data_;
	}

private:
	idx_t capacity_;
	idx_t pos_ = 0;
	data_t *data_;
};

//! 公共助手(P3-L2 去重:storage 与 functions 共用同一实现)
//! seal(当前 provider)→ 私有权限临时文件 + 原子 rename
void VaultWriteEncryptedFile(class FileSystem &fs, const string &dir, const string &name, const void *plaintext,
                             size_t plain_len);
//! 整读密文文件 + vault_open(AAD 绑定 name)
string VaultReadDecryptedFile(class FileSystem &fs, const string &path, const string &name);

//! 全局存储实例(单 DB 假设,README 语义节;settings/status/函数层经此触达)
class VaultSecretStorage;
VaultSecretStorage *GetVaultStorage();
void SetVaultStorage(VaultSecretStorage *storage);

//===--------------------------------------------------------------------===//
// 存储与懒加载生成器
//===--------------------------------------------------------------------===//

//! VaultSecretStorage 的懒加载生成器:读 `.duckdb_secret.vault` 密文 →
//! vault_open 解密(AAD 绑定原始文件名) → MemoryStream 反序列化。
class VaultSecretGenerator : public DefaultGenerator {
public:
	VaultSecretGenerator(Catalog &catalog, SecretManager &secret_manager, identifier_set_t &persistent_secrets,
	                     identifier_map_t<string> &file_names, string vault_path_p);

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
	//! 归一化 Identifier → 原始文件名(无后缀):AAD 与路径都以原始文件名为准,
	//! 避免大小写归一化导致的 AAD 不一致
	identifier_map_t<string> file_names;
	string vault_path;
};

//! 加密持久化 secret 存储:WriteSecret = 序列化→vault_seal→密文原子落盘;
//! 懒加载 = vault_open→反序列化;权限/原子 rename 行为对齐 LocalFileSecretStorage。
class VaultSecretStorage : public CatalogSetSecretStorage {
public:
	VaultSecretStorage(SecretManager &manager, DatabaseInstance &db, const string &name, const string &vault_path);

	static string DefaultVaultPath(DatabaseInstance &db);

	//! SET secret_vault_directory:仅在尚未加载/写入任何 secret 时允许(否则须重启)
	void RebindDirectory(const string &new_path);

	//! 诊断:当前目录下 .vault 文件数
	idx_t CountFilesOnDisk();
	//! 诊断:当前存储目录
	const string &PublicDirectory() {
		return vault_path;
	}

	//! v1.1 fleet(阶段A/r14):重扫目录 → 逐文件校验(失败聚合不中断)→
	//! 全量重建 CatalogSet+生成器(热加载;活动连接边界见 README)。
	//! detail 聚合失败文本(无敏感字节)。
	VaultReloadStats Reload(string &detail);

protected:
	void WriteSecret(const BaseSecret &secret, OnCreateConflict on_conflict) override;
	void RemoveSecret(const string &name, OnEntryNotFound on_entry_not_found) override;

private:
	void ScanDirectory();

	SecretManager &manager;
	identifier_set_t persistent_secrets;
	identifier_map_t<string> file_names;
	//! 文件状态快照(reload 变更检测):原始名 → (mtime µs, size)。
	//! 与 catalog 懒加载无关(不随加载擦除),仅 reload/写/删时维护。
	std::unordered_map<string, std::pair<int64_t, uint64_t>> file_states_;
	string vault_path;
	mutex rebind_lock;
	//! 是否发生过写入(限制 secret_vault_directory 只能在空状态变更)
	std::atomic<bool> has_written {false};
};

} // namespace duckdb
