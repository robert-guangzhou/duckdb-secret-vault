# UPDATING(duckdb 版本升级/repin 流程)

本扩展依赖 DuckDB 内部 C++ 接口(`SecretStorage` 体系),**无 ABI 稳定承诺**——
duckdb 升级可能破坏编译。流程如下(蓝本:tresor spec 014/038、nats_rw UPDATING)。

## 1. 决定新钉定

- 本仓库 `duckdb/` 子模块指向新 commit(或复制新源码树)。
- 首先核对高危接口是否有签名/语义变化:
  - `src/include/duckdb/main/secret/secret_storage.hpp`(`CatalogSetSecretStorage`/
    `SecretStorage`/`DefaultGenerator`)
  - `SecretManager::LoadSecretStorage`、`DeserializeSecret`、`DBConfig::AddExtensionOption`
    及 `set_option_callback_t` 签名
  - 表函数签名 API(`FunctionSignature`/`TypedKwargs`——v2.0 已改过一轮)
  - PEG 语法:`create_secret.gram`(`IN <storage>` 子句位置)
- 逐项与本仓 `docs/lessons-2026-10.md` 第一节对照。

## 2. 构建与最小验证

```bash
# builder 容器内
make reldebug
cargo test                      # rust 侧 16 用例(若 rust 无改动可直接复跑)
./build/reldebug/test/unittest test/sql/spike-storage-registration.test   # 存储注册冒烟
```

## 3. 全量回归

```bash
bash scripts/phase2-verify.sh
bash scripts/verify-edge-cases.sh
bash scripts/phase3-verify.sh   # NATS 联调段需 docker network connect + nats_rw 扩展在 /tmp
```

## 4. 回写

- 本文件与 README 的版本口径;
- `docs/lessons-2026-10.md` 追加本轮升级新踩的坑;
- 若 `secret_vault_rust.h` 因 cbindgen 版本变化需重生成:容器内
  `bash rust/regen-header.sh` 并**提交产物**(构建确定性约定)。

## 已知版本敏感点(历史教训)

| 版本现象 | 教训 |
|---|---|
| dev 构建扩展版本串取自**构建仓** git describe | 跨仓 dev 扩展互载需 `allow_extensions_metadata_mismatch=true`(仅 dev) |
| v2.0 表函数具名参数 API 变更 | `FunctionSignature`+`TypedKwargs`,`.named_parameters` 已不存在 |
| 头文件位置随版本移动 | include 前对源码树 `find` 批量核对 |
