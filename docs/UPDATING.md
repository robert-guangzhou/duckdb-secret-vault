# UPDATING(DuckDB 版本升级 / repin 流程)| UPDATING (DuckDB upgrade / repin procedure)

本扩展依赖 DuckDB 内部 C++ 接口(`SecretStorage` 体系),**无 ABI 稳定承诺** ——
duckdb 升级可能破坏编译。流程如下(蓝本:tresor spec 014/038、nats_rw UPDATING)。

This extension depends on DuckDB-internal C++ interfaces (the `SecretStorage`
family) with **no ABI-stability promise** — a duckdb upgrade can break the
build. Follow the procedure below (modeled on tresor specs 014/038 and the
nats_rw UPDATING doc).

## 1. 决定新钉定 | Decide the new pin

- 本仓库 `duckdb/` 子模块指向新 commit(或复制新源码树)。
- 首先核对高危接口是否有签名/语义变化:
  - `src/include/duckdb/main/secret/secret_storage.hpp`(`CatalogSetSecretStorage`/
    `SecretStorage`/`DefaultGenerator`)
  - `SecretManager::LoadSecretStorage`、`DeserializeSecret`、
    `DBConfig::AddExtensionOption` 及 `set_option_callback_t` 签名
  - 表函数签名 API(`FunctionSignature`/`TypedKwargs`——v2.0 已改过一轮)
  - PEG 语法:`create_secret.gram`(`IN <storage>` 子句位置)
- 逐项与本仓 `docs/lessons-2026-10.md` 第一节对照。

- Point this repo's `duckdb/` submodule at the new commit (or copy in a new
  source tree).
- First check the high-risk interfaces for signature/semantic changes:
  - `src/include/duckdb/main/secret/secret_storage.hpp`
    (`CatalogSetSecretStorage` / `SecretStorage` / `DefaultGenerator`)
  - `SecretManager::LoadSecretStorage`, `DeserializeSecret`,
    `DBConfig::AddExtensionOption` and the `set_option_callback_t` signature
  - table-function signature API (`FunctionSignature` / `TypedKwargs` —
    already changed once in v2.0)
  - PEG grammar: `create_secret.gram` (position of the `IN <storage>` clause)
- Cross-check each item against section 1 of `docs/lessons-2026-10.md`.

## 2. 构建与最小验证 | Build & minimal verification

```bash
# builder 容器内 / inside the builder container
make reldebug
cargo test                      # rust 侧 17 用例:13 lib(含 KEY_OLD 回退)+ 2 FFI + 2 向量 /
                                # 17 Rust cases: 13 lib (incl. KEY_OLD fallback) + 2 FFI + 2 vectors
./build/reldebug/test/unittest test/sql/spike-storage-registration.test   # 存储注册冒烟 / storage-registration smoke
```

## 3. 全量回归 | Full regression

```bash
bash scripts/phase2-verify.sh
bash scripts/verify-edge-cases.sh
bash scripts/phase3-verify.sh   # NATS 联调段需 docker network connect + nats_rw 扩展在 /tmp /
                                # the NATS section needs docker network connect + the nats_rw extension in /tmp
```

## 4. 回写 | Write-back

- 本文件与 README 的版本口径;
- `docs/lessons-2026-10.md` 追加本轮升级新踩的坑;
- 若 `secret_vault_rust.h` 因 cbindgen 版本变化需重生成:容器内
  `bash rust/regen-header.sh` 并**提交产物**(构建确定性约定)。

- Version wording in this file and the README;
- Append newly-hit pitfalls of this upgrade round to `docs/lessons-2026-10.md`;
- If `secret_vault_rust.h` must be regenerated due to a cbindgen version
  change: run `bash rust/regen-header.sh` inside the container and **commit
  the artifact** (build-determinism convention).

## 已知版本敏感点(历史教训)| Known version-sensitive points (past lessons)

| 版本现象 | 教训 |
|---|---|
| dev 构建扩展版本串取自**构建仓** git describe | 跨仓 dev 扩展互载需 `allow_extensions_metadata_mismatch=true`(仅 dev) |
| v2.0 表函数具名参数 API 变更 | `FunctionSignature`+`TypedKwargs`,`.named_parameters` 已不存在 |
| 头文件位置随版本移动 | include 前对源码树 `find` 批量核对 |

| version symptom | lesson |
|---|---|
| dev-build extension version string comes from the **building repo's** git describe | cross-repo dev extension loading needs `allow_extensions_metadata_mismatch=true` (dev only) |
| v2.0 table-function named-argument API change | `FunctionSignature` + `TypedKwargs`; `.named_parameters` no longer exists |
| Header locations move between versions | batch-verify every include against the source tree with `find` before writing them |
