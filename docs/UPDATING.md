# UPDATING (DuckDB upgrade / repin procedure)

**English** | [中文](UPDATING.zh-CN.md)

This extension depends on DuckDB-internal C++ interfaces (the `SecretStorage`
family) with **no ABI-stability promise** — a duckdb upgrade can break the
build. Follow the procedure below (modeled on tresor specs 014/038 and the
nats_rw UPDATING doc).

## 1. Decide the new pin

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
- Cross-check each item against section 1 of `lessons-2026-10.md`.

## 2. Build & minimal verification

```bash
# inside the builder container
make reldebug
cargo test                      # 17 Rust cases: 13 lib (incl. KEY_OLD fallback) + 2 FFI + 2 vectors
./build/reldebug/test/unittest test/sql/spike-storage-registration.test   # storage-registration smoke
```

## 3. Full regression

```bash
bash scripts/phase2-verify.sh
bash scripts/verify-edge-cases.sh
bash scripts/phase3-verify.sh   # the NATS section needs docker network connect + the nats_rw extension in /tmp
```

## 4. Write-back

- Version wording in this file and the README;
- Append newly-hit pitfalls of this upgrade round to `lessons-2026-10.md`;
- If `secret_vault_rust.h` must be regenerated due to a cbindgen version
  change: run `bash rust/regen-header.sh` inside the container and **commit
  the artifact** (build-determinism convention).

## Known version-sensitive points (past lessons)

| version symptom | lesson |
|---|---|
| dev-build extension version string comes from the **building repo's** git describe | cross-repo dev extension loading needs `allow_extensions_metadata_mismatch=true` (dev only) |
| v2.0 table-function named-argument API change | `FunctionSignature` + `TypedKwargs`; `.named_parameters` no longer exists |
| Header locations move between versions | batch-verify every include against the source tree with `find` before writing them |
