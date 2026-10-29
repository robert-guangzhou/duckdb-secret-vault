# duckdb-secret-vault

DuckDB 扩展 `secret_vault`:为 `CREATE PERSISTENT SECRET` 提供本地**加密**存储
(存储名 `local_encrypted`),替换默认 `local_file` 的明文落盘。

> **当前状态:阶段零(spike)** —— SecretStorage 注册/CRUD/自动加载/脱敏接缝已打通,
> 落盘暂为明文序列化;AES-256-GCM 加密、KeyProvider(keyring/passphrase/env)、
> 一次性封套 export/import 按计划分阶段接入。
>
> 设计文档:`../plans/secret-vault-duckdb-extension-plan.md`(r4)

## 构建(minis Docker 模式,与 duckdb-nats-rw 同链路)

```bash
# builder 容器内
make build_debug          # 或 GEN=ninja make build
build/debug/duckdb -c "LOAD 'build/debug/extension/secret_vault/secret_vault.duckdb_extension'; \
  CREATE PERSISTENT SECRET t (TYPE vault_test, USER 'u', PASSWORD 'p') IN local_encrypted; \
  SELECT name, storage, secret_string FROM duckdb_secrets();"
```

## 阶段零出口判据(证据:tmp/secret-vault/phase0/)

1. `local_encrypted` 存储注册成功,`CREATE PERSISTENT SECRET ... IN local_encrypted` 全链路可用;
2. `SET default_secret_storage='local_encrypted'` 后无 IN 子句的 CREATE 正确路由;
3. 新进程自动加载 vault 目录中的 secret,`duckdb_secrets()` 脱敏正常;
4. keyring crate 在 minis 容器(Linux/无 dbus)的可用性结论。
