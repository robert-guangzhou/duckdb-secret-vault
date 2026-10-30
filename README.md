# duckdb-secret-vault

DuckDB 扩展 `secret_vault`:为 `CREATE PERSISTENT SECRET` 提供本地**加密**存储
(存储名 `local_encrypted`),替换默认 `local_file` 的明文落盘。

> **当前状态:阶段零(spike)+ 阶段一(Rust 加密核心)+ 阶段二(C++ 加密存储层)完成**
> —— SecretStorage 接缝已验证;AES-256-GCM 核心单测/FFI/向量全绿;**落盘已是真密文**
> (DSVLT 头 + AEAD,at-rest 字节断言通过),settings(secret_vault_provider/secret_vault_directory)
> 与 `secret_vault_status()` 已实现。一次性封套 export/import 属阶段三。
>
> ⚠ 已知边界:文件损坏(篡改/坏密钥遗留)时 `CREATE OR REPLACE` 会因懒加载失败而报错,
> 唯一恢复路径是**手动删除该 secret 文件后重建**(与 local_file 损坏文件语义一致)。
>
> 设计文档:`../plans/secret-vault-duckdb-extension-plan.md`(r6)

## 构建(minis Docker 模式,与 duckdb-nats-rw 同链路)

```bash
# secret-vault-builder 容器内(注意 PATH 需含 /usr/local/cargo/bin)
cd /workspace
make reldebug                # 实际 Makefile 目标:debug / reldebug / release
build/reldebug/duckdb -unsigned -c "LOAD 'build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; \
  CREATE PERSISTENT SECRET t IN local_encrypted (TYPE vault_test, USER 'u', PASSWORD 'p'); \
  SELECT name, storage, secret_string FROM duckdb_secrets();"
```

注意:dev 构建的扩展未签名,CLI 必须带 `-unsigned` 才能 LOAD。

## Rust 核心单测(阶段一,与 DuckDB 构建无关)

```bash
cd rust
cargo test                       # 单测 + FFI 回归 + 向量回归
VECTORS_GEN=1 cargo test --test vectors   # 首次生成 tests/vectors.json 后提交
```

## 阶段零/一出口判据(证据:../../tmp/secret-vault/phase0,1/)

1. `local_encrypted` 存储注册成功,`CREATE PERSISTENT SECRET ... IN local_encrypted`(IN 子句在括号选项之前)全链路可用;
2. `SET default_secret_storage='local_encrypted'` 后无 IN 子句的 CREATE 正确路由;
3. 新进程自动加载 vault 目录中的 secret,`duckdb_secrets()` 脱敏正常,文件权限 600;
4. keyring crate 在 minis 容器(无 dbus)明确报错不降级;Windows 本机验证待办(需本地 Rust 工具链);
5. cargo test 全绿(格式/AEAD 向量/AAD 绑定/nonce/口令/env 校验/zeroize 钩子/FFI 契约/向量回归)。
