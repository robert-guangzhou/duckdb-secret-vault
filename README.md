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
> **语义与假设(必读)**:
> - `secret_vault_provider` 是**进程级全局**设置:任一会话 SET 后对全进程生效,
>   多会话并发设不同值属未定义行为(单会话/单调度进程场景设计)。
> - 存储实例为**单 DatabaseInstance 假设**;同进程 attach 多个数据库并各自 LOAD 时,
>   settings 与 status 仅反映最后注册的实例。
> - 环境变量 `SECRET_VAULT_DIRECTORY` 可在 LOAD 前指定存储目录(默认
>   `~/.duckdb/stored_secrets_vault`);运行期变更用 `SET secret_vault_directory`
>   (仅空存储状态允许)。
> - 环境变量(`SECRET_VAULT_KEY/PASSPHRASE`)应在进程启动前设置;
>   运行中并发修改 env 与查询属未定义行为(Rust env 非线程安全)。
> - 崩溃/异常可能残留 `<name>.duckdb_secret.vault.tmp-<uuid>` 临时文件:
>   它们不被加载,可安全手动删除(`rm *.tmp-*`)。
>
> 设计文档:`../plans/secret-vault-duckdb-extension-plan.md`(r7)

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
