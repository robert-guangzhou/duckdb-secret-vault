# duckdb-secret-vault

DuckDB 扩展 `secret_vault`:为 `CREATE PERSISTENT SECRET` 提供本地**加密**存储
(存储名 `local_encrypted`),替换默认 `local_file` 的明文落盘。

> **当前状态:v1.1 功能齐备(阶段零~四全部完成)**
> —— 加密存储(AES-256-GCM,keyring/passphrase/env 三 provider)+ 运维函数
> (`secret_vault_migrate/rotate/export/import/status/reload`)+ 一次性封套跨实例转移
> (stdin 隐藏输码,含重放防护)+ nats_rw 真实联调 + **v1.1 fleet 增强**(热加载/KEY_OLD
> 轮换过渡)。阶段四文档(THREAT-MODEL/UPDATING/description.yml)已完成;
> 唯一待办 = GitHub 发布与社区提交(需外网管道)。
>
> ## 密钥生成指南(部署前必读)
>
> - **env provider**(调度/CI):`export SECRET_VAULT_KEY="$(openssl rand -base64 32)"`
>   ——由调度器凭据存储注入,**禁止**写进脚本/任务定义明文;同用户进程可读
>   `/proc/<pid>/environ` 属已声明边界(见 THREAT-MODEL)。
> - **keyring provider**(工作站默认):无需生成——首次使用自动在 OS 凭据库生成
>   256-bit 主密钥;轮换主密钥 = 清除凭据条目 `duckdb.secret_vault/master` 后
>   `secret_vault_rotate`(注意:长驻进程缓存主密钥,轮换后需重启进程)。
> - **passphrase provider**:口令需 ≥4 个随机词或 ≥16 字符随机串;弱口令可被
>   离线暴力猜测(Argon2id 抬高单次成本但不替代熵);**遗忘即数据不可恢复**。
> - 传输封套的一次性码:导出结果行显示一次,经密码管理器/口头传递;再导出即作废旧包。
> - **import 即时可见**(v1.1):导入落盘后当前进程立即可用(内部触发热加载)。
> - **KEY_OLD 轮换过渡**(v1.1,env provider):换钥窗口内设 `SECRET_VAULT_KEY_OLD=旧钥`
>   可继续读旧密文;轮换 runbook:①全实例部署 {KEY=新,KEY_OLD=旧} 并重启 → ②发布新密文
>   (`secret_vault_rotate` 或目录重写)→ ③观察期 → ④撤除 KEY_OLD。仅 env provider;
>   keyring 主密钥被进程缓存,**外部轮换 keyring 主密钥后需重启进程**。
>
> ## 常用操作
>
> ```sql
> LOAD secret_vault;
> SET secret_vault_provider = 'env';            -- 或 keyring(默认)/passphrase
> CREATE PERSISTENT SECRET s IN local_encrypted (TYPE s3, ...);
> SELECT * FROM secret_vault_status();
> SELECT * FROM secret_vault_migrate();          -- local_file 明文迁入(默认保留源)
> SELECT * FROM secret_vault_rotate(new_provider := 'env');
> SELECT * FROM secret_vault_export('/tmp/b.svb');  -- 一次性码显示于结果行
> SELECT * FROM secret_vault_import('/tmp/b.svb');  -- 默认 stdin 输码(隐藏回显);code := '...' 供自动化(会入 SQL 历史)
> SELECT * FROM secret_vault_reload();              -- 热加载:长驻实例重扫目录(增/改/删对齐,坏文件聚合报告)
> ```
>
> ⚠ 已知边界:文件损坏(篡改/坏密钥遗留)时 `CREATE OR REPLACE` 会因懒加载失败而报错,
> 唯一恢复路径是**手动删除该 secret 文件后重建**(与 local_file 损坏文件语义一致)。
>
> **语义与假设(必读)**:
> - `secret_vault_migrate` 同名冲突默认报错,`on_conflict := 'overwrite'|'skip'` 显式选择;源文件须为 600 私有权限。
> - `secret_vault_rotate` 为两遍式:读阶段任一失败不动盘;**写阶段中途失败会留下新旧密钥混合状态**(进程已自动恢复旧 provider 与旧环境密钥)——恢复步骤:重新以旧口令/密钥 SET 后再次 rotate。
> - `secret_vault_export` 的信封文件以 600 私有权限落盘(承载全部 secret 明文,仅一次性码保护)。
> - passphrase 的交互提示只在 stdin 为 tty 且未设环境变量时出现,**输入隐藏回显**
>   (v1.1;termios/SetConsoleMode 关闭失败时降级为可见输入并打印 WARNING);多连接并发触发提示属未定义行为(单会话设计)。
> - `secret_vault_reload` 前请先关闭正在使用 secret 的活动查询/连接(reload 会整体重建
>   该存储的 catalog;持旧条目引用的活动查询行为未定义)。
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
