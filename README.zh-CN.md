# duckdb-secret-vault

[English](README.md) | **中文**

DuckDB 扩展 `secret_vault`:为 `CREATE PERSISTENT SECRET` 提供本地**加密**存储
(存储名 `local_encrypted`),替换默认 `local_file` 的明文落盘。

## 为什么需要它

DuckDB 默认把持久 secret 以**明文二进制**写在 `~/.duckdb/stored_secrets` ——
磁盘失窃、备份外泄、多用户主机上的其他账号,都可能直接读到你的 S3 key、
数据库口令、NATS 凭证。本扩展注册一个替代存储 `local_encrypted`:每个 secret
以 AES-256-GCM 密文落盘(per-file 随机 nonce,AEAD tag 绑定 secret 名 —— 改名/
篡改必然解密失败报错),文件保持 600 私有权限,密钥永不落盘。因为是加密
DuckDB 自己的序列化 blob,所以对任意 secret 类型(s3 / mysql / postgres /
nats_rw / …)都透明生效。

## 当前状态

v1.1 功能齐备:加密存储(keyring/passphrase/env 三种密钥来源)+ 运维函数
(`secret_vault_migrate/rotate/export/import/status/reload`)+ 一次性加密封套
跨实例转移(stdin 隐藏输码,含重放防护)+ fleet 增强(热加载 / KEY_OLD 轮换
过渡)。社区扩展提交准备中。

## 快速开始

```sql
-- 社区扩展被接受后可用:INSTALL secret_vault FROM community;
LOAD secret_vault;                         -- dev 构建需按路径 LOAD 并加 -unsigned

-- 选择密钥来源:keyring(默认)/ passphrase / env
SET secret_vault_provider = 'env';         -- 例:SECRET_VAULT_KEY 由调度器注入

-- 持久 secret 从此以密文落盘(DSVLT 头 + AES-256-GCM)
CREATE PERSISTENT SECRET my_s3 IN local_encrypted (
    TYPE s3, KEY_ID 'AKIA...', SECRET 'shhh', REGION 'us-east-1');

-- 新进程自动加载;duckdb_secrets() 照常脱敏
SELECT name, storage, secret_string FROM duckdb_secrets();

-- 也可设为默认存储(无 IN 子句的 CREATE 自动路由到这里)
SET default_secret_storage = 'local_encrypted';
```

## 密钥来源

| provider | 密钥保管 | 磁盘上出现密钥? |
|---|---|---|
| `keyring`(默认) | OS 凭据库(Windows Credential Manager / macOS Keychain / Linux Secret Service),首次使用自动生成 256-bit 主密钥 | 否;Linux 无 Secret Service 时明确报错,不降级 |
| `passphrase` | 使用者记忆;Argon2id(m=64MiB, t=3, p=1)+ per-file 随机 salt 派生 | 否 |
| `env`(无人值守) | 调度器/CI 按次注入 `SECRET_VAULT_KEY`(base64 32B) | 否(仅进程环境) |

## 密钥生成指南(部署前必读)

- **env provider**(调度/CI):`export SECRET_VAULT_KEY="$(openssl rand -base64 32)"`
  —— 由调度器凭据存储注入,**禁止**写进脚本/任务定义明文;同用户进程可读
  `/proc/<pid>/environ` 属已声明威胁边界(见 [THREAT-MODEL](docs/THREAT-MODEL.md))。
- **keyring provider**(工作站默认):无需生成 —— 首次使用自动在 OS 凭据库生成
  256-bit 主密钥;轮换主密钥 = 清除凭据条目 `duckdb.secret_vault/master` 后
  `secret_vault_rotate`(长驻进程缓存主密钥,轮换后需重启进程)。
- **passphrase provider**:口令需 ≥4 个随机词或 ≥16 字符随机串;弱口令可被
  离线暴力猜测(Argon2id 抬高单次成本但不替代熵);**遗忘即数据不可恢复**。
- 传输封套的一次性码:导出结果行显示一次,经密码管理器/口头传递;再导出即
  作废旧包。
- **import 即时可见**(v1.1):导入落盘后当前进程立即可用(内部触发热加载)。
- **KEY_OLD 轮换过渡**(v1.1,仅 env provider):换钥窗口内设
  `SECRET_VAULT_KEY_OLD=旧钥` 可继续读旧密文;轮换 runbook:
  ① 全实例部署 {KEY=新, KEY_OLD=旧} 并重启 → ② 发布新密文
  (`secret_vault_rotate` 或目录重写)→ ③ 观察期 → ④ 撤除 KEY_OLD。

## 常用操作

```sql
LOAD secret_vault;
SET secret_vault_provider = 'env';              -- 或 keyring(默认)/ passphrase
CREATE PERSISTENT SECRET s IN local_encrypted (TYPE s3, ...);
SELECT * FROM secret_vault_status();
SELECT * FROM secret_vault_migrate();           -- local_file 明文迁入(默认保留源)
SELECT * FROM secret_vault_rotate(new_provider := 'env');
SELECT * FROM secret_vault_export('/tmp/b.svb'); -- 一次性码显示于结果行
SELECT * FROM secret_vault_import('/tmp/b.svb'); -- 默认 stdin 输码(隐藏回显);code := '...' 供自动化(会入 SQL 历史)
SELECT * FROM secret_vault_reload();             -- 热加载:长驻实例重扫目录(增/改/删对齐,坏文件聚合报告)
```

## 语义与假设(必读)

- `secret_vault_migrate` 同名冲突默认报错,`on_conflict := 'overwrite'|'skip'`
  显式选择;源文件须为 600 私有权限。
- `secret_vault_rotate` 为两遍式:读阶段任一失败不动盘;**写阶段中途失败会
  留下新旧密钥混合状态**(进程已自动恢复旧 provider 与旧环境密钥)—— 恢复
  步骤:重新以旧口令/密钥 SET 后再次 rotate。
- `secret_vault_export` 的信封文件以 600 私有权限落盘(承载全部 secret 明文,
  仅一次性码保护)。
- passphrase 的交互提示只在 stdin 为 tty 且未设环境变量时出现,**输入隐藏
  回显**(v1.1;termios/SetConsoleMode 关闭失败时降级为可见输入并打印
  WARNING);多连接并发触发提示属未定义行为(单会话设计)。
- `secret_vault_reload` 前请先关闭正在使用 secret 的活动查询/连接(reload 会
  整体重建该存储的 catalog;持旧条目引用的活动查询行为未定义)。
- `secret_vault_provider` 是**进程级全局**设置:任一会话 SET 后对全进程生效,
  多会话并发设不同值属未定义行为(单会话/单调度进程场景设计)。
- 存储实例为**单 DatabaseInstance 假设**;同进程 attach 多个数据库并各自
  LOAD 时,settings 与 status 仅反映最后注册的实例。
- 环境变量 `SECRET_VAULT_DIRECTORY` 可在 LOAD 前指定存储目录(默认
  `~/.duckdb/stored_secrets_vault`);运行期变更用
  `SET secret_vault_directory`(仅空存储状态允许)。
- 环境变量(`SECRET_VAULT_KEY/PASSPHRASE`)应在进程启动前设置;运行中并发
  修改 env 与查询属未定义行为(Rust env 非线程安全)。
- 崩溃/异常可能残留 `<name>.duckdb_secret.vault.tmp-<uuid>` 临时文件:它们
  不被加载,可安全手动删除(`rm *.tmp-*`)。

## 已知边界

文件损坏(篡改/坏密钥遗留)时 `CREATE OR REPLACE` 会因懒加载失败而报错,
唯一恢复路径是**手动删除该 secret 文件后重建**(与 local_file 损坏文件语义
一致)。
