# 威胁模型(secret_vault v0.1)

本文是 `secret_vault` 扩展的安全边界声明,与 Dev Plan 六章(安全考量)配套。

## 资产与保护对象

- DuckDB `CREATE PERSISTENT SECRET` 落盘的 secret 文件(凭证:s3 key、数据库口令、
  NATS 凭证等),位于 `~/.duckdb/stored_secrets_vault/<name>.duckdb_secret.vault`。
- 一次性传输封套 `secret_vault_export()` 的 bundle 文件(承载全部 secret 的明文,
  仅由一次性 256-bit transport key 保护)。

## In scope(本扩展承诺防护)

| 威胁 | 机制 |
|---|---|
| 整机磁盘失窃 / 磁盘镜像 | AES-256-GCM 静态加密;密钥不在磁盘(见密钥来源) |
| 备份文件泄露(密文被一并备份) | 同上——备份只见密文 |
| 多用户主机上**其他 OS 用户**读取 | 密文 + 文件权限 600(`FILE_FLAGS_PRIVATE`);读取前校验私有性 |
| secret 文件被篡改/调包/改名 | AEAD tag + AAD 绑定(头部 40 字节 + secret 名),解密必失败且报错 |
| 传输封套在搬运通道被截获 | bundle 字节级不含明文与导出方密钥材料;满熵一次性码(52 字符 base32) |
| 意外的明文残留 | 序列化明文/解密明文/码/口令缓冲用后清零(zeroize;已知残余见"已知残余") |

## 密钥来源与静态属性

| provider | 密钥保管 | 磁盘上是否出现密钥 |
|---|---|---|
| `keyring`(默认) | OS 凭据库(Windows Credential Manager / macOS Keychain / Linux Secret Service),首次使用自动生成 256-bit 主密钥 | 否(keychain 内部存储;Linux 无 Secret Service 时明确报错,不降级) |
| `passphrase` | 使用者记忆;Argon2id(m=64MiB,t=3,p=1)派生,per-file 随机 salt | 否 |
| `env`(无人值守) | 调度器按次注入 `SECRET_VAULT_KEY`(base64 32B,生成:`openssl rand -base64 32`) | 否(仅进程环境) |

口令强度要求(passphrase):≥4 个随机词或 ≥16 字符随机串;弱口令会被离线暴力猜测
(Argon2id 抬高每次猜测成本,但不替代熵)。

## Out of scope(明确不防,与 ssh-agent / tresor 同界)

1. **以同一 OS 用户身份运行的任意代码**:可直接调 DuckDB 读出解密后的 secret,
   或读取进程内存/env(`/proc/<pid>/environ`、`ps eww`)。
2. **root / 管理员**:可读 OS keychain 与进程内存。
3. **进程内存转储 / core dump**:解密后的 secret 存在于进程内存。
4. **passphrase 遗忘**:无后门(后门=泄露面),文件永久不可恢复。
5. **同用户侧信道**:stdin 输码为明文回显(tty 无回显需 termios,列入后续增强);
   一次性码经剪贴板/聊天记录泄露属操作面风险,须走密码管理器传递。

## 已知残余(诚实声明)

- **keyring 主密钥常驻进程内存**(r13 起 OnceLock 缓存,CR-H4 修复引入):旧实现每次
  派生从 keychain 读入 Zeroizing 用后清零;新实现首次读取后缓存在进程静态存储中
  **全生命周期不清零**。威胁模型下可辩护(同用户攻击者 out-of-scope,keychain 本身
  也是持久存储),但密钥驻留窗口从"使用瞬间"扩大到"进程存活期"——外部轮换
  keyring 主密钥后需重启进程才生效。

- 序列化 MemoryStream 扩容过程中的**中间缓冲**未清零(有效长度与 capacity 已清);
  v1.1 已实现 ZeroizingMemoryStream 后解决。
- 错误路径资源清零由 RAII 守卫保证,ASan 级泄漏量化未做(minis 上有 ASan 风暴前科,
  以 RSS 启发式循环替代,结论按启发式标注)。
- `secret_vault_rotate` 写阶段中途失败会留下新旧密钥混合文件(进程自动恢复旧
  provider/env;恢复步骤见 README)。极端场景需手动重设旧口令后重试。
- 封套 v1.1 起含 per-entry mtime,导入默认拒绝早于现存文件的条目(防旧包重放);
  对**目标不存在**的新条目无时间参照,不做重放判定。
- **KEY_OLD 轮换过渡窗口**(v1.1,env provider):`SECRET_VAULT_KEY_OLD` 与主密钥同为
  满权限密钥材料、共存于进程环境直至撤除——窗口期"旧钥泄露=旧密文全泄"的旧边界
  依旧存在;撤除步骤是 runbook 的必做收尾。
- passphrase 交互输入已隐藏回显(v1.1,termios/SetConsoleMode);关闭失败时降级为
  可见输入并打印 WARNING(不静默)。
