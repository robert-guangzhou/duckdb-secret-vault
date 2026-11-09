# 威胁模型 | Threat Model(secret_vault v0.1)

本文是 `secret_vault` 扩展的安全边界声明,与 Dev Plan 六章(安全考量)配套。

This document declares the security boundary of the `secret_vault` extension;
it pairs with chapter 6 (security considerations) of the dev plan.

## 资产与保护对象 | Assets & protected objects

- DuckDB `CREATE PERSISTENT SECRET` 落盘的 secret 文件(凭证:s3 key、数据库
  口令、NATS 凭证等),位于 `~/.duckdb/stored_secrets_vault/<name>.duckdb_secret.vault`。
- 一次性传输封套 `secret_vault_export()` 的 bundle 文件(承载全部 secret 的
  明文,仅由一次性 256-bit transport key 保护)。

- The on-disk secret files written by DuckDB `CREATE PERSISTENT SECRET`
  (credentials: s3 keys, database passwords, NATS credentials, ...) at
  `~/.duckdb/stored_secrets_vault/<name>.duckdb_secret.vault`.
- The one-time transport-envelope bundle file of `secret_vault_export()`
  (carries all secrets' plaintext, protected only by a single-use 256-bit
  transport key).

## In scope(本扩展承诺防护)| In scope (what this extension defends against)

| 威胁 | 机制 |
|---|---|
| 整机磁盘失窃 / 磁盘镜像 | AES-256-GCM 静态加密;密钥不在磁盘(见密钥来源) |
| 备份文件泄露(密文被一并备份) | 同上——备份只见密文 |
| 多用户主机上**其他 OS 用户**读取 | 密文 + 文件权限 600(`FILE_FLAGS_PRIVATE`);读取前校验私有性 |
| secret 文件被篡改/调包/改名 | AEAD tag + AAD 绑定(头部 40 字节 + secret 名),解密必失败且报错 |
| 传输封套在搬运通道被截获 | bundle 字节级不含明文与导出方密钥材料;满熵一次性码(52 字符 base32) |
| 意外的明文残留 | 序列化明文/解密明文/码/口令缓冲用后清零(zeroize;已知残余见"已知残余") |

| threat | mechanism |
|---|---|
| Whole-disk theft / disk imaging | AES-256-GCM encryption at rest; the key is not on disk (see key sources) |
| Backup leakage (ciphertext backed up too) | same — backups only ever see ciphertext |
| Reads by **other OS users** on a shared host | ciphertext + 600 file permissions (`FILE_FLAGS_PRIVATE`); privacy is verified before reading |
| Secret file tampered / swapped / renamed | AEAD tag + AAD binding (40-byte header + secret name); decryption fails loudly |
| Envelope intercepted in transit | bundle contains no plaintext and no exporter key material at the byte level; full-entropy one-time code (52-char base32) |
| Accidental plaintext residue | serialization plaintext / decrypted plaintext / code / passphrase buffers are zeroized after use (see "known residuals") |

## 密钥来源与静态属性 | Key sources & at-rest properties

| provider | 密钥保管 | 磁盘上是否出现密钥 |
|---|---|---|
| `keyring`(默认) | OS 凭据库(Windows Credential Manager / macOS Keychain / Linux Secret Service),首次使用自动生成 256-bit 主密钥 | 否(keychain 内部存储;Linux 无 Secret Service 时明确报错,不降级) |
| `passphrase` | 使用者记忆;Argon2id(m=64MiB,t=3,p=1)派生,per-file 随机 salt | 否 |
| `env`(无人值守) | 调度器按次注入 `SECRET_VAULT_KEY`(base64 32B,生成:`openssl rand -base64 32`) | 否(仅进程环境) |

| provider | key custody | key on disk? |
|---|---|---|
| `keyring` (default) | OS credential store (Windows Credential Manager / macOS Keychain / Linux Secret Service); random 256-bit master key generated on first use | no (keychain-internal storage; on Linux without a Secret Service it errors out instead of downgrading) |
| `passphrase` | human memory; Argon2id (m=64MiB, t=3, p=1) derivation with a per-file random salt | no |
| `env` (unattended) | injected per run by the scheduler as `SECRET_VAULT_KEY` (base64 32B; generate: `openssl rand -base64 32`) | no (process env only) |

口令强度要求(passphrase):≥4 个随机词或 ≥16 字符随机串;弱口令会被离线
暴力猜测(Argon2id 抬高每次猜测成本,但不替代熵)。

Passphrase strength requirement: ≥4 random words or a ≥16-char random string;
weak passphrases can be brute-forced offline (Argon2id raises the per-guess
cost but is no substitute for entropy).

## Out of scope(明确不防,与 ssh-agent / tresor 同界)| Out of scope (explicitly not defended; same boundary as ssh-agent / tresor)

1. **以同一 OS 用户身份运行的任意代码**:可直接调 DuckDB 读出解密后的
   secret,或读取进程内存/env(`/proc/<pid>/environ`、`ps eww`)。
2. **root / 管理员**:可读 OS keychain 与进程内存。
3. **进程内存转储 / core dump**:解密后的 secret 存在于进程内存。
4. **passphrase 遗忘**:无后门(后门=泄露面),文件永久不可恢复。
5. **同用户侧信道**:stdin 输码已隐藏回显(v1.1);一次性码经剪贴板/聊天
   记录泄露属操作面风险,须走密码管理器传递。

1. **Arbitrary code running as the same OS user**: it can simply call DuckDB
   to read the decrypted secrets, or read process memory / env
   (`/proc/<pid>/environ`, `ps eww`).
2. **root / administrators**: can read the OS keychain and process memory.
3. **Process memory dumps / core dumps**: decrypted secrets live in process
   memory.
4. **Forgotten passphrase**: no backdoor (a backdoor is a leak surface); the
   files are permanently unrecoverable.
5. **Same-user side channels**: stdin code entry has hidden echo (v1.1);
   leaking the one-time code via clipboard/chat history is an operational
   risk — hand it over through a password manager.

## 已知残余(诚实声明)| Known residuals (honesty statement)

- **keyring 主密钥常驻进程内存**(r13 起 OnceLock 缓存,CR-H4 修复引入):
  旧实现每次派生从 keychain 读入 Zeroizing 用后清零;新实现首次读取后缓存
  在进程静态存储中**全生命周期不清零**。威胁模型下可辩护(同用户攻击者
  out-of-scope,keychain 本身也是持久存储),但密钥驻留窗口从"使用瞬间"
  扩大到"进程存活期"——外部轮换 keyring 主密钥后需重启进程才生效。
- 序列化 MemoryStream 扩容过程中的**中间缓冲**未清零(有效长度与 capacity
  已清);v1.1 已实现 ZeroizingMemoryStream 后解决。
- 错误路径资源清零由 RAII 守卫保证,ASan 级泄漏量化未做(minis 上有 ASan
  风暴前科,以 RSS 启发式循环替代,结论按启发式标注)。
- `secret_vault_rotate` 写阶段中途失败会留下新旧密钥混合文件(进程自动恢复
  旧 provider/env;恢复步骤见 README)。极端场景需手动重设旧口令后重试。
- 封套 v1.1 起含 per-entry mtime,导入默认拒绝早于现存文件的条目(防旧包
  重放);对**目标不存在**的新条目无时间参照,不做重放判定。
- **KEY_OLD 轮换过渡窗口**(v1.1,env provider):`SECRET_VAULT_KEY_OLD` 与
  主密钥同为满权限密钥材料、共存于进程环境直至撤除——窗口期"旧钥泄露=旧
  密文全泄"的旧边界依旧存在;撤除步骤是 runbook 的必做收尾。
- passphrase 交互输入已隐藏回显(v1.1,termios/SetConsoleMode);关闭失败时
  降级为可见输入并打印 WARNING(不静默)。

- **The keyring master key stays in process memory** (OnceLock cache since
  r13, introduced by the CR-H4 fix): the old implementation read it from the
  keychain into a Zeroizing buffer on every derivation; the new one caches it
  in process static storage for the **whole process lifetime without
  zeroizing**. This is defensible under the threat model (same-user attackers
  are out of scope; the keychain itself is persistent storage anyway), but the
  key-residency window widens from "moment of use" to "process lifetime" —
  after externally rotating the keyring master key, the process must be
  restarted for it to take effect.
- **Intermediate buffers** during MemoryStream growth were not zeroized
  (length and capacity were); resolved in v1.1 by ZeroizingMemoryStream.
- Zeroization on error paths is guaranteed by RAII guards; ASan-grade leak
  quantification was not done (the build host has a history of ASan storms;
  an RSS-heuristic loop was used instead, and conclusions are labeled as
  heuristic).
- A mid-write failure of `secret_vault_rotate` leaves a mixed old/new-key
  directory (the process auto-restores the old provider/env; recovery steps in
  the README). In extreme cases, manually re-SET the old passphrase and retry.
- Since v1.1 envelopes carry a per-entry mtime, and import rejects entries
  older than existing files by default (anti-replay); entries whose **target
  does not exist** have no time reference and get no replay check.
- **KEY_OLD rotation transition window** (v1.1, env provider):
  `SECRET_VAULT_KEY_OLD` is full-power key material coexisting with the main
  key in process env until removed — during the window the old boundary
  "old-key leak = all old ciphertext leaked" still holds; the removal step is
  a mandatory end of the runbook.
- Passphrase interactive input has hidden echo (v1.1,
  termios/SetConsoleMode); if disabling echo fails it degrades to visible
  input and prints a WARNING (never silently).
