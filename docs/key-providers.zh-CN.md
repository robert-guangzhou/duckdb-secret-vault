# 密钥提供方对比与 FAQ(keyring / passphrase / env)

[English](key-providers.md) | **中文**(英文版待补)

> 本文整合 `secret_vault` 三种密钥来源的优劣对比与常见问题。
> 依据:实现代码实测 + [THREAT-MODEL](THREAT-MODEL.zh-CN.md) 已声明边界(2026-11)。

## 一、总览对比

| 维度 | keyring(默认) | passphrase | env |
|---|---|---|---|
| 密钥本质 | 256-bit 随机主密钥,首用自动生成 | 人记忆的口令,Argon2id(m=64MiB,t=3)派生 | base64 32B,调度器按次注入 |
| 密钥落盘 | ❌ 只在 OS 凭据库 | ❌ 只在人脑 | ❌ 只在进程环境 |
| 密钥强度 | **满熵,最优** | 取决于人:≥4 随机词/≥16 字符才够 | 满熵(若 `openssl rand` 生成) |
| 无人值守 | ⚠️ 需 OS keychain 服务在跑(Linux 无 dbus 直接报错) | ⚠️ 需退化为 `SECRET_VAULT_PASSPHRASE` 环境变量(变相 env) | ✅ **为调度器/CI 设计** |
| 跨实例分发 | ❌ 每台机器独立主密钥,目录拷贝无效 → 只能走封套 | ✅ 口令在人脑,目录拷贝+同口令即可 | ✅ 同 key 部署即同读 |
| 轮换路径 | 清凭据条目 → rotate → **必须重启进程**(OnceLock 缓存) | 两遍式 rotate(中失败留混合态,有恢复步骤) | **KEY_OLD 过渡窗口**(v1.1,零停机,仅此 provider) |
| 每次 open 开销 | 直接用缓存密钥(实测 ~0.24ms/op) | **每文件独立 salt → 每次都跑完整 Argon2id(64MiB 内存硬)**,最慢 | 直接用密钥,最快 |
| 平台依赖 | Windows/macOS 原生;Linux 要 Secret Service | 无 | 无 |
| 丢失后果 | 凭据条目删了=密文不可恢复 | **口令遗忘=永久不可恢复**(无后门是设计) | key 泄漏/丢失同理 |
| 额外攻击面 | 同用户代码可读 keychain(边界外) | **密文可被离线暴力猜口令** | `/proc/<pid>/environ` 同用户可读、`ps eww`、core dump(边界外已声明) |

### 各自的独特优势

- **keyring**:零操作成本(用户什么都不用记/不用配),熵最高,工作站交互场景体验最好;密钥驻留窗口从"使用瞬间"扩大到"进程存活期"是唯一让步(THREAT-MODEL 已声明)。
- **passphrase**:唯一**不依赖任何机器设施**(无 OS 服务、无调度器)的方案;口令随人走,跨机器搬密文最直观;Argon2id 把单次猜测成本抬高 64MiB 内存+时间,但对**低熵口令**只是减速带不是防线。
- **env**:调度器凭据存储做唯一信任锚(密钥永不进脚本/任务定义);全 fleet 同 key 时目录级同步即可;独有的 **KEY_OLD 轮换 runbook**({新+旧} 并存 → 重加密 → 撤旧)是三个里唯一零停机的轮换路径。

### 各自的硬伤

- **keyring**:headless Linux(无 dbus)直接不可用(明确报错不降级);跨机器即失效;外部轮换后需重启进程。
- **passphrase**:性能最差(每文件全量 Argon2id 派生);人为因素是最大风险(弱口令=形同虚设,遗忘=数据蒸发);多连接并发触发交互提示属未定义行为。
- **env**:密钥暴露面最宽(进程环境是多处可读的"半公开"位置);运行中改 env 与查询并发是未定义(Rust env 非线程安全);一旦有人把 key 写进脚本/任务定义,整个模型退化。

### 选型建议

| 场景 | 推荐 |
|---|---|
| 个人工作站、交互式使用 | **keyring**(默认即为此) |
| 服务器/CI/调度器(dolphinscheduler 等) | **env** |
| 无 OS 设施、少量机器、人可到场 | **passphrase** |
| fleet 大规模分发 | env 做运行态 + **一次性封套**(export/import)做初始引导——封套让 key 永远不进传输通道 |

三者可经 `secret_vault_rotate(new_provider := ...)` 互相切换,不是一次性选择。

## 二、FAQ:keyring 机器重启会失效吗?

**不会失效 —— 机器重启恰恰是 keyring 的设计场景**。主密钥存在 OS 的**持久凭据库**里(磁盘上),重启后新进程照常读回:

| 平台 | 存储机制 | 重启后 |
|---|---|---|
| Windows | Credential Manager(条目 `duckdb.secret_vault/master`,按用户落盘,DPAPI 加密) | ✅ 持久,登录该用户即 |
| macOS | Keychain | ✅ 持久 |
| Linux | Secret Service(gnome-keyring 等)的磁盘存储(通常 `~/.local/share/keyring/`,用登录口令加密) | ✅ 持久,但见下 |

实测印证(keyring 扩展层 e2e):**进程 1** 生成主密钥 → **进程 2**(全新进程)从 Credential Manager 读回并解密成功 —— 重启后开机的新进程与此完全同构,只是间隔更长。

### 三个"看起来像失效"的边界情况

1. **Linux 无图形登录的服务器**:Secret Service 的盘上 keyring 通常在图形登录时解锁;headless 服务器若没配 `pam_gnome_keyring` 之类的自动解锁,守护进程可能处于锁定态 → 扩展会**明确报 KeyUnavailable**(不静默降级)。表现是"重启后报错",根因是服务未解锁而非密钥丢了 —— 登录解锁后即恢复。这也是 headless 场景推荐 env 的原因。
2. **OnceLock 进程内缓存**:主密钥首次读取后缓存在进程静态区**全生命周期** —— 这只影响"运行中外部换了 keychain 条目需重启进程生效",与机器重启无关(重启本来就是新进程)。
3. **真正的密钥丢失**:OS 磁盘损坏、用户 profile 被删、手动删掉凭据条目 —— 那就不是"失效"而是**密文永久不可恢复**(与 passphrase 遗忘同级,无后门是设计)。

### 灾备提示

keyring 主密钥**绑定机器+用户**(Windows 下 DPAPI 加密,拷走凭据库文件到别的机器也解不开)—— 所以 keyring 体系下的跨机灾备只能走**一次性封套**(`secret_vault_export`/`import`)把 secret 转移到有自己密钥体系的实例,而不是备份凭据库本身。
