# secret_vault 开发教训(2026-10 会话蒸馏)

> 按全局规则「重复陷阱提升」整理:每条 = 症状 → 根因 → **复用规则**。
> 来源:阶段零~三实施 + 四轮诚实审查。其中标 ⭐ 的条目直接复用自 duckdb-nats-rw 的
> `docs/lessons-2026-10.md` / fix-plan,并在本项目实测生效(防复发成功)。

## 一、DuckDB v2.0-dev 扩展 API 陷阱(钉 d54cbe3)

1. **头文件路径不可凭记忆写**。症状:连续 4 轮编译失败(`buffered_file_reader.hpp` 在
   `common/serializer/` 而非 `common/buffer/`;`uuid.hpp` 在 `common/types/`;缺
   `binary_deserializer.hpp`/`main/config.hpp`)。规则:写 include 前对钉定源码树
   `find src/include -name "<basename>"` **批量核对全部** include,不要修一个编译一轮。
2. **语法问题读 .gram 文件**。`CREATE PERSISTENT SECRET name IN <storage> (OPTIONS)` 的
   IN 子句在括号**之前**——parser 报错后读 `src/parser/peg/grammar/statements/create_secret.gram`
   定论。规则:SQL 语法疑义以 PEG 语法文件为准,不猜。
3. **表函数必须显式终止**。症状:status() 查询无限挂起(坏 key 时反而不挂——快乐路径才走到)。
   规则:一次性结果的表函数必须"发一行后 `SetCardinality(0)` 收尾",done 标志放
   `GlobalTableFunctionState`(`data.bind_data->Cast<T>()` 返回 const 引用,不能放 bind data)。
4. **表函数具名参数 API 已变**。`.named_parameters` 不存在;用
   `FunctionSignature().AddPositionalOnly("x", type)` + `GetSignature().WithTypedKwargs("options",
   [](TypedKwargs &o){ o.Add("k", type); })`,bind 侧仍读 `input.named_parameters`。
5. **扩展设置注册**:`DBConfig::AddExtensionOption(name, desc, LogicalType, default,
   callback, SetScope)`;回调是**函数指针** `void(*)(ClientContext&, SetScope, Value&)`。
   RESET 会以默认值重走回调(实测;勿凭 ResetOption 源码推断"RESET 不回调"——CR-H5 误报教训)。
6. **`secret.GetName()` 返回 Identifier**(非 string);AAD/路径统一用
   `GetName() + 后缀` 再反推基名,并维护 `identifier_map_t<string>`(归一化→原始名)防
   大小写归一化造成 AAD 不一致。
7. **SecretStorage 扩展点**:继承 `CatalogSetSecretStorage`(照抄 `LocalFileSecretStorage` +
   `DefaultSecretGenerator` 模板,替换路径/后缀/storage_mode);注册用公开的
   `SecretManager::LoadSecretStorage`;`DBConfig::GetConfig(db).secret_manager` 可达。
8. **内存序列化用 `MemoryStream`**(WriteStream+ReadStream 一体);整文件读用
   `BufferedFileReader::FileSize()+ReadData()`。
9. **dev 构建扩展版本串取自构建仓 git describe** → 跨仓 dev 扩展互载必须
   `SET allow_extensions_metadata_mismatch=true`(正式社区 CI 构建无此问题)。

## 二、构建与远端运维(Windows 工作站 + minis Docker)

10. ⭐ **LF 强制**(.gitattributes)、⭐ **cbindgen 头文件新鲜度编译闸**、⭐ **构建/测试命令
    timeout + 有界日志 + BUILD_EXIT 标记轮询**、⭐ **reldebug 而非 debug**(ASan 风暴)——
    全部继承 nats_rw,本项目零复发。
11. **docker cp 在该宿主不可靠**:曾一次事务失败把容器内文件清成 0 字节,随后对同路径 cp
    报成功仍为空,宿主侧文件也一度消失。规则:文件进容器一律走
    `docker exec -i <c> bash -c 'cat > path' < 本地文件` + **两侧 md5 校验**。
12. `docker exec bash -s` 吃 stdin 必须 `-i`;该镜像 PATH 不含 `/usr/local/cargo/bin`,
    每次 exec 前显式 `export PATH=/usr/local/cargo/bin:$PATH`。
13. **跨容器互通用 `docker network connect`**(builder 接入 `nats-rw_default` 即可按服务名
    连 NATS)。本机无 github 直连(git https 不通):duckdb 源码从既有树复制(免外网),
    网页类走 WebFetch、raw.githubusercontent 常复位(换 web reader)。

## 三、测试与脚本陷阱(最高频踩坑区)

14. **unittest 按文件单跑**:多个 .test 路径参数会被**拼接为一个过滤器**导致"No test cases
    matched"。`.test` 运行进程需注入 env(KEY/PASSPHRASE)与隔离 HOME。
15. **CLI `-list` 输出含全部语句结果**:多语句取值会吸进 `true` 等噪声行(E3 根因)。
    规则:取单值用独立查询或 `| tail -1`。
16. **`set -o pipefail` 吞断言**:`(cmd|grep) && echo PASS` 在 cmd 退出非零时永不打 PASS,
    却混在 FAIL:0 里假绿(B7a 教训)。规则:先 `OUT=$(cmd 2>&1 || true)` 再
    `if echo "$OUT"|grep -q`;**断言必须有可见的 PASS 字样输出**。
17. **每命令一进程的 helper 让 SET 不跨命令存活**(E1 首轮测的是默认值)。规则:会话级语义
    (SET/临时对象)必须在单条 `-c` 多语句内完成。
18. **跨轮残留破坏可重复性**:NATS 流名复用导致消息累积(1→3);旧 bundle(644)撞
    CREATE_NEW。规则:测试用资源(流名/文件路径)加时间戳,或前置清理 + 幂等且**安全**的
    覆盖(见 21)。
19. **local_file 同名 CREATE 跨进程冲突**:文件在即报 already exists——冲突场景用 cp 源文件
    构造,别重 CREATE。
20. **批量文本替换会误伤"故意的值"**:曾把测试里故意的错码 `A×52` 批量替换成正码。
    规则:批量替换必须显式排除清单。
21. **修 bug 时警惕引入更糟语义(r11 双例)**:export 幂等化 → 无条件删任意既有文件(后改为
    仅空文件/有效 magic 才覆盖);rotate 恢复 env → 空串退化(后区分 unsetenv)。
    规则:**破坏性操作前校验目标身份**;"恢复原状"要区分"原本存在/原本不存在"。

## 四、Rust/C++ 边界

22. **FFI 返回缓冲必须带回真实 capacity**:`Vec::from_raw_parts(ptr,len,len)` 在 cap≠len 时
    是分配器 UB(诚实审查一 HIGH-1)。结构体带 `cap` 字段,契约写进头文件注释。
23. **`Zeroizing<GenericArray>` 不满足 Zeroize**:密钥统一 `Zeroizing<[u8;32]>`,
    `Aes256Gcm::new(Key::from_slice(&*key))`。
24. **staticlib 不产 rlib**:集成测试需要 `crate-type=["staticlib","rlib"]`(corrosion 显式
    `--crate-type=staticlib` 不受影响)。
25. **匿名 namespace 结构体不可跨 TU**:共用 RAII/助手放头文件(如 VaultBufGuard)。
    const bind 字符串 zeroize 需 `const_cast`。
26. **cargo 测试并行共享进程 env** → 同名 Mutex(ENV_LOCK)串行化所有动 env 的用例;
    env 依赖的集成测试放独立 tests/ 二进制。
27. **算术当场验**:32B=256bit → base32 是 **52** 字符不是 56(断言写错一轮)。

## 五、诚实流程(六轮审查的方法论沉淀)

28. **修复本身必须复审**:r9/r11 的多处在修复中引入新问题(见 21)。每轮修复后:全量回归 +
    至少一个针对修复本身的新负向场景(如 E2e)。
29. **源码推断可能被实测推翻**(CR-H5 RESET 误报):能实测的结论不要停留在读码推断;
    误报要显式撤销并转常驻回归,不能悄悄放过。
30. **声明精度以证据为界**:"验收 7 全部达成"因一个未测负向(重放)被判过载;"FAIL:0"掩盖过
    从未触发的断言(16)。规则:汇总断言 = 可见 PASS 行数 + 逐场景点名,不数"没失败"。
31. **错误路径系统性欠测**:所有泄漏/半失败问题都出在异常分支(反序列化抛出/写盘 IO 失败/
    rotate 中途失败),快乐路径测试全绿也发现不了。规则:评审时专读 catch 块;泄漏类问题
    列 ASan 量化债,不凭"代码看着对"关闭。
32. **测试期望从实现语义推导,不从直觉推导**(HC7-H1):"写入即入快照"的直觉 vs 实际"擦除失效"设计——首跑即证伪。规则:写 reload/快照类断言前先读该路径的状态维护代码;没跑过的测试永远标注"未执行",禁止写成"已同步执行"。
33. **修复本身必须复审(实证二)**:r11 幂等化引入破坏性删除、r13 KEY_OLD 缓存引入密钥常驻未声明、r11 后 fleet-verify 首轮暴露毒化缺口——每轮修复带来的新代码/新测试都会引入新风险面,修复轮次必须自带针对性负向/边界用例。
34. **计划文档会静默漂移**(文件清单列不存在的文件/漏列新增脚本/函数签名与措辞滞后):
    每阶段收尾做一次 plan↔代码双向清单核对(曾两轮专审各抓 8~9 处),revisions 链是唯一
    可信审计轨迹;重大范围决策(如裁掉 fleet/重放降级 v1.1)必须当日回写 plan。
    **收尾 checklist(HC9 三连实证后的固化)**:宣告"完成"前逐项勾——①全部状态声明
    文件(README 状态块/UPDATING 计数/plan 待办项)与事实一致;②新增测试已执行且
    revisions 落盘;③容器/产物与 HEAD 无漂移(md5)。漂移三连实例:r14 停在"待恢复"、
    r10 误记"同步执行"、README/UPDATING 滞后两代。
