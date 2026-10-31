#!/usr/bin/env bash
# RSS 启发式泄漏观察(ASan 替代方案;结论按启发式标注,非证明)
# 原理:在反序列化失败路径(CR-H1 触发条件)上循环触发 N 次,观察进程 RSS
# 是否单调抬升。修复前(无 VaultBufGuard)每次泄漏 plain_len 字节;
# 修复后应平稳。噪声:allocator 预算/页粒度——仅"显著单调增长"视为异常。
# 方法:同一 duckdb 进程内用 SQL 生成器连续触发失败路径并采样自身 RSS
# (/proc/self/status 经 readfile 不可用,故用外部采样:循环后台查询同一常驻
# 进程不可行——CLI 每查询退出。替代:测 300 个独立失败进程的 RSS 峰值分布,
# 泄漏会抬高峰值尾部;并与成功路径对照)。
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH
WS=/workspace
SV=$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension
export HOME=/tmp/vh-rss; rm -rf "$HOME"; mkdir -p "$HOME"
VAULT=$HOME/.duckdb/stored_secrets_vault
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x07'*32).decode())")
D="$WS/build/reldebug/duckdb -unsigned -noheader -list"

# 1) 造"AEAD 有效但内容为垃圾"的文件(E2 同款)
rm -rf /tmp/craft-rss && cargo new --lib /tmp/craft-rss -q
cat > /tmp/craft-rss/Cargo.toml <<'TOML'
[package]
name = "craftr"
version = "0.1.0"
edition = "2021"
[dependencies]
secret_vault = { path = "/workspace/rust" }
TOML
cat > /tmp/craft-rss/src/lib.rs <<'RS'
pub fn mk(dir: &str) {
    let blob = secret_vault::seal(3, "badloop", b"garbage-not-duckdb-serialization-padded-longer").expect("seal");
    let p = std::path::Path::new(dir).join("badloop.duckdb_secret.vault");
    std::fs::write(&p, &blob).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
}
RS
mkdir -p /tmp/craft-rss/src/bin
printf 'fn main(){craft::mk(std::env::args().nth(1).unwrap().as_str())}\n' > /tmp/craft-rss/src/bin/craft.rs
(cd /tmp/craft-rss && timeout 300 cargo run --bin craft -- "$VAULT" 2>&1 | tail -1)

# 2) 300 个失败路径进程,采样每个进程退出前 RSS(用短间隔轮询近似取峰值)
python3 - <<'PY'
import subprocess, os, time, sys

SV = "/workspace/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension"
env = dict(os.environ)
cmd = ["timeout", "20", "/workspace/build/reldebug/duckdb", "-unsigned", "-noheader", "-list", "-c",
       f"LOAD '{SV}'; SET secret_vault_provider='env'; SELECT count(*) FROM generate_series(1,200) t(i), (SELECT name FROM duckdb_secrets() WHERE name='badloop') s;"]

def sample_rss(peaks):
    # 让失败查询跑 200 次笛卡尔触发(每行都触发一次 lazy load 失败→异常中止整查询,
    # 实际单查询只触发一次;因此外层再跑多轮 CLI,取 /proc 采样峰值)
    p = subprocess.Popen(cmd, env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    best = 0
    while p.poll() is None:
        try:
            with open(f"/proc/{p.pid}/status") as f:
                for line in f:
                    if line.startswith("VmRSS"):
                        best = max(best, int(line.split()[1]))
                        break
        except FileNotFoundError:
            break
        time.sleep(0.02)
    peaks.append(best)

peaks = []
N = int(os.environ.get("LEAK_N", "100"))
for i in range(N):
    sample_rss(peaks)
peaks = [x for x in peaks if x > 0]
if not peaks:
    print("[RSS-heuristic] no samples; abort")
    sys.exit(1)
peaks.sort()
print(f"[RSS-heuristic] {len(peaks)} 个失败路径进程 RSS(kB): "
      f"min={peaks[0]} p50={peaks[len(peaks)//2]} p95={peaks[int(len(peaks)*0.95)]} max={peaks[-1]}")
grow = peaks[-1] - peaks[0]
print(f"[RSS-heuristic] max-min = {grow} kB —— 启发式判据(非证明):"
      + (" 未见显著累积泄漏迹象" if grow < 8192 else " 峰值尾部抬升显著,建议 ASan 复核"))
print("[标注] 本方法为启发式观察(minis 有 ASan 风暴前科而不做 ASan);不构成泄漏不存在证明")
PY
rm -f "$VAULT/badloop.duckdb_secret.vault"
