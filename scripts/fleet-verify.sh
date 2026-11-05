#!/usr/bin/env bash
# v1.1 fleet 验证(阶段A/B/C;TP-F1..F6;证据 → /workspace/tmp/phase5/)
# 长驻进程用 FIFO 模拟(TP-F2);tty 无回显用 pty(TP-F5)。
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH

EV=/workspace/tmp/phase5
mkdir -p "$EV"
WS=/workspace
SV=$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension
DUCKDB=$WS/build/reldebug/duckdb
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x07'*32).decode())")

CODE_K1=$(python3 -c "import base64;print(base64.b64encode(b'\xA1'*32).decode())")
CODE_K2=$(python3 -c "import base64;print(base64.b64encode(b'\xB2'*32).decode())")

{
echo "== env =="; $DUCKDB --version

echo "== F1/F2/F6. 长驻实例(FIFO):reload 热加载 + 失败聚合 + import 即时可见 =="
export HOME=/tmp/vh-p5; rm -rf "$HOME"; mkdir -p "$HOME"
FIFO=/tmp/p5fifo
rm -f "$FIFO"; mkfifo "$FIFO"
$DUCKDB -unsigned -noheader -list < "$FIFO" > /tmp/p5out.txt 2>&1 &
DPID=$!
exec 3>"$FIFO"
echo "LOAD '$SV'; SET secret_vault_provider='env';" >&3
echo "CREATE PERSISTENT SECRET f1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'F1-OLD');" >&3
echo "CALL secret_vault_reload();" >&3
sleep 1
# 外部:另一进程建 f2(新文件)+ craft 工具造损坏文件 g1
$DUCKDB -unsigned -noheader -list -c "LOAD '$SV'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET f2 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'F1-NEW');" >/dev/null
rm -rf /tmp/craft-p5 && cargo new --lib /tmp/craft-p5 -q 2>/dev/null
cat > /tmp/craft-p5/Cargo.toml <<TOML
[package]
name = "craftr5"
version = "0.1.0"
edition = "2021"
[dependencies]
secret_vault = { path = "/workspace/rust" }
TOML
cat > /tmp/craft-p5/src/lib.rs <<'RS'
pub fn mk(dir: &str) {
    let blob = secret_vault::seal(3, "g1", b"garbage-for-reload-aggregation-test").expect("seal");
    let p = std::path::Path::new(dir).join("g1.duckdb_secret.vault");
    std::fs::write(&p, &blob).unwrap();
    use std::os::unix::fs::PermissionsExt;
    std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).unwrap();
}
RS
mkdir -p /tmp/craft-p5/src/bin && printf 'fn main(){craftr5::mk(std::env::args().nth(1).unwrap().as_str())}\n' > /tmp/craft-p5/src/bin/craft.rs
(cd /tmp/craft-p5 && timeout 300 cargo run --bin craft -- "$HOME/.duckdb/stored_secrets_vault" >/dev/null 2>&1)
# reload:added=2(f2+g1) changed=0 removed=0 invalid=1(g1),detail 提及 g1;f2 热加载可见;g1 不入 catalog
echo "SELECT 'F1', added, changed, removed, invalid, detail FROM secret_vault_reload();" >&3
echo "SELECT 'F2', count(*) FROM duckdb_secrets() WHERE name='f2';" >&3
echo "SELECT 'F2b', count(*) FROM duckdb_secrets() WHERE name='g1';" >&3
sleep 1
# F6:外部进程导出 bundle → FIFO 内 import → 同进程立即可见
$DUCKDB -unsigned -noheader -list -c "LOAD '$SV'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET e1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'F6-1'); CREATE PERSISTENT SECRET e2 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'F6-2');" >/dev/null
F6CODE=$($DUCKDB -unsigned -noheader -list -c "LOAD '$SV'; SET secret_vault_provider='env'; SELECT transport_code FROM secret_vault_export('/tmp/f6.svb');" | tail -1)
echo "F6 code len=${#F6CODE}"
echo "SELECT 'F6i', imported, skipped FROM secret_vault_import('/tmp/f6.svb', code := '$F6CODE', on_conflict := 'overwrite');" >&3
echo "SELECT 'F6v', count(*) FROM duckdb_secrets() WHERE name IN ('e1','e2');" >&3
echo "SELECT 'DONE-MARK', 1;" >&3
exec 3>&-
wait $DPID 2>/dev/null || true
grep -E "\|F1\||\|F2\||\|F2b\||\|F6i\||\|F6v\|" /tmp/p5out.txt
F1V=$(grep -oP "F1\|\K\d+\|\d+\|\d+\|\d+" /tmp/p5out.txt | head -1)
[ "$F1V" = "2|0|0|1" ] && echo "[F1] reload stats 2|0|0|1 (added=2,invalid=1): PASS" || echo "[F1] FAIL: got '$F1V' expect 2|0|0|1"
grep -q "F1.*g1" /tmp/p5out.txt && echo "[F1b] detail mentions g1: PASS" || echo "[F1b] FAIL"
grep -qP "F2\|1" /tmp/p5out.txt && echo "[F2] hot-loaded f2 visible same-process: PASS" || echo "[F2] FAIL"
grep -qP "F2b\|0" /tmp/p5out.txt && echo "[F2b] invalid g1 excluded from catalog: PASS" || echo "[F2b] FAIL"
grep -qP "F6i\|\d+\|0" /tmp/p5out.txt && echo "[F6] import same-process imported (>=1, dir accumulates): PASS" || echo "[F6] FAIL"
grep -qP "F6v\|2" /tmp/p5out.txt && echo "[F6v] imported secrets visible immediately: PASS" || echo "[F6v] FAIL"

echo "== F3/F4. KEY_OLD 三态 + 文本无密钥字节 =="
export HOME=/tmp/vh-p5-f3; rm -rf "$HOME"; mkdir -p "$HOME"
D="$DUCKDB -unsigned -noheader -list"
# state0: 旧钥 K1 建 r1
export SECRET_VAULT_KEY="$CODE_K1"
$D -c "LOAD '$SV'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET r1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'F3-MARK');" >/dev/null
# state1: KEY=K2 + OLD=K1 → 回退可读
export SECRET_VAULT_KEY="$CODE_K2" SECRET_VAULT_KEY_OLD="$CODE_K1"
N=$($D -c "LOAD '$SV'; SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE name='r1';")
echo "[F3a] KEY=K2+OLD=K1 fallback read: N=$N (expect 1)"; [ "$N" = "1" ] && echo "[F3a] PASS" || echo "[F3a] FAIL"
# state2: 撤 OLD → AEAD 失败;错误文本无 K1/K2 字节
unset SECRET_VAULT_KEY_OLD
ERR=$($D -c "LOAD '$SV'; SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE name='r1';" 2>&1 | head -1)
echo "[F3b] without OLD: $ERR" | head -1
echo "$ERR" | grep -qi "AEAD tag mismatch" && echo "[F3b] AEAD failure: PASS" || echo "[F3b] FAIL"
echo "$ERR" | grep -q "$CODE_K1\|$CODE_K2" && echo "[F4] FAIL: key bytes leaked" || echo "[F4] error text free of key bytes: PASS"
# state3(正向收尾): runbook —— 部署双钥 + rotate 到 K2 + 撤 OLD → 无 OLD 可读
export SECRET_VAULT_KEY="$CODE_K2" SECRET_VAULT_KEY_OLD="$CODE_K1"
$D -c "LOAD '$SV'; SET secret_vault_provider='env'; SELECT rotated FROM secret_vault_rotate(new_provider := 'env');" >/dev/null
unset SECRET_VAULT_KEY_OLD
N=$($D -c "LOAD '$SV'; SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE name='r1';")
echo "[F3c] after runbook rotate + OLD removed: N=$N (expect 1)"; [ "$N" = "1" ] && echo "[F3c] PASS" || echo "[F3c] FAIL"

echo "== F5. tty 无回显(pty) =="
export HOME=/tmp/vh-p5-f5; rm -rf "$HOME"; mkdir -p "$HOME"
unset SECRET_VAULT_KEY
python3 - <<'PY'
import os, pty, select, subprocess, time, sys

SV = "/workspace/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension"
PASS = b"p5-hidden-pass"
master, slave = pty.openpty()
cmd = ["/workspace/build/reldebug/duckdb", "-unsigned", "-noheader", "-list", "-c",
       f"LOAD '{SV}'; SET secret_vault_provider='passphrase';"
       "CREATE PERSISTENT SECRET pp1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'pp-x');"
       "SELECT 'F5-DONE', count(*) FROM duckdb_secrets() WHERE name='pp1';"]
p = subprocess.Popen(cmd, stdin=slave, stdout=slave, stderr=slave)
os.close(slave)
sent_pass = False
buf = b""
deadline = time.time() + 90
done = False
while time.time() < deadline and not done:
    r, _, _ = select.select([master], [], [], 0.5)
    if r:
        try:
            chunk = os.read(master, 4096)
        except OSError:
            break
        if not chunk:
            break
        buf += chunk
        if not sent_pass and b"input hidden" in buf:
            time.sleep(0.4)
            os.write(master, PASS + b"\n")
            sent_pass = True
    if sent_pass and b"F5-DONE" in buf:
        done = True
        # 收尾:发送退出不需要;进程会在 EOF 前自行结束?CLI 从 -c 执行完即退出
        time.sleep(0.5)
        try:
            os.write(master, b"\n")
        except OSError:
            pass
try:
    p.wait(timeout=10)
except subprocess.TimeoutExpired:
    p.kill()
print("[F5] prompt-hidden-marker seen:", b"input hidden" in buf)
leak = PASS in buf
print("[F5] passphrase echoed:", leak)
print("[F5] F5-DONE row seen:", b"F5-DONE" in buf)
ok = (b"input hidden" in buf) and (not leak) and (b"F5-DONE" in buf)
print("[F5] hidden-echo verification:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
echo "F5_EXIT:$?"
} 2>&1 | tee "$EV/fleet-evidence.txt"
echo "EVIDENCE -> $EV/fleet-evidence.txt"
