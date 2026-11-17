#!/bin/bash
# 审计修复验证(阶段:pre-fix-red / post-fix-green 二选一,第一参数)
# pre-fix-red: 仅跑 R1 段,预期"旧文件被删"(红证据)
# post-fix-green: 全量,预期全绿
set -u
export PATH=/usr/local/cargo/bin:$PATH
MODE=${1:-post-fix-green}
EV=/tmp/audit-fixes.log
: > "$EV"
log() { echo "$@" | tee -a "$EV"; }
PASS=0; FAIL=0
chk() { if [ "$2" = "$3" ]; then echo "[$1] PASS ($2=$3)" | tee -a "$EV"; PASS=$((PASS+1)); else echo "[$1] FAIL: got '$2' expect '$3'" | tee -a "$EV"; FAIL=$((FAIL+1)); fi; }

D=/workspace-ci/ext/build/release/duckdb
EXT=/workspace-ci/ext/build/release/extension/secret_vault/secret_vault.duckdb_extension
KEY=$(python3 -c "import base64;print(base64.b64encode(bytes([7])*32).decode())")
LD="LOAD '$EXT'; SET secret_vault_provider='env';"
run() { timeout 60 env SECRET_VAULT_KEY=$2 HOME=$1 $D -unsigned -noheader -list -c "$LD $3" 2>&1; }

log "=== audit-fixes $MODE $(date -u +%FT%TZ) ==="

# ---------- R1: 写路径原子性(rotate 写阶段注入:非法新 key 使 seal 在预删后失败) ----------
# 注入原理:rotate 读阶段用旧 key(有效)全部解密 → 切换 env 为非法新 key →
# 写第一个文件时 TryRemoveFile(旧) 已执行、vault_seal 抛错。
#   修复前:首个被处理的秘密文件丢失(预删已发生)
#   修复后:文件完好,仅报错
H=/tmp/vaf-r1; rm -rf $H; mkdir -p $H
run $H "$KEY" "CREATE PERSISTENT SECRET r1a IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'R1-A');" >/dev/null 2>&1
DIR=$H/.duckdb/stored_secrets_vault
OUT=$(run $H "$KEY" "SELECT rotated FROM secret_vault_rotate(new_provider := 'env', new_key := '!!!invalid-key###');")
if echo "$OUT" | grep -qi "encrypt failed"; then
  echo "[R1-seal-error] PASS" | tee -a "$EV"; PASS=$((PASS+1))
else
  echo "[R1-seal-error] FAIL: $OUT" | tee -a "$EV"; FAIL=$((FAIL+1))
fi
EXISTS=$([ -f $DIR/r1a.duckdb_secret.vault ] && echo yes || echo no)
N=$(run $H "$KEY" "SELECT count(*) FROM duckdb_secrets() WHERE name='r1a' AND persistent;" | tail -1 | tr -d ' ')
if [ "$MODE" = "pre-fix-red" ]; then
  chk R1-oldfile-alive "$EXISTS" "no"   # 修复前:预删已发生 → 文件消失(红证据)
  log "=== pre-fix-red done PASS=$PASS FAIL=$FAIL ==="
  exit 0
fi
chk R1-oldfile-alive "$EXISTS" "yes"
chk R1-readable-after "$N" "1"

# ---------- A1: rotate 读阶段中止零改写 ----------
H=/tmp/vaf-a1; rm -rf $H; mkdir -p $H
run $H "$KEY" "CREATE PERSISTENT SECRET a1x IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'A1-X'); CREATE PERSISTENT SECRET a1y IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'A1-Y');" >/dev/null 2>&1
VD=$H/.duckdb/stored_secrets_vault
truncate -s -8 $VD/a1y.duckdb_secret.vault   # 破坏第二个文件(快照前完成,属夹具一部分)
BEFORE=$(md5sum $VD/a1x.duckdb_secret.vault $VD/a1y.duckdb_secret.vault | awk '{print $1}')
OUT=$(run $H "$KEY" "SELECT rotated FROM secret_vault_rotate(new_provider := 'passphrase');")
if echo "$OUT" | grep -qi "decrypt failed"; then
  echo "[A1-abort-error] PASS" | tee -a "$EV"; PASS=$((PASS+1))
else
  echo "[A1-abort-error] FAIL: $OUT" | tee -a "$EV"; FAIL=$((FAIL+1))
fi
AFTER=$(md5sum $VD/a1x.duckdb_secret.vault $VD/a1y.duckdb_secret.vault | awk '{print $1}')
chk A1-zero-rewrite "$AFTER" "$BEFORE"

# ---------- A2: export 遇坏文件 → 报错且不产生封套 ----------
rm -f /tmp/vaf-env.svb
OUT=$(run $H "$KEY" "SELECT secrets FROM secret_vault_export('/tmp/vaf-env.svb');")
if echo "$OUT" | grep -qi "decrypt failed"; then
  echo "[A2-abort-error] PASS" | tee -a "$EV"; PASS=$((PASS+1))
else
  echo "[A2-abort-error] FAIL: $OUT" | tee -a "$EV"; FAIL=$((FAIL+1)); fi
chk A2-no-envelope "$([ -f /tmp/vaf-env.svb ] && echo yes || echo no)" "no"

# ---------- A6: import 无码错误文案全英文 ----------
OUT=$(echo -n "" | run $H "$KEY" "SELECT imported FROM secret_vault_import('/tmp/vaf-env.svb');" 2>&1)
CN=$(echo "$OUT" | grep -c "会入" || true)
chk A6-no-chinese "$CN" "0"

log "=== audit-fixes done PASS=$PASS FAIL=$FAIL ==="
