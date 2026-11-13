#!/bin/bash
# phase7: 真实后端集成测试(pg / mysql / minio-S3)—— 在 sv-e2e-builder 容器内运行
# plan: plans/secret-vault-backend-e2e.md(TP-B1..B15)
# 前置:build/v2release(DuckDB v2.0.0 + secret_vault)已构建;
#       sv-e2e-pg / sv-e2e-mysql / sv-e2e-minio 容器已 seed。
# 证据 → /workspace/tmp/phase7/e2e.log(逐断言 PASS/FAIL 可见输出;教训 #16 防假绿)
set -u
export PATH="/usr/local/cargo/bin:$PATH"
EV=${EV:-/workspace/tmp/phase7}
D=/workspace/build/v2release/duckdb
EXT=/workspace/build/v2release/extension/secret_vault/secret_vault.duckdb_extension
LOG="$EV/e2e.log"
mkdir -p "$EV"
: > "$LOG"

# 凭证(一次性测试容器;参数化便于复跑)
PG_HOST=${PG_HOST:-sv-e2e-pg};      PG_USER=${PG_USER:-svuser};  PG_PASS=${PG_PASS:-sv-pg-pass-E2E-2026};  PG_DB=${PG_DB:-sv_e2e}
MY_HOST=${MY_HOST:-sv-e2e-mysql};   MY_USER=${MY_USER:-svuser};  MY_PASS=${MY_PASS:-sv-mysql-pass-E2E-2026}; MY_DB=${MY_DB:-sv_e2e}
S3_HOST=${S3_HOST:-sv-e2e-minio};   S3_KEY=${S3_KEY:-svminio};   S3_SECRET=${S3_SECRET:-sv-minio-secret-E2E-2026}; S3_BUCKET=${S3_BUCKET:-sv-e2e}

export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(bytes([7])*32).decode())")
export HOME=/root

PASS=0; FAIL=0
chk() { # chk <name> <期望输出子串> <实际输出>
  if printf '%s' "$3" | grep -qF "$2"; then echo "[$1] PASS" | tee -a "$LOG"; PASS=$((PASS+1));
  else echo "[$1] FAIL: expect '$2' got: $(printf '%s' "$3" | tail -c 200)" | tee -a "$LOG"; FAIL=$((FAIL+1)); fi
}
run() { timeout 120 "$D" -unsigned -noheader -list -c "$1" 2>&1; }
LD="LOAD '$EXT'; SET secret_vault_provider='env';"

echo "=== phase7 backend e2e $(date -u +%FT%TZ) ===" | tee -a "$LOG"
echo "duckdb: $(run 'SELECT version();' | head -1)" | tee -a "$LOG"

# ---- 扩展就位(B0)----
OUT=$(run "INSTALL httpfs; INSTALL postgres_scanner; INSTALL mysql_scanner; $LD LOAD httpfs; LOAD postgres_scanner; LOAD mysql_scanner; SELECT 'B0 loaded';")
chk B0_extensions "B0 loaded" "$OUT"

# ==== PostgreSQL(B1..B5)====
OUT=$(run "$LD CREATE PERSISTENT SECRET pg1 IN local_encrypted (TYPE postgres, HOST '$PG_HOST', PORT 5432, DATABASE '$PG_DB', USER '$PG_USER', PASSWORD '$PG_PASS', SCOPE 'postgresql://$PG_HOST:5432/$PG_DB'); SELECT 'B1';")
chk B1_pg_create "B1" "$OUT"

OUT=$(python3 - "$HOME/.duckdb/stored_secrets_vault/pg1.duckdb_secret.vault" "$PG_PASS" <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
print(b[:8]==b'DSVLT\x00\x00\x00', b[10]==3, b.count(sys.argv[2].encode()))
PY
)
chk B2_pg_at_rest "True True 0" "$OUT"

# v2.0.0: postgres_scan 已移除,改 ATTACH + 显式 SECRET(凭证只在点名时注入)
OUT=$(run "$LD LOAD postgres_scanner; ATTACH 'host=$PG_HOST port=5432 dbname=$PG_DB' AS pgdb (TYPE postgres, SECRET pg1); SELECT marker FROM pgdb.public.sv_probe;")
chk B3_pg_scan "PG-E2E-MARK-2026" "$OUT"

OUT=$(run "$LD SELECT secret_string FROM duckdb_secrets() WHERE name='pg1';")
if printf '%s' "$OUT" | grep -qF "$PG_PASS"; then echo "[B4_pg_redact] FAIL: password visible" | tee -a "$LOG"; FAIL=$((FAIL+1));
else echo "[B4_pg_redact] PASS" | tee -a "$LOG"; PASS=$((PASS+1)); fi

OUT=$(run "$LD LOAD postgres_scanner; ATTACH 'host=$PG_HOST port=5432 dbname=$PG_DB' AS pgdb (TYPE postgres); SELECT marker FROM pgdb.public.sv_probe;")
chk B5_pg_noscope "no password supplied" "$OUT"

# ==== MySQL(B6..B10)====
OUT=$(run "$LD CREATE PERSISTENT SECRET my1 IN local_encrypted (TYPE mysql, HOST '$MY_HOST', PORT 3306, DATABASE '$MY_DB', USER '$MY_USER', PASSWORD '$MY_PASS', SCOPE 'mysql://$MY_HOST:3306/$MY_DB'); SELECT 'B6';")
chk B6_mysql_create "B6" "$OUT"

OUT=$(python3 - "$HOME/.duckdb/stored_secrets_vault/my1.duckdb_secret.vault" "$MY_PASS" <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
print(b[:8]==b'DSVLT\x00\x00\x00', b[10]==3, b.count(sys.argv[2].encode()))
PY
)
chk B7_mysql_at_rest "True True 0" "$OUT"

OUT=$(run "$LD LOAD mysql_scanner; ATTACH 'host=$MY_HOST port=3306 database=$MY_DB' AS mydb (TYPE mysql, SECRET my1); SELECT marker FROM mydb.$MY_DB.sv_probe;")
chk B8_mysql_scan "MYSQL-E2E-MARK-2026" "$OUT"

OUT=$(run "$LD SELECT secret_string FROM duckdb_secrets() WHERE name='my1';")
if printf '%s' "$OUT" | grep -qF "$MY_PASS"; then echo "[B9_mysql_redact] FAIL" | tee -a "$LOG"; FAIL=$((FAIL+1));
else echo "[B9_mysql_redact] PASS" | tee -a "$LOG"; PASS=$((PASS+1)); fi

OUT=$(run "$LD LOAD mysql_scanner; ATTACH 'host=$MY_HOST port=3306 database=$MY_DB' AS mydb (TYPE mysql); SELECT marker FROM mydb.$MY_DB.sv_probe;")
chk B10_mysql_noscope "using password: NO" "$OUT"

# ==== MinIO / S3(B11..B15)====
OUT=$(run "$LD CREATE PERSISTENT SECRET s31 IN local_encrypted (TYPE s3, KEY_ID '$S3_KEY', SECRET '$S3_SECRET', ENDPOINT '$S3_HOST:9000', URL_STYLE 'path', REGION 'us-east-1', SCOPE 's3://$S3_BUCKET'); SELECT 'B11';")
chk B11_s3_create "B11" "$OUT"

OUT=$(python3 - "$HOME/.duckdb/stored_secrets_vault/s31.duckdb_secret.vault" "$S3_SECRET" <<'PY'
import sys
b=open(sys.argv[1],'rb').read()
print(b[:8]==b'DSVLT\x00\x00\x00', b[10]==3, b.count(sys.argv[2].encode()))
PY
)
chk B12_s3_at_rest "True True 0" "$OUT"

OUT=$(run "$LD LOAD httpfs; SET s3_use_ssl=false; COPY (SELECT 42 AS v, 'S3-E2E-MARK' AS m) TO 's3://$S3_BUCKET/roundtrip.parquet' (FORMAT parquet); SELECT count(*) FROM read_parquet('s3://$S3_BUCKET/roundtrip.parquet') WHERE m='S3-E2E-MARK';")
chk B13_s3_roundtrip "1" "$OUT"

OUT=$(run "$LD SELECT secret_string FROM duckdb_secrets() WHERE name='s31';")
if printf '%s' "$OUT" | grep -qF "$S3_SECRET"; then echo "[B14_s3_redact] FAIL" | tee -a "$LOG"; FAIL=$((FAIL+1));
else echo "[B14_s3_redact] PASS" | tee -a "$LOG"; PASS=$((PASS+1)); fi

OUT=$(run "$LD LOAD httpfs; SET s3_use_ssl=false; SELECT count(*) FROM read_parquet('s3://other-bucket-no-scope/x.parquet');")
if printf '%s' "$OUT" | grep -qE "403|404|Access Denied"; then echo "[B15_s3_noscope] PASS" | tee -a "$LOG"; PASS=$((PASS+1));
else echo "[B15_s3_noscope] FAIL: anonymous read unexpectedly: $(printf '%s' "$OUT" | tail -c 120)" | tee -a "$LOG"; FAIL=$((FAIL+1)); fi

echo "PHASE7: PASS=$PASS FAIL=$FAIL" | tee -a "$LOG"
echo "=== done ===" | tee -a "$LOG"
