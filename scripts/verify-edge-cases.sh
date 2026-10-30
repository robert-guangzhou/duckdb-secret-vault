#!/usr/bin/env bash
# 边界与压力验证(Test Plan r5 TP-41..44;证据 → /workspace/tmp/phase2-edge/)
# 覆盖全面 review 指出的四条未执行路径:
#   E1 RESET 一致性(CR-H5):current_setting 显示值 vs 文件 provider 字节
#   E2 反序列化失败路径(CR-H1 触发条件):AEAD 有效但内容非 DuckDB 序列化
#   E3 多进程并发写同目录:40 并发新建 + 同名竞态 + 无 .tmp 残留
#   E4 规模路径:>100 secrets 建立与整目录加载(env),passphrase 小样本计时(CR-H4 数据点)
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH

EV=/workspace/tmp/phase2-edge
mkdir -p "$EV"
WS=/workspace
DUCKDB=$WS/build/reldebug/duckdb
EXT='$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'
export HOME=/tmp/vault-home-edge
rm -rf "$HOME"; mkdir -p "$HOME"
VAULT_DIR=$HOME/.duckdb/stored_secrets_vault
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x07'*32).decode())")
export SECRET_VAULT_PASSPHRASE=pp
D="$DUCKDB -unsigned -noheader -list"
SQL() { $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; $1"; }

{
echo "== env =="; $DUCKDB --version

echo "== E1. RESET 一致性(CR-H5,已知缺陷行为登记;单进程内完整序列) =="
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension';
  SET secret_vault_provider='env';
  SELECT 'after-set' AS phase, current_setting('secret_vault_provider') AS shown;
  RESET secret_vault_provider;
  SELECT 'after-reset' AS phase, current_setting('secret_vault_provider') AS shown;
  CREATE PERSISTENT SECRET r1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'E1');
  SELECT 'after-reset-create' AS phase, 'CREATE-SUCCEEDED' AS outcome;"
python3 - <<'PY2'
import os
p = "/tmp/vault-home-edge/.duckdb/stored_secrets_vault/r1.duckdb_secret.vault"
if os.path.exists(p):
    b = open(p,"rb").read()
    print(f"[E1-byte] file provider byte = {b[10]} (3=env,1=keyring) —— 显示 keyring 而实际 env ⇒ 脱钩坐实")
else:
    print("[E1-byte] r1 file absent ⇒ CREATE failed ⇒ 无脱钩(keyring 实际生效)")
PY2
SQL "SET secret_vault_provider='env'; DROP PERSISTENT SECRET r1;" >/dev/null 2>&1 || true

echo "== E2. 反序列化失败路径(CR-H1 触发条件:AEAD 有效、内容非序列化) =="
rm -rf /tmp/craft && cargo new --lib /tmp/craft -q
cat > /tmp/craft/Cargo.toml <<'TOML'
[package]
name = "craft"
version = "0.1.0"
edition = "2021"

[dependencies]
secret_vault = { path = "/workspace/rust" }
TOML
cat > /tmp/craft/src/lib.rs <<'RS'
pub fn main_rs(dir: &str) {
    let blob = secret_vault::seal(3, "badtype", b"garbage-not-duckdb-serialization").expect("seal");
    let path = std::path::Path::new(dir).join("badtype.duckdb_secret.vault");
    std::fs::write(&path, &blob).expect("write");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    println!("[E2-1] crafted valid-AEAD garbage file written ({} bytes)", blob.len());
}
RS
mkdir -p /tmp/craft/src/bin && printf 'fn main(){ let d = std::env::args().nth(1).unwrap(); craft::main_rs(&d); }\n' > /tmp/craft/src/bin/craft.rs
(cd /tmp/craft && timeout 300 cargo run --bin craft -- "$VAULT_DIR" 2>&1 | tail -1)
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='badtype';" 2>&1 | grep -m1 -E "Error" || true
echo "[E2-2] 上行应为 Failed to deserialize(路径已触发;该路径当前存在 plain 缓冲泄漏=CR-H1,泄漏本体需 ASan 方可量化)"
rm -f "$VAULT_DIR/badtype.duckdb_secret.vault"

echo "== E3. 多进程并发写同目录 =="
T0=$(date +%s)
for i in $(seq 1 8); do
  ( for j in $(seq 1 5); do SQL "SET secret_vault_provider='env'; CREATE PERSISTENT SECRET c${i}_${j} IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'p${i}${j}');" >/dev/null 2>&1 || echo "[E3] create c${i}_${j} FAILED"; done ) &
done
# 同名竞态:4 进程同时 OR REPLACE 同一 secret
for k in $(seq 1 4); do
  ( SQL "SET secret_vault_provider='env'; CREATE OR REPLACE PERSISTENT SECRET racer IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'race$k');" >/dev/null 2>&1 || true ) &
done
wait
T1=$(date +%s)
N=$(ls "$VAULT_DIR" | grep -c "\.duckdb_secret\.vault$")
TMPN=$(ls "$VAULT_DIR" | grep -c "\.tmp-" || true)
echo "[E3-1] files on disk = $N (expect 40+1=41) | tmp residue = $TMPN (expect 0) | wall=$((T1-T0))s"
LOADED=$(SQL "SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE storage='local_encrypted';")
echo "[E3-2] fresh-process loaded & decrypted = $LOADED (expect 41)"
RACER=$(SQL "SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE name='racer';")
echo "[E3-3] racer intact after 4-way race = $RACER (expect 1)"

echo "== E4. 规模路径:120 secrets(env) + passphrase 计时(CR-H4 数据点) =="
python3 - <<'PY' > /tmp/bulk.sql
print("SET secret_vault_provider='env';")
for i in range(120):
    print(f"CREATE PERSISTENT SECRET bulk{i} IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'bulk{i}');")
PY
T0=$(date +%s)
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; $(cat /tmp/bulk.sql | tr '\n' ' ')" >/dev/null 2>&1 || echo "[E4] bulk create error"
T1=$(date +%s)
BULK_N=$(ls "$VAULT_DIR" | grep -c "^bulk")
echo "[E4-1] bulk files = $BULK_N (expect 120) | create wall=$((T1-T0))s (env,含 41 既有)"
T2=$(date +%s)
TOTAL=$(SQL "SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE storage='local_encrypted';")
T3=$(date +%s)
echo "[E4-2] full-dir load = $TOTAL (expect 161) | load wall=$((T3-T2))s"
# passphrase 小样本计时:10 个(每文件 Argon2id)
python3 - <<'PY' > /tmp/bulk2.sql
print("SET secret_vault_provider='passphrase';")
for i in range(10):
    print(f"CREATE PERSISTENT SECRET ph{i} IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'ph{i}');")
PY
T4=$(date +%s)
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; $(cat /tmp/bulk2.sql | tr '\n' ' ')" >/dev/null 2>&1 || echo "[E4] passphrase batch error"
T5=$(date +%s)
echo "[E4-3] passphrase 10-secret create wall=$((T5-T4))s (≈Argon2id ×10,CR-H4 数据点)"
} 2>&1 | tee "$EV/edge-evidence.txt"
echo "EVIDENCE -> $EV/edge-evidence.txt"
