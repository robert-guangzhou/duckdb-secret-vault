#!/usr/bin/env bash
# 阶段二验证运行器(builder 容器内;证据 → /workspace/tmp/phase2/)
# 覆盖:sqllogictest(storage-basics/negative-security)+ CLI 面负向(TP-20/21/22/23/24 的进程级场景)+ at-rest 字节断言。
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH

EV=/workspace/tmp/phase2
mkdir -p "$EV"
WS=/workspace
DUCKDB=$WS/build/reldebug/duckdb
UNITTEST=$WS/build/reldebug/test/unittest
export HOME=/tmp/vault-home-p2
rm -rf "$HOME"; mkdir -p "$HOME"
VAULT_DIR=$HOME/.duckdb/stored_secrets_vault
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x07'*32).decode())")
export SECRET_VAULT_PASSPHRASE=pp
D="$DUCKDB -unsigned -noheader -list"
L() { "$@"; echo; }

{
echo "== env =="; $DUCKDB --version

echo "== A. sqllogictest(测试进程继承本环境:KEY/PASSPHRASE 均设) =="
( cd $WS && timeout 300 $UNITTEST test/sql/storage-basics.test test/sql/negative-security.test 2>&1 | tail -6 ); echo "UNITTEST_EXIT:$?"

echo "== B. TP-10/TP-14:at-rest 字节断言 =="
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET tp10 IN local_encrypted (TYPE vault_test, URL 'nats://x:4222', USER 'AKIA-TP10', PASSWORD 'MARKER-TP10-PLAINTEXT');"
cp "$VAULT_DIR/tp10.duckdb_secret.vault" "$EV/tp10-first.bin"
python3 $WS/scripts/verify-at-rest.py "$VAULT_DIR" tp10 'MARKER-TP10-PLAINTEXT'; echo "ATREST_EXIT:$?"
# AKIA-TP10(user 字段)也不得出现
python3 - <<'PY'
blob = open("/tmp/vault-home-p2/.duckdb/stored_secrets_vault/tp10.duckdb_secret.vault","rb").read()
print("[extra] user-marker occurrences =", blob.count(b"AKIA-TP10"), "(expect 0)")
assert blob.count(b"AKIA-TP10") == 0
PY
# TP-14 双写随机性:nonce(28..40) 与整文件字节不同
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; CREATE OR REPLACE PERSISTENT SECRET tp10 IN local_encrypted (TYPE vault_test, URL 'nats://x:4222', USER 'AKIA-TP10', PASSWORD 'MARKER-TP10-PLAINTEXT');"
python3 - <<PY
a = open("$EV/tp10-first.bin","rb").read()
b = open("$VAULT_DIR/tp10.duckdb_secret.vault","rb").read()
print("[TP-14] nonce differs:", a[28:40] != b[28:40], "| file differs:", a != b)
assert a[28:40] != b[28:40] and a != b
PY

echo "== C. 新进程自动加载(env 同密钥) =="
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name, storage, secret_string FROM duckdb_secrets() WHERE name='tp10';"
echo "== C2. 自动加载且脱敏 =="
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE secret_string LIKE '%MARKER-TP10-PLAINTEXT%';"

echo "== D. TP-24:env provider 缺 SECRET_VAULT_KEY → 明确报错 =="
(env -u SECRET_VAULT_KEY $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='tp10';" 2>&1 | tail -2) || true

echo "== E. TP-20:错密钥(env 换 KEY) → AEAD 明确报错 =="
(export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x08'*32).decode())"); $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='tp10';" 2>&1 | tail -2) || true

echo "== F. TP-21:篡改密文 1 字节 → 解密失败 =="
cp "$VAULT_DIR/tp10.duckdb_secret.vault" "$EV/tp10-tampered.bin"
python3 - <<'PY'
p = "/tmp/vault-home-p2/.duckdb/stored_secrets_vault/tp10.duckdb_secret.vault"
b = bytearray(open(p,"rb").read()); b[-1] ^= 1; open(p,"wb").write(b)
print("[tamper] last byte flipped")
PY
($D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='tp10';" 2>&1 | tail -2) || true
# 还原
cp "$EV/tp10-first.bin" /dev/null 2>/dev/null
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; CREATE OR REPLACE PERSISTENT SECRET tp10 IN local_encrypted (TYPE vault_test, URL 'nats://x:4222', USER 'AKIA-TP10', PASSWORD 'MARKER-TP10-PLAINTEXT');" >/dev/null

echo "== G. TP-22:文件改名(调包) → AAD 失败 =="
cp "$VAULT_DIR/tp10.duckdb_secret.vault" "$VAULT_DIR/tp22copy.duckdb_secret.vault"
($D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='tp22copy';" 2>&1 | tail -2) || true
rm -f "$VAULT_DIR/tp22copy.duckdb_secret.vault"

echo "== H. TP-23:权限放宽(644) → 拒读 =="
chmod 644 "$VAULT_DIR/tp10.duckdb_secret.vault"
($D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; SELECT name FROM duckdb_secrets() WHERE name='tp10';" 2>&1 | tail -2) || true
chmod 600 "$VAULT_DIR/tp10.duckdb_secret.vault"

echo "== I. keyring 在无 dbus 容器 → 明确报错引导(TP-24b) =="
($D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='keyring'; SELECT name FROM duckdb_secrets() WHERE name='tp10';" 2>&1 | tail -2) || true

echo "== J. 清理 =="
$D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; DROP PERSISTENT SECRET tp10;"
ls "$VAULT_DIR" 2>/dev/null; echo "(empty expected)"
} 2>&1 | tee "$EV/phase2-evidence.txt"

echo "EVIDENCE -> $EV/phase2-evidence.txt"
