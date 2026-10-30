#!/usr/bin/env bash
# 阶段三验证运行器(builder 容器内;证据 → /workspace/tmp/phase3/)
# 覆盖:sqllogictest(rotate/export-import)+ migrate 文件级流程 + rotate 跨 provider +
#       nats_rw 真实联调(TP-30/31)+ 封套跨实例 stdin 导入与负向(TP-34/35)。
# 前置(宿主侧完成):docker network connect nats-rw_default secret-vault-builder;
#                    docker cp nats_rw 扩展 → /tmp/nats_rw.duckdb_extension
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH

EV=/workspace/tmp/phase3
mkdir -p "$EV"
WS=/workspace
DUCKDB=$WS/build/reldebug/duckdb
UNITTEST=$WS/build/reldebug/test/unittest
NATS_EXT=/tmp/nats_rw.duckdb_extension
NATS_URL='nats://nats_userpass:4222'
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(b'\x07'*32).decode())")
D="$DUCKDB -unsigned -noheader -list"
SQLL() { $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; $1"; }

new_home() { export HOME="$1"; rm -rf "$HOME"; mkdir -p "$HOME"; }

{
echo "== env =="; $DUCKDB --version; ls -la "$NATS_EXT" 2>&1 | head -1

echo "== A. sqllogictest(migrate-rotate / export-import) =="
for t in migrate-rotate export-import; do
  new_home /tmp/vh-p3-a
  ( cd $WS && timeout 300 $UNITTEST test/sql/$t.test 2>&1 | tail -4 ); echo "UNITTEST_$t:$?"
done

echo "== B. migrate 文件级流程(TP-32) =="
new_home /tmp/vh-p3-b
# 两个明文 secret 落默认 local_file(不指定 IN)
SQLL "CREATE PERSISTENT SECRET m1 (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'MIG-PLAIN-1'); CREATE PERSISTENT SECRET m2 (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'MIG-PLAIN-2');"
echo "[B1] local_file sources:"; ls "$HOME/.duckdb/stored_secrets/" | sort
N=$(SQLL "SET secret_vault_provider='env'; SELECT migrated FROM secret_vault_migrate();")
echo "[B2] migrated = $N (expect 2)"
echo "[B3] vault files:"; ls "$HOME/.duckdb/stored_secrets_vault/"
python3 $WS/scripts/verify-at-rest.py "$HOME/.duckdb/stored_secrets_vault" m1 'MIG-PLAIN-1' | tail -1
echo "[B4] 源文件默认保留:"; ls "$HOME/.duckdb/stored_secrets/" | wc -l
N=$(SQLL "SET secret_vault_provider='env'; SELECT count(*) FROM duckdb_secrets() WHERE storage='local_encrypted' AND secret_string LIKE '%password=redacted%';")
echo "[B5] 新进程读迁移件(脱敏) = $N (expect 2)"
# delete_source 变体
SQLL "SET secret_vault_provider='env'; CREATE PERSISTENT SECRET m3 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'MIG-3');" >/dev/null
SQLL "CREATE PERSISTENT SECRET m3lf (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'MIG-3LF');" >/dev/null
SQLL "SET secret_vault_provider='env'; SELECT migrated FROM secret_vault_migrate(delete_source := true);" >/dev/null
echo "[B6] delete_source 后源目录:"; ls "$HOME/.duckdb/stored_secrets/" | wc -l

echo "== C. rotate 跨口令(TP-33:旧口令失效新口令可读) =="
new_home /tmp/vh-p3-c
export SECRET_VAULT_PASSPHRASE=old-pass
SQLL "SET secret_vault_provider='passphrase'; CREATE PERSISTENT SECRET rt IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'ROT-CROSS');" >/dev/null
# 以旧口令进程执行 rotate → 新口令
SQLL "SET secret_vault_provider='passphrase'; SELECT rotated FROM secret_vault_rotate(new_provider := 'passphrase', new_passphrase := 'brand-new-pass');" | tail -1
N=$(SECRET_VAULT_PASSPHRASE=old-pass SQLL "SET secret_vault_provider='passphrase'; SELECT count(*) FROM duckdb_secrets() WHERE name='rt';" 2>/dev/null || echo ERR)
echo "[C1] 旧口令读取 = $N (expect 报错/AEAD,上面应无 1)"
N=$(SECRET_VAULT_PASSPHRASE=brand-new-pass SQLL "SET secret_vault_provider='passphrase'; SELECT count(*) FROM duckdb_secrets() WHERE name='rt' AND secret_string LIKE '%password=redacted%';")
echo "[C2] 新口令读取(脱敏) = $N (expect 1)"
unset SECRET_VAULT_PASSPHRASE

echo "== D. nats_rw 真实联调(TP-30/31:类型无关 + scope 自动匹配) =="
new_home /tmp/vh-p3-d
$DUCKDB -unsigned -noheader -list -c "SET allow_extensions_metadata_mismatch=true; LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; LOAD '$NATS_EXT'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET np IN local_encrypted (TYPE nats_rw, URL '$NATS_URL', USER 'admin', PASSWORD 's3cret-pass', SCOPE 'nats://nats_userpass');" >/dev/null
echo "[D1] nats_rw secret 落盘密文断言:"
python3 $WS/scripts/verify-at-rest.py "$HOME/.duckdb/stored_secrets_vault" np 's3cret-pass' | tail -1
P3STREAM="p3_rt_$(date +%s)"
LD2="SET allow_extensions_metadata_mismatch=true; LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; LOAD '$NATS_EXT'; SET secret_vault_provider='env';"
# 写入:不传 secret → scope 自动匹配加密存储里的凭证(TP-31)
$DUCKDB -unsigned -noheader -list -c "$LD2 COPY (SELECT 'p3-hello' AS v) TO '"$P3STREAM"' (FORMAT nats_rw, url '$NATS_URL', create_stream 'true', payload_column 'v');"
N=$($DUCKDB -unsigned -noheader -list -c "$LD2 SELECT count(*) FROM nats_rw_scan('$P3STREAM', url := '$NATS_URL') WHERE decode(payload) = 'p3-hello';")
echo "[D2] 写+读回(scope 匹配认证) count = $N (expect 1)"
N=$($DUCKDB -unsigned -noheader -list -c "$LD2 SELECT count(*) FROM duckdb_secrets() WHERE name='np' AND storage='local_encrypted' AND secret_string LIKE '%s3cret-pass%';")
echo "[D3] 脱敏不变 = $N (expect 0)"

echo "== E. 封套跨实例 + stdin 导入(TP-34)与负向(TP-35) =="
new_home /tmp/vh-p3-ea
SQLL "SET secret_vault_provider='env'; CREATE PERSISTENT SECRET s1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'ENV-MARK-1'); CREATE PERSISTENT SECRET s2 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'ENV-MARK-2');" >/dev/null
CODE=$(SQLL "SET secret_vault_provider='env'; SELECT transport_code FROM secret_vault_export('/tmp/p3bundle.svb');" | tail -1)
echo "[E1] transport code captured: ${CODE:0:8}...(len=${#CODE}, expect 52)"
echo "[E2] bundle at-rest:"
python3 - <<PY
b = open("/tmp/p3bundle.svb","rb").read()
print("[E2a] magic:", b[:8] == b"DSVLTENV", "| size:", len(b))
print("[E2b] 明文 marker:", b.count(b"ENV-MARK-1") + b.count(b"ENV-MARK-2"), "(expect 0)")
import os, base64
keyb64 = base64.b64encode(b"\x07"*32)
print("[E2c] 导出方密钥材料:", b.count(keyb64), "(expect 0)")
PY
# 实例 B:passphrase 体系(无 SECRET_VAULT_KEY)
new_home /tmp/vh-p3-eb
export SECRET_VAULT_PASSPHRASE=import-side-pass
echo "[E3-debug] code head: ${CODE:0:8} len=${#CODE}"
N=$(echo "$CODE" | $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='passphrase'; SELECT imported FROM secret_vault_import('/tmp/p3bundle.svb');" 2>&1 | tail -1)
echo "[E3] stdin 导入(B 无 KEY,passphrase 体系) imported = $N (expect 2)"
N=$(SQLL "SET secret_vault_provider='passphrase'; SELECT count(*) FROM duckdb_secrets() WHERE name IN ('s1','s2') AND secret_string LIKE '%password=redacted%';")
echo "[E4] B 用自己口令读取(脱敏) = $N (expect 2)"
# 负向:错码 / 篡改 bundle
(echo "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" | $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SELECT imported FROM secret_vault_import('/tmp/p3bundle.svb');" 2>&1 | grep -m1 Error) || true
python3 -c "
p='/tmp/p3bundle.svb'; b=bytearray(open(p,'rb').read()); b[-1]^=1; open(p,'wb').write(b); print('[E5] bundle tampered')"
(echo "$CODE" | $D -c "LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SELECT imported FROM secret_vault_import('/tmp/p3bundle.svb', on_conflict := 'overwrite');" 2>&1 | grep -m1 "Error\|mismatch") || true
unset SECRET_VAULT_PASSPHRASE

echo "== F. mysql 类型注册(尽力而为:网络可达则 INSTALL) =="
new_home /tmp/vh-p3-f
($DUCKDB -unsigned -noheader -list -c "INSTALL mysql; LOAD mysql; LOAD '$WS/build/reldebug/extension/secret_vault/secret_vault.duckdb_extension'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET my IN local_encrypted (TYPE mysql, HOST 'h', USER 'u', PASSWORD 'MY-PASS'); SELECT count(*) FROM duckdb_secrets() WHERE name='my' AND storage='local_encrypted' AND secret_string LIKE '%password=redacted%';" 2>&1 | tail -1) || echo "[F] mysql INSTALL 不可达(跳过,nats_rw 已满足'至少一种扩展类型')"
} 2>&1 | tee "$EV/phase3-evidence.txt"
echo "EVIDENCE -> $EV/phase3-evidence.txt"
