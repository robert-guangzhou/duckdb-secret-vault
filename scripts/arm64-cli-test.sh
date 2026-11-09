#!/bin/bash
export HOME=/root
export PATH=/usr/local/cargo/bin:/usr/bin:$PATH
ulimit -s unlimited 2>/dev/null || true
EV=/workspace/tmp/phase6/linux-arm64
cd /workspace/build/arm64-v2
echo "=== CLI approach: build shell target ===" >> $EV/build.log

for i in $(seq 1 30); do
  gmake -j 2 shell >> $EV/build.log 2>&1
  RC=$?
  if [ $RC -eq 0 ]; then
    echo "SHELL_BUILD=0 at attempt $i" >> $EV/build.log
    break
  fi
  echo "shell attempt $i failed(rc=$RC)" >> $EV/build.log
  sleep 2
done

if [ -f /workspace/build/arm64-v2/duckdb ]; then
  cd /workspace
  export SECRET_VAULT_KEY=BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=
  export HOME=/tmp/vh-arm64-cli
  rm -rf $HOME; mkdir -p $HOME
  D="/workspace/build/arm64-v2/duckdb -unsigned -noheader -list -c"
  EXT=/workspace/build/arm64-v2/extension/secret_vault/secret_vault.duckdb_extension

  echo "[T1] version:" >> $EV/build.log
  $D "LOAD '$EXT'; SET secret_vault_provider='env'; SELECT secret_vault_version();" >> $EV/build.log 2>&1

  echo "[T2] create+at-rest:" >> $EV/build.log
  $D "LOAD '$EXT'; SET secret_vault_provider='env'; CREATE PERSISTENT SECRET t1 IN local_encrypted (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'ARM64-TEST-MARK');" >> $EV/build.log 2>&1
  python3 -c "
b = open('/tmp/vh-arm64-cli/.duckdb/stored_secrets_vault/t1.duckdb_secret.vault','rb').read()
print('[T2a] magic:', b[:8] == b'DSVLT\x00\x00\x00', 'marker:', b.count(b'ARM64-TEST-MARK'))
" >> $EV/build.log 2>&1

  echo "[T3] fresh-process load+redact:" >> $EV/build.log
  $D "LOAD '$EXT'; SET secret_vault_provider='env'; SELECT name, storage, secret_string FROM duckdb_secrets() WHERE name='t1';" >> $EV/build.log 2>&1

  echo "[T4] reload+drop:" >> $EV/build.log
  $D "LOAD '$EXT'; SET secret_vault_provider='env'; DROP PERSISTENT SECRET t1;" >> $EV/build.log 2>&1

  echo "ARM64-CLI: COMPLETE" >> $EV/build.log
else
  echo "SHELL not built" >> $EV/build.log
fi
echo "=== done ===" >> $EV/build.log
