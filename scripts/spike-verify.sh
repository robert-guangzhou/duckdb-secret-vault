#!/usr/bin/env bash
# 阶段零 spike 验证(builder 容器内运行;证据落盘 /workspace/tmp/phase0/)
# 覆盖 Dev Plan 阶段零出口判据:注册/CRUD/自动加载/脱敏/默认存储路由/文件形态。
# SPIKE 语义:落盘为明文序列化(阶段二接加密),故"明文 marker 存在"在本阶段为预期。
set -uo pipefail
export PATH=/usr/local/cargo/bin:$PATH

EV=/workspace/tmp/phase0
mkdir -p "$EV"
BUILD=/workspace/build/reldebug
DUCKDB=$BUILD/duckdb

# 定位扩展产物(静态链接时 CLI 已内置,无需 LOAD;否则用 LOADABLE 路径)
EXT=$(find $BUILD/extension -name "secret_vault*.duckdb_extension" 2>/dev/null | head -1)
if [ -n "$EXT" ]; then
  LOAD_CMD="LOAD '$EXT';"
else
  LOAD_CMD=""   # 静态链接进 CLI
fi

export HOME=/tmp/vault-home          # 隔离 HOME,避免污染容器/宿主真实目录
rm -rf "$HOME"; mkdir -p "$HOME"

run() { echo "== $1 =="; shift; "$@"; echo; }

{
run "duckdb version" $DUCKDB --version
run "artifact" bash -c "echo EXT=${EXT:-<statically-linked>}"

run "1. version fn (corrosion+cbindgen+staticlib 链路)" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} SELECT secret_vault_version();"

run "2. CREATE PERSISTENT SECRET ... IN local_encrypted" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} CREATE PERSISTENT SECRET s1 (TYPE vault_test, URL 'nats://x:4222', USER 'admin', PASSWORD 'spike-mark-PLAIN') IN local_encrypted;"

run "2b. vault 目录与文件形态" \
  bash -c "ls -la $HOME/.duckdb/stored_secrets_vault/ && stat -c '%a %n' $HOME/.duckdb/stored_secrets_vault/s1.duckdb_secret.vault"

run "3. at-rest 字节(spike 预期:明文 marker 存在;阶段二起必须为 0)" \
  bash -c "grep -c spike-mark-PLAIN $HOME/.duckdb/stored_secrets_vault/s1.duckdb_secret.vault && echo PLAINTEXT-PRESENT-SPIKE-EXPECTED || echo MARKER-ABSENT"

run "4. 新进程自动加载 + 脱敏" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} SELECT name, type, provider, persistent, storage, secret_string FROM duckdb_secrets() WHERE name='s1';"
run "4b. secret_string 不含明文密码" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} SELECT count(*) FROM duckdb_secrets() WHERE secret_string LIKE '%spike-mark-PLAIN%';"

run "5. SET default_secret_storage 路由" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} SET default_secret_storage='local_encrypted'; CREATE PERSISTENT SECRET s2 (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'p2'); SELECT name, storage FROM duckdb_secrets() WHERE name='s2';"

run "6. DROP PERSISTENT SECRET 删除文件" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} DROP PERSISTENT SECRET s2;"
run "6b. 文件已消失" \
  bash -c "ls $HOME/.duckdb/stored_secrets_vault/"

run "7. 与 local_file 共存互不干扰" \
  $DUCKDB -noheader -list -c "${LOAD_CMD} SET default_secret_storage='local_file'; CREATE PERSISTENT SECRET lf1 (TYPE vault_test, URL 'u', USER 'u', PASSWORD 'p3'); SELECT name, storage FROM duckdb_secrets() WHERE name='lf1';"
run "7b. local_file 目录(非 vault)" \
  bash -c "ls $HOME/.duckdb/stored_secrets/ 2>/dev/null || echo <no-local-file-dir>"

run "8. keyring Linux 无 dbus 结论(来自 /tmp/kr 实测)" \
  bash -c "cd /tmp/kr && timeout 120 cargo run --bin kr 2>/dev/null | tail -2"
} 2>&1 | tee "$EV/spike-cli-evidence.txt"

echo "EVIDENCE -> $EV/spike-cli-evidence.txt"
