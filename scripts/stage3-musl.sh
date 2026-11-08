#!/usr/bin/env sh
# stage-3: linux_amd64_musl (alpine) — run inside alpine container
# Evidence → /workspace/tmp/phase6/linux-amd64-musl/
set -e
export PATH="/usr/local/cargo/bin:$PATH"
EV=/workspace/tmp/phase6/linux-amd64-musl
mkdir -p "$EV"

echo "=== stage-3: musl (alpine) ===" | tee "$EV/build.log"
echo "rustc: $(rustc --version) | cc: $(cc --version 2>&1 | head -1)" | tee -a "$EV/build.log"

# 1) Rust 依赖树先验(不含扩展构建,只看 crate 能否编译)
echo "--- cargo check ---" | tee -a "$EV/build.log"
cd /workspace/rust && timeout 900 cargo check 2>&1 | tail -3 | tee -a "$EV/build.log"
echo "CARGO_CHECK_EXIT=$?" >> "$EV/build.log"

# 2) cmake 构建(duckdb + 扩展)
cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDUCKDB_EXTENSION_CONFIGS=/workspace/extension_config.cmake \
  -DUNITTEST_ROOT_DIRECTORY=/workspace \
  -DENABLE_UNITTEST_CPP_TESTS=FALSE \
  -DENABLE_EXTENSION_AUTOLOADING=1 -DENABLE_EXTENSION_AUTOINSTALL=1 \
  -DOS_NAME=linux -DOS_ARCH=amd64 \
  -S /workspace/duckdb -B /workspace/build/musl-release 2>&1 | tail -5 | tee -a "$EV/build.log"
echo "CONFIGURE_EXIT=$?" >> "$EV/build.log"

cmake --build /workspace/build/musl-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j $(nproc) 2>&1 | tail -5 | tee -a "$EV/build.log"
echo "BUILD_EXIT=$?" >> "$EV/build.log"

# 3) 产物类型
file /workspace/build/musl-release/extension/secret_vault/secret_vault.duckdb_extension 2>&1 | tee -a "$EV/build.log"
ldd /workspace/build/musl-release/extension/secret_vault/secret_vault.duckdb_extension 2>&1 | tee -a "$EV/build.log"

# 4) 测试
export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(bytes([7])*32).decode())")
export HOME=/tmp/vh-musl; rm -rf "$HOME"; mkdir -p "$HOME"
PASS=0; FAIL=0; SKIP=0
for T in spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute; do
  /workspace/build/musl-release/test/unittest test/sql/$T.test > "$EV/$T.log" 2>&1
  if grep -qE "No tests ran|All tests were skipped" "$EV/$T.log"; then
    echo "TEST_$T=SKIP_DETECTED" | tee -a "$EV/build.log"; SKIP=$((SKIP+1))
  elif grep -q "All tests passed" "$EV/$T.log"; then
    echo "TEST_$T=PASS" | tee -a "$EV/build.log"; PASS=$((PASS+1))
  else
    echo "TEST_$T=FAIL" | tee -a "$EV/build.log"; FAIL=$((FAIL+1))
  fi
done
echo "TESTS: PASS=$PASS FAIL=$FAIL SKIP=$SKIP" | tee -a "$EV/build.log"
echo "=== done ===" | tee -a "$EV/build.log"
