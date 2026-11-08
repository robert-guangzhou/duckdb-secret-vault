#!/usr/bin/env bash
# stage-2: linux_arm64 (QEMU) — run inside arm64 bookworm container
set -e
export PATH="/usr/local/cargo/bin:$PATH"
EV=/workspace/tmp/phase6/linux-arm64
mkdir -p "$EV"
ulimit -s unlimited 2>/dev/null || true

echo "=== stage-2: arm64 (QEMU) ===" | tee "$EV/build.log"
echo "arch: $(uname -m) | rustc: $(rustc --version)" | tee -a "$EV/build.log"
rustup target add aarch64-unknown-linux-gnu 2>&1 | tail -1 | tee -a "$EV/build.log"

apt-get update -qq && apt-get install -y -qq cmake ninja-build python3 file 2>&1 | tail -1 | tee -a "$EV/build.log"

cmake -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DDUCKDB_EXTENSION_CONFIGS=/workspace/extension_config.cmake \
  -DUNITTEST_ROOT_DIRECTORY=/workspace \
  -DENABLE_UNITTEST_CPP_TESTS=FALSE \
  -DENABLE_EXTENSION_AUTOLOADING=1 -DENABLE_EXTENSION_AUTOINSTALL=1 \
  -DOS_NAME=linux -DOS_ARCH=arm64 \
  -S /workspace/duckdb -B /workspace/build/arm64-release 2>&1 | tail -3 | tee -a "$EV/build.log"
echo "CONFIGURE_EXIT=$?" >> "$EV/build.log"

cmake --build /workspace/build/arm64-release --target secret_vault_loadable_extension unittest duckdb_local_extension_repo -j $(nproc) 2>&1 | tail -3 | tee -a "$EV/build.log"
echo "BUILD_EXIT=$?" >> "$EV/build.log"

file /workspace/build/arm64-release/extension/secret_vault/secret_vault.duckdb_extension 2>&1 | tee -a "$EV/build.log"

export SECRET_VAULT_KEY=$(python3 -c "import base64;print(base64.b64encode(bytes([7])*32).decode())")
export HOME=/tmp/vh-arm64; rm -rf "$HOME"; mkdir -p "$HOME"
PASS=0; FAIL=0; SKIP=0
for T in spike-storage-registration storage-basics negative-security migrate-rotate export-import fleet-distribute; do
  /workspace/build/arm64-release/test/unittest test/sql/$T.test > "$EV/$T.log" 2>&1
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
