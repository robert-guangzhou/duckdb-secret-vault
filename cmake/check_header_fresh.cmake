# FFI 头文件滞后检测（沿用 duckdb-nats-rw 2026-10-27 根治方案）
# rust/src/lib.rs 比 src/include/secret_vault_rust.h 新 → 编译前 FATAL_ERROR
# 防止：改了 Rust FFI 签名但忘跑 regen-header.sh，到 C++ 编译才报
#       "too many arguments" 的晚发现

set(RUST_LIB "${BASE_DIR}/rust/src/lib.rs")
set(CBINDGEN_CFG "${BASE_DIR}/rust/cbindgen.toml")
set(FFI_HEADER "${BASE_DIR}/src/include/secret_vault_rust.h")

if(NOT EXISTS "${RUST_LIB}")
    return()  # Rust 源不可达（如 CI 只下载了头文件的场景），跳过
endif()

if(NOT EXISTS "${FFI_HEADER}")
    message(FATAL_ERROR
        "secret_vault: FFI header missing: ${FFI_HEADER}\n"
        "Generate it: run 'rust/regen-header.sh' in the builder container,\n"
        "then commit the result (build determinism by design).")
endif()

file(TIMESTAMP "${RUST_LIB}" RUST_TS "%s")
file(TIMESTAMP "${FFI_HEADER}" HEADER_TS "%s")

if(RUST_TS GREATER HEADER_TS)
    message(FATAL_ERROR
        "secret_vault: rust/src/lib.rs (${RUST_TS}) is NEWER than "
        "src/include/secret_vault_rust.h (${HEADER_TS}).\n"
        "FFI signatures may have changed without regenerating the C header.\n"
        "Fix: run 'rust/regen-header.sh' in the builder container,\n"
        "then commit the regenerated header. Do NOT hand-edit secret_vault_rust.h.")
endif()

# cbindgen 配置变更同样影响头文件产出格式
if(EXISTS "${CBINDGEN_CFG}")
    file(TIMESTAMP "${CBINDGEN_CFG}" CFG_TS "%s")
    if(CFG_TS GREATER HEADER_TS)
        message(FATAL_ERROR
            "secret_vault: rust/cbindgen.toml (${CFG_TS}) is NEWER than "
            "src/include/secret_vault_rust.h (${HEADER_TS}).\n"
            "The header generation config changed; regenerate with "
            "'rust/regen-header.sh' in the builder container.")
    endif()
endif()
