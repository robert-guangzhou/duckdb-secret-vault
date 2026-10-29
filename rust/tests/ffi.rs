//! FFI 回归测试:直接调用 C ABI 入口(vault_seal/open/free_buf/last_error),
//! 即阶段二 C++ 存储层将使用的同一组函数——覆盖 释放契约(HIGH-1 修复后)与错误路径。
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::ffi::{CStr, CString};

use secret_vault::{vault_free_buf, vault_last_error, vault_open, vault_seal, VaultBuf, KEY_LEN, PROVIDER_ENV};

fn cstr(s: &str) -> CString {
    CString::new(s).unwrap()
}

fn last_error_string() -> String {
    unsafe { CStr::from_ptr(vault_last_error()) }.to_string_lossy().into_owned()
}

#[test]
fn ffi_roundtrip_and_free_contract() {
    std::env::set_var("SECRET_VAULT_KEY", B64.encode([7u8; KEY_LEN]));
    let name = cstr("ffi_secret");
    let pt = b"serialized-duckdb-blob-for-ffi";
    let mut out = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let rc = unsafe {
        vault_seal(PROVIDER_ENV, name.as_ptr(), pt.as_ptr(), pt.len(), &mut out)
    };
    assert_eq!(rc, 0, "seal rc, err: {}", last_error_string());
    assert!(!out.ptr.is_null());
    assert!(out.len > 40);
    assert!(out.cap >= out.len, "cap must be reported and >= len");

    // open 回来比对
    let mut back = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let rc = unsafe { vault_open(PROVIDER_ENV, name.as_ptr(), out.ptr, out.len, &mut back) };
    assert_eq!(rc, 0, "open rc, err: {}", last_error_string());
    let slice = unsafe { std::slice::from_raw_parts(back.ptr, back.len) };
    assert_eq!(slice, pt);

    // 释放契约:原样传回 len/cap(修复后的契约,错容量即 UB)
    unsafe {
        vault_free_buf(back);
        vault_free_buf(out);
    }
}

#[test]
fn ffi_error_paths_and_last_error_contract() {
    std::env::set_var("SECRET_VAULT_KEY", B64.encode([7u8; KEY_LEN]));
    let name = cstr("ffi_err");
    let pt = b"x";
    let mut out = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let sealed = unsafe {
        assert_eq!(vault_seal(PROVIDER_ENV, name.as_ptr(), pt.as_ptr(), pt.len(), &mut out), 0);
        out
    };

    // 错名 → AEAD 失败 + last_error 可读且立即拷贝(契约:下次调用失效)
    let wrong = cstr("ffi_other");
    let mut out2 = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let rc = unsafe { vault_open(PROVIDER_ENV, wrong.as_ptr(), sealed.ptr, sealed.len, &mut out2) };
    assert_eq!(rc, 1);
    let msg = last_error_string();
    assert!(msg.contains("AEAD tag mismatch"), "got: {msg}");

    // null 输出指针 → 报错而非崩溃
    let rc = unsafe {
        vault_seal(PROVIDER_ENV, name.as_ptr(), pt.as_ptr(), pt.len(), std::ptr::null_mut())
    };
    assert_eq!(rc, 1);

    unsafe { vault_free_buf(sealed) };
}
