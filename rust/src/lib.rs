//! secret_vault 加密核心。
//!
//! 阶段零(spike):仅版本标识,证明 corrosion + cbindgen + staticlib 链路。
//! 阶段一将实现:文件格式(DSVLT 头)、AES-256-GCM 加解密、KeyProvider
//! (keyring/passphrase/env)、zeroize 密钥卫生(Dev Plan 3.2/3.3)。

use std::os::raw::c_char;

static VERSION: &[u8] = b"0.1.0-spike\0";

/// C ABI:返回 Rust core 版本串(静态存储,无需释放)。
#[no_mangle]
pub extern "C" fn secret_vault_core_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_is_nul_terminated() {
        let ptr = secret_vault_core_version();
        assert!(!ptr.is_null());
        let bytes = unsafe { std::ffi::CStr::from_ptr(ptr).to_bytes() };
        assert_eq!(bytes, b"0.1.0-spike");
    }
}
