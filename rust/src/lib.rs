//! secret_vault 加密核心(阶段一)。
//!
//! - 文件格式 v1(Dev Plan 3.2):40 字节头 + AES-256-GCM 密文‖tag
//!   `magic "DSVLT\0\0\0" | version u16 BE | provider u8 | flags u8 | salt 16B | nonce 12B`
//!   AAD = 40 字节头 + secret 名(防改名/调包)。
//! - KeyProvider(Dev Plan 3.3):keyring(1)=OS keychain 主密钥;passphrase(2)=Argon2id
//!   (m=64MiB,t=3,p=1,per-file salt);env(3)=SECRET_VAULT_KEY(base64 32B)。
//!   密钥材料只在 Rust 侧出现,C++ 层不接触(见 FFI 注释)。
//! - 卫生:口令/密钥缓冲 Zeroizing;错误信息不含密钥材料。

use std::cell::RefCell;
use std::ffi::{c_char, CStr};
use std::os::raw::c_int;

use aes_gcm::aead::{Aead, AeadCore, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use rand::{RngCore, rngs::OsRng};
use zeroize::{Zeroize, Zeroizing};

// ==== 常量与文件格式 ====

pub const MAGIC: &[u8; 8] = b"DSVLT\0\0\0";
pub const FORMAT_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 40; // 8+2+1+1+16+12
pub const KEY_LEN: usize = 32;
pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
pub const TAG_LEN: usize = 16;

pub const PROVIDER_KEYRING: u8 = 1;
pub const PROVIDER_PASSPHRASE: u8 = 2;
pub const PROVIDER_ENV: u8 = 3;

const ENV_KEY: &str = "SECRET_VAULT_KEY";
const ENV_PASSPHRASE: &str = "SECRET_VAULT_PASSPHRASE";

// Argon2id 参数(Dev Plan 3.3:64MiB/3/1;随 version 字段可升级)
const ARGON2_M_KIB: u32 = 65536;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 1;

// ==== 错误(信息中禁止出现密钥材料) ====

#[derive(Debug)]
pub enum VaultError {
    BadProvider(u8),
    KeyUnavailable(String), // provider 不可用的原因类别(如无 dbus),不含密钥
    BadKeyMaterial(String),
    BadFormat(String),
    NotPrivate(String),
    OpenFailed, // AEAD tag 校验失败:错密钥/错名/篡改统一此错误(by design)
    Io(String),
}

impl std::fmt::Display for VaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            VaultError::BadProvider(id) => write!(f, "unknown key provider id {id}"),
            VaultError::KeyUnavailable(why) => write!(f, "key provider unavailable: {why}"),
            VaultError::BadKeyMaterial(why) => write!(f, "bad key material: {why}"),
            VaultError::BadFormat(why) => write!(f, "bad vault file format: {why}"),
            VaultError::NotPrivate(what) => write!(f, "not allowed: {what}"),
            VaultError::OpenFailed => write!(
                f,
                "vault open failed: AEAD tag mismatch (wrong key, wrong secret name, or tampered file)"
            ),
            VaultError::Io(why) => write!(f, "io error: {why}"),
        }
    }
}

pub type VaultResult<T> = Result<T, VaultError>;

// ==== KeyProvider ====

fn derive_key(provider: u8, salt: &[u8; SALT_LEN]) -> VaultResult<Zeroizing<[u8; KEY_LEN]>> {
    match provider {
        PROVIDER_KEYRING => {
            // OS keychain 主密钥(salt 置零,主密钥直接作 AEAD key)。
            // 首次使用自动生成随机 256-bit 主密钥并写入 keychain(Dev Plan 3.3);
            // 无 Secret Service(如 headless Linux)时明确报错,不静默降级(Dev Plan 六)。
            let entry = keyring::Entry::new("duckdb.secret_vault", "master")
                .map_err(|e| VaultError::KeyUnavailable(format!("keyring: {e}")))?;
            let master = match entry.get_secret() {
                Ok(m) => m,
                Err(keyring::Error::NoEntry) => {
                    // 首次使用:生成并持久化主密钥
                    let mut mk = Zeroizing::new([0u8; KEY_LEN]);
                    OsRng.fill_bytes(&mut mk);
                    entry
                        .set_secret(&mk)
                        .map_err(|e| VaultError::KeyUnavailable(format!("keyring set: {e}")))?;
                    mk.to_vec()
                }
                Err(e) => return Err(VaultError::KeyUnavailable(format!("keyring: {e}"))),
            };
            if master.len() != KEY_LEN {
                return Err(VaultError::KeyUnavailable(format!(
                    "keyring master key must be {KEY_LEN} bytes, found {}",
                    master.len()
                )));
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&master);
            Ok(key)
        }
        PROVIDER_PASSPHRASE => {
            let pass = Zeroizing::new(std::env::var(ENV_PASSPHRASE).map_err(|_| {
                VaultError::KeyUnavailable(format!("{ENV_PASSPHRASE} not set and no interactive prompt in this build"))
            })?);
            let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
                .map_err(|e| VaultError::Io(format!("argon2 params: {e}")))?;
            let a2 = Argon2::new(Algorithm::Argon2id, Version::V0x13, params);
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            a2.hash_password_into(pass.as_bytes(), salt, key.as_mut())
                .map_err(|e| VaultError::Io(format!("argon2: {e}")))?;
            Ok(key)
        }
        PROVIDER_ENV => {
            // base64 编码的 32 字节随机密钥(生成:openssl rand -base64 32)
            let b64 = std::env::var(ENV_KEY)
                .map_err(|_| VaultError::KeyUnavailable(format!("{ENV_KEY} not set")))?;
            let raw = Zeroizing::new(
                B64.decode(b64.trim())
                    .map_err(|_| VaultError::BadKeyMaterial(format!("{ENV_KEY} is not valid base64")))?,
            );
            if raw.len() != KEY_LEN {
                return Err(VaultError::BadKeyMaterial(format!(
                    "{ENV_KEY} must decode to {KEY_LEN} bytes, found {}",
                    raw.len()
                )));
            }
            let mut key = Zeroizing::new([0u8; KEY_LEN]);
            key.copy_from_slice(&raw);
            Ok(key)
        }
        other => Err(VaultError::BadProvider(other)),
    }
}

// ==== 加/解密 ====

/// 加密:DuckDB 序列化 blob → 完整 vault 文件字节(头+密文+tag)。
pub fn seal(provider: u8, name: &str, plaintext: &[u8]) -> VaultResult<Vec<u8>> {
    let mut salt = [0u8; SALT_LEN];
    if provider == PROVIDER_PASSPHRASE {
        OsRng.fill_bytes(&mut salt); // per-file salt,防跨文件关联与预计算
    }
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    let key = derive_key(provider, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));

    let mut out = Vec::with_capacity(HEADER_LEN + plaintext.len() + TAG_LEN);
    out.extend_from_slice(MAGIC);
    out.extend_from_slice(&FORMAT_VERSION.to_be_bytes());
    out.push(provider);
    out.push(0); // flags 预留
    out.extend_from_slice(&salt);
    out.extend_from_slice(nonce_bytes.as_slice());
    debug_assert_eq!(out.len(), HEADER_LEN);

    // AAD = 头 + 名:文件改名/调包后解密必失败
    let mut aad = out.clone();
    aad.extend_from_slice(name.as_bytes());

    let ct = cipher
        .encrypt(
            &nonce_bytes,
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| VaultError::OpenFailed)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解密:完整 vault 文件字节 → DuckDB 序列化 blob。
/// 校验 magic/version/provider;错密钥/错名/篡改统一 OpenFailed。
pub fn open(provider: u8, name: &str, blob: &[u8]) -> VaultResult<Vec<u8>> {
    if blob.len() < HEADER_LEN + TAG_LEN {
        return Err(VaultError::BadFormat(format!(
            "file too small ({} bytes, need at least {})",
            blob.len(),
            HEADER_LEN + TAG_LEN
        )));
    }
    if &blob[0..8] != MAGIC {
        return Err(VaultError::BadFormat("bad magic (not a vault file)".into()));
    }
    let version = u16::from_be_bytes([blob[8], blob[9]]);
    if version != FORMAT_VERSION {
        return Err(VaultError::BadFormat(format!("unsupported version {version}")));
    }
    let file_provider = blob[10];
    if file_provider != provider {
        return Err(VaultError::BadFormat(format!(
            "file was written with provider {file_provider}, requested provider {provider}"
        )));
    }
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&blob[12..28]);
    let nonce = Nonce::from_slice(&blob[28..40]);

    let key = derive_key(provider, &salt)?;
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));

    // AAD = 头 + 名(与 seal 一致)
    let mut aad = blob[..HEADER_LEN].to_vec();
    aad.extend_from_slice(name.as_bytes());

    cipher
        .decrypt(nonce, Payload { msg: &blob[HEADER_LEN..], aad: &aad })
        .map_err(|_| VaultError::OpenFailed)
}

// ==== C ABI(供 C++ 存储层调用;密钥材料不出 Rust) ====

#[repr(C)]
pub struct VaultBuf {
    pub ptr: *mut u8,
    pub len: usize,
    /// 分配容量:与 Rust 侧 Vec 真实 capacity 一致,vault_free_buf 依此释放;
    /// 错值 = 分配器 UB(诚实审查 HIGH-1 修复)。C++ 侧必须原样回传。
    pub cap: usize,
}

thread_local! {
    static LAST_ERROR: RefCell<Option<String>> = const { RefCell::new(None) };
}

fn set_last_error(err: &VaultError) -> c_int {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(err.to_string()));
    1
}

fn set_last_error_msg(msg: &str) -> c_int {
    LAST_ERROR.with(|e| *e.borrow_mut() = Some(msg.to_string()));
    1
}

fn wrap_result(r: VaultResult<Vec<u8>>, out: *mut VaultBuf) -> c_int {
    match r {
        Ok(v) => {
            if out.is_null() {
                return set_last_error_msg("output buffer pointer is null");
            }
            let mut v = std::mem::ManuallyDrop::new(v);
            unsafe {
                (*out).len = v.len();
                (*out).cap = v.capacity();
                (*out).ptr = v.as_mut_ptr();
            }
            0
        }
        Err(e) => set_last_error(&e),
    }
}

/// 加密。name 以 NUL 结尾;plaintext 为 DuckDB 序列化 blob。
#[no_mangle]
pub extern "C" fn vault_seal(
    provider: u8,
    name: *const c_char,
    plaintext: *const u8,
    plaintext_len: usize,
    out: *mut VaultBuf,
) -> c_int {
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return set_last_error_msg("secret name is not valid UTF-8"),
    };
    if plaintext.is_null() || plaintext_len == 0 {
        return set_last_error_msg("plaintext is empty");
    }
    let pt = unsafe { std::slice::from_raw_parts(plaintext, plaintext_len) };
    wrap_result(seal(provider, &name, pt), out)
}

/// 解密。blob 为完整 vault 文件字节。
#[no_mangle]
pub extern "C" fn vault_open(
    provider: u8,
    name: *const c_char,
    blob: *const u8,
    blob_len: usize,
    out: *mut VaultBuf,
) -> c_int {
    let name = match unsafe { CStr::from_ptr(name) }.to_str() {
        Ok(s) => s.to_string(),
        Err(_) => return set_last_error_msg("secret name is not valid UTF-8"),
    };
    if blob.is_null() || blob_len == 0 {
        return set_last_error_msg("blob is empty");
    }
    let b = unsafe { std::slice::from_raw_parts(blob, blob_len) };
    wrap_result(open(provider, &name, b), out)
}

/// 最近一次错误的描述(线程本地;不含密钥材料)。
/// ⚠ 契约:返回指向线程本地缓冲的指针,下一次 vault_* 调用即失效——
/// 调用方必须立即拷贝,不得跨调用持有(诚实审查 LOW-1)。
#[no_mangle]
pub extern "C" fn vault_last_error() -> *const c_char {
    thread_local! {
        static ERR_BUF: RefCell<std::ffi::CString> = RefCell::new(std::ffi::CString::new("no error").unwrap());
    }
    LAST_ERROR.with(|e| {
        let msg = e.borrow().as_deref().unwrap_or("no error").to_string();
        ERR_BUF.with(|buf| {
            *buf.borrow_mut() = std::ffi::CString::new(msg).unwrap_or_else(|_| std::ffi::CString::new("error").unwrap());
            buf.borrow().as_ptr()
        })
    })
}

/// 释放 vault_seal/vault_open 返回的缓冲。buf.len/buf.cap 必须原样传回,不得篡改。
#[no_mangle]
pub extern "C" fn vault_free_buf(buf: VaultBuf) {
    if !buf.ptr.is_null() && buf.len > 0 && buf.cap >= buf.len {
        unsafe {
            let _ = Vec::from_raw_parts(buf.ptr, buf.len, buf.cap);
        }
    }
}

/// 显式清零一段缓冲(密钥材料跨边界后的卫生钩子,Dev Plan 六)。
#[no_mangle]
pub extern "C" fn vault_zeroize_buf(ptr: *mut u8, len: usize) {
    if !ptr.is_null() && len > 0 {
        unsafe {
            std::slice::from_raw_parts_mut(ptr, len).zeroize();
        }
    }
}

/// Rust core 版本(静态存储,无需释放)。
static VERSION: &[u8] = b"0.1.0\0";

#[no_mangle]
pub extern "C" fn secret_vault_core_version() -> *const c_char {
    VERSION.as_ptr() as *const c_char
}

// ==== 单元测试(阶段一出口判据:全部真实运行) ====

#[cfg(test)]
mod tests {
    use super::*;

    // env 变量是进程级共享,cargo test 默认多线程并行 → 串行化所有动 env 的测试
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn env_provider_key() -> u8 {
        // 测试用 env provider(不依赖 keychain/口令输入)
        std::env::set_var(ENV_KEY, B64.encode([7u8; KEY_LEN]));
        PROVIDER_ENV
    }

    #[test]
    fn tp01_format_roundtrip() {
        let _g = ENV_LOCK.lock().unwrap();
        let p = env_provider_key();
        let blob = seal(p, "s1", b"duckdb-serialized-blob").unwrap();
        assert_eq!(&blob[0..8], MAGIC);
        assert_eq!(u16::from_be_bytes([blob[8], blob[9]]), FORMAT_VERSION);
        assert_eq!(blob[10], p);
        assert_eq!(blob.len(), HEADER_LEN + b"duckdb-serialized-blob".len() + TAG_LEN);
        let pt = open(p, "s1", &blob).unwrap();
        assert_eq!(pt, b"duckdb-serialized-blob");
    }

    #[test]
    fn tp03_aad_name_binding() {
        let _g = ENV_LOCK.lock().unwrap();
        let p = env_provider_key();
        let blob = seal(p, "secret_a", b"payload").unwrap();
        // 改名后解密必须失败(AAD 绑定 secret 名)
        assert!(matches!(open(p, "secret_b", &blob), Err(VaultError::OpenFailed)));
        // 密文翻转 1 字节必须失败
        let mut bad = blob.clone();
        let last = bad.len() - 1;
        bad[last] ^= 0x01;
        assert!(matches!(open(p, "secret_a", &bad), Err(VaultError::OpenFailed)));
    }

    #[test]
    fn tp06_nonce_randomness() {
        let _g = ENV_LOCK.lock().unwrap();
        let p = env_provider_key();
        let a = seal(p, "s", b"same plaintext").unwrap();
        let b = seal(p, "s", b"same plaintext").unwrap();
        assert_ne!(&a[28..40], &b[28..40], "nonce must be random per write");
        assert_ne!(a, b);
    }

    #[test]
    fn tp04_passphrase_deterministic_and_salted() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_PASSPHRASE, "correct horse battery staple");
        let blob = seal(PROVIDER_PASSPHRASE, "s", b"x").unwrap();
        let pt = open(PROVIDER_PASSPHRASE, "s", &blob).unwrap();
        assert_eq!(pt, b"x");
        // 错口令 → AEAD 失败
        std::env::set_var(ENV_PASSPHRASE, "wrong pass");
        assert!(matches!(open(PROVIDER_PASSPHRASE, "s", &blob), Err(VaultError::OpenFailed)));
        // 两次 seal 的 salt 不同(per-file salt)
        std::env::set_var(ENV_PASSPHRASE, "p2");
        let b1 = seal(PROVIDER_PASSPHRASE, "s", b"x").unwrap();
        let b2 = seal(PROVIDER_PASSPHRASE, "s", b"x").unwrap();
        assert_ne!(&b1[12..28], &b2[12..28]);
        std::env::remove_var(ENV_PASSPHRASE);
    }

    #[test]
    fn tp04b_env_key_validation() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_KEY, "not-base64!!!");
        let err = seal(PROVIDER_ENV, "s", b"x").unwrap_err();
        assert!(matches!(err, VaultError::BadKeyMaterial(_)));
        std::env::set_var(ENV_KEY, B64.encode([1u8; 10])); // 长度错
        let err = seal(PROVIDER_ENV, "s", b"x").unwrap_err();
        assert!(matches!(err, VaultError::BadKeyMaterial(_)));
    }

    #[test]
    fn tp0x_provider_mismatch_and_magic() {
        let _g = ENV_LOCK.lock().unwrap();
        let p = env_provider_key();
        let blob = seal(p, "s", b"x").unwrap();
        // provider 不匹配(文件由 env 写,按 passphrase 读)
        std::env::set_var(ENV_PASSPHRASE, "pp");
        assert!(matches!(open(PROVIDER_PASSPHRASE, "s", &blob), Err(VaultError::BadFormat(_))));
        // 坏 magic
        let mut bad = blob.clone();
        bad[0] = b'X';
        assert!(matches!(open(p, "s", &bad), Err(VaultError::BadFormat(_))));
        // 过短
        assert!(matches!(open(p, "s", &blob[..10]), Err(VaultError::BadFormat(_))));
    }

    #[test]
    fn tp0x_error_text_has_no_key_material() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var(ENV_KEY, B64.encode([9u8; KEY_LEN]));
        let _ = std::env::var(ENV_KEY).unwrap();
        let secret_b64 = B64.encode([9u8; KEY_LEN]);
        let blob = seal(PROVIDER_ENV, "s", b"x").unwrap();
        std::env::set_var(ENV_KEY, B64.encode([8u8; KEY_LEN])); // 换 key
        let err = open(PROVIDER_ENV, "s", &blob).unwrap_err().to_string();
        assert!(!err.contains(&secret_b64), "error must not contain key material");
    }

    // TP-05:zeroize 卫生钩子(C ABI 的 vault_zeroize_buf 是 C++ 侧清零入口)
    #[test]
    fn tp05_zeroize_buf_hook() {
        let mut v = vec![0xABu8; 64];
        let (ptr, len) = (v.as_mut_ptr(), v.len());
        vault_zeroize_buf(ptr, len);
        assert!(v.iter().all(|&b| b == 0), "vault_zeroize_buf must zero the whole buffer");
        // 空指针/零长不崩溃
        vault_zeroize_buf(std::ptr::null_mut(), 0);
    }

    // AES-256-GCM 官方向量(NIST AES-256-GCM PDF,Test Case 16)
    #[test]
    fn tp02_official_vector_tc16() {
        // NIST GCM Test Case 16:zero key/zero IV,空 PT,已知 tag
        let key = Key::<Aes256Gcm>::from_slice(&[0u8; 32]);
        let cipher = Aes256Gcm::new(key);
        let nonce = Nonce::from_slice(&[0u8; 12]);
        let ct = cipher
            .encrypt(nonce, Payload { msg: &[], aad: &[] })
            .expect("seal");
        assert_eq!(ct.len(), TAG_LEN);
        assert_eq!(
            ct,
            [
                0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9, 0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b
            ]
        );
    }
}
