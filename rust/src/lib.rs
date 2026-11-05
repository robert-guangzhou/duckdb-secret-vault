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
use hkdf::Hkdf;
use rand::{RngCore, rngs::OsRng};
use sha2::Sha256;
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

/// tty 无回显读口令(阶段B/r14)。失败返回 Err → 调用方降级为可见输入 + 警告。
#[cfg(unix)]
fn read_passphrase_hidden(prompt: &str) -> std::io::Result<String> {
    use std::io::{self, BufRead, Write};
    let mut saved: libc::termios = unsafe { std::mem::zeroed() };
    if unsafe { libc::tcgetattr(0, &mut saved) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let mut noecho = saved;
    noecho.c_lflag &= !libc::ECHO;
    if unsafe { libc::tcsetattr(0, libc::TCSANOW, &noecho) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let read_result = (|| {
        let mut stderr = io::stderr();
        write!(stderr, "{prompt}")?;
        stderr.flush()?;
        let mut line = String::new();
        io::stdin().lock().read_line(&mut line)?;
        writeln!(stderr)?; // 回显关闭时补换行
        Ok(line)
    })();
    // 无论读成败都恢复原 termios(guard 语义)
    unsafe { libc::tcsetattr(0, libc::TCSANOW, &saved) };
    read_result
}

#[cfg(windows)]
fn read_passphrase_hidden(prompt: &str) -> std::io::Result<String> {
    use std::io::{self, Write};
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct Handle(*mut core::ffi::c_void);
    extern "system" {
        fn GetStdHandle(which: u32) -> Handle;
        fn GetConsoleMode(h: Handle, mode: *mut u32) -> i32;
        fn SetConsoleMode(h: Handle, mode: u32) -> i32;
    }
    const STD_INPUT_HANDLE: u32 = u32::MAX - 9; // (DWORD)-10
    const ENABLE_ECHO_INPUT: u32 = 0x0004;
    unsafe {
        let h = GetStdHandle(STD_INPUT_HANDLE);
        let mut mode: u32 = 0;
        if GetConsoleMode(h, &mut mode) == 0 {
            return Err(io::Error::last_os_error());
        }
        let saved = mode;
        if SetConsoleMode(h, mode & !ENABLE_ECHO_INPUT) == 0 {
            return Err(io::Error::last_os_error());
        }
        let res = (|| {
            let mut stderr = io::stderr();
            write!(stderr, "{prompt}")?;
            stderr.flush()?;
            let mut line = String::new();
            io::stdin().read_line(&mut line)?;
            writeln!(stderr)?;
            Ok(line)
        })();
        SetConsoleMode(h, saved);
        res
    }
}

fn load_or_create_keyring_master() -> VaultResult<[u8; KEY_LEN]> {
    let entry = keyring::Entry::new("duckdb.secret_vault", "master")
        .map_err(|e| VaultError::KeyUnavailable(format!("keyring: {e}")))?;
    let master = match entry.get_secret() {
        Ok(m) => m,
        Err(keyring::Error::NoEntry) => {
            // 首次使用:生成并持久化主密钥
            let mut mk = Zeroizing::new([0u8; KEY_LEN]);
            OsRng.fill_bytes(&mut *mk);
            entry
                .set_secret(&*mk)
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
    let mut key = [0u8; KEY_LEN];
    key.copy_from_slice(&master);
    Ok(key)
}

fn derive_key(provider: u8, salt: &[u8; SALT_LEN]) -> VaultResult<Zeroizing<[u8; KEY_LEN]>> {
    match provider {
        PROVIDER_KEYRING => {
            // OS keychain 主密钥(salt 置零,主密钥直接作 AEAD key)。
            // 首次使用自动生成随机 256-bit 主密钥并写入 keychain(Dev Plan 3.3);
            // 无 Secret Service(如 headless Linux)时明确报错,不静默降级(Dev Plan 六)。
            // CR-H4(r13):每进程仅读取一次 keychain(OnceLock 缓存,对齐 Dev Plan 七);
            // 代价 = keyring 主密钥外部轮换后需重启进程(README/THREAT-MODEL 已声明)。
            static MASTER: std::sync::OnceLock<Result<[u8; KEY_LEN], String>> = std::sync::OnceLock::new();
            let cached = MASTER.get_or_init(|| load_or_create_keyring_master().map_err(|e| e.to_string()));
            let key_arr = cached.as_ref().map_err(|msg| VaultError::KeyUnavailable(msg.clone()))?;
            Ok(Zeroizing::new(*key_arr))
        }
        PROVIDER_PASSPHRASE => {
            // 取口令优先级:env(无人值守)→ 交互 stdin(tty 时提示;
            // 回显关闭需 termios,当前版本明文回显,记录为已知限制)。
            let pass = match std::env::var(ENV_PASSPHRASE) {
                Ok(p) => Zeroizing::new(p),
                Err(_) => {
                    use std::io::IsTerminal;
                    if std::io::stdin().is_terminal() {
                        // tty 无回显(阶段B/r14):termios(Unix)/SetConsoleMode(Windows);
                        // 失败降级为明文回显 + WARNING 行,不静默(计划 3.2)
                        match read_passphrase_hidden("secret_vault: enter passphrase (input hidden): ") {
                            Ok(line) => {
                                if line.trim().is_empty() {
                                    return Err(VaultError::KeyUnavailable("empty passphrase".into()));
                                }
                                Zeroizing::new(line.trim().to_string())
                            }
                            Err(e) => {
                                eprintln!("WARNING: echo could not be disabled ({e}); input will be visible");
                                eprint!("secret_vault: enter passphrase: ");
                                let mut line = String::new();
                                std::io::stdin()
                                    .read_line(&mut line)
                                    .map_err(|e2| VaultError::KeyUnavailable(format!("stdin: {e2}")))?;
                                if line.trim().is_empty() {
                                    return Err(VaultError::KeyUnavailable("empty passphrase".into()));
                                }
                                Zeroizing::new(line.trim().to_string())
                            }
                        }
                    } else {
                        return Err(VaultError::KeyUnavailable(format!(
                            "{ENV_PASSPHRASE} not set and stdin is not interactive"
                        )));
                    }
                }
            };
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

    match cipher.decrypt(nonce, Payload { msg: &blob[HEADER_LEN..], aad: &aad }) {
        Ok(pt) => Ok(pt),
        // KEY_OLD(r14,fleet 阶段A):轮换过渡回退——仅在 provider==ENV 且恰好
        // tag mismatch 时尝试 SECRET_VAULT_KEY_OLD;其他 provider/错误不回退
        // (计划 3.1:避免性能损耗与语义混淆)。回退钥材料用后清零。
        Err(_) if provider == PROVIDER_ENV => {
            if let Ok(old_b64) = std::env::var("SECRET_VAULT_KEY_OLD") {
                if let Ok(raw) = B64.decode(old_b64.trim()) {
                    if raw.len() == KEY_LEN {
                        let mut old_key = Zeroizing::new([0u8; KEY_LEN]);
                        old_key.copy_from_slice(&raw);
                        let cipher_old = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*old_key));
                        if let Ok(pt) =
                            cipher_old.decrypt(nonce, Payload { msg: &blob[HEADER_LEN..], aad: &aad })
                        {
                            return Ok(pt);
                        }
                    }
                }
            }
            Err(VaultError::OpenFailed)
        }
        Err(_) => Err(VaultError::OpenFailed),
    }
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

// ==== 一次性传输封套(plan 3.5:export/import) ====
// 封套与 per-secret 文件格式完全独立:transport key(一次性 256-bit)经
// HKDF-SHA256 域分隔派生封套密钥,加密「已解密的 secret 序列化明文」整包。
// 导入方解开封套后用本机 provider 重新 seal 落盘——transport key 与任何
// 实例运行时密钥解耦。
// v2(r13):payload 内含 per-entry mtime manifest,导入侧默认拒绝早于
// 现存文件的条目(防旧包重放,allow_older 显式放行)。

pub const ENV_MAGIC: &[u8; 8] = b"DSVLTENV";
pub const ENV_FORMAT_VERSION: u16 = 2;
pub const ENV_HEADER_LEN: usize = 8 + 2 + 2 + 12; // magic + version + reserved + nonce
const HKDF_INFO: &[u8] = b"secret_vault.envelope.v1";

fn envelope_key(transport: &[u8; KEY_LEN]) -> Zeroizing<[u8; KEY_LEN]> {
    let hk = Hkdf::<Sha256>::from_prk(transport).expect("prk len");
    let mut okm = Zeroizing::new([0u8; KEY_LEN]);
    hk.expand(HKDF_INFO, okm.as_mut()).expect("okm len");
    okm
}

/// 打包加密:payload(调用方组装的 entries)→ 封套字节。
pub fn envelope_seal(transport: &[u8; KEY_LEN], payload: &[u8]) -> VaultResult<Vec<u8>> {
    let key = envelope_key(transport);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    let nonce_bytes = Aes256Gcm::generate_nonce(&mut OsRng);

    let mut out = Vec::with_capacity(ENV_HEADER_LEN + payload.len() + TAG_LEN);
    out.extend_from_slice(ENV_MAGIC);
    out.extend_from_slice(&ENV_FORMAT_VERSION.to_be_bytes());
    out.extend_from_slice(&0u16.to_be_bytes()); // reserved
    out.extend_from_slice(nonce_bytes.as_slice());
    debug_assert_eq!(out.len(), ENV_HEADER_LEN);

    let ct = cipher
        .encrypt(&nonce_bytes, Payload { msg: payload, aad: &out[..ENV_HEADER_LEN] })
        .map_err(|_| VaultError::OpenFailed)?;
    out.extend_from_slice(&ct);
    Ok(out)
}

/// 解开封套:错 transport key/篡改统一 OpenFailed。
pub fn envelope_open(transport: &[u8; KEY_LEN], envelope: &[u8]) -> VaultResult<Vec<u8>> {
    if envelope.len() < ENV_HEADER_LEN + TAG_LEN {
        return Err(VaultError::BadFormat(format!(
            "envelope too small ({} bytes, need at least {})",
            envelope.len(),
            ENV_HEADER_LEN + TAG_LEN
        )));
    }
    if &envelope[0..8] != ENV_MAGIC {
        return Err(VaultError::BadFormat("bad envelope magic (not a vault envelope)".into()));
    }
    let version = u16::from_be_bytes([envelope[8], envelope[9]]);
    if version != ENV_FORMAT_VERSION {
        return Err(VaultError::BadFormat(format!("unsupported envelope version {version}")));
    }
    let nonce = Nonce::from_slice(&envelope[12..24]);

    let key = envelope_key(transport);
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&*key));
    cipher
        .decrypt(
            nonce,
            Payload {
                msg: &envelope[ENV_HEADER_LEN..],
                aad: &envelope[..ENV_HEADER_LEN],
            },
        )
        .map_err(|_| VaultError::OpenFailed)
}

// RFC 4648 base32(无填充,A-Z2-7):长密钥码的可抄录表示
const B32_ALPHABET: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

fn key_to_base32(key: &[u8; KEY_LEN]) -> String {
    let mut out = String::with_capacity(56);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &b in key {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(B32_ALPHABET[((acc >> bits) & 0x1f) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(B32_ALPHABET[((acc << (5 - bits)) & 0x1f) as usize] as char);
    }
    out
}

fn base32_to_key(code: &str) -> Option<[u8; KEY_LEN]> {
    let mut cleaned: Vec<u8> = code
        .trim()
        .chars()
        .filter(|c| !c.is_whitespace() && *c != '-')
        .map(|c| c.to_ascii_uppercase() as u8)
        .collect();
    let mut out = Vec::with_capacity(KEY_LEN);
    let mut acc: u32 = 0;
    let mut bits: u32 = 0;
    for &c in cleaned.iter() {
        let v = B32_ALPHABET.iter().position(|&a| a == c)? as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push(((acc >> bits) & 0xff) as u8);
        }
    }
    if bits > 0 && (acc & ((1 << bits) - 1)) != 0 {
        cleaned.zeroize();
        return None; // 尾部非零位 = 非规范编码
    }
    let mut key = [0u8; KEY_LEN];
    if out.len() != KEY_LEN {
        cleaned.zeroize();
        out.zeroize();
        return None;
    }
    key.copy_from_slice(&out);
    cleaned.zeroize();
    out.zeroize();
    Some(key)
}

#[no_mangle]
pub extern "C" fn vault_transport_key_generate(out_key: *mut u8) -> c_int {
    if out_key.is_null() {
        return set_last_error_msg("out_key is null");
    }
    unsafe {
        let slice = std::slice::from_raw_parts_mut(out_key, KEY_LEN);
        OsRng.fill_bytes(slice);
    }
    0
}

#[no_mangle]
pub extern "C" fn vault_envelope_seal(
    key: *const u8,
    payload: *const u8,
    payload_len: usize,
    out: *mut VaultBuf,
) -> c_int {
    if key.is_null() || payload.is_null() || payload_len == 0 {
        return set_last_error_msg("envelope seal: null/empty input");
    }
    let transport = match unsafe { std::slice::from_raw_parts(key, KEY_LEN) }.try_into() {
        Ok(k) => k,
        Err(_) => return set_last_error_msg("transport key length mismatch"),
    };
    let pt = unsafe { std::slice::from_raw_parts(payload, payload_len) };
    wrap_result(envelope_seal(&transport, pt), out)
}

#[no_mangle]
pub extern "C" fn vault_envelope_open(key: *const u8, envelope: *const u8, len: usize, out: *mut VaultBuf) -> c_int {
    if key.is_null() || envelope.is_null() || len == 0 {
        return set_last_error_msg("envelope open: null/empty input");
    }
    let transport = match unsafe { std::slice::from_raw_parts(key, KEY_LEN) }.try_into() {
        Ok(k) => k,
        Err(_) => return set_last_error_msg("transport key length mismatch"),
    };
    let env = unsafe { std::slice::from_raw_parts(envelope, len) };
    wrap_result(envelope_open(&transport, env), out)
}

/// 传输钥 → base32 码(out 至少 56 字节,NUL 结尾)。
#[no_mangle]
pub extern "C" fn vault_key_to_base32(key: *const u8, out: *mut c_char, out_len: usize) -> c_int {
    if key.is_null() || out.is_null() || out_len < 56 {
        return set_last_error_msg("key_to_base32: bad buffer");
    }
    let transport = match unsafe { std::slice::from_raw_parts(key, KEY_LEN) }.try_into() {
        Ok(k) => k,
        Err(_) => return set_last_error_msg("transport key length mismatch"),
    };
    let code = key_to_base32(&transport);
    unsafe {
        std::ptr::copy_nonoverlapping(code.as_ptr(), out as *mut u8, code.len());
        *out.add(code.len()) = 0;
    }
    0
}

/// base32 码 → 传输钥(非法/长度不符返回 1,不产出半成品)。
#[no_mangle]
pub extern "C" fn vault_base32_to_key(code: *const c_char, out_key: *mut u8) -> c_int {
    let code = match unsafe { CStr::from_ptr(code) }.to_str() {
        Ok(s) => s,
        Err(_) => return set_last_error_msg("code is not valid UTF-8"),
    };
    match base32_to_key(code) {
        Some(k) => {
            unsafe {
                std::ptr::copy_nonoverlapping(k.as_ptr(), out_key, KEY_LEN);
            }
            0
        }
        None => set_last_error_msg("invalid transport code (bad base32 or wrong length)"),
    }
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

    // ==== 封套(阶段三)====

    fn tp_key() -> [u8; KEY_LEN] {
        let mut k = [0u8; KEY_LEN];
        OsRng.fill_bytes(&mut k);
        k
    }

    #[test]
    fn tp0e_envelope_roundtrip_and_negatives() {
        let k = tp_key();
        let payload = b"entry1\0serialized-blob-1;entry2\0serialized-blob-2";
        let env = envelope_seal(&k, payload).unwrap();
        assert_eq!(&env[0..8], ENV_MAGIC);
        assert_eq!(env.len(), ENV_HEADER_LEN + payload.len() + TAG_LEN);
        assert_eq!(envelope_open(&k, &env).unwrap(), payload);

        // 错 transport key → AEAD 失败
        let wrong = tp_key();
        assert!(matches!(envelope_open(&wrong, &env), Err(VaultError::OpenFailed)));
        // 篡改 1 字节 → 失败
        let mut bad = env.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        assert!(matches!(envelope_open(&k, &bad), Err(VaultError::OpenFailed)));
        // 坏 magic / 过短
        let mut m = env.clone();
        m[0] = b'X';
        assert!(matches!(envelope_open(&k, &m), Err(VaultError::BadFormat(_))));
        assert!(matches!(envelope_open(&k, &env[..10]), Err(VaultError::BadFormat(_))));
    }

    #[test]
    fn tp0e_hkdf_domain_separation() {
        // 同 transport key 派生确定;封套密钥 ≠ 原始 transport key(域分隔)
        let k = tp_key();
        let e1 = envelope_key(&k);
        let e2 = envelope_key(&k);
        assert_eq!(*e1, *e2);
        assert_ne!(*e1, k, "HKDF must derive a distinct key");
    }

    #[test]
    fn tp0e_base32_roundtrip_and_validation() {
        let k = tp_key();
        let code = key_to_base32(&k);
        assert_eq!(code.len(), 52, "32 bytes = 256 bits -> ceil(256/5) = 52 base32 chars");
        assert!(code.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()));
        assert_eq!(base32_to_key(&code).unwrap(), k);
        // 分隔符/空白容忍
        let grouped: String = code
            .chars()
            .enumerate()
            .fold(String::new(), |mut acc, (i, c)| {
                if i > 0 && i % 8 == 0 {
                    acc.push('-');
                }
                acc.push(c);
                acc
            });
        assert_eq!(base32_to_key(&grouped).unwrap(), k);
        // 非法字符/长度拒绝
        assert!(base32_to_key("NOT-A-VALID-CODE-!!!").is_none());
        assert!(base32_to_key("AAAA").is_none());
    }

    // ==== fleet 阶段A:KEY_OLD 轮换过渡 ====

    #[test]
    fn tp0f_key_old_fallback_env_only() {
        let _g = ENV_LOCK.lock().unwrap();
        // 旧钥 K1 加密
        std::env::set_var(ENV_KEY, B64.encode([0xA1u8; KEY_LEN]));
        let blob = seal(PROVIDER_ENV, "s", b"rotate-me").unwrap();
        // 主钥换 K2 + KEY_OLD=K1 → 回退可读
        std::env::set_var(ENV_KEY, B64.encode([0xB2u8; KEY_LEN]));
        std::env::set_var("SECRET_VAULT_KEY_OLD", B64.encode([0xA1u8; KEY_LEN]));
        assert!(open(PROVIDER_ENV, "s", &blob).is_ok(), "fallback must read K1 files");
        // 撤除 KEY_OLD → AEAD 失败
        std::env::remove_var("SECRET_VAULT_KEY_OLD");
        assert!(matches!(open(PROVIDER_ENV, "s", &blob), Err(VaultError::OpenFailed)));
        // KEY_OLD 垃圾值 → 同样失败,不 panic
        std::env::set_var("SECRET_VAULT_KEY_OLD", "not-base64!!");
        assert!(matches!(open(PROVIDER_ENV, "s", &blob), Err(VaultError::OpenFailed)));
        std::env::remove_var("SECRET_VAULT_KEY_OLD");
        // 非 ENV provider 不回退:passphrase 文件 + KEY_OLD 在场 → 仍 AEAD 失败
        std::env::set_var(ENV_PASSPHRASE, "pp");
        let pb = seal(PROVIDER_PASSPHRASE, "s2", b"y").unwrap();
        std::env::set_var("SECRET_VAULT_KEY_OLD", B64.encode([0xA1u8; KEY_LEN]));
        assert!(matches!(open(PROVIDER_PASSPHRASE, "s2", &pb), Err(VaultError::OpenFailed)),
            "fallback must not apply to non-env providers");
        // 错误文本不含密钥字节(F5 类断言)
        std::env::remove_var("SECRET_VAULT_KEY_OLD");
        let err = open(PROVIDER_PASSPHRASE, "s2", &pb).unwrap_err().to_string();
        assert!(!err.contains("pp"), "error must not contain passphrase");
        std::env::remove_var(ENV_PASSPHRASE);
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
