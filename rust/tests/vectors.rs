//! 跨实现验证向量(阶段一出口判据修订版,plan r5):
//! 固定 key 的 env provider 下 seal 若干样本( nonce 随机故密文不定),
//! 向量文件记录 (name, blob, plaintext) —— 任何实现(含阶段二的 C++ 调用方)
//! 用 vault_open(blob) 必须还原出 plaintext。open 是给定 blob 的确定性函数,
//! 因此这组向量对 FFI/ABI 回归有效。
//!
//! 再生成:`VECTORS_GEN=1 cargo test --test vectors`(builder 容器内),提交产物。
use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use std::ffi::CString;
use std::path::Path;

use secret_vault::{vault_free_buf, vault_open, vault_seal, VaultBuf, KEY_LEN, PROVIDER_ENV};

const FIXTURE_KEY: [u8; KEY_LEN] = [0x42; KEY_LEN];
const FIXTURES: &[(&str, &[u8])] = &[
    ("vec_basic", b"duckdb-secret-serialized-blob-1"),
    ("vec_emptyish", b"{ }"),
    ("vec_utf8_name_payload", "多字节内容-{'k':'v'}".as_bytes()),
    ("vec_long", &[0x5Au8; 4096]),
];

fn seal_to_vec(name: &str, pt: &[u8]) -> Vec<u8> {
    let cname = CString::new(name).unwrap();
    let mut out = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let rc = unsafe { vault_seal(PROVIDER_ENV, cname.as_ptr(), pt.as_ptr(), pt.len(), &mut out) };
    assert_eq!(rc, 0, "seal failed for {name}");
    let v = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { vault_free_buf(out) };
    v
}

fn open_from_vec(name: &str, blob: &[u8]) -> Result<Vec<u8>, i32> {
    let cname = CString::new(name).unwrap();
    let mut out = VaultBuf {
        ptr: std::ptr::null_mut(),
        len: 0,
        cap: 0,
    };
    let rc = unsafe { vault_open(PROVIDER_ENV, cname.as_ptr(), blob.as_ptr(), blob.len(), &mut out) };
    if rc != 0 {
        return Err(rc);
    }
    let v = unsafe { std::slice::from_raw_parts(out.ptr, out.len) }.to_vec();
    unsafe { vault_free_buf(out) };
    Ok(v)
}

#[test]
fn vectors_open_deterministic() {
    std::env::set_var("SECRET_VAULT_KEY", B64.encode(FIXTURE_KEY));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors.json");
    let text = std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read {}: {e}(若首次生成,运行 VECTORS_GEN=1 cargo test --test vectors)", path.display()));

    if std::env::var("VECTORS_GEN").is_ok() {
        eprintln!("VECTORS_GEN set but vectors.json already exists; delete it to regenerate");
    }

    let cases: Vec<(String, String, String)> = serde_json::from_str(&text).expect("valid vectors.json");
    assert!(cases.len() >= 4, "expected at least 4 fixtures");
    for (name, blob_b64, pt_b64) in &cases {
        let blob = B64.decode(blob_b64).expect("blob b64");
        let pt = B64.decode(pt_b64).expect("pt b64");
        let got = open_from_vec(name, &blob).unwrap_or_else(|rc| panic!("open {name} rc={rc}"));
        assert_eq!(got, pt, "fixture {name} must open to its plaintext");
        // 头部布局恒定
        assert_eq!(&blob[0..8], b"DSVLT\0\0\0", "fixture {name} magic");
    }
    // 负向:篡改任一 fixture 的 1 字节必须失败
    let (name, blob_b64, _) = &cases[0];
    let mut bad = B64.decode(blob_b64).unwrap();
    let last = bad.len() - 1;
    bad[last] ^= 1;
    assert!(open_from_vec(name, &bad).is_err(), "tampered fixture must fail");
}

// 生成模式:VECTORS_GEN=1 且文件不存在时,产出 vectors.json 并通过(内容自校验)。
#[test]
fn vectors_generate_when_requested() {
    if std::env::var("VECTORS_GEN").is_err() {
        return; // 普通运行跳过
    }
    std::env::set_var("SECRET_VAULT_KEY", B64.encode(FIXTURE_KEY));
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors.json");
    if path.exists() {
        return;
    }
    let mut cases = Vec::new();
    for (name, pt) in FIXTURES {
        let blob = seal_to_vec(name, pt);
        // 自校验:能 open 回原明文才允许入库
        let back = open_from_vec(name, &blob).expect("self-check open");
        assert_eq!(&back, pt);
        cases.push((name.to_string(), B64.encode(&blob), B64.encode(pt)));
    }
    let json = serde_json::to_string_pretty(&cases).unwrap();
    std::fs::write(&path, json).expect("write vectors.json");
    eprintln!("generated {} fixtures -> {}", cases.len(), path.display());
}
