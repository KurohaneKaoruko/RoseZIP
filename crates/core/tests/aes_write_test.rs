//! WinZip AES write-path tests: extra-field byte layout, write→read
//! round-trips (AE-1/AE-2 × AES-128/256 × Store/Deflate × non-ASCII names)
//! and wrong-password rejection.
//!
//! SPDX-License-Identifier: GPL-3.0-only

use rosezip_core::archive;
use rosezip_core::ops::{self, ZipEncryption};
use rosezip_core::zipcrypt::{aes_iterations, AesStrength};
use std::io::Read;
use std::path::PathBuf;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rosezip-aw-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn path(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Small deterministic content set: compressible, tiny (below the deflate
/// threshold → Store), and a non-ASCII name.
fn make_inputs(dir: &std::path::Path) -> Vec<PathBuf> {
    let big = dir.join("big.txt");
    std::fs::write(&big, "compress me please, over the 64-byte deflate threshold. ".repeat(4))
        .unwrap();
    let tiny = dir.join("tiny.bin");
    std::fs::write(&tiny, [7u8; 40]).unwrap();
    let cn = dir.join("中文文件.txt");
    std::fs::write(&cn, "天地玄黄，宇宙洪荒。".repeat(2)).unwrap();
    vec![big, tiny, cn]
}

// ---------------------------------------------------------------------------
// Extra field byte layout
// ---------------------------------------------------------------------------

#[test]
fn extra_field_exact_bytes() {
    use rosezip_core::aes_writer::{extra_field, AE_VERSION_1, AE_VERSION_2};
    // Observed 7-Zip output for AE-2/AES-256/deflate:
    let got = extra_field(AE_VERSION_2, AesStrength::Aes256, 8);
    assert_eq!(got, vec![0x01, 0x99, 0x07, 0x00, 0x02, 0x00, b'A', b'E', 0x03, 0x08, 0x00]);
    // AE-1/AES-128/Store:
    let got = extra_field(AE_VERSION_1, AesStrength::Aes128, 0);
    assert_eq!(got, vec![0x01, 0x99, 0x07, 0x00, 0x01, 0x00, b'A', b'E', 0x01, 0x00, 0x00]);
}

#[test]
fn iterations_fixed_at_1000_for_all_strengths() {
    // WinZip AES spec: 1000 iterations regardless of strength (not stored in
    // the archive); 7-Zip and pyzipper both write 1000.
    for s in [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256] {
        assert_eq!(aes_iterations(s), 1000, "strength {:?}", s);
    }
}

// ---------------------------------------------------------------------------
// Round-trips through our own reader
// ---------------------------------------------------------------------------

fn assert_roundtrip(zip: &std::path::Path, inputs: &[PathBuf], pw: &str) {
    let out_dir = zip.with_extension("out");
    std::fs::create_dir_all(&out_dir).unwrap();
    ops::extract(zip, &out_dir, Some(pw.as_bytes())).unwrap();
    for f in inputs {
        let name = f.file_name().unwrap();
        let got = std::fs::read(out_dir.join(name)).unwrap();
        let want = std::fs::read(f).unwrap();
        assert_eq!(got, want, "content mismatch for {}", name.to_string_lossy());
    }
    let _ = std::fs::remove_dir_all(&out_dir);
}

#[test]
fn aes_roundtrip_all_variants() {
    let s = Scratch::new("rt");
    let inputs = make_inputs(&s.0);

    for (enc, tag) in [
        (ZipEncryption::WinZipAes, "ae2-256"),
        (ZipEncryption::WinZipAesAe1, "ae1-256"),
        (ZipEncryption::WinZipAes128, "ae2-128"),
        (ZipEncryption::WinZipAes128Ae1, "ae1-128"),
    ] {
        let zip = s.path(&format!("rt-{}.zip", tag));
        ops::compress_zip(&inputs, &zip, Some(b"RoundTrip1"), 6, enc).unwrap();
        assert_roundtrip(&zip, &inputs, "RoundTrip1");
    }
}

#[test]
fn aes_entries_use_method_99_and_9901_extra() {
    let s = Scratch::new("xf");
    let inputs = make_inputs(&s.0);
    let zip = s.path("xf.zip");
    ops::compress_zip(&inputs, &zip, Some(b"pw"), 6, ZipEncryption::WinZipAes).unwrap();

    let mut f = std::fs::File::open(&zip).unwrap();
    let entries = archive::parse_zip_central_directory(&mut f).unwrap();
    assert_eq!(entries.len(), inputs.len());
    for e in &entries {
        assert!(e.encrypted, "{} should be flagged encrypted", e.name);
        assert_eq!(e.method, 99, "{} outer method must be 99", e.name);
        // inner method: deflate for big.txt, store for the tiny + non-ASCII files
        let want_inner = if e.uncompressed_size >= 64 && e.compressed_size < e.uncompressed_size {
            8
        } else {
            0
        };
        assert_eq!(e.aes_inner_method, want_inner, "{} inner method", e.name);
    }
    // AE-2: CRC fields are zero
    assert!(entries.iter().all(|e| e.crc32 == 0));

    // AE-1 keeps the real CRCs.
    let zip1 = s.path("xf1.zip");
    ops::compress_zip(&inputs, &zip1, Some(b"pw"), 6, ZipEncryption::WinZipAesAe1).unwrap();
    let mut f1 = std::fs::File::open(&zip1).unwrap();
    let entries1 = archive::parse_zip_central_directory(&mut f1).unwrap();
    for (e, src) in entries1.iter().zip(&inputs) {
        let data = std::fs::read(src).unwrap();
        assert_eq!(e.crc32, archive::crc32(&data), "{} AE-1 keeps CRC", e.name);
    }
}

#[test]
fn wrong_password_fails_all_variants() {
    let s = Scratch::new("wp");
    let inputs = make_inputs(&s.0);
    for enc in [
        ZipEncryption::WinZipAes,
        ZipEncryption::WinZipAesAe1,
        ZipEncryption::WinZipAes128,
        ZipEncryption::WinZipAes128Ae1,
    ] {
        let zip = s.path("wp.zip");
        ops::compress_zip(&inputs, &zip, Some(b"CorrectPw"), 6, enc).unwrap();
        let out_dir = s.path("wp-out");
        let _ = std::fs::remove_dir_all(&out_dir);
        std::fs::create_dir_all(&out_dir).unwrap();
        let report = ops::extract(&zip, &out_dir, Some(b"WrongPw")).unwrap();
        // every file must fail — either skipped or errored, never extracted
        assert!(
            report.files == 0 && !report.errors.is_empty(),
            "{:?}: wrong password must not extract anything (files={}, errors={})",
            enc,
            report.files,
            report.errors.len()
        );
        let _ = std::fs::remove_dir_all(&out_dir);
    }
}

#[test]
fn zipcrypto_regression_unaffected() {
    let s = Scratch::new("zc");
    let inputs = make_inputs(&s.0);
    let zip = s.path("zc.zip");
    ops::compress_zip(&inputs, &zip, Some(b"pw"), 6, ZipEncryption::ZipCrypto).unwrap();
    assert_roundtrip(&zip, &inputs, "pw");

    // no password: plain zip, unencrypted flag
    let plain = s.path("plain.zip");
    ops::compress_zip(&inputs, &plain, None, 6, ZipEncryption::None).unwrap();
    let mut f = std::fs::File::open(&plain).unwrap();
    let entries = archive::parse_zip_central_directory(&mut f).unwrap();
    assert!(entries.iter().all(|e| !e.encrypted));
    assert_roundtrip(&plain, &inputs, "");
}

#[test]
fn salt_is_fresh_per_entry_and_random() {
    let s = Scratch::new("salt");
    let inputs = make_inputs(&s.0);
    let zip = s.path("salt.zip");
    ops::compress_zip(&inputs, &zip, Some(b"pw"), 6, ZipEncryption::WinZipAes).unwrap();

    // Collect the 16-byte salts from every local header; they must all differ.
    let raw = std::fs::read(&zip).unwrap();
    let mut salts = Vec::new();
    let mut off = 0usize;
    while off + 30 <= raw.len() && &raw[off..off + 4] == b"PK\x03\x04" {
        let nl = u16::from_le_bytes([raw[off + 26], raw[off + 27]]) as usize;
        let el = u16::from_le_bytes([raw[off + 28], raw[off + 29]]) as usize;
        let cs = u32::from_le_bytes([
            raw[off + 18],
            raw[off + 19],
            raw[off + 20],
            raw[off + 21],
        ]) as usize;
        let data_start = off + 30 + nl + el;
        salts.push(raw[data_start..data_start + 16].to_vec());
        off = data_start + cs;
    }
    assert_eq!(salts.len(), inputs.len());
    for i in 0..salts.len() {
        for j in i + 1..salts.len() {
            assert_ne!(salts[i], salts[j], "salts must be unique per entry");
        }
    }
}

#[test]
fn encryption_requires_password() {
    let s = Scratch::new("nopw");
    let inputs = make_inputs(&s.0);
    let zip = s.path("nopw.zip");
    let err = ops::compress_zip(&inputs, &zip, None, 6, ZipEncryption::WinZipAes);
    assert!(err.is_err(), "AES without password must be rejected");
}

// ---------------------------------------------------------------------------
// Reader cross-check: entries written by us decrypt via the read path used
// for foreign archives (decrypt_winzip_aes), including strength probing.
// ---------------------------------------------------------------------------

#[test]
fn written_aes_readable_via_inspect_and_test() {
    let s = Scratch::new("chk");
    let inputs = make_inputs(&s.0);
    let zip = s.path("chk.zip");
    ops::compress_zip(&inputs, &zip, Some(b"pw"), 6, ZipEncryption::WinZipAes).unwrap();

    let view = ops::inspect(&zip).unwrap();
    assert!(view.encryption.is_some(), "AES archive should report encryption");

    let report = ops::test_archive(&zip, Some(b"pw")).unwrap();
    assert!(report.errors.is_empty(), "test_archive with right pw: {:?}", report.errors);

    let bad = ops::test_archive(&zip, Some(b"nope")).unwrap();
    assert!(!bad.errors.is_empty(), "test_archive with wrong pw must report errors");
}

#[test]
fn fresh_salt_changes_ciphertext_but_still_roundtrips() {
    // Two archives from identical input+password differ byte-wise (random
    // salt), yet both decrypt correctly.
    let s = Scratch::new("rnd");
    let inputs = make_inputs(&s.0);
    let a = s.path("a.zip");
    let b = s.path("b.zip");
    ops::compress_zip(&inputs, &a, Some(b"pw"), 6, ZipEncryption::WinZipAes).unwrap();
    ops::compress_zip(&inputs, &b, Some(b"pw"), 6, ZipEncryption::WinZipAes).unwrap();
    let ra = std::fs::read(&a).unwrap();
    let rb = std::fs::read(&b).unwrap();
    assert_ne!(ra, rb, "random salts must produce different ciphertext");
    assert_roundtrip(&a, &inputs, "pw");
    assert_roundtrip(&b, &inputs, "pw");
    let _ = std::fs::File::open(&a).unwrap().read(&mut []).unwrap();
}
