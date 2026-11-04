//! Tests for round-two enhancements: mask cracking, format filtering,
//! compression level handling and multi-thread 7z attack primitives.

use rosezip_core::charset::MaskGen;
use rosezip_core::crack::{self, CrackOptions, CrackTarget};
use rosezip_core::ops::{self, OutFormat};
use std::path::PathBuf;

struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rosezip-en-{}-{}", tag, std::process::id()));
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

// ---------------------------------------------------------------------------
// MaskGen
// ---------------------------------------------------------------------------

#[test]
fn mask_parse_and_space() {
    // Two digit slots → 100 candidates.
    let m = MaskGen::parse("?d?d").unwrap();
    assert_eq!(m.slots.len(), 2);
    assert_eq!(m.total, 100);

    // Literal text is pinned: Rose2024 = "Rose" + 4 digits.
    let m = MaskGen::parse("Rose?d?d?d?d").unwrap();
    assert_eq!(m.total, 10_000);
    assert_eq!(m.password_at(0).as_slice(), b"Rose0000");
    assert_eq!(m.password_at(2024).as_slice(), b"Rose2024");
    assert_eq!(m.password_at(9999).as_slice(), b"Rose9999");
}

#[test]
fn mask_placeholders() {
    let m = MaskGen::parse("?l?u?h").unwrap();
    assert_eq!(m.total, 26 * 26 * 16);
    // index 0 = first symbol of every slot: a, A, 0
    assert_eq!(m.password_at(0).as_slice(), b"aA0");
    // ?h covers 0-9a-f
    let m = MaskGen::parse("?h").unwrap();
    assert_eq!(m.total, 16);
    assert_eq!(m.password_at(10).as_slice(), b"a");
    assert_eq!(m.password_at(15).as_slice(), b"f");
    // ?? escapes a literal question mark
    let m = MaskGen::parse("??x").unwrap();
    assert_eq!(m.password_at(0).as_slice(), b"?x");
    assert_eq!(m.total, 1);
}

#[test]
fn mask_errors() {
    assert!(MaskGen::parse("").is_err());
    assert!(MaskGen::parse("?").is_err());
    assert!(MaskGen::parse("?z").is_err());
    assert!(MaskGen::parse("?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d?d").is_err());
}

// ---------------------------------------------------------------------------
// Mask attack end-to-end (ZipCrypto via spawn_job, the GUI path)
// ---------------------------------------------------------------------------

#[test]
fn mask_crack_finds_password() {
    let s = Scratch::new("mask");
    let src = s.path("data.txt");
    std::fs::write(&src, "mask attack payload ".repeat(10)).unwrap();
    let zip = s.path("m.zip");
    ops::compress(&[src], &zip, Some(b"Rose2024"), 6).unwrap();

    let plan = ops::prepare_crack(&zip).unwrap();
    let mask = MaskGen::parse("Rose?d?d?d?d").unwrap();
    let handle = crack::spawn_job(
        CrackTarget::Mask { mask },
        plan.verifier.clone(),
        std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2),
    );
    for _ in 0..400 {
        if handle.status().finished {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let res = handle.join();
    assert_eq!(res.password.as_deref(), Some(b"Rose2024".as_slice()));
}

#[test]
fn mask_crack_blocking_api() {
    let s = Scratch::new("maskb");
    let src = s.path("data.txt");
    std::fs::write(&src, "blocking mask payload ".repeat(10)).unwrap();
    let zip = s.path("mb.zip");
    ops::compress(&[src], &zip, Some(b"x7"), 6).unwrap();

    let plan = ops::prepare_crack(&zip).unwrap();
    let result = crack::crack_mask(
        "x?d",
        plan.verifier,
        &CrackOptions { threads: 2, quiet: true },
    )
    .unwrap();
    assert_eq!(result.password.as_deref(), Some(b"x7".as_slice()));
}

// ---------------------------------------------------------------------------
// Filtered extraction (CLI --include/--exclude)
// ---------------------------------------------------------------------------

fn make_fixture_zip(dir: &std::path::Path, tag: &str) -> PathBuf {
    // Build a real directory tree so the archive contains `sub/…` entries.
    let root = dir.join(format!("tree-{}", tag));
    std::fs::create_dir_all(root.join("sub")).unwrap();
    std::fs::write(root.join("a.txt"), "alpha").unwrap();
    std::fs::write(root.join("b.log"), "beta-log").unwrap();
    std::fs::write(root.join("sub/c.txt"), "gamma").unwrap();
    std::fs::write(root.join("sub/d.log"), "delta-log").unwrap();
    let zip = dir.join(format!("fx-{}.zip", tag));
    ops::compress(&[root], &zip, None, 6).unwrap();
    zip
}

#[test]
fn extract_exclude_removes_matching() {
    let s = Scratch::new("excl");
    let zip = make_fixture_zip(&s.0, "e");
    let out = s.path("out");
    // Entries are rooted at "tree-e/", so exclude everything under its sub/.
    let rep = ops::extract_filtered(&zip, &out, None, &[], &["tree-e/sub/".to_string()]).unwrap();
    assert_eq!(rep.files, 2, "only a.txt and b.log");
    assert!(out.join("tree-e/a.txt").exists());
    assert!(out.join("tree-e/b.log").exists());
    assert!(!out.join("tree-e/sub/c.txt").exists());
    assert!(!out.join("tree-e/sub/d.log").exists());
}

#[test]
fn extract_include_only_matching() {
    let s = Scratch::new("incl");
    let zip = make_fixture_zip(&s.0, "i");
    let out2 = s.path("out2");
    let rep = ops::extract_filtered(&zip, &out2, None, &["tree-i/sub/".to_string()], &[]).unwrap();
    assert_eq!(rep.files, 2, "sub/c.txt + sub/d.log");
    assert!(!out2.join("tree-i/a.txt").exists());
    assert!(out2.join("tree-i/sub/c.txt").exists());
}

#[test]
fn exclude_wins_over_include() {
    let s = Scratch::new("both");
    let zip = make_fixture_zip(&s.0, "b");
    let out = s.path("out");
    let rep = ops::extract_filtered(
        &zip,
        &out,
        None,
        &["tree-b/sub/".to_string()],
        &["tree-b/sub/d.log".to_string()],
    )
    .unwrap();
    assert_eq!(rep.files, 1, "sub/c.txt only — exclusion beats inclusion");
    assert!(out.join("tree-b/sub/c.txt").exists());
    assert!(!out.join("tree-b/sub/d.log").exists());
}

// ---------------------------------------------------------------------------
// Compression levels actually flow through (7z/gz/xz/bz2)
// ---------------------------------------------------------------------------

#[test]
fn gz_level_changes_output_size() {
    let s = Scratch::new("gzlvl");
    // Highly compressible, large enough for level differences to show.
    const CHUNK: usize = b"compress me please, rosezip! ".len();
    let src = s.path("input.bin");
    let mut data = Vec::with_capacity(40_000 * CHUNK);
    for _ in 0..40_000 {
        data.extend_from_slice(b"compress me please, rosezip! ");
    }
    std::fs::write(&src, &data).unwrap();

    let fast = s.path("fast.gz");
    let best = s.path("best.gz");
    ops::compress_as(&[src.clone()], &fast, None, 1, Some(OutFormat::Gz)).unwrap();
    ops::compress_as(&[src], &best, None, 9, Some(OutFormat::Gz)).unwrap();
    let fsz = std::fs::metadata(&fast).unwrap().len();
    let bsz = std::fs::metadata(&best).unwrap().len();
    assert!(bsz <= fsz, "level 9 ({}B) should not exceed level 1 ({}B)", bsz, fsz);

    // Round-trip integrity at both levels. The .gz extractor strips the
    // extension, so "fast.gz" → "fast" and "best.gz" → "best".
    for (gz, stem) in [(fast, "fast"), (best, "best")] {
        let out = s.path("rt");
        ops::extract(&gz, &out, None).unwrap();
        let back = std::fs::read(out.join(stem)).unwrap();
        assert_eq!(back.len(), 40_000 * CHUNK);
    }
}

#[test]
fn sevenz_roundtrip_with_password_and_level() {
    let s = Scratch::new("7zlvl");
    // Enough content that header compression is worthwhile (tiny headers are
    // stored raw and then even unencrypted — library behaviour).
    let mut inputs = Vec::new();
    for i in 0..24 {
        let p = s.path(&format!("doc{}.txt", i));
        std::fs::write(&p, format!("7z encrypted roundtrip content file {}", i).repeat(400)).unwrap();
        inputs.push(p);
    }
    let arc = s.path("enc.7z");
    ops::compress_as(&inputs, &arc, Some(b"pw7z"), 5, Some(OutFormat::SevenZ)).unwrap();

    let out = s.path("out");
    ops::extract(&arc, &out, Some(b"pw7z")).unwrap();
    let back = std::fs::read_to_string(out.join("doc0.txt")).unwrap();
    assert_eq!(back.len(), format!("7z encrypted roundtrip content file 0",).repeat(400).len());
    assert!(back.starts_with("7z encrypted"));

    // Wrong password must fail extraction.
    let out2 = s.path("out2");
    assert!(ops::extract(&arc, &out2, Some(b"wrong")).is_err());
}

#[test]
fn out_format_parse() {
    assert!(matches!(OutFormat::parse_out_format("tgz"), Ok(OutFormat::TarGz)));
    assert!(matches!(OutFormat::parse_out_format("TXZ"), Ok(OutFormat::TarXz)));
    assert!(matches!(OutFormat::parse_out_format("zip"), Ok(OutFormat::Zip)));
    assert!(OutFormat::parse_out_format("rar").is_err());
}

// ---------------------------------------------------------------------------
// WinZip AES entries: real-writer interop regressions
// ---------------------------------------------------------------------------

/// Hand-build a minimal ZIP with one WinZip AES entry (the way 7-Zip does),
/// to lock down the AES decode path without an external fixture generator.
///
/// Layout per the WinZip AES spec: outer method 99, local+central CRC 0,
/// 0x9901 extra field (strength id + inner method), entry data =
/// salt | 2-byte pw verifier | AES-CTR cipher | 10-byte HMAC-SHA1.
/// Counter starts at 1, little-endian u32 increment (7-Zip behaviour).
fn build_aes_zip(
    path: &std::path::Path,
    name: &str,
    content: &[u8],
    inner_method: u16,
    inner: Vec<u8>,
    crc: u32,
    pw: &[u8],
) {
    use rosezip_core::zipcrypt::{aes_iterations, hmac_sha1, pbkdf2_hmac_sha1_multi, Aes, AesCtr, AesStrength};

    let strength = AesStrength::Aes256;
    let sl = strength.salt_len();
    let salt: Vec<u8> = (0..sl).map(|i| (i * 7 + 3) as u8).collect();
    let mut dk = vec![0u8; strength.key_len() * 2 + 2];
    pbkdf2_hmac_sha1_multi(pw, &salt, aes_iterations(strength), &mut dk);
    let pw_verify = [dk[dk.len() - 2], dk[dk.len() - 1]];
    let mut cipher = inner;
    let mut ctr = AesCtr::new_little_endian(Aes::new(&dk[..strength.key_len()]), {
        let mut iv = [0u8; 16];
        iv[0] = 1;
        iv
    });
    ctr.apply(&mut cipher);
    let mac = &hmac_sha1(&dk[strength.key_len()..strength.key_len() * 2], &cipher)[..10];

    let mut entry_data = Vec::new();
    entry_data.extend_from_slice(&salt);
    entry_data.extend_from_slice(&pw_verify);
    entry_data.extend_from_slice(&cipher);
    entry_data.extend_from_slice(mac);

    let mut extra = Vec::new();
    extra.extend_from_slice(&0x9901u16.to_le_bytes());
    extra.extend_from_slice(&7u16.to_le_bytes());
    extra.extend_from_slice(&2u16.to_le_bytes()); // vendor version
    extra.extend_from_slice(b"AE"); // vendor id
    extra.push(3); // AES-256
    extra.extend_from_slice(&inner_method.to_le_bytes());

    let name_bytes = name.as_bytes();
    let mut blob: Vec<u8> = Vec::new();

    // local file header
    blob.extend_from_slice(b"PK\x03\x04");
    blob.extend_from_slice(&20u16.to_le_bytes()); // version
    blob.extend_from_slice(&1u16.to_le_bytes()); // flags: encrypted
    blob.extend_from_slice(&99u16.to_le_bytes()); // outer method
    blob.extend_from_slice(&0u16.to_le_bytes()); // dos time
    blob.extend_from_slice(&0x5B99u16.to_le_bytes()); // dos date
    blob.extend_from_slice(&crc.to_le_bytes());
    let csize = entry_data.len() as u32;
    blob.extend_from_slice(&csize.to_le_bytes());
    blob.extend_from_slice(&(content.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    blob.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    blob.extend_from_slice(name_bytes);
    blob.extend_from_slice(&extra);
    blob.extend_from_slice(&entry_data);
    let cd_offset = blob.len() as u32;

    // central directory
    let cd_start = blob.len();
    blob.extend_from_slice(b"PK\x01\x02");
    blob.extend_from_slice(&20u16.to_le_bytes()); // version made by
    blob.extend_from_slice(&20u16.to_le_bytes()); // version needed
    blob.extend_from_slice(&1u16.to_le_bytes()); // flags
    blob.extend_from_slice(&99u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0x5B99u16.to_le_bytes());
    blob.extend_from_slice(&crc.to_le_bytes());
    blob.extend_from_slice(&csize.to_le_bytes());
    blob.extend_from_slice(&(content.len() as u32).to_le_bytes());
    blob.extend_from_slice(&(name_bytes.len() as u16).to_le_bytes());
    blob.extend_from_slice(&(extra.len() as u16).to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes()); // comment len
    blob.extend_from_slice(&0u16.to_le_bytes()); // disk
    blob.extend_from_slice(&0u16.to_le_bytes()); // internal attrs
    blob.extend_from_slice(&0u32.to_le_bytes()); // external attrs
    blob.extend_from_slice(&0u32.to_le_bytes()); // local header offset
    blob.extend_from_slice(name_bytes);
    blob.extend_from_slice(&extra);
    let cd_size = (blob.len() - cd_start) as u32;

    // EOCD
    blob.extend_from_slice(b"PK\x05\x06");
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&1u16.to_le_bytes());
    blob.extend_from_slice(&cd_size.to_le_bytes());
    blob.extend_from_slice(&cd_offset.to_le_bytes());
    blob.extend_from_slice(&0u16.to_le_bytes());

    std::fs::write(path, &blob).unwrap();
}

#[test]
fn winzip_aes_store_inner_decodes() {
    // 7-Zip stores small files as AES over an uncompressed (method 0) inner
    // stream with CRC zeroed. Regression: the decoder used to treat method
    // 99 as "deflate inner", corrupting every such entry while test still
    // reported ok (CRC check was skipped for method 99).
    let s = Scratch::new("aesstore");
    let zip = s.path("aes_store.zip");
    let content = "hello rosezip aes interop 中文内容\n".as_bytes();
    build_aes_zip(&zip, "data.txt", content, 0, content.to_vec(), 0, b"pw42");

    let out = s.path("out");
    let rep = ops::extract(&zip, &out, Some(b"pw42")).unwrap();
    assert_eq!(rep.files, 1, "errors: {:?}", rep.errors);
    let back = std::fs::read(out.join("data.txt")).unwrap();
    assert_eq!(back, content);

    // wrong password is an error, not garbage output
    let out2 = s.path("out2");
    let rep2 = ops::extract(&zip, &out2, Some(b"bad")).unwrap();
    assert!(!rep2.errors.is_empty());
}

#[test]
fn winzip_aes_deflate_inner_decodes() {
    // Larger file: 7-Zip uses AES over deflate (inner method 8), still with
    // CRC 0 in both headers.
    let s = Scratch::new("aesdeflate");
    let zip = s.path("aes_deflate.zip");
    let mut content = Vec::new();
    for _ in 0..40 {
        content.extend_from_slice("deflate payload for aes inner method test 中文\n".as_bytes());
    }
    let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
    std::io::Write::write_all(&mut enc, &content).unwrap();
    let inner = enc.finish().unwrap();
    build_aes_zip(&zip, "big2.txt", &content, 8, inner, 0, b"pw42");

    let out = s.path("out");
    let rep = ops::extract(&zip, &out, Some(b"pw42")).unwrap();
    assert_eq!(rep.files, 1, "errors: {:?}", rep.errors);
    let back = std::fs::read(out.join("big2.txt")).unwrap();
    assert_eq!(back, content);

    // integrity test must actually verify (it used to pass on garbage)
    let report = ops::test_archive(&zip, Some(b"pw42")).unwrap();
    assert_eq!(report.errors.len(), 0);
    let bad = ops::test_archive(&zip, Some(b"nope"));
    assert!(bad.is_err() || !bad.unwrap().errors.is_empty());
}

#[test]
fn winzip_aes_crack_and_roundtrip_nonzero_crc() {
    // AE-1 style entry (real CRC stored): crack finds the password and the
    // extract path round-trips byte-identical content.
    let s = Scratch::new("aesae1");
    let zip = s.path("aes_ae1.zip");
    let content = "python pyzipper aes interop 内容\n".as_bytes();
    let crc = rosezip_core::archive::crc32(content);
    build_aes_zip(&zip, "hello.txt", content, 0, content.to_vec(), crc, b"pw42");

    let plan = ops::prepare_crack(&zip).unwrap();
    assert_eq!(plan.kind, "WinZip-AES");
    let handle = rosezip_core::crack::spawn_job(
        rosezip_core::crack::CrackTarget::Mask {
            mask: rosezip_core::charset::MaskGen::parse("pw?d?d").unwrap(),
        },
        plan.verifier.clone(),
        2,
    );
    for _ in 0..600 {
        if handle.status().finished {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(25));
    }
    let res = handle.join();
    assert_eq!(res.password.as_deref(), Some(b"pw42".as_slice()));

    let out = s.path("out");
    let rep = ops::extract(&zip, &out, Some(b"pw42")).unwrap();
    assert_eq!(rep.files, 1);
    assert_eq!(std::fs::read(out.join("hello.txt")).unwrap(), content);
}
