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
