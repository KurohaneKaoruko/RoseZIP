//! Integration tests for archive editing, round-trips and encryption paths.
//! Self-contained: every fixture is built with the engine's own compressors.

use rosezip_core::ops::{self, OutFormat};
use std::path::PathBuf;

/// Deterministic scratch dir for one test, cleaned on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Self {
        let dir = std::env::temp_dir().join(format!("rosezip-it-{}-{}", tag, std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Scratch(dir)
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Build the canonical test tree inside `root`:
/// `tree/src/data.bin`, `tree/src/main.py`, `tree/docs/notes.txt`, `tree/README.md`.
fn make_tree(root: &std::path::Path) -> PathBuf {
    let tree = root.join("tree");
    std::fs::create_dir_all(tree.join("src")).unwrap();
    std::fs::create_dir_all(tree.join("docs")).unwrap();
    std::fs::write(tree.join("src/data.bin"), vec![0xABu8; 2048]).unwrap();
    std::fs::write(tree.join("src/main.py"), b"print('hello rosezip')\n").unwrap();
    std::fs::write(tree.join("docs/notes.txt"), "notes with UTF-8: 中文\n").unwrap();
    std::fs::write(tree.join("README.md"), "# tree\n").unwrap();
    tree
}

#[test]
fn zip_delete_and_rename() {
    let zt = Scratch::new("zipedit");
    let tree = make_tree(&zt.0);
    let src = zt.0.join("tree.zip");
    ops::compress(&[tree.clone()], &src, None, 6).unwrap();
    let work = zt.0.join("edit_work.zip");
    std::fs::copy(&src, &work).unwrap();

    // delete tree/docs/ subtree
    let n = ops::delete_entries(&work, &["tree/docs/".into()], None).unwrap();
    assert_eq!(n, 2, "dir entry + notes.txt");
    let view = ops::inspect(&work).unwrap();
    assert!(!view.entries.iter().any(|e| e.name.contains("docs")));

    // rename a file (UTF-8 target exercises the EFS flag)
    let n = ops::rename_entries(
        &work,
        &[("tree/README.md".into(), "tree/读我.md".into())],
        None,
    )
    .unwrap();
    assert_eq!(n, 1);
    let view = ops::inspect(&work).unwrap();
    assert!(view.entries.iter().any(|e| e.name == "tree/读我.md"));

    // round-trip extract still works
    let dest = zt.0.join("rt_edit");
    let rep = ops::extract(&work, &dest, None).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert!(dest.join("tree/读我.md").exists());

    // delete whole subtree by prefix
    let n = ops::delete_entries(&work, &["tree/".into()], None).unwrap();
    assert!(n >= 4);
    let view = ops::inspect(&work).unwrap();
    assert!(!view.entries.iter().any(|e| e.name.starts_with("tree")));
}

#[test]
fn sevenz_edit_roundtrip() {
    let zt = Scratch::new("7edit");
    let tree = make_tree(&zt.0);
    let src = zt.0.join("tree.7z");
    ops::compress_as(&[tree], &src, None, 6, Some(OutFormat::SevenZ)).unwrap();
    let work = zt.0.join("edit7.7z");
    std::fs::copy(&src, &work).unwrap();

    let n = ops::delete_entries(&work, &["tree/docs/".into()], None).unwrap();
    assert_eq!(n, 2);
    let n = ops::rename_entries(
        &work,
        &[("tree/README.md".into(), "tree/renamed.md".into())],
        None,
    )
    .unwrap();
    assert_eq!(n, 1);

    let dest = zt.0.join("rt_edit7");
    let rep = ops::extract(&work, &dest, None).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert!(dest.join("tree/renamed.md").exists());
    assert!(!dest.join("tree/docs").exists());
}

#[test]
fn tar_gz_roundtrip_preserves_tree() {
    let zt = Scratch::new("tgz");
    let tree = make_tree(&zt.0);
    let tgz = zt.0.join("ci.tar.gz");
    ops::compress_as(&[tree], &tgz, None, 6, Some(OutFormat::TarGz)).unwrap();
    let dest = zt.0.join("rt_citgz");
    ops::extract(&tgz, &dest, None).unwrap();
    assert!(dest.join("tree/src/data.bin").exists());
    assert!(dest.join("tree/docs/notes.txt").exists());
}

#[test]
fn zip_roundtrip_all_formats_and_test() {
    let zt = Scratch::new("fmts");
    let tree = make_tree(&zt.0);

    let cases = [
        ("t.tar", OutFormat::Tar),
        ("t.tar.gz", OutFormat::TarGz),
        ("t.tar.xz", OutFormat::TarXz),
        ("t.tar.bz2", OutFormat::TarBz2),
    ];
    for (name, fmt) in cases {
        let out = zt.0.join(name);
        ops::compress_as(&[tree.clone()], &out, None, 6, Some(fmt)).unwrap();
        // integrity test must pass
        let rep = ops::test_archive(&out, None).unwrap();
        assert!(rep.errors.is_empty(), "{}: {:?}", name, rep.errors);
        // and a round-trip must restore every file
        let dest = zt.0.join(format!("rt-{}", name));
        ops::extract(&out, &dest, None).unwrap();
        assert!(dest.join("tree/src/data.bin").exists(), "{}", name);
        assert!(dest.join("tree/docs/notes.txt").exists(), "{}", name);
    }

    // single-stream formats: compress one file, verify, extract and compare.
    // The extracted file lands under the archive's stem (data.bin -> d).
    let data = zt.0.join("data.bin");
    std::fs::copy(tree.join("src/data.bin"), &data).unwrap();
    for (name, fmt) in [("d.gz", OutFormat::Gz), ("d.xz", OutFormat::Xz), ("d.bz2", OutFormat::Bz2)] {
        let out = zt.0.join(name);
        ops::compress_as(&[data.clone()], &out, None, 6, Some(fmt)).unwrap();
        let rep = ops::test_archive(&out, None).unwrap();
        assert!(rep.errors.is_empty(), "{}: {:?}", name, rep.errors);
        // listing shows the stem as the single entry
        let view = ops::inspect(&out).unwrap();
        assert_eq!(view.entries.len(), 1, "{}", name);
        assert_eq!(view.entries[0].name, "d", "{}", name);
        let dest = zt.0.join(format!("rt-{}", name));
        ops::extract(&out, &dest, None).unwrap();
        assert_eq!(std::fs::read(dest.join("d")).unwrap(), vec![0xABu8; 2048], "{}", name);
    }
}

#[test]
fn zip_encrypted_roundtrip_and_crack() {
    let zt = Scratch::new("enc");
    let tree = make_tree(&zt.0);
    let enc = zt.0.join("enc.zip");
    ops::compress(&[tree], &enc, Some(b"pw42"), 6).unwrap();

    // check detects encryption
    let view = ops::inspect(&enc).unwrap();
    assert!(view.encryption.is_some());
    assert!(view.entries.iter().any(|e| e.encrypted));

    // extract with the right password works
    let ok = zt.0.join("rt_ok");
    let rep = ops::extract(&enc, &ok, Some(b"pw42")).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert!(ok.join("tree/README.md").exists());

    // extract without a password skips encrypted entries and reports them
    let no = zt.0.join("rt_no");
    let rep = ops::extract(&enc, &no, None).unwrap();
    assert_eq!(rep.skipped_encrypted, 4);

    // a wrong password surfaces as an error, not a panic
    let bad = zt.0.join("rt_bad");
    let rep = ops::extract(&enc, &bad, Some(b"wrong")).unwrap();
    assert!(!rep.errors.is_empty());
}

#[test]
fn empty_dirs_survive_zip_roundtrip() {
    let zt = Scratch::new("empty");
    let tree = make_tree(&zt.0);
    std::fs::create_dir_all(tree.join("emptydir/nested")).unwrap();
    let zip = zt.0.join("empty.zip");
    ops::compress(&[tree], &zip, None, 6).unwrap();

    let view = ops::inspect(&zip).unwrap();
    assert!(view.entries.iter().any(|e| e.name == "tree/emptydir/"));
    assert!(view.entries.iter().any(|e| e.name == "tree/emptydir/nested/"));

    let dest = zt.0.join("rt");
    ops::extract(&zip, &dest, None).unwrap();
    assert!(dest.join("tree/emptydir/nested").is_dir());

    // deleting every entry yields a valid, still-listable empty archive
    let all: Vec<String> = ops::inspect(&zip)
        .unwrap()
        .entries
        .iter()
        .map(|e| e.name.clone())
        .collect();
    let n = ops::delete_entries(&zip, &all, None).unwrap();
    assert_eq!(n, all.len());
    let view = ops::inspect(&zip).unwrap();
    assert!(view.entries.is_empty(), "empty archive must remain listable");
}

#[test]
fn utf8_names_survive_zip_roundtrip() {
    let zt = Scratch::new("utf8");
    let dir = zt.0.join("中文目录");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("文件.txt"), "utf-8 content\n").unwrap();

    let zip = zt.0.join("utf.zip");
    ops::compress(&[dir], &zip, None, 6).unwrap();

    let view = ops::inspect(&zip).unwrap();
    assert!(view.entries.iter().any(|e| e.name == "中文目录/文件.txt"));

    let dest = zt.0.join("rt");
    let rep = ops::extract(&zip, &dest, None).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert_eq!(std::fs::read(dest.join("中文目录/文件.txt")).unwrap(), b"utf-8 content\n");
}

#[test]
fn extract_rejects_traversal_names() {
    let zt = Scratch::new("trav");
    // Hand-craft a malicious ZIP whose entry name tries to escape the dest dir.
    let evil_name = "../rosezip-traversal-payload";
    let mut z = crate_zip_helpers::build_min_zip(evil_name, b"evil");
    let zip = zt.0.join("evil.zip");
    std::fs::write(&zip, &mut z).unwrap();

    let dest = zt.0.join("dest");
    ops::extract(&zip, &dest, None).unwrap();
    // the payload must have landed inside `dest`, never outside
    assert!(dest.join("rosezip-traversal-payload").exists());
    let escaped = zt.0.parent().unwrap().join("rosezip-traversal-payload");
    assert!(!escaped.exists(), "zip traversal must be contained");
}

#[test]
fn unsupported_and_missing_inputs_error() {
    let zt = Scratch::new("err");
    // missing input
    let out = zt.0.join("out.zip");
    assert!(ops::compress(&[zt.0.join("nope.txt")], &out, None, 6).is_err());
    // empty inputs
    assert!(ops::compress_as(&[], &out, None, 6, Some(OutFormat::Zip)).is_err());
    // unrecognized archive
    let junk = zt.0.join("junk.bin");
    std::fs::write(&junk, b"not an archive at all").unwrap();
    assert!(ops::inspect(&junk).is_err());
}

/// Minimal hand-rolled ZIP writer used to craft adversarial inputs.
mod crate_zip_helpers {
    use rosezip_core::archive;

    pub fn build_min_zip(name: &str, content: &[u8]) -> Vec<u8> {
        let crc = archive::crc32(content);
        let mut out = Vec::new();

        // local file header
        let mut lfh = [0u8; 30];
        lfh[..4].copy_from_slice(b"PK\x03\x04");
        lfh[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
        out.extend_from_slice(&lfh);
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(content);

        // central directory
        let cd_offset = out.len() as u32;
        let mut cdh = [0u8; 46];
        cdh[..4].copy_from_slice(b"PK\x01\x02");
        cdh[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
        cdh[16..20].copy_from_slice(&crc.to_le_bytes());
        cdh[20..24].copy_from_slice(&(content.len() as u32).to_le_bytes());
        cdh[24..28].copy_from_slice(&(content.len() as u32).to_le_bytes());
        out.extend_from_slice(&cdh);
        out.extend_from_slice(name.as_bytes());

        // EOCD
        let cd_size = out.len() as u32 - cd_offset;
        let mut eocd = [0u8; 22];
        eocd[..4].copy_from_slice(b"PK\x05\x06");
        eocd[8..10].copy_from_slice(&1u16.to_le_bytes());
        eocd[10..12].copy_from_slice(&1u16.to_le_bytes());
        eocd[12..16].copy_from_slice(&cd_size.to_le_bytes());
        eocd[16..20].copy_from_slice(&cd_offset.to_le_bytes());
        out.extend_from_slice(&eocd);
        out
    }
}
