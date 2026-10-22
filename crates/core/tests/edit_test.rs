use rosezip_core::ops;
use std::path::PathBuf;

#[test]
fn zip_delete_and_rename() {
    let zt = PathBuf::from("/tmp/opencode/zt");
    let src = zt.join("wt.zip");
    let work = zt.join("edit_work.zip");
    std::fs::copy(&src, &work).unwrap();

    // delete treetest/docs/ subtree
    let n = ops::delete_entries(&work, &["treetest/docs/".into()], None).unwrap();
    assert_eq!(n, 2, "dir entry + notes.txt");
    let view = ops::inspect(&work).unwrap();
    assert!(!view.entries.iter().any(|e| e.name.contains("docs")));

    // rename a file
    let n = ops::rename_entries(&work, &[("treetest/README.md".into(), "treetest/读我.md".into())], None).unwrap();
    assert_eq!(n, 1);
    let view = ops::inspect(&work).unwrap();
    assert!(view.entries.iter().any(|e| e.name == "treetest/读我.md"));

    // round-trip extract still works
    let dest = zt.join("rt_edit");
    let _ = std::fs::remove_dir_all(&dest);
    let rep = ops::extract(&work, &dest, None).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert!(dest.join("treetest/读我.md").exists());

    // delete whole subtree by prefix
    let n = ops::delete_entries(&work, &["treetest/".into()], None).unwrap();
    assert!(n >= 4);
    let view = ops::inspect(&work).unwrap();
    assert!(!view.entries.iter().any(|e| e.name.starts_with("treetest")));
    assert!(view.entries.iter().any(|e| e.name == "emptydir/"), "empty dir survives");
    std::fs::remove_file(&work).unwrap();
    let _ = std::fs::remove_dir_all(&dest);
}

#[test]
fn sevenz_edit_roundtrip() {
    let zt = PathBuf::from("/tmp/opencode/zt");
    let src = zt.join("new7z.7z");
    let work = zt.join("edit7.7z");
    std::fs::copy(&src, &work).unwrap();

    let n = ops::delete_entries(&work, &["treetest/docs/".into()], None).unwrap();
    assert_eq!(n, 2);
    let n = ops::rename_entries(
        &work,
        &[("treetest/README.md".into(), "treetest/renamed.md".into())],
        None,
    )
    .unwrap();
    assert_eq!(n, 1);

    let dest = zt.join("rt_edit7");
    let _ = std::fs::remove_dir_all(&dest);
    let rep = ops::extract(&work, &dest, None).unwrap();
    assert_eq!(rep.errors.len(), 0);
    assert!(dest.join("treetest/renamed.md").exists());
    assert!(!dest.join("treetest/docs").exists());
    std::fs::remove_file(&work).unwrap();
    let _ = std::fs::remove_dir_all(&dest);
}

#[test]
fn tar_gz_roundtrip_preserves_tree() {
    let zt = PathBuf::from("/tmp/opencode/zt");
    let tgz = zt.join("ci.tar.gz");
    let _ = std::fs::remove_file(&tgz);
    ops::compress_as(
        &[zt.join("treetest")],
        &tgz,
        None,
        6,
        Some(ops::OutFormat::TarGz),
    )
    .unwrap();
    let dest = zt.join("rt_citgz");
    let _ = std::fs::remove_dir_all(&dest);
    ops::extract(&tgz, &dest, None).unwrap();
    assert!(dest.join("treetest/src/data.bin").exists());
    assert!(dest.join("treetest/docs/notes.txt").exists());
    std::fs::remove_file(&tgz).unwrap();
    let _ = std::fs::remove_dir_all(&dest);
}
