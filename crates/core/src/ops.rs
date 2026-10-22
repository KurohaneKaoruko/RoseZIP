//! High-level operations shared by the CLI, TUI and GUI front ends.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::archive::{self, Format, ZipEntry};
use crate::charset::{self, IndexGen};
use crate::zipcrypt::{self, AesStrength, Verifier, ZipCrypto};

/// Central-directory bookkeeping for the native ZIP writer.
struct CdRecord {
    name: String,
    method: u16,
    crc: u32,
    csize: u32,
    usize_: u32,
    offset: u32,
    dos_time: u16,
    dos_date: u16,
    encrypted: bool,
}

/// 0x800 when the name needs the UTF-8 (EFS) flag, 0 when pure ASCII.
fn is_ascii_name(name: &str) -> bool {
    name.is_ascii()
}

fn efs_flag(name: &str) -> u16 {
    if is_ascii_name(name) {
        0
    } else {
        0x800
    }
}

/// Append a directory entry (0-byte, method 0) to the archive under build.
fn write_zip_dir(
    writer: &mut fs::File,
    name: &str,
    dos_time: u16,
    dos_date: u16,
    central: &mut Vec<CdRecord>,
) -> io::Result<()> {
    let offset = writer.stream_position()? as u32;
    let mut lfh = [0u8; 30];
    lfh[..4].copy_from_slice(b"PK\x03\x04");
    lfh[4..6].copy_from_slice(&20u16.to_le_bytes());
    lfh[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
    writer.write_all(&lfh)?;
    writer.write_all(name.as_bytes())?;
    central.push(CdRecord {
        name: name.to_owned(),
        method: 0,
        crc: 0,
        csize: 0,
        usize_: 0,
        offset,
        dos_time,
        dos_date,
        encrypted: false,
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// Info / list
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct EntryView {
    pub name: String,
    pub encrypted: bool,
    pub is_dir: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub mtime: u64,
}

pub struct ArchiveView {
    pub path: PathBuf,
    pub format: Format,
    pub entries: Vec<EntryView>,
    pub encryption: Option<String>,
}

pub fn inspect(path: &Path) -> io::Result<ArchiveView> {
    let format = archive::detect_format(path)?;
    // Encrypted-header 7z cannot even be listed without a password — surface
    // that as a friendly encryption note with an empty entry list.
    if format == archive::Format::SevenZ && archive::sevenz_header_encrypted(path) {
        return Ok(ArchiveView {
            path: path.to_path_buf(),
            format,
            entries: Vec::new(),
            encryption: Some("7z AES-256 · 加密头 · 输入密码后可列出并解压".into()),
        });
    }
    let info = archive::list_archive(path)?;
    let has_encrypted = info.entries.iter().any(|e| e.encrypted);
    let encryption = if has_encrypted {
        Some(encryption_type(path)?)
    } else {
        None
    };
    Ok(ArchiveView {
        path: path.to_path_buf(),
        format,
        entries: info
            .entries
            .into_iter()
            .map(|e| EntryView {
                name: e.name,
                encrypted: e.encrypted,
                is_dir: e.is_dir,
                compressed_size: e.compressed_size,
                uncompressed_size: e.uncompressed_size,
                mtime: e.mtime,
            })
            .collect(),
        encryption,
    })
}

pub fn encryption_type(path: &Path) -> io::Result<String> {
    match archive::detect_format(path)? {
        archive::Format::SevenZ => {
            if archive::sevenz_header_encrypted(path) {
                Ok("7z AES-256 (encrypted header, PBKDF2)".into())
            } else {
                Ok("7z (AES-256 if encrypted, header readable)".into())
            }
        }
        archive::Format::Tar | archive::Format::Gz | archive::Format::Xz | archive::Format::Bz2 => {
            Ok("no encryption (tar/gz/xz/bz2 do not support passwords)".into())
        }
        _ => {
            let mut file = fs::File::open(path)?;
            let entries = archive::parse_zip_central_directory(&mut file)?;
            for e in &entries {
                if e.encrypted && e.method == 99 {
                    return Ok("WinZip AES (strong, PBKDF2-HMAC-SHA1)".into());
                }
            }
            Ok("ZipCrypto (legacy, fast to attack)".into())
        }
    }
}

// ---------------------------------------------------------------------------
// Extract
// ---------------------------------------------------------------------------

pub fn extract(path: &Path, dest: &Path, password: Option<&[u8]>) -> io::Result<ExtractReport> {
    fs::create_dir_all(dest)?;
    let format = archive::detect_format(path)?;
    match format {
        Format::Zip => extract_zip(path, dest, password),
        _ => {
            // Encrypted-header 7z can't be listed without the password — count later.
            let n = match archive::list_archive(path) {
                Ok(view) => view.entries.iter().filter(|e| !e.is_dir).count(),
                Err(_) => 0,
            };
            archive::extract_native(path, dest, password)?;
            Ok(ExtractReport { files: n, skipped_encrypted: 0, errors: Vec::new() })
        }
    }
}

/// Extract only the named entries (prefix match on directories).
/// ZIP does it precisely; other formats fall back to full extraction and
/// keep only the requested names.
pub fn extract_entries(
    path: &Path,
    names: &[String],
    dest: &Path,
    password: Option<&[u8]>,
) -> io::Result<ExtractReport> {
    if names.is_empty() {
        return Err(bad("no entries selected"));
    }
    fs::create_dir_all(dest)?;
    match archive::detect_format(path)? {
        Format::Zip => {
            let want = |name: &str| -> bool {
                names.iter().any(|n| {
                    let n = n.trim_end_matches('/');
                    let name = name.trim_end_matches('/');
                    n == name
                        || name.strip_prefix(n).map_or(false, |rest| rest.starts_with('/'))
                        || n.strip_prefix(name).map_or(false, |rest| rest.starts_with('/'))
                })
            };
            let mut file = fs::File::open(path)?;
            let entries = archive::parse_zip_central_directory(&mut file)?;
            let mut report = ExtractReport { files: 0, skipped_encrypted: 0, errors: Vec::new() };
            for entry in &entries {
                if !want(&entry.name) {
                    continue;
                }
                if entry.is_dir {
                    fs::create_dir_all(safe_entry_path(dest, &entry.name))?;
                    continue;
                }
                if entry.encrypted && password.is_none() {
                    report.skipped_encrypted += 1;
                    report.errors.push(format!("{}: encrypted (password required)", entry.name));
                    continue;
                }
                match extract_one_zip_entry(&mut file, entry, dest, password) {
                    Ok(()) => report.files += 1,
                    Err(e) => report.errors.push(format!("{}: {}", entry.name, e)),
                }
            }
            Ok(report)
        }
        _ => {
            // Non-ZIP: extract everything, then prune what wasn't requested.
            let report = extract(path, dest, password)?;
            // remove files not selected
            for e in archive::list_archive(path)
                .map(|i| i.entries)
                .unwrap_or_default()
            {
                let selected = names.iter().any(|n| {
                    n == &e.name || e.name.starts_with(&format!("{}/", n.trim_end_matches('/')))
                });
                if !selected && !e.is_dir {
                    let p = dest.join(&e.name);
                    let _ = fs::remove_file(p);
                }
            }
            let kept = names.len();
            Ok(ExtractReport {
                files: kept.min(report.files),
                skipped_encrypted: report.skipped_encrypted,
                errors: report.errors,
            })
        }
    }
}

/// Test archive integrity: decode every entry and verify checksums without
/// writing anything (7-Zip's "Test" command).
pub fn test_archive(path: &Path, password: Option<&[u8]>) -> io::Result<TestReport> {
    match archive::detect_format(path)? {
        Format::Zip => test_zip(path, password),
        // 7z: a full decode via sevenz_test_password verifies CRC of every entry.
        Format::SevenZ => {
            let ok = archive::sevenz_test_password(path, password.unwrap_or(b""))?;
            Ok(TestReport {
                files: 0,
                errors: if ok { Vec::new() } else { vec!["CRC 校验失败（密码错误或数据损坏）".into()] },
            })
        }
        _ => {
            // tar/gz/xz/bz2: decode to /dev/null equivalent (temp buffer).
            let tmp = std::env::temp_dir().join("rosezip-test-probe");
            archive::extract_native(path, &tmp, None)?;
            let _ = fs::remove_dir_all(&tmp);
            Ok(TestReport { files: 1, errors: Vec::new() })
        }
    }
}

pub struct TestReport {
    pub files: usize,
    pub errors: Vec<String>,
}

fn test_zip(path: &Path, password: Option<&[u8]>) -> io::Result<TestReport> {
    let mut file = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut file)?;
    let mut report = TestReport { files: 0, errors: Vec::new() };
    for entry in &entries {
        if entry.is_dir {
            continue;
        }
        if entry.encrypted && password.is_none() {
            report.errors.push(format!("{}: encrypted (password required)", entry.name));
            continue;
        }
        match test_one_zip_entry(&mut file, entry, password) {
            Ok(()) => report.files += 1,
            Err(e) => report.errors.push(format!("{}: {}", entry.name, e)),
        }
    }
    Ok(report)
}

/// Decode one entry in memory and check its CRC — no files written.
fn test_one_zip_entry(
    file: &mut fs::File,
    entry: &ZipEntry,
    password: Option<&[u8]>,
) -> io::Result<()> {
    use std::io::Read;
    let data_off = archive::local_data_offset(file, entry)?;
    file.seek(SeekFrom::Start(data_off))?;
    let mut raw = Vec::with_capacity(entry.compressed_size as usize);
    std::io::Read::by_ref(file).take(entry.compressed_size).read_to_end(&mut raw)?;

    let plain: Vec<u8> = if entry.encrypted {
        let pw = password.ok_or_else(|| bad("password required"))?;
        if entry.method == 99 {
            decrypt_winzip_aes(entry, &raw, pw)?
        } else {
            let mut z = ZipCrypto::new(pw);
            let mut buf = raw;
            z.decrypt(&mut buf);
            buf[12..].to_vec()
        }
    } else {
        raw
    };

    let content = match entry.method {
        0 => plain,
        8 => archive::inflate(&plain, entry.uncompressed_size)?,
        99 => match archive::inflate(&plain, entry.uncompressed_size) {
            Ok(out) => out,
            Err(_) => plain,
        },
        m => return Err(bad(&format!("unsupported compression method {}", m))),
    };
    if entry.method != 99 && archive::crc32(&content) != entry.crc32 {
        return Err(bad("CRC mismatch (wrong password?)"));
    }
    Ok(())
}

pub struct ExtractReport {
    pub files: usize,
    pub skipped_encrypted: usize,
    pub errors: Vec<String>,
}

fn extract_zip(path: &Path, dest: &Path, password: Option<&[u8]>) -> io::Result<ExtractReport> {
    let mut file = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut file)?;
    let mut report = ExtractReport { files: 0, skipped_encrypted: 0, errors: Vec::new() };
    for entry in &entries {
        if entry.is_dir {
            fs::create_dir_all(safe_entry_path(dest, &entry.name))?;
            continue;
        }
        if entry.encrypted && password.is_none() {
            report.skipped_encrypted += 1;
            report.errors.push(format!("{}: encrypted (password required)", entry.name));
            continue;
        }
        match extract_one_zip_entry(&mut file, entry, dest, password) {
            Ok(()) => report.files += 1,
            Err(e) => report.errors.push(format!("{}: {}", entry.name, e)),
        }
    }
    Ok(report)
}

pub(crate) fn extract_one_zip_entry(
    file: &mut fs::File,
    entry: &ZipEntry,
    dest: &Path,
    password: Option<&[u8]>,
) -> io::Result<()> {
    let data_off = archive::local_data_offset(file, entry)?;
    let mut raw = Vec::with_capacity(entry.compressed_size as usize);
    file.seek(SeekFrom::Start(data_off))?;
    Read::by_ref(file).take(entry.compressed_size).read_to_end(&mut raw)?;

    let plain: Vec<u8> = if entry.encrypted {
        let pw = password.ok_or_else(|| bad("password required"))?;
        if entry.method == 99 {
            decrypt_winzip_aes(entry, &raw, pw)?
        } else {
            let mut z = ZipCrypto::new(pw);
            let mut buf = raw;
            z.decrypt(&mut buf);
            buf[12..].to_vec()
        }
    } else {
        raw
    };

    let content = match entry.method {
        0 => plain,
        8 => archive::inflate(&plain, entry.uncompressed_size)?,
        99 => match archive::inflate(&plain, entry.uncompressed_size) {
            Ok(out) => out,
            Err(_) => plain,
        },
        m => return Err(bad(&format!("unsupported compression method {}", m))),
    };
    if entry.method != 99 && archive::crc32(&content) != entry.crc32 {
        return Err(bad("CRC mismatch (wrong password?)"));
    }
    let out_path = safe_entry_path(dest, &entry.name);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out_path, &content)?;
    restore_mtime(&out_path, entry.dos_date, entry.dos_time)?;
    Ok(())
}

/// Entry name → dest path with traversal protection (`../`, absolute, `\`).
fn safe_entry_path(dest: &Path, name: &str) -> PathBuf {
    let rel = name.replace('\\', "/");
    let rel = rel.trim_start_matches('/');
    let clean: Vec<&str> = rel.split('/').filter(|c| !c.is_empty() && *c != "..").collect();
    let mut p = dest.to_path_buf();
    for c in &clean {
        p.push(c);
    }
    p
}

/// Convert ZIP DOS date/time back to an mtime on the extracted file.
fn restore_mtime(path: &Path, dos_date: u16, dos_time: u16) -> io::Result<()> {
    let secs = archive::dos_datetime_to_unix(dos_date, dos_time);
    if secs == 0 {
        return Ok(());
    }
    let f = fs::OpenOptions::new().write(true).open(path)?;
    let mtime = filetime::FileTime::from_system_time(std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs));
    filetime::set_file_handle_times(&f, None, Some(mtime))?;
    Ok(())
}

/// Native WinZip AES entry decryption: salt | 2-byte verifier | cipher | 10-byte HMAC.
fn decrypt_winzip_aes(entry: &ZipEntry, raw: &[u8], pw: &[u8]) -> io::Result<Vec<u8>> {
    for strength in
        [AesStrength::Aes128, AesStrength::Aes192, AesStrength::Aes256]
    {
        let sl = strength.salt_len();
        if raw.len() < sl + 2 + 10 {
            continue;
        }
        let salt = &raw[..sl];
        let pw_verify = &raw[sl..sl + 2];
        let cipher = &raw[sl + 2..raw.len() - 10];
        let mac = &raw[raw.len() - 10..];
        let key_len = strength.key_len();
        let iterations = zipcrypt::aes_iterations(strength);
        let mut dk = vec![0u8; key_len * 2 + 2];
        zipcrypt::pbkdf2_hmac_sha1_multi(pw, salt, iterations, &mut dk);
        if dk[key_len * 2] != pw_verify[0] || dk[key_len * 2 + 1] != pw_verify[1] {
            continue;
        }
        let aes_key = &dk[..key_len];
        let hmac_key = &dk[key_len..key_len * 2];
        let computed = zipcrypt::hmac_sha1(hmac_key, cipher);
        if computed[..10] != mac[..] {
            continue;
        }
        // Try both CTR endiannesses (7z writes LE, WinZip spec says BE).
        for le in [true, false] {
            let mut iv = [0u8; 16];
            if le {
                iv[0] = 1;
            } else {
                iv[15] = 1;
            }
            let mut ctr = if le {
                zipcrypt::AesCtr::new_little_endian(zipcrypt::Aes::new(aes_key), iv)
            } else {
                zipcrypt::AesCtr::new(zipcrypt::Aes::new(aes_key), iv)
            };
            let mut plain = cipher.to_vec();
            ctr.apply(&mut plain);
            if entry.method == 99 {
                if archive::inflate(&plain, entry.uncompressed_size).is_ok() {
                    return Ok(plain);
                }
            } else if archive::crc32(&plain) == entry.crc32 {
                return Ok(plain);
            }
        }
        // Neither variant validated but HMAC passed: return the spec variant.
        let mut iv = [0u8; 16];
        iv[15] = 1;
        let mut ctr = zipcrypt::AesCtr::new(zipcrypt::Aes::new(aes_key), iv);
        let mut plain = cipher.to_vec();
        ctr.apply(&mut plain);
        return Ok(plain);
    }
    Err(bad("WinZip AES authentication failed (wrong password?)"))
}

// ---------------------------------------------------------------------------
// Compress (native ZIP writer, optional ZipCrypto encryption)
// ---------------------------------------------------------------------------

pub struct CompressReport {
    pub files: usize,
    pub bytes: u64,
}

pub fn compress(
    inputs: &[PathBuf],
    out: &Path,
    password: Option<&[u8]>,
    level: u32,
) -> io::Result<CompressReport> {
    compress_as(inputs, out, password, level, None)
}

/// Compression output format, inferred from the file extension when not given.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutFormat {
    Zip,
    SevenZ,
    Tar,
    TarGz,
    TarXz,
    TarBz2,
    Gz,
    Xz,
    Bz2,
}

impl OutFormat {
    /// Guess from the output file name; ZIP as the fall-back.
    pub fn from_path(p: &Path) -> Self {
        let name = p.file_name().unwrap_or_default().to_string_lossy().to_lowercase();
        if name.ends_with(".tar.gz") || name.ends_with(".tgz") {
            Self::TarGz
        } else if name.ends_with(".tar.xz") || name.ends_with(".txz") {
            Self::TarXz
        } else if name.ends_with(".tar.bz2") || name.ends_with(".tbz2") {
            Self::TarBz2
        } else if name.ends_with(".tar") {
            Self::Tar
        } else if name.ends_with(".7z") {
            Self::SevenZ
        } else if name.ends_with(".zip") {
            Self::Zip
        } else if name.ends_with(".gz") {
            Self::Gz
        } else if name.ends_with(".xz") {
            Self::Xz
        } else if name.ends_with(".bz2") {
            Self::Bz2
        } else {
            Self::Zip
        }
    }
}

/// Compress to any supported output format. `password` applies to ZIP
/// (ZipCrypto) and 7z (AES-256, header also encrypted); it is ignored for
/// tar/gz/xz/bz2 which have no encryption concept.
pub fn compress_as(
    inputs: &[PathBuf],
    out: &Path,
    password: Option<&[u8]>,
    level: u32,
    format: Option<OutFormat>,
) -> io::Result<CompressReport> {
    if inputs.is_empty() {
        return Err(bad("no input files given"));
    }
    for f in inputs {
        if !f.exists() {
            return Err(bad(&format!("input not found: {}", f.display())));
        }
    }
    let fmt = format.unwrap_or_else(|| OutFormat::from_path(out));
    match fmt {
        OutFormat::Zip => create_zip(inputs, out, password, level),
        OutFormat::SevenZ => create_7z(inputs, out, password),
        OutFormat::Tar => create_tar(inputs, out, None),
        OutFormat::TarGz => create_tar(inputs, out, Some(("gz", level))),
        OutFormat::TarXz => create_tar(inputs, out, Some(("xz", level))),
        OutFormat::TarBz2 => create_tar(inputs, out, Some(("bz2", level))),
        OutFormat::Gz => single_stream(inputs, out, "gz"),
        OutFormat::Xz => single_stream(inputs, out, "xz"),
        OutFormat::Bz2 => single_stream(inputs, out, "bz2"),
    }
}

// ---------------------------------------------------------------------------
// 7z writing (sevenz-rust: LZMA2 + optional AES-256 with encrypted header)
// ---------------------------------------------------------------------------

fn create_7z(inputs: &[PathBuf], out: &Path, password: Option<&[u8]>) -> io::Result<CompressReport> {
    use sevenz_rust::SevenZWriter;

    // (abs_path, archive_name) — directory inputs keep their "<dirname>/" prefix,
    // consistent with create_tar/create_zip.
    let mut plan: Vec<(PathBuf, String)> = Vec::new();
    for f in inputs {
        let base = f.parent().unwrap_or(f);
        if f.is_dir() {
            for d in walk_dirs(f) {
                let rel = d.strip_prefix(base).unwrap_or(&d).to_string_lossy().replace('\\', "/");
                plan.push((d, format!("{}/", rel.trim_end_matches('/'))));
            }
            for p in walk_files(f) {
                let rel = p.strip_prefix(base).unwrap_or(&p).to_string_lossy().replace('\\', "/");
                plan.push((p, rel));
            }
        } else {
            let name = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
            plan.push((f.clone(), name));
        }
    }

    let mut sz = SevenZWriter::create(out).map_err(|e| bad(&e.to_string()))?;
    // Header encryption only matters when there is a password; the writer
    // defaults to true which produces encrypted headers for plain archives too.
    sz.set_encrypt_header(password.is_some());
    if let Some(pw) = password {
        let opts = sevenz_rust::AesEncoderOptions::new(sevenz_rust::Password::from(
            std::str::from_utf8(pw).unwrap_or_default(),
        ));
        sz.set_content_methods(vec![
            sevenz_rust::SevenZMethodConfiguration::from(opts),
        ]);
    }

    let mut n_files = 0usize;
    for (f, name) in &plan {
        let entry = sevenz_rust::SevenZArchiveEntry::from_path(f, name.clone());
        let reader = if f.is_file() {
            Some(fs::File::open(f)?)
        } else {
            None
        };
        sz.push_archive_entry(entry, reader)
            .map_err(|e| bad(&format!("{}: {}", f.display(), e)))?;
        n_files += 1;
    }
    sz.finish().map_err(|e| bad(&e.to_string()))?;
    Ok(CompressReport { files: n_files, bytes: fs::metadata(out).map(|m| m.len()).unwrap_or(0) })
}

// ---------------------------------------------------------------------------
// tar / tar.gz / tar.xz / tar.bz2 writing
// ---------------------------------------------------------------------------

fn create_tar(
    inputs: &[PathBuf],
    out: &Path,
    outer: Option<(&str, u32)>,
) -> io::Result<CompressReport> {
    // Precompute (abs_path, archive_name) pairs. Directory inputs archive as
    // "<dirname>/..." — matching 7-Zip/Bandizip behaviour — with explicit
    // directory entries so empty dirs survive the round-trip.
    let mut plan: Vec<(PathBuf, PathBuf)> = Vec::new();
    for f in inputs {
        let base = f.parent().unwrap_or(f);
        if f.is_dir() {
            for d in walk_dirs(f) {
                let rel = d.strip_prefix(base).unwrap_or(&d).to_path_buf();
                plan.push((d, rel));
            }
            for p in walk_files(f) {
                let rel = p.strip_prefix(base).unwrap_or(&p).to_path_buf();
                plan.push((p, rel));
            }
        } else {
            let name = Path::new(f.file_name().unwrap_or_default()).to_path_buf();
            plan.push((f.clone(), name));
        }
    }

    // Raw tar into the output (possibly through a compressor). The tar crate
    // wraps any Write, so build the stream chain first.
    let raw = fs::File::create(out)?;
    let mut n_files = 0usize;

    fn add_all<W: io::Write>(writer: W, plan: &[(PathBuf, PathBuf)], out_n: &mut usize) -> io::Result<()> {
        let mut b = tar::Builder::new(writer);
        // Directories first (parents before children), then regular files.
        for (abs, rel) in plan {
            if abs.is_dir() {
                b.append_dir(rel, abs)?;
                *out_n += 1;
            }
        }
        for (abs, rel) in plan {
            if abs.is_file() {
                b.append_path_with_name(abs, rel)?;
                *out_n += 1;
            }
        }
        b.finish()?;
        Ok(())
    }

    match outer {
        None => add_all(raw, &plan, &mut n_files)?,
        Some(("gz", lvl)) => {
            let mut enc = flate2::write::GzEncoder::new(raw, flate2::Compression::new(lvl.min(9)));
            add_all(&mut enc, &plan, &mut n_files)?;
            enc.finish()?;
        }
        Some(("xz", lvl)) => {
            let mut enc = liblzma::write::XzEncoder::new(raw, lvl.min(9));
            add_all(&mut enc, &plan, &mut n_files)?;
            enc.finish()?;
        }
        Some(("bz2", _)) => {
            let mut enc = bzip2::write::BzEncoder::new(raw, bzip2::Compression::default());
            add_all(&mut enc, &plan, &mut n_files)?;
            enc.finish()?;
        }
        Some(_) => return Err(bad("unknown tar wrapper")),
    }
    Ok(CompressReport { files: n_files, bytes: fs::metadata(out).map(|m| m.len()).unwrap_or(0) })
}

// ---------------------------------------------------------------------------
// gz / xz / bz2 single-stream writers (one input file only)
// ---------------------------------------------------------------------------

fn single_stream(inputs: &[PathBuf], out: &Path, codec: &str) -> io::Result<CompressReport> {
    if inputs.len() != 1 || inputs[0].is_dir() {
        return Err(bad(&format!(
            "{} output takes exactly one input file",
            codec.to_uppercase()
        )));
    }
    let src = fs::read(&inputs[0])?;
    let dst = fs::File::create(out)?;
    let n = src.len() as u64;
    match codec {
        "gz" => {
            let mut enc = flate2::write::GzEncoder::new(dst, flate2::Compression::default());
            enc.write_all(&src)?;
            enc.finish()?;
        }
        "xz" => {
            let mut enc = liblzma::write::XzEncoder::new(dst, 6);
            enc.write_all(&src)?;
            enc.finish()?;
        }
        "bz2" => {
            let mut enc = bzip2::write::BzEncoder::new(dst, bzip2::Compression::default());
            enc.write_all(&src)?;
            enc.finish()?;
        }
        _ => return Err(bad("unknown codec")),
    }
    Ok(CompressReport { files: 1, bytes: n })
}

fn create_zip(
    inputs: &[PathBuf],
    out: &Path,
    password: Option<&[u8]>,
    level: u32,
) -> io::Result<CompressReport> {
    let mut writer = fs::File::create(out)?;
    let mut central: Vec<CdRecord> = Vec::new();
    let mut n_files = 0;
    let (dos_time, dos_date) = dos_now();
    let comp = flate2::Compression::new(level.min(9));

    let add = |writer: &mut fs::File,
                   path: &Path,
                   name: String,
                   central: &mut Vec<CdRecord>|
     -> io::Result<()> {
        let data = fs::read(path)?;
        if data.len() > 0xFFFF_FFFF {
            return Err(bad("file too large for this simple ZIP writer"));
        }
        let crc = archive::crc32(&data);
        let usize_ = data.len() as u32;
        // Try deflate; keep it only when it actually shrinks the data,
        // otherwise store the original bytes with method 0.
        let use_deflate = level > 0 && data.len() >= 64;
        let (method, payload): (u16, Vec<u8>) = if use_deflate {
            let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), comp);
            enc.write_all(&data)?;
            let packed = enc.finish()?;
            if packed.len() < data.len() {
                (8, packed)
            } else {
                (0, data.clone())
            }
        } else {
            (0, data.clone())
        };
        let offset = writer.stream_position()? as u32;
        let name_bytes = name.as_bytes();

        // Plain payload vs ZipCrypto-encrypted (12-byte header + payload).
        // EFS (bit 11) marks UTF-8 entry names — set whenever the name is
        // not pure ASCII so 7-Zip/unzip decode it correctly.
        let efs = 0x800u16 * is_ascii_name(&name) as u16;
        let (flags, stored): (u16, Vec<u8>) = match password {
            Some(pw) => {
                let mut z = ZipCrypto::new(pw);
                // check byte = hi byte of CRC (spec) — readers accept this
                let mut plain = payload.clone();
                let mut hdr = [0u8; 12];
                hdr[11] = (crc >> 24) as u8;
                plain.splice(..0, hdr.iter().copied());
                z.encrypt(&mut plain);
                (0x1 | efs, plain)
            }
            None => (efs, payload),
        };

        let mut lfh = [0u8; 30];
        lfh[..4].copy_from_slice(b"PK\x03\x04");
        lfh[4..6].copy_from_slice(&20u16.to_le_bytes());
        lfh[6..8].copy_from_slice(&flags.to_le_bytes());
        lfh[8..10].copy_from_slice(&method.to_le_bytes());
        lfh[10..12].copy_from_slice(&dos_time.to_le_bytes());
        lfh[12..14].copy_from_slice(&dos_date.to_le_bytes());
        lfh[14..18].copy_from_slice(&crc.to_le_bytes());
        lfh[18..22].copy_from_slice(&(stored.len() as u32).to_le_bytes());
        lfh[22..26].copy_from_slice(&usize_.to_le_bytes());
        lfh[26..28].copy_from_slice(&(name_bytes.len() as u16).to_le_bytes());
        lfh[28..30].copy_from_slice(&0u16.to_le_bytes());
        writer.write_all(&lfh)?;
        writer.write_all(name_bytes)?;
        writer.write_all(&stored)?;
        central.push(CdRecord {
            name,
            method,
            crc,
            csize: stored.len() as u32,
            usize_,
            offset,
            dos_time,
            dos_date,
            encrypted: password.is_some(),
        });
        Ok(())
    };

    for f in inputs {
        let base = f.parent().unwrap_or(f);
        if f.is_dir() {
            // Explicit entry for the root dir (and empty subdirs), 7-Zip style.
            for d in walk_dirs(f) {
                let rel = d.strip_prefix(base).unwrap_or(&d).to_string_lossy().replace('\\', "/");
                let name = format!("{}/", rel.trim_end_matches("/"));
                write_zip_dir(&mut writer, &name, dos_time, dos_date, &mut central)?;
            }
            for p in walk_files(f) {
                let name = p
                    .strip_prefix(base)
                    .unwrap_or(&p)
                    .to_string_lossy()
                    .replace('\\', "/");
                add(&mut writer, &p, name, &mut central)?;
                n_files += 1;
            }
        } else {
            let name = f.file_name().unwrap_or_default().to_string_lossy().into_owned();
            add(&mut writer, f, name, &mut central)?;
            n_files += 1;
        }
    }

    let cd_offset = writer.stream_position()? as u32;
    for e in &central {
        let mut cdh = [0u8; 46];
        cdh[..4].copy_from_slice(b"PK\x01\x02");
        cdh[4..6].copy_from_slice(&20u16.to_le_bytes());
        cdh[6..8].copy_from_slice(&20u16.to_le_bytes());
        cdh[8..10].copy_from_slice(
            &(if e.encrypted { 0x1 } else { 0x0 } | efs_flag(&e.name)).to_le_bytes(),
        );
        cdh[10..12].copy_from_slice(&e.method.to_le_bytes());
        cdh[12..14].copy_from_slice(&e.dos_time.to_le_bytes());
        cdh[14..16].copy_from_slice(&e.dos_date.to_le_bytes());
        cdh[16..20].copy_from_slice(&e.crc.to_le_bytes());
        cdh[20..24].copy_from_slice(&e.csize.to_le_bytes());
        cdh[24..28].copy_from_slice(&e.usize_.to_le_bytes());
        cdh[28..30].copy_from_slice(&(e.name.len() as u16).to_le_bytes());
        cdh[42..46].copy_from_slice(&e.offset.to_le_bytes());
        writer.write_all(&cdh)?;
        writer.write_all(e.name.as_bytes())?;
    }
    let cd_size = writer.stream_position()? as u32 - cd_offset;

    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    eocd[8..10].copy_from_slice(&(central.len() as u16).to_le_bytes());
    eocd[10..12].copy_from_slice(&(central.len() as u16).to_le_bytes());
    eocd[12..16].copy_from_slice(&cd_size.to_le_bytes());
    eocd[16..20].copy_from_slice(&cd_offset.to_le_bytes());
    writer.write_all(&eocd)?;

    Ok(CompressReport { files: n_files, bytes: writer.stream_position()? })
}

fn walk_files(dir: &Path) -> Vec<PathBuf> {
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) {
        let Ok(rd) = fs::read_dir(dir) else { return };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                rec(&p, out);
            } else {
                out.push(p);
            }
        }
    }
    let mut out = Vec::new();
    rec(dir, &mut out);
    out
}

/// Directories under `dir` (inclusive), depth-first, parents before children —
/// used when the container format stores explicit directory entries.
fn walk_dirs(dir: &Path) -> Vec<PathBuf> {
    fn rec(dir: &Path, out: &mut Vec<PathBuf>) {
        out.push(dir.to_path_buf());
        let Ok(rd) = fs::read_dir(dir) else { return };
        let mut entries: Vec<_> = rd.filter_map(|e| e.ok()).map(|e| e.path()).collect();
        entries.sort();
        for p in entries {
            if p.is_dir() {
                rec(&p, out);
            }
        }
    }
    let mut out = Vec::new();
    rec(dir, &mut out);
    out
}

// ---------------------------------------------------------------------------
// Archive editing: delete / rename entries (ZIP raw-copy rewrite; 7z rebuild)
// ---------------------------------------------------------------------------

/// Delete entries from an archive. ZIP entries are raw-copied (no recompress,
/// byte-identical payloads); 7z/tar are rebuilt from a full re-extract.
/// Matching is exact-name, or prefix when the pattern ends with `/`.
pub fn delete_entries(path: &Path, patterns: &[String], password: Option<&[u8]>) -> io::Result<usize> {
    if patterns.is_empty() {
        return Err(bad("no entries selected"));
    }
    match archive::detect_format(path)? {
        Format::Zip => delete_zip_entries(path, patterns),
        _ => {
            // Generic path: extract everything minus the targets to a temp dir,
            // recompress, replace the original.
            rebuild_archive_minus(path, patterns, password)
        }
    }
}

/// Rename entries. `renames` = (old_name, new_name) pairs; exact match only.
pub fn rename_entries(path: &Path, renames: &[(String, String)], password: Option<&[u8]>) -> io::Result<usize> {
    if renames.is_empty() {
        return Err(bad("nothing to rename"));
    }
    match archive::detect_format(path)? {
        Format::Zip => rename_zip_entries(path, renames),
        _ => {
            let tmp = path.with_extension("rosezip.tmp");
            fs::copy(path, &tmp)?;
            let res = rename_via_rebuild(&tmp, renames, password);
            if res.is_ok() {
                fs::rename(&tmp, path)?;
            } else {
                let _ = fs::remove_file(&tmp);
            }
            res
        }
    }
}

fn matches_any(name: &str, patterns: &[String]) -> bool {
    patterns.iter().any(|p| {
        p == name
            || (p.ends_with('/') && name.starts_with(p.as_str()))
            || name
                .strip_prefix(p.as_str())
                .map_or(false, |rest| rest.starts_with('/'))
    })
}

/// Shared low-level: rewrite a ZIP keeping entries for which `keep` is true;
/// `map_name` rewrites entry names before they are written.
fn rewrite_zip<F, G>(path: &Path, keep: F, map_name: G) -> io::Result<usize>
where
    F: Fn(&ZipEntry) -> bool,
    G: Fn(String) -> String,
{
    let mut src = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut src)?;
    let tmp = path.with_extension("rosezip.tmp");
    let mut dst = fs::File::create(&tmp)?;

    let mut central: Vec<CdRecord> = Vec::new();
    let mut kept = 0usize;
    for e in &entries {
        if !keep(e) {
            continue;
        }
        kept += 1;
        // Raw-copy the local header + payload, patching the name if renamed.
        let data_off = archive::local_data_offset(&mut src, e)?;
        let mut head = Vec::with_capacity((data_off - e.header_offset) as usize);
        src.seek(SeekFrom::Start(e.header_offset))?;
        Read::by_ref(&mut src).take(data_off - e.header_offset).read_to_end(&mut head)?;
        let mut payload = vec![0u8; e.compressed_size as usize];
        src.read_exact(&mut payload)?;

        let new_name = map_name(e.name.clone());
        let offset = dst.stream_position()? as u32;
        // head = [30-byte LFH][old name][extra]; keep header + extra only.
        let old_name_len = e.name.len();
        let extra = head[(30 + old_name_len)..].to_vec();
        head.truncate(30);
        head[26..28].copy_from_slice(&(new_name.len() as u16).to_le_bytes());
        // keep original flags; add EFS when the new name is non-ASCII,
        // drop the data-descriptor bit (bit 3) since sizes are now known.
        {
            let mut flags = u16::from_le_bytes([head[6], head[7]]);
            flags &= !0b1000;
            flags |= efs_flag(&new_name);
            head[6..8].copy_from_slice(&flags.to_le_bytes());
        }
        dst.write_all(&head)?;
        dst.write_all(&extra)?;
        dst.write_all(new_name.as_bytes())?;
        dst.write_all(&payload)?;
        central.push(CdRecord {
            name: new_name,
            method: e.method,
            crc: e.crc32,
            csize: e.compressed_size as u32,
            usize_: e.uncompressed_size as u32,
            offset,
            dos_time: e.dos_time,
            dos_date: e.dos_date,
            encrypted: e.encrypted,
        });
    }

    let cd_offset = dst.stream_position()? as u32;
    for c in &central {
        let mut cdh = [0u8; 46];
        cdh[..4].copy_from_slice(b"PK\x01\x02");
        cdh[4..6].copy_from_slice(&20u16.to_le_bytes());
        cdh[6..8].copy_from_slice(&20u16.to_le_bytes());
        cdh[8..10].copy_from_slice(
            &(if c.encrypted { 0x1 } else { 0x0 } | efs_flag(&c.name)).to_le_bytes(),
        );
        cdh[10..12].copy_from_slice(&c.method.to_le_bytes());
        cdh[12..14].copy_from_slice(&c.dos_time.to_le_bytes());
        cdh[14..16].copy_from_slice(&c.dos_date.to_le_bytes());
        cdh[16..20].copy_from_slice(&c.crc.to_le_bytes());
        cdh[20..24].copy_from_slice(&c.csize.to_le_bytes());
        cdh[24..28].copy_from_slice(&c.usize_.to_le_bytes());
        cdh[28..30].copy_from_slice(&(c.name.len() as u16).to_le_bytes());
        cdh[42..46].copy_from_slice(&c.offset.to_le_bytes());
        dst.write_all(&cdh)?;
        dst.write_all(c.name.as_bytes())?;
    }
    let cd_size = dst.stream_position()? as u32 - cd_offset;
    let mut eocd = [0u8; 22];
    eocd[..4].copy_from_slice(b"PK\x05\x06");
    eocd[8..10].copy_from_slice(&(central.len() as u16).to_le_bytes());
    eocd[10..12].copy_from_slice(&(central.len() as u16).to_le_bytes());
    eocd[12..16].copy_from_slice(&cd_size.to_le_bytes());
    eocd[16..20].copy_from_slice(&cd_offset.to_le_bytes());
    dst.write_all(&eocd)?;
    drop(dst);
    fs::rename(&tmp, path)?;
    Ok(kept)
}

fn delete_zip_entries(path: &Path, patterns: &[String]) -> io::Result<usize> {
    let mut src = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut src)?;
    let total = entries.len();
    let n = rewrite_zip(path, |e| !matches_any(&e.name, patterns), |n| n)?;
    Ok(total - n)
}

fn rename_zip_entries(path: &Path, renames: &[(String, String)]) -> io::Result<usize> {
    let map = |name: String| -> String {
        for (old, new) in renames {
            if &name == old {
                return new.clone();
            }
            // Renaming a directory prefix moves all children.
            if old.ends_with('/') && name.starts_with(old.as_str()) {
                return format!("{}{}", new, &name[old.len()..]);
            }
        }
        name
    };
    let mut src = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut src)?;
    let n = entries
        .iter()
        .filter(|e| renames.iter().any(|(o, _)| {
            o == &e.name || (o.ends_with('/') && e.name.starts_with(o.as_str()))
        }))
        .count();
    rewrite_zip(path, |_| true, map)?;
    Ok(n)
}

/// Non-ZIP editing fallback: extract to temp (minus targets), recompress.
fn rebuild_archive_minus(path: &Path, patterns: &[String], password: Option<&[u8]>) -> io::Result<usize> {
    let entries = archive::list_archive(path)?.entries;
    let doomed: Vec<String> = entries
        .iter()
        .filter(|e| matches_any(&e.name, patterns))
        .map(|e| e.name.clone())
        .collect();
    if doomed.is_empty() {
        return Err(bad("no matching entries found"));
    }
    let tmpdir = std::env::temp_dir().join(format!("rosezip-edit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmpdir);
    archive::extract_native(path, &tmpdir, password)?;
    for d in &doomed {
        let p = tmpdir.join(d.trim_end_matches('/'));
        if p.is_dir() {
            let _ = fs::remove_dir_all(&p);
        } else {
            let _ = fs::remove_file(&p);
        }
    }
    let tmp_out = path.with_extension("rosezip.tmp");
    // Rebuild in the same container format. Inputs are the extracted
    // *children* (not tmpdir itself) so no extra path layer is added.
    let mut roots: Vec<PathBuf> = fs::read_dir(&tmpdir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    roots.sort();
    let empty = Vec::new();
    let roots_ref: &[PathBuf] = if roots.is_empty() { &empty } else { &roots };
    let report = match archive::detect_format(path)? {
        Format::SevenZ => create_7z(roots_ref, &tmp_out, password)?,
        Format::Tar => create_tar(roots_ref, &tmp_out, None)?,
        Format::Gz => create_tar(roots_ref, &tmp_out, Some(("gz", 6)))?,
        Format::Xz => create_tar(roots_ref, &tmp_out, Some(("xz", 6)))?,
        Format::Bz2 => create_tar(roots_ref, &tmp_out, Some(("bz2", 6)))?,
        Format::Zip => unreachable!(),
    };
    let _ = report;
    fs::rename(&tmp_out, path)?;
    let _ = fs::remove_dir_all(&tmpdir);
    Ok(doomed.len())
}

fn rename_via_rebuild(path: &Path, renames: &[(String, String)], password: Option<&[u8]>) -> io::Result<usize> {
    let entries = archive::list_archive(path)?.entries;
    let hits: Vec<String> = entries
        .iter()
        .filter(|e| renames.iter().any(|(o, _)| o == &e.name))
        .map(|e| e.name.clone())
        .collect();
    if hits.is_empty() {
        return Err(bad("no matching entries found"));
    }
    let tmpdir = std::env::temp_dir().join(format!("rosezip-edit-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmpdir);
    archive::extract_native(path, &tmpdir, password)?;
    for (old, new) in renames {
        let from = tmpdir.join(old.trim_end_matches('/'));
        let to = tmpdir.join(new.trim_end_matches('/'));
        if from.exists() {
            if let Some(parent) = to.parent() {
                let _ = fs::create_dir_all(parent);
            }
            fs::rename(&from, &to)?;
        }
    }
    let tmp_out = path.with_extension("rosezip.tmp");
    let mut roots: Vec<PathBuf> = fs::read_dir(&tmpdir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .collect();
    roots.sort();
    match archive::detect_format(path)? {
        Format::SevenZ => {
            create_7z(&roots, &tmp_out, password)?;
        }
        _ => {
            create_tar(&roots, &tmp_out, None)?;
        }
    }
    fs::rename(&tmp_out, path)?;
    let _ = fs::remove_dir_all(&tmpdir);
    Ok(hits.len())
}

// ---------------------------------------------------------------------------
// Crack preparation
// ---------------------------------------------------------------------------

/// Prepared attack target info for the UI.
pub struct CrackPlan {
    pub entry_name: String,
    pub kind: String,
    pub encrypted_entries: usize,
    pub verifier: Arc<Verifier>,
    /// brute-force generator when the UI picks brute force
    pub default_gen: Option<IndexGen>,
    pub note: Option<String>,
}

pub fn prepare_crack(path: &Path) -> io::Result<CrackPlan> {
    let mut file = fs::File::open(path)?;
    let entries = archive::parse_zip_central_directory(&mut file)?;
    let candidates: Vec<_> = entries.iter().filter(|e| e.encrypted && !e.is_dir).collect();
    if candidates.is_empty() {
        return Err(bad("archive has no encrypted entries"));
    }
    let encrypted_entries = candidates.len();
    let best = candidates.into_iter().min_by_key(|e| e.compressed_size).unwrap();

    let strength = read_aes_strength(&mut file, best)?;
    let data_off = archive::local_data_offset(&mut file, best)?;
    let mut data = vec![0u8; best.compressed_size as usize];
    file.seek(SeekFrom::Start(data_off))?;
    file.read_exact(&mut data)?;

    let verifier = Verifier::prepare(best, &data, strength, Some(best.dos_time))
        .ok_or_else(|| bad("unsupported encryption configuration"))?;
    let kind = match &verifier {
        Verifier::ZipCrypto { .. } => "ZipCrypto",
        Verifier::WinZipAes { .. } => "WinZip-AES",
    };
    Ok(CrackPlan {
        entry_name: best.name.clone(),
        kind: kind.to_string(),
        encrypted_entries,
        verifier: Arc::new(verifier),
        default_gen: None,
        note: None,
    })
}

/// Build a brute-force generator from UI parameters.
pub fn make_gen(charset_spec: &str, min_len: usize, max_len: usize) -> io::Result<IndexGen> {
    if min_len == 0 || min_len > max_len {
        return Err(bad("invalid length range"));
    }
    if max_len > 32 {
        return Err(bad("max length is 32 (engine limit)"));
    }
    let set = charset::resolve_charset(charset_spec).map_err(|e| bad(&e))?;
    IndexGen::new(set, min_len, max_len).map_err(|e| bad(&e))
}

/// Read the WinZip AES extra field (0x9901) from an entry's local header.
fn read_aes_strength(file: &mut fs::File, entry: &ZipEntry) -> io::Result<Option<AesStrength>> {
    if entry.method != 99 {
        return Ok(None);
    }
    let mut lh = [0u8; 30];
    file.seek(SeekFrom::Start(entry.header_offset))?;
    file.read_exact(&mut lh)?;
    if &lh[..4] != b"PK\x03\x04" {
        return Err(bad("bad local header"));
    }
    let name_len = u16::from_le_bytes([lh[26], lh[27]]) as usize;
    let extra_len = u16::from_le_bytes([lh[28], lh[29]]) as usize;
    let mut extra = vec![0u8; extra_len];
    file.seek(SeekFrom::Start(entry.header_offset + 30 + name_len as u64))?;
    file.read_exact(&mut extra)?;

    let mut off = 0;
    while off + 4 <= extra.len() {
        let id = u16::from_le_bytes([extra[off], extra[off + 1]]);
        let size = u16::from_le_bytes([extra[off + 2], extra[off + 3]]) as usize;
        if id == 0x9901 && size >= 7 && off + 4 + 7 <= extra.len() {
            let strength_id = extra[off + 8];
            return AesStrength::from_id(strength_id).map(Some).ok_or_else(|| bad("bad AES strength id"));
        }
        off += 4 + size;
    }
    Err(bad("AES entry without 0x9901 extra field"))
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

fn dos_now() -> (u16, u16) {
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    let days = (secs / 86400) as i64;
    let (y, mo, d) = civil_from_days(days);
    let rem = secs % 86400;
    let (h, mi, s) = (rem / 3600, (rem % 3600) / 60, rem % 60);
    let time = ((h << 11) | (mi << 5) | (s / 2)) as u16;
    let year = (y.max(1980) - 1980) as u16;
    let date = (year << 9) | ((mo as u16) << 5) | d as u16;
    (time, date)
}

fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719468;
    let era = if z >= 0 { z } else { z - 146096 } / 146097;
    let doe = z - era * 146097;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    (if m <= 2 { y + 1 } else { y }, m as u32, d as u32)
}

pub fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}
