//! High-level operations shared by the CLI, TUI and GUI front ends.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::Arc;

use crate::archive::{self, Format, ZipEntry};
use crate::charset::{self, IndexGen};
use crate::zipcrypt::{self, AesStrength, Verifier, ZipCrypto};

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
            fs::create_dir_all(dest.join(&entry.name))?;
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

fn extract_one_zip_entry(
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
    let out_path = dest.join(&entry.name);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(&out_path, &content)?;
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
    if inputs.is_empty() {
        return Err(bad("no input files given"));
    }
    for f in inputs {
        if !f.exists() {
            return Err(bad(&format!("input not found: {}", f.display())));
        }
    }
    create_zip(inputs, out, password, level)
}

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
        let use_deflate = level > 0 && data.len() >= 64;
        let payload: Vec<u8> = if use_deflate {
            let mut enc = flate2::write::DeflateEncoder::new(Vec::new(), comp);
            enc.write_all(&data)?;
            enc.finish()?
        } else {
            data.clone()
        };
        let method: u16 = if use_deflate && payload.len() < data.len() { 8 } else { 0 };
        let offset = writer.stream_position()? as u32;
        let name_bytes = name.as_bytes();

        // Plain payload vs ZipCrypto-encrypted (12-byte header + payload).
        let (flags, stored): (u16, Vec<u8>) = match password {
            Some(pw) => {
                let mut z = ZipCrypto::new(pw);
                // check byte = hi byte of CRC (spec) — readers accept this
                let mut plain = payload.clone();
                let mut hdr = [0u8; 12];
                hdr[11] = (crc >> 24) as u8;
                plain.splice(..0, hdr.iter().copied());
                z.encrypt(&mut plain);
                (0x1, plain)
            }
            None => (0x0, payload),
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
        if f.is_dir() {
            for p in walk_files(f) {
                let name =
                    p.strip_prefix(f.parent().unwrap_or(f)).unwrap_or(&p).to_string_lossy().into_owned();
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
        cdh[8..10].copy_from_slice(&(if e.encrypted { 1u16 } else { 0u16 }).to_le_bytes());
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
