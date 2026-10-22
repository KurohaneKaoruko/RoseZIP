//! Archive abstraction over ZIP, 7z, tar, gz, xz, bz2 — all fully native
//! (in-process), no external binaries.
//!
//! ZIP: self-parsed central directory + flate2 (zlib-ng) inflate. This is the
//! hot path for `crack zip`, so it never spawns processes.
//!
//! 7z: `sevenz-rust` (pure Rust, incl. AES-256-SHA-256 decoder).
//! tar: `tar` crate; gz/xz/bz2: streamed via flate2 / liblzma(static) / bzip2.

use std::fs;
use std::io::{self, Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use flate2::read::DeflateDecoder;

// ---------------------------------------------------------------------------
// Detection
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Zip,
    SevenZ,
    Tar,
    Gz,
    Xz,
    Bz2,
}

/// Inner format of a gz/xz/bz2 stream: `Some(inner)` when the decompressed
/// payload is itself an archive we support (tar), `None` otherwise.
pub fn compressed_inner_format(path: &Path, format: Format) -> Option<Format> {
    if !matches!(format, Format::Gz | Format::Xz | Format::Bz2) {
        return None;
    }
    let peek = match format {
        Format::Gz => {
            let raw = fs::read(path).ok()?;
            let mut out = Vec::with_capacity(512);
            flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out).ok()?;
            out
        }
        Format::Xz => {
            let raw = fs::read(path).ok()?;
            let mut out = Vec::with_capacity(512);
            liblzma::read::XzDecoder::new(&raw[..]).read_to_end(&mut out).ok()?;
            out
        }
        Format::Bz2 => {
            let raw = fs::read(path).ok()?;
            let mut out = Vec::with_capacity(512);
            bzip2::read::BzDecoder::new(&raw[..]).read_to_end(&mut out).ok()?;
            out
        }
        _ => return None,
    };
    // ustar magic at offset 257 → it's a tar.
    if peek.len() > 262 && &peek[257..262] == b"ustar" {
        return Some(Format::Tar);
    }
    None
}

pub fn detect_format(path: &Path) -> io::Result<Format> {
    let mut file = fs::File::open(path)?;
    let mut magic = [0u8; 6];
    let n = file.read(&mut magic)?;
    let magic = &magic[..n];
    if magic.starts_with(b"PK") {
        return Ok(Format::Zip);
    } else if magic.starts_with(b"7z\xbc\xaf\x27\x1c") {
        return Ok(Format::SevenZ);
    } else if magic.starts_with(b"\x1f\x8b") {
        return Ok(Format::Gz);
    } else if magic.starts_with(b"BZh") {
        return Ok(Format::Bz2);
    } else if magic.starts_with(b"\xfd7zXZ\x00") {
        return Ok(Format::Xz);
    }
    // tar has no magic at offset 0; check the ustar magic at offset 257.
    let mut ustar = [0u8; 5];
    if file.seek(SeekFrom::Start(257)).is_ok() && file.read_exact(&mut ustar).is_ok() {
        if &ustar == b"ustar" {
            return Ok(Format::Tar);
        }
    }
    Err(bad("unrecognized archive format"))
}

// ---------------------------------------------------------------------------
// ZIP central directory parsing
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct ZipEntry {
    pub name: String,
    pub encrypted: bool,
    /// local file header offset in the file
    pub header_offset: u64,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    pub method: u16,
    pub crc32: u32,
    pub is_dir: bool,
    /// DOS mod-time, used as an alternative ZipCrypto check byte
    pub dos_time: u16,
    /// DOS mod-date (date half of the same timestamp)
    pub dos_date: u16,
}

fn bad(msg: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, msg)
}

fn rd16(b: &[u8], o: usize) -> u16 {
    u16::from_le_bytes([b[o], b[o + 1]])
}

fn rd32(b: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([b[o], b[o + 1], b[o + 2], b[o + 3]])
}

/// Locate and parse the EOCD + central directory of a ZIP file.
pub fn parse_zip_central_directory(file: &mut fs::File) -> io::Result<Vec<ZipEntry>> {
    let file_len = file.metadata()?.len();
    if file_len < 22 {
        return Err(bad("file too small to be a ZIP"));
    }

    // EOCD is at the end; scan backwards over the comment (max 65535 bytes).
    let scan_start = file_len.saturating_sub(22 + 65535);
    let scan_len = (file_len - scan_start) as usize;
    let mut tail = vec![0u8; scan_len];
    file.seek(SeekFrom::Start(scan_start))?;
    file.read_exact(&mut tail)?;

    let eocd_off = tail
        .windows(4)
        .rev()
        .position(|w| w == b"PK\x05\x06")
        .map(|p| tail.len() - p - 4)
        .ok_or_else(|| bad("EOCD signature not found"))?;

    let n_entries = rd16(&tail, eocd_off + 10) as usize;
    let cd_size = rd32(&tail, eocd_off + 12) as usize;
    let cd_offset = rd32(&tail, eocd_off + 16) as u64;

    let mut cd = vec![0u8; cd_size];
    file.seek(SeekFrom::Start(cd_offset))?;
    file.read_exact(&mut cd)?;

    let mut entries = Vec::with_capacity(n_entries);
    let mut off = 0usize;
    for _ in 0..n_entries {
        if off + 46 > cd.len() || &cd[off..off + 4] != b"PK\x01\x02" {
            break;
        }
        let flags = rd16(&cd, off + 8);
        let method = rd16(&cd, off + 10);
        let dos_time = rd16(&cd, off + 12);
        let dos_date = rd16(&cd, off + 14);
        let crc32 = rd32(&cd, off + 16);
        let csize = rd32(&cd, off + 20) as u64;
        let usize_ = rd32(&cd, off + 24) as u64;
        let name_len = rd16(&cd, off + 28) as usize;
        let extra_len = rd16(&cd, off + 30) as usize;
        let comment_len = rd16(&cd, off + 32) as usize;
        let header_offset = rd32(&cd, off + 42) as u64;
        let name = String::from_utf8_lossy(&cd[off + 46..off + 46 + name_len]).into_owned();
        entries.push(ZipEntry {
            encrypted: flags & 0x1 != 0,
            is_dir: name.ends_with('/'),
            name,
            header_offset,
            compressed_size: csize,
            uncompressed_size: usize_,
            method,
            crc32,
            dos_time,
            dos_date,
        });
        off += 46 + name_len + extra_len + comment_len;
    }
    if entries.is_empty() {
        return Err(bad("no entries found in central directory"));
    }
    Ok(entries)
}

/// Read the local file header at `header_offset` and return the offset where
/// the entry's actual (compressed/encrypted) data starts.
pub fn local_data_offset(file: &mut fs::File, entry: &ZipEntry) -> io::Result<u64> {
    let mut lh = [0u8; 30];
    file.seek(SeekFrom::Start(entry.header_offset))?;
    file.read_exact(&mut lh)?;
    if &lh[..4] != b"PK\x03\x04" {
        return Err(bad("bad local header"));
    }
    let name_len = rd16(&lh, 26) as u64;
    let extra_len = rd16(&lh, 28) as u64;
    Ok(entry.header_offset + 30 + name_len + extra_len)
}

/// Inflate raw deflate data; used by both extraction and verification.
pub fn inflate(compressed: &[u8], expected_size: u64) -> io::Result<Vec<u8>> {
    let mut out = Vec::with_capacity(expected_size.min(1 << 30) as usize);
    DeflateDecoder::new(compressed).read_to_end(&mut out)?;
    Ok(out)
}

pub fn crc32(data: &[u8]) -> u32 {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    let table = TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, c) in t.iter_mut().enumerate() {
            let mut v = i as u32;
            for _ in 0..8 {
                v = if v & 1 != 0 { 0xEDB88320 ^ (v >> 1) } else { v >> 1 };
            }
            *c = v;
        }
        t
    });
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

// ---------------------------------------------------------------------------
// 7z (native via sevenz-rust)
// ---------------------------------------------------------------------------

/// True when the 7z archive's *header* is encrypted (password needed to list).
pub fn sevenz_header_encrypted(path: &Path) -> bool {
    sevenz_rust::SevenZReader::open(path, sevenz_rust::Password::empty()).is_err()
}

fn sevenz_password(pw: Option<&[u8]>) -> sevenz_rust::Password {
    match pw {
        // 7z encodes passwords as UTF-16LE, so convert raw bytes via lossy UTF-8.
        Some(p) => sevenz_rust::Password::from(String::from_utf8_lossy(p).as_ref()),
        None => sevenz_rust::Password::empty(),
    }
}

fn sevenz_map_err(e: sevenz_rust::Error) -> io::Error {
    match e {
        sevenz_rust::Error::MaybeBadPassword(_) => bad("wrong password or corrupt data"),
        other => bad(&format!("7z: {}", other)),
    }
}

pub fn sevenz_entries(path: &Path, pw: Option<&[u8]>) -> io::Result<Vec<(String, bool, bool, u64, u64)>> {
    let ar = sevenz_rust::SevenZReader::open(path, sevenz_password(pw))
        .map_err(|_| bad("cannot read archive (encrypted header? supply password)"))?;
    Ok(ar
        .archive()
        .files
        .iter()
        .map(|f| {
            (
                f.name().to_string(),
                f.is_directory(),
                f.has_stream && ar.archive().folders.iter().any(|_| is_folder_encrypted(ar.archive())),
                f.size(),
                f.size(),
            )
        })
        .collect())
}

fn is_folder_encrypted(_a: &sevenz_rust::Archive) -> bool {
    // sevenz-rust does not expose coders publicly; treat 7z encryption at
    // entry level as "unknown" and let decode decide. We mark false here and
    // detect during extraction instead.
    false
}

/// Test a password against a 7z archive natively: open, decode the first
/// streamed entry, verify CRC. Pure in-process, ~1-2ms per candidate.
pub fn sevenz_test_password(archive: &Path, password: &[u8]) -> io::Result<bool> {
    let pw = sevenz_rust::Password::from(String::from_utf8_lossy(password).as_ref());
    let mut ar = match sevenz_rust::SevenZReader::open(archive, pw.clone()) {
        Ok(ar) => ar,
        Err(_) => return Ok(false), // header encrypted + wrong password
    };
    let mut any_stream = false;
    let result = ar.for_each_entries(|entry, data| {
        if entry.has_stream {
            any_stream = true;
            let mut buf = Vec::with_capacity(entry.size().min(1 << 24) as usize);
            data.read_to_end(&mut buf)?;
            if entry.has_crc && rose_crc32(&buf) != entry.crc as u32 {
                return Err(sevenz_rust::Error::MaybeBadPassword(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "crc mismatch",
                )));
            }
        }
        Ok(true)
    });
    Ok(match result {
        Ok(()) => true,
        Err(sevenz_rust::Error::MaybeBadPassword(_)) => false,
        // Some decoders surface wrong passwords as corrupt input.
        Err(_) => !any_stream,
    })
}

fn rose_crc32(data: &[u8]) -> u32 {
    crc32(data)
}

// ---------------------------------------------------------------------------
// Unified listing API
// ---------------------------------------------------------------------------

pub struct ArchiveInfo {
    pub path: PathBuf,
    pub format: Format,
    pub entries: Vec<EntryInfo>,
}

#[derive(Debug, Clone)]
pub struct EntryInfo {
    pub name: String,
    pub encrypted: bool,
    pub is_dir: bool,
    pub compressed_size: u64,
    pub uncompressed_size: u64,
    /// Unix mtime (seconds); 0 = unknown.
    pub mtime: u64,
}

/// Decompress a gz/xz/bz2 stream into a temp file (used when its payload is
/// itself an archive, e.g. .tar.gz). Returns the temp file path.
fn decompressed_to_temp(path: &Path, format: Format) -> io::Result<PathBuf> {
    let raw = fs::read(path)?;
    let mut out = Vec::with_capacity(raw.len() * 4);
    match format {
        Format::Gz => {
            flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out).map(|_| ())?
        }
        Format::Xz => {
            liblzma::read::XzDecoder::new(&raw[..]).read_to_end(&mut out).map(|_| ())?
        }
        Format::Bz2 => {
            bzip2::read::BzDecoder::new(&raw[..]).read_to_end(&mut out).map(|_| ())?
        }
        _ => return Err(bad("not a compressed stream")),
    }
    let tmp = std::env::temp_dir().join(format!("rosezip-inner-{}", std::process::id()));
    fs::write(&tmp, &out)?;
    Ok(tmp)
}

pub fn list_archive(path: &Path) -> io::Result<ArchiveInfo> {
    let format = detect_format(path)?;
    // .tar.gz / .tar.xz / .tar.bz2: list the inner tar with full entry info.
    if let Some(Format::Tar) = compressed_inner_format(path, format) {
        let tmp = decompressed_to_temp(path, format)?;
        let res = list_archive(&tmp);
        let _ = fs::remove_file(&tmp);
        let mut info = res?;
        info.format = format;
        info.path = path.to_path_buf();
        return Ok(info);
    }
    let entries = match format {
        Format::Zip => {
            let mut file = fs::File::open(path)?;
            parse_zip_central_directory(&mut file)?
                .into_iter()
                .map(|e| {
                    // DOS 时间 → 简单 UTC 时间戳
                    let mtime = dos_datetime_to_unix(e.dos_date, e.dos_time);
                    EntryInfo {
                        name: e.name,
                        encrypted: e.encrypted && !e.is_dir,
                        is_dir: e.is_dir,
                        compressed_size: e.compressed_size,
                        uncompressed_size: e.uncompressed_size,
                        mtime,
                    }
                })
                .collect()
        }
        Format::SevenZ => sevenz_entries(path, None)?
            .into_iter()
            .map(|(name, is_dir, encrypted, _packed, size)| EntryInfo {
                name,
                encrypted: encrypted && !is_dir,
                is_dir,
                compressed_size: 0,
                uncompressed_size: size,
                mtime: 0,
            })
            .collect(),
        Format::Tar => {
            let mut ar = tar::Archive::new(fs::File::open(path)?);
            let mut list = Vec::new();
            for e in ar.entries().map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))? {
                let e = e.map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
                let header = e.header();
                list.push(EntryInfo {
                    name: e.path().unwrap_or_default().to_string_lossy().into_owned(),
                    encrypted: false,
                    is_dir: header.entry_type().is_dir(),
                    compressed_size: 0,
                    uncompressed_size: header.size().unwrap_or(0),
                    mtime: header.mtime().unwrap_or(0),
                });
            }
            list
        }
        Format::Gz => {
            // gz wraps exactly one stream; peek the original name/size heuristically.
            vec![EntryInfo {
                name: path.file_stem().unwrap_or_default().to_string_lossy().into_owned(),
                encrypted: false,
                is_dir: false,
                compressed_size: fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                uncompressed_size: 0,
                mtime: 0,
            }]
        }
        Format::Xz | Format::Bz2 => {
            vec![EntryInfo {
                name: path
                    .file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .trim_end_matches(".xz")
                    .trim_end_matches(".bz2")
                    .to_owned(),
                encrypted: false,
                is_dir: false,
                compressed_size: fs::metadata(path).map(|m| m.len()).unwrap_or(0),
                uncompressed_size: 0,
                mtime: 0,
            }]
        }
    };
    Ok(ArchiveInfo { path: path.to_path_buf(), format, entries })
}

/// DOS date + time (as stored in ZIP records) → Unix seconds (UTC).
pub fn dos_datetime_to_unix(dos_date: u16, dos_time: u16) -> u64 {
    let year = ((dos_date >> 9) & 0x7f) as u64 + 1980;
    let month = ((dos_date >> 5) & 0x0f) as u64;
    let day = (dos_date & 0x1f) as u64;
    let hour = ((dos_time >> 11) & 0x1f) as u64;
    let minute = ((dos_time >> 5) & 0x3f) as u64;
    let second = (dos_time & 0x1f) as u64 * 2;
    if !(1..=12).contains(&month) || !(1..=31).contains(&day) || hour > 23 || minute > 59 {
        return 0;
    }
    // days since epoch for the first of the month, then add day-1
    const CUM: [u64; 12] = [0, 31, 59, 90, 120, 151, 181, 212, 243, 273, 304, 334];
    let mut days = (year - 1970) * 365 + (year - 1969) / 4 - (year - 1901) / 100
        + (year - 1601) / 400;
    days += CUM[(month - 1) as usize] + day - 1;
    // leap day already passed this year?
    let leap = (year % 4 == 0 && year % 100 != 0) || year % 400 == 0;
    if leap && month > 2 {
        days += 1;
    }
    days * 86400 + hour * 3600 + minute * 60 + second
}

/// DOS time field alone (no date) — never valid for display; kept only for
/// source compatibility with the ZipCrypto check-byte path.
pub fn dos_to_unix(dos_time: u16) -> u64 {
    let _ = dos_time;
    0
}
// ---------------------------------------------------------------------------
// Native extraction for every format
// ---------------------------------------------------------------------------

/// Extract an archive into `dest` — fully in-process for all supported formats.
pub fn extract_native(archive: &Path, dest: &Path, password: Option<&[u8]>) -> io::Result<()> {
    fs::create_dir_all(dest)?;
    let format = detect_format(archive)?;
    // .tar.gz / .tar.xz / .tar.bz2: decompress to a temp file, unpack the tar.
    if let Some(Format::Tar) = compressed_inner_format(archive, format) {
        let tmp = decompressed_to_temp(archive, format)?;
        let res = extract_native(&tmp, dest, None);
        let _ = fs::remove_file(&tmp);
        return res;
    }
    match format {
        Format::Zip => Err(bad("zip handled by ops::extract")),
        Format::SevenZ => extract_7z(archive, dest, password),
        Format::Tar => extract_tar(archive, dest),
        Format::Gz => extract_gz(archive, dest),
        Format::Xz => extract_xz(archive, dest),
        Format::Bz2 => extract_bz2(archive, dest),
    }
}

fn extract_7z(archive: &Path, dest: &Path, password: Option<&[u8]>) -> io::Result<()> {
    let pw = sevenz_password(password);
    let mut ar = sevenz_rust::SevenZReader::open(archive, pw).map_err(|_| {
        bad("cannot open 7z (encrypted header? wrong password?)")
    })?;
    ar.for_each_entries(|entry, data| {
        let out_path = safe_join(dest, entry.name())?;
        if entry.is_directory() {
            fs::create_dir_all(out_path)?;
            return Ok(true);
        }
        if let Some(parent) = out_path.parent() {
            fs::create_dir_all(parent)?;
        }
        if !entry.has_stream {
            fs::File::create(out_path)?;
            return Ok(true);
        }
        let mut out = fs::File::create(out_path)?;
        std::io::copy(data, &mut out)?;
        Ok(true)
    })
    .map_err(sevenz_map_err)?;
    Ok(())
}

/// Refuse path traversal (`../`, absolute paths) when extracting.
fn safe_join(dest: &Path, name: &str) -> io::Result<PathBuf> {
    let rel = name.replace('\\', "/");
    let rel = rel.trim_start_matches('/');
    if rel.split('/').any(|c| c == "..") {
        return Err(bad(&format!("unsafe entry path: {}", name)));
    }
    Ok(dest.join(rel))
}

fn extract_tar(archive: &Path, dest: &Path) -> io::Result<()> {
    let mut ar = tar::Archive::new(fs::File::open(archive)?);
    ar.unpack(dest)?;
    Ok(())
}

fn gz_decode(archive: &Path) -> io::Result<Vec<u8>> {
    let raw = fs::read(archive)?;
    let mut out = Vec::with_capacity(raw.len() * 4);
    // Multi-member gzip: MultiGzDecoder already concatenates members.
    flate2::read::MultiGzDecoder::new(&raw[..]).read_to_end(&mut out)?;
    Ok(out)
}

fn extract_gz(archive: &Path, dest: &Path) -> io::Result<()> {
    let data = gz_decode(archive)?;
    let stem = archive
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .trim_end_matches(".gz")
        .trim_end_matches(".tgz")
        .to_owned();
    let out_path = dest.join(stem);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, data)?;
    Ok(())
}

fn extract_xz(archive: &Path, dest: &Path) -> io::Result<()> {
    let raw = fs::read(archive)?;
    let mut out = Vec::with_capacity(raw.len() * 4);
    liblzma::read::XzDecoder::new(&raw[..]).read_to_end(&mut out)?;
    let stem = archive
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .trim_end_matches(".xz")
        .to_owned();
    let out_path = dest.join(stem);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, out)?;
    Ok(())
}

fn extract_bz2(archive: &Path, dest: &Path) -> io::Result<()> {
    let raw = fs::read(archive)?;
    let mut out = Vec::with_capacity(raw.len() * 4);
    bzip2::read::BzDecoder::new(&raw[..]).read_to_end(&mut out)?;
    let stem = archive
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .trim_end_matches(".bz2")
        .to_owned();
    let out_path = dest.join(stem);
    if let Some(parent) = out_path.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::write(out_path, out)?;
    Ok(())
}
