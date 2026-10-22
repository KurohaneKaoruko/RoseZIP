//! RoseZIP Tauri backend: exposes the engine as IPC commands.
//!
//! SPDX-License-Identifier: GPL-3.0-only

use std::path::PathBuf;
use std::sync::Arc;

use rosezip_core::crack::{self, CrackTarget};
use rosezip_core::ops;
use rosezip_core::zipcrypt::Verifier;
use serde::Serialize;
use tauri::State;
// ---------------------------------------------------------------------------
// DTOs
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct EntryDto {
    name: String,
    encrypted: bool,
    is_dir: bool,
    compressed_size: u64,
    uncompressed_size: u64,
    mtime: u64,
}

#[derive(Serialize)]
pub struct InspectDto {
    path: String,
    format: String,
    encryption: Option<String>,
    entries: Vec<EntryDto>,
}

#[derive(Serialize)]
pub struct ReportDto {
    ok: bool,
    message: String,
    errors: Vec<String>,
}

#[derive(Serialize)]
pub struct CrackInfoDto {
    entry: String,
    kind: String,
    encrypted_entries: usize,
    format: String,
}

#[derive(Serialize)]
pub struct BenchDto {
    zipcrypto_per_sec: f64,
    aes_per_sec: f64,
    threads: usize,
}

#[derive(Serialize, Clone)]
pub struct StatusDto {
    pub done: u64,
    pub total: Option<u64>,
    pub rate_per_sec: f64,
    pub elapsed_secs: f64,
    pub finished: bool,
    pub found: Option<String>,
    pub cancelled: bool,
}

// ---------------------------------------------------------------------------
// Job registry (one crack job at a time is plenty for a GUI)
// ---------------------------------------------------------------------------

struct JobSlot {
    handle: std::sync::Mutex<Option<crack::CrackHandle>>,
    meta: std::sync::Mutex<Option<String>>,
}

impl JobSlot {
    fn new() -> Self {
        Self {
            handle: std::sync::Mutex::new(None),
            meta: std::sync::Mutex::new(None),
        }
    }
}

// ---------------------------------------------------------------------------
// Commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn inspect_archive(path: String, password: Option<String>) -> Result<InspectDto, String> {
    let p = PathBuf::from(&path);
    // 7z with encrypted headers: unlock listing with the password when given.
    let view = if rosezip_core::archive::detect_format(&p).map_err(|e| e.to_string())?
        == rosezip_core::archive::Format::SevenZ
        && rosezip_core::archive::sevenz_header_encrypted(&p)
    {
        let pw = password.filter(|s| !s.is_empty());
        let entries = rosezip_core::archive::sevenz_entries(&p, pw.as_deref().map(|s| s.as_bytes()))
            .map_err(|_| "7z 密码错误（无法解密文件头）".to_string())?;
        crate::view_from_sevenz(&p, entries)?
    } else {
        ops::inspect(&p).map_err(|e| e.to_string())?
    };
    Ok(InspectDto {
        path: view.path.display().to_string(),
        format: format!("{:?}", view.format),
        encryption: view.encryption,
        entries: view
            .entries
            .into_iter()
            .map(|e| EntryDto {
                name: e.name,
                encrypted: e.encrypted,
                is_dir: e.is_dir,
                compressed_size: e.compressed_size,
                uncompressed_size: e.uncompressed_size,
                mtime: e.mtime,
            })
            .collect(),
    })
}

/// Build an ArchiveView from raw 7z entry tuples (used by encrypted-header unlock).
fn view_from_sevenz(
    p: &std::path::Path,
    entries: Vec<(String, bool, bool, u64, u64)>,
) -> Result<ops::ArchiveView, String> {
    Ok(ops::ArchiveView {
        path: p.to_path_buf(),
        format: rosezip_core::archive::Format::SevenZ,
        entries: entries
            .into_iter()
            .map(|(name, is_dir, encrypted, _packed, size)| ops::EntryView {
                name,
                encrypted: encrypted && !is_dir,
                is_dir,
                compressed_size: 0,
                uncompressed_size: size,
                mtime: 0,
            })
            .collect(),
        encryption: Some("7z AES-256 (encrypted header)".into()),
    })
}

/// Extract only the selected entries.
#[tauri::command]
fn extract_selected(
    path: String,
    names: Vec<String>,
    dest: String,
    password: Option<String>,
) -> Result<ReportDto, String> {
    let pw = password.filter(|s| !s.is_empty());
    let pw_bytes = pw.as_deref().map(|s| s.as_bytes());
    match ops::extract_entries(&PathBuf::from(&path), &names, &PathBuf::from(&dest), pw_bytes) {
        Ok(r) => Ok(ReportDto {
            ok: r.errors.is_empty(),
            message: format!("已解压 {} 个文件到 {}", r.files, dest),
            errors: r.errors,
        }),
        Err(e) => Ok(ReportDto { ok: false, message: e.to_string(), errors: vec![] }),
    }
}

/// Test archive integrity (7-Zip style "Test" command).
#[tauri::command]
fn test_archive_cmd(path: String, password: Option<String>) -> Result<ReportDto, String> {
    let pw = password.filter(|s| !s.is_empty());
    let pw_bytes = pw.as_deref().map(|s| s.as_bytes());
    match ops::test_archive(&PathBuf::from(&path), pw_bytes) {
        Ok(r) => {
            if r.errors.is_empty() {
                Ok(ReportDto {
                    ok: true,
                    message: format!("测试通过：{} 个条目校验成功", r.files),
                    errors: vec![],
                })
            } else {
                Ok(ReportDto { ok: false, message: "测试失败".into(), errors: r.errors })
            }
        }
        Err(e) => Ok(ReportDto { ok: false, message: e.to_string(), errors: vec![] }),
    }
}

#[tauri::command]
fn extract_archive(path: String, dest: String, password: Option<String>) -> Result<ReportDto, String> {
    let pw = password.filter(|s| !s.is_empty());
    let pw_bytes = pw.as_deref().map(|s| s.as_bytes());
    match ops::extract(&PathBuf::from(&path), &PathBuf::from(&dest), pw_bytes) {
        Ok(r) => Ok(ReportDto {
            ok: r.errors.is_empty(),
            message: format!("已解压 {} 个文件到 {}", r.files, dest),
            errors: r.errors,
        }),
        Err(e) => Ok(ReportDto { ok: false, message: e.to_string(), errors: vec![] }),
    }
}

#[tauri::command]
fn compress_archive(
    files: Vec<String>,
    out: String,
    password: Option<String>,
    level: Option<u32>,
    format: Option<String>,
) -> Result<ReportDto, String> {
    let inputs: Vec<PathBuf> = files.into_iter().map(PathBuf::from).collect();
    let pw = password.filter(|s| !s.is_empty());
    let pw_bytes = pw.as_deref().map(|s| s.as_bytes());
    let fmt = match format.as_deref() {
        None | Some("") | Some("auto") => None,
        Some(s) => Some(match s {
            "zip" => ops::OutFormat::Zip,
            "7z" => ops::OutFormat::SevenZ,
            "tar" => ops::OutFormat::Tar,
            "tar.gz" => ops::OutFormat::TarGz,
            "tar.xz" => ops::OutFormat::TarXz,
            "tar.bz2" => ops::OutFormat::TarBz2,
            "gz" => ops::OutFormat::Gz,
            "xz" => ops::OutFormat::Xz,
            "bz2" => ops::OutFormat::Bz2,
            other => return Err(format!("未知格式: {}", other)),
        }),
    };
    match ops::compress_as(&inputs, &PathBuf::from(&out), pw_bytes, level.unwrap_or(6), fmt) {
        Ok(r) => Ok(ReportDto {
            ok: true,
            message: format!("已添加 {} 个文件（{} 字节）→ {}", r.files, r.bytes, out),
            errors: vec![],
        }),
        Err(e) => Ok(ReportDto { ok: false, message: e.to_string(), errors: vec![] }),
    }
}

#[tauri::command]
fn delete_entries_cmd(
    path: String,
    entries: Vec<String>,
    password: Option<String>,
) -> Result<ReportDto, String> {
    let n = ops::delete_entries(
        &PathBuf::from(&path),
        &entries,
        password.as_deref().map(|s| s.as_bytes()),
    )
    .map_err(|e| e.to_string())?;
    Ok(ReportDto {
        ok: true,
        message: format!("已删除 {} 个条目", n),
        errors: vec![],
    })
}

#[tauri::command]
fn rename_entry_cmd(
    path: String,
    old_name: String,
    new_name: String,
    password: Option<String>,
) -> Result<ReportDto, String> {
    let n = ops::rename_entries(
        &PathBuf::from(&path),
        &[(old_name, new_name)],
        password.as_deref().map(|s| s.as_bytes()),
    )
    .map_err(|e| e.to_string())?;
    Ok(ReportDto {
        ok: true,
        message: format!("已重命名 {} 个条目", n),
        errors: vec![],
    })
}

#[tauri::command]
fn bench_speed() -> Result<BenchDto, String> {
    let entry = rosezip_core::archive::ZipEntry {
        name: "bench".into(),
        encrypted: true,
        header_offset: 0,
        compressed_size: 32,
        uncompressed_size: 32,
        method: 8,
        crc32: 0x11223344,
        is_dir: false,
        dos_time: 0x98b,
        dos_date: 0x5B99,
    };
    let verifier = Arc::new(
        Verifier::prepare(&entry, &vec![0u8; 32], None, Some(0x98b))
            .ok_or_else(|| "bench setup failed".to_string())?,
    );
    let threads = crack::num_cpus();
    let per = 4_000_000u64;
    let start = std::time::Instant::now();
    let hs: Vec<_> = (0..threads)
        .map(|_| {
            let v = verifier.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                let mut n = 0u64;
                for i in 0..per {
                    let s = format!("{:016x}", i);
                    buf.copy_from_slice(s.as_bytes());
                    let _ = v.quick_check(&buf);
                    n += 1;
                }
                n
            })
        })
        .collect();
    let total: u64 = hs.into_iter().map(|h| h.join().unwrap()).sum();
    let rate = total as f64 / start.elapsed().as_secs_f64();
    Ok(BenchDto {
        zipcrypto_per_sec: rate,
        aes_per_sec: rate / 1000.0,
        threads,
    })
}

// ---------------------------------------------------------------------------
// Crack commands
// ---------------------------------------------------------------------------

#[tauri::command]
fn crack_prepare(path: String) -> Result<CrackInfoDto, String> {
    let plan = ops::prepare_crack(&PathBuf::from(&path)).map_err(|e| e.to_string())?;
    Ok(CrackInfoDto {
        entry: plan.entry_name,
        kind: plan.kind,
        encrypted_entries: plan.encrypted_entries,
        format: "ZIP".into(),
    })
}

#[derive(Serialize)]
struct SpaceEstimate {
    total: u64,
    total_pretty: String,
}

/// Estimate the brute-force search space for UI display.
#[tauri::command]
fn estimate_space(charset: String, min_len: usize, max_len: usize) -> Result<SpaceEstimate, String> {
    let gen = ops::make_gen(&charset, min_len, max_len).map_err(|e| e.to_string())?;
    let total = gen.total;
    let pretty = if total >= 1_000_000_000_000 {
        format!("{:.2}T", total as f64 / 1e12)
    } else if total >= 1_000_000_000 {
        format!("{:.2}G", total as f64 / 1e9)
    } else if total >= 1_000_000 {
        format!("{:.2}M", total as f64 / 1e6)
    } else if total >= 1_000 {
        format!("{:.1}K", total as f64 / 1e3)
    } else {
        total.to_string()
    };
    Ok(SpaceEstimate { total, total_pretty: format!("{} 个候选", pretty) })
}

#[tauri::command]
fn crack_start(
    path: String,
    mode: String,
    charset: Option<String>,
    min_len: Option<usize>,
    max_len: Option<usize>,
    dictionary: Option<String>,
    threads: Option<usize>,
    job: State<'_, JobSlot>,
) -> Result<StatusDto, String> {
    // Replace any running job.
    if let Some(h) = job.handle.lock().unwrap().take() {
        h.cancel();
        std::thread::spawn(|| {
            let _ = h.join();
        });
    }

    let p = PathBuf::from(&path);

    // 7z: native in-process attack, dictionary mode (each candidate is a full
    // AES-256 key derivation, so brute force is impractical in the GUI).
    if rosezip_core::archive::detect_format(&p).map_err(|e| e.to_string())?
        == rosezip_core::archive::Format::SevenZ
    {
        let dict = dictionary.ok_or_else(|| {
            "7z 攻击仅支持字典模式：请选择字典文件（AES-256 密钥派生使暴力破解不可行）".to_string()
        })?;
        let words = std::fs::read_to_string(&dict).map_err(|e| e.to_string())?;
        let start = std::time::Instant::now();
        let mut tried: u64 = 0;
        for line in words.lines() {
            let pw = line.trim_end_matches('\r');
            tried += 1;
            if rosezip_core::archive::sevenz_test_password(&p, pw.as_bytes())
                .map_err(|e| e.to_string())?
            {
                return Ok(StatusDto {
                    done: tried,
                    total: None,
                    rate_per_sec: tried as f64 / start.elapsed().as_secs_f64().max(1e-9),
                    elapsed_secs: start.elapsed().as_secs_f64(),
                    finished: true,
                    found: Some(pw.to_string()),
                    cancelled: false,
                });
            }
        }
        return Ok(StatusDto {
            done: tried,
            total: None,
            rate_per_sec: tried as f64 / start.elapsed().as_secs_f64().max(1e-9),
            elapsed_secs: start.elapsed().as_secs_f64(),
            finished: true,
            found: None,
            cancelled: false,
        });
    }

    // Other non-ZIP formats (tar/gz/xz/bz2) have no encryption at all.
    if rosezip_core::archive::detect_format(&p).map_err(|e| e.to_string())?
        != rosezip_core::archive::Format::Zip
    {
        return Err("该格式（tar/gz/xz/bz2）不支持加密，无需破解".into());
    }

    let plan = ops::prepare_crack(&p).map_err(|e| e.to_string())?;
    let target = match (mode.as_str(), dictionary) {
        ("dictionary", Some(d)) => CrackTarget::Dictionary { path: PathBuf::from(d) },
        (_, d) if d.is_some() => CrackTarget::Dictionary { path: PathBuf::from(d.unwrap()) },
        _ => {
            let gen = ops::make_gen(
                charset.as_deref().unwrap_or("lower"),
                min_len.unwrap_or(1),
                max_len.unwrap_or(6),
            )
            .map_err(|e| e.to_string())?;
            CrackTarget::Brute { gen }
        }
    };
    let handle = crack::spawn_job(target, plan.verifier.clone(), threads.unwrap_or_else(crack::num_cpus));
    let dto = handle.status().into();
    *job.handle.lock().unwrap() = Some(handle);
    *job.meta.lock().unwrap() = Some(format!("{} · {}", plan.kind, plan.entry_name));
    Ok(dto)
}

impl From<crack::CrackStatus> for StatusDto {
    fn from(s: crack::CrackStatus) -> Self {
        StatusDto {
            done: s.done,
            total: s.total,
            rate_per_sec: s.rate_per_sec,
            elapsed_secs: s.elapsed_secs,
            finished: s.finished,
            found: s.found,
            cancelled: s.cancelled,
        }
    }
}

#[tauri::command]
fn crack_status(job: State<'_, JobSlot>) -> StatusDto {
    match job.handle.lock().unwrap().as_ref() {
        Some(h) => h.status().into(),
        None => StatusDto {
            done: 0,
            total: None,
            rate_per_sec: 0.0,
            elapsed_secs: 0.0,
            finished: true,
            found: None,
            cancelled: false,
        },
    }
}

#[tauri::command]
fn crack_cancel(job: State<'_, JobSlot>) -> Result<(), String> {
    if let Some(h) = job.handle.lock().unwrap().as_ref() {
        h.cancel();
        Ok(())
    } else {
        Err("no job running".into())
    }
}

// 启动参数里带来的归档路径（文件管理器双击 / `rosezip-app foo.zip`）
#[tauri::command]
fn startup_path() -> Option<String> {
    std::env::args().nth(1).filter(|p| !p.starts_with('-'))
}

#[tauri::command]
fn app_version() -> String {
    env!("CARGO_PKG_VERSION").to_string()
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .manage(JobSlot::new())
        .invoke_handler(tauri::generate_handler![
            inspect_archive,
            extract_archive,
            compress_archive,
            bench_speed,
            crack_prepare,
            estimate_space,
            crack_start,
            crack_status,
            crack_cancel,
            startup_path,
            app_version,
            extract_selected,
            test_archive_cmd,
            delete_entries_cmd,
            rename_entry_cmd
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}

