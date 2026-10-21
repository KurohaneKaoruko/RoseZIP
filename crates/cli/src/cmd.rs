//! Direct command implementations (thin wrappers over rosezip_core::ops).

use std::io;
use std::path::{Path, PathBuf};

use rosezip_core::crack::{self, CrackOptions};
use rosezip_core::{archive, ops};

use crate::Cmd;

pub fn dispatch(cmd: Cmd) -> io::Result<String> {
    match cmd {
        Cmd::List { file } => cmd_list(&file),
        Cmd::Extract { file, out_dir, password } => {
            let dest = out_dir.unwrap_or_else(|| PathBuf::from("."));
            cmd_extract(&file, &dest, password.as_deref())
        }
        Cmd::Compress { files, out, password, level } => {
            cmd_compress(files, &out, password.as_deref(), level)
        }
        Cmd::Check { file } => cmd_check(&file),
        Cmd::Bench => cmd_bench(),
        Cmd::Crack { file, charset, min_len, max_len, dictionary, threads, quiet } => {
            cmd_crack(&file, &charset, min_len, max_len, dictionary.as_deref(), threads, quiet)
        }
        Cmd::Test { file, password } => cmd_test(&file, password.as_deref()),
    }
}

fn cmd_test(path: &Path, password: Option<&str>) -> io::Result<String> {
    let report = ops::test_archive(path, password.map(|s| s.as_bytes()))?;
    if report.errors.is_empty() {
        Ok(format!(
            "test ok: {} entries verified, no errors\nchecksums match — archive is healthy",
            if report.files == 0 { "all".to_string() } else { report.files.to_string() }
        ))
    } else {
        let mut out = format!("test FAILED: {} problem(s)\n", report.errors.len());
        for e in &report.errors {
            out.push_str(&format!("  {}\n", e));
        }
        // A failed integrity test is an error for scripts/CI.
        return Err(io::Error::new(io::ErrorKind::InvalidData, out));
    }
}

fn cmd_list(path: &Path) -> io::Result<String> {
    let view = ops::inspect(path)?;
    let mut out = format!("archive: {} (format: {:?})\n", view.path.display(), view.format);
    out.push_str(&format!("{:<4} {:>10} {:>10}  name\n", "enc", "packed", "size"));
    let (mut tp, mut ts, mut n) = (0u64, 0u64, 0);
    for e in &view.entries {
        if e.is_dir {
            out.push_str(&format!("     {:>10} {:>10}  {}/\n", "-", "-", e.name));
            continue;
        }
        n += 1;
        tp += e.compressed_size;
        ts += e.uncompressed_size;
        out.push_str(&format!(
            "{:<4} {:>10} {:>10}  {}\n",
            if e.encrypted { "*" } else { "" },
            human(tp.min(e.compressed_size).max(e.compressed_size)),
            human(ts.min(e.uncompressed_size).max(e.uncompressed_size)),
            e.name
        ));
    }
    out.push_str(&format!("\n{} files, {} packed, {} total\n", n, human(tp), human(ts)));
    Ok(out)
}

fn cmd_extract(path: &Path, dest: &Path, password: Option<&str>) -> io::Result<String> {
    let report = ops::extract(path, dest, password.map(|s| s.as_bytes()))?;
    let mut out = format!("extracted {} files to {}", report.files, dest.display());
    if report.skipped_encrypted > 0 {
        out.push_str(&format!(" ({} skipped: encrypted)", report.skipped_encrypted));
    }
    if !report.errors.is_empty() {
        out.push_str(&format!("\n{} errors:", report.errors.len()));
        for e in report.errors.iter().take(10) {
            out.push_str(&format!("\n  {}", e));
        }
    }
    Ok(out)
}

fn cmd_compress(files: Vec<PathBuf>, out: &Path, password: Option<&str>, level: u32) -> io::Result<String> {
    let report = ops::compress(&files, out, password.map(|s| s.as_bytes()), level)?;
    Ok(format!("added {} files, {} -> {}", report.files, human(report.bytes), out.display()))
}

fn cmd_check(path: &Path) -> io::Result<String> {
    let view = ops::inspect(path)?;
    let n_enc = view.entries.iter().filter(|e| e.encrypted).count();
    let mut out = format!("format: {:?}\n", view.format);
    out.push_str(&format!("entries: {} ({} encrypted)\n", view.entries.len(), n_enc));
    if let Some(enc) = view.encryption {
        out.push_str(&format!("encryption: {}\n", enc));
        out.push_str("crackable: yes — try `rosezip crack <file>`\n");
    }
    Ok(out)
}

fn cmd_bench() -> io::Result<String> {
    let threads = crack::num_cpus();
    println!("benchmarking ZipCrypto verification on {} threads...", threads);
    let entry = archive::ZipEntry {
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
    let verifier = std::sync::Arc::new(
        rosezip_core::zipcrypt::Verifier::prepare(&entry, &vec![0u8; 32], None, Some(0x98b))
            .ok_or_else(|| ops::bad("bench setup failed"))?,
    );
    let per_thread = 4_000_000u64;
    let start = std::time::Instant::now();
    let handles: Vec<_> = (0..threads)
        .map(|_| {
            let v = verifier.clone();
            std::thread::spawn(move || {
                let mut buf = [0u8; 16];
                let mut n = 0u64;
                for i in 0..per_thread {
                    let s = format!("{:016x}", i);
                    buf.copy_from_slice(s.as_bytes());
                    let _ = v.quick_check(&buf);
                    n += 1;
                }
                n
            })
        })
        .collect();
    let total: u64 = handles.into_iter().map(|h| h.join().unwrap()).sum();
    let elapsed = start.elapsed().as_secs_f64();
    let rate = total as f64 / elapsed;
    Ok(format!(
        "ZipCrypto header-check: {:.2}M passwords/s total ({:.2}M/s per thread)\n\
         WinZip-AES (PBKDF2-1000): roughly {:.0}K passwords/s total",
        rate / 1e6,
        rate / 1e6 / threads as f64,
        rate / 1000.0
    ))
}

fn cmd_crack(
    path: &Path,
    charset_spec: &str,
    min_len: usize,
    max_len: usize,
    dictionary: Option<&Path>,
    threads: usize,
    quiet: bool,
) -> io::Result<String> {
    // Non-ZIP formats: shell out to 7z per candidate.
    if archive::detect_format(path)? != archive::Format::Zip {
        return crack_via_sevenz(path, dictionary, charset_spec, min_len, max_len, quiet);
    }

    let plan = ops::prepare_crack(path)?;
    if plan.kind == "WinZip-AES" && dictionary.is_none() {
        return Ok(
            "WinZip-AES detected (PBKDF2). Brute force is ~1000x slower than ZipCrypto;\n\
             use a dictionary: rosezip crack <file> -d wordlist.txt"
                .into(),
        );
    }

    println!(
        "target: {} [{}] entry `{}`, {} threads, mode: {}",
        path.display(),
        plan.kind,
        plan.entry_name,
        threads,
        if dictionary.is_some() { "dictionary" } else { "brute force" }
    );

    let opts = CrackOptions { threads, quiet };
    let start = std::time::Instant::now();
    let result = match dictionary {
        Some(dict) => crack::crack_dictionary(dict, plan.verifier, &opts)?,
        None => {
            let gen = ops::make_gen(charset_spec, min_len, max_len)?;
            println!("space: {} ({}..{} over {} symbols)", gen.total, min_len, max_len, gen.charset.len());
            crack::crack_bruteforce(gen, plan.verifier, &opts)?
        }
    };
    let elapsed = start.elapsed().as_secs_f64();

    match &result.password {
        Some(pw) => Ok(format!(
            "FOUND password: \"{}\"\ntried {} candidates in {:.2}s ({:.0}/s)",
            String::from_utf8_lossy(pw),
            result.tried,
            elapsed,
            result.tried as f64 / elapsed.max(1e-9)
        )),
        None => Ok(format!(
            "password not found; tried {} candidates in {:.2}s",
            result.tried, elapsed
        )),
    }
}

/// Password attack for non-ZIP formats — native, in-process 7z decoding
/// (~1-2ms per candidate vs ~50/s with an external binary).
fn crack_via_sevenz(
    path: &Path,
    dictionary: Option<&Path>,
    charset_spec: &str,
    min_len: usize,
    max_len: usize,
    quiet: bool,
) -> io::Result<String> {
    if archive::detect_format(path)? != archive::Format::SevenZ {
        return Err(ops::bad("native password attack supports 7z; tar/gz/xz/bz2 have no encryption"));
    }
    let start = std::time::Instant::now();
    let mut tried: u64 = 0;
    let mut result: Option<Vec<u8>> = None;

    if let Some(dict) = dictionary {
        let words = std::fs::read_to_string(dict)?;
        for line in words.lines() {
            let pw = line.trim_end_matches('\r');
            tried += 1;
            if !quiet && tried % 20 == 0 {
                eprint!("\rtried {} ({:.0}/s)", tried, tried as f64 / start.elapsed().as_secs_f64().max(1e-9));
            }
            if archive::sevenz_test_password(path, pw.as_bytes())? {
                result = Some(pw.as_bytes().to_vec());
                break;
            }
        }
    } else {
        let gen = ops::make_gen(charset_spec, min_len, max_len)?;
        println!("note: 7z = AES-256 + key derivation, native attack is ~500/s; prefer -d <dictionary>");
        for idx in 0..gen.total {
            let cand = gen.password_at(idx);
            tried += 1;
            if !quiet && tried % 20 == 0 {
                eprint!("\rtried {} ({:.0}/s)", tried, tried as f64 / start.elapsed().as_secs_f64().max(1e-9));
            }
            if archive::sevenz_test_password(path, cand.as_slice())? {
                result = Some(cand.as_slice().to_vec());
                break;
            }
        }
    }
    let elapsed = start.elapsed().as_secs_f64();
    Ok(match result {
        Some(pw) => format!(
            "FOUND password: \"{}\"\ntried {} candidates in {:.2}s",
            String::from_utf8_lossy(&pw),
            tried,
            elapsed
        ),
        None => format!("password not found; tried {} candidates in {:.2}s", tried, elapsed),
    })
}

fn human(n: u64) -> String {
    const UNITS: [&str; 6] = ["B", "K", "MB", "GB", "TB", "PB"];
    let mut n = n as f64;
    let mut u = 0;
    while n >= 1024.0 && u < UNITS.len() - 1 {
        n /= 1024.0;
        u += 1;
    }
    if u == 0 {
        format!("{}{}", n as u64, UNITS[0])
    } else {
        format!("{:.1}{}", n, UNITS[u])
    }
}
