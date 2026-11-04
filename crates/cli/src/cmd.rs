//! Direct command implementations (thin wrappers over rosezip_core::ops).

use std::io;
use std::path::{Path, PathBuf};

use rosezip_core::crack::{self, CrackOptions};
use rosezip_core::{archive, ops};

use crate::Cmd;

pub fn dispatch(cmd: Cmd) -> io::Result<String> {
    match cmd {
        Cmd::List { file } => cmd_list(&file),
        Cmd::Extract { file, out_dir, password, include, exclude } => {
            let dest = out_dir.unwrap_or_else(|| PathBuf::from("."));
            cmd_extract(&file, &dest, password.as_deref(), &include, &exclude)
        }
        Cmd::Compress { files, out, password, level, format } => {
            cmd_compress(files, &out, password.as_deref(), level, format.as_deref())
        }
        Cmd::Check { file } => cmd_check(&file),
        Cmd::Bench => cmd_bench(),
        Cmd::Crack { file, charset, min_len, max_len, mask, dictionary, threads, quiet } => {
            cmd_crack(&file, &charset, min_len, max_len, mask.as_deref(), dictionary.as_deref(), threads, quiet)
        }
        Cmd::Test { file, password } => cmd_test(&file, password.as_deref()),
        Cmd::Delete { file, entries, password } => {
            cmd_delete(&file, &entries, password.as_deref())
        }
        Cmd::Rename { file, pairs, password } => cmd_rename(&file, &pairs, password.as_deref()),
    }
}

fn cmd_delete(file: &Path, entries: &[String], password: Option<&str>) -> io::Result<String> {
    let n = ops::delete_entries(file, entries, password.map(|s| s.as_bytes()))?;
    Ok(format!("deleted {} entr{} from {}", n, if n == 1 { "y" } else { "ies" }, file.display()))
}

fn cmd_rename(file: &Path, pairs: &[String], password: Option<&str>) -> io::Result<String> {
    let mut renames = Vec::new();
    for p in pairs {
        let (old, new) = p.split_once('=').ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                format!("rename pair must be OLD=NEW, got '{}'", p),
            )
        })?;
        renames.push((old.to_owned(), new.to_owned()));
    }
    let n = ops::rename_entries(file, &renames, password.map(|s| s.as_bytes()))?;
    Ok(format!("renamed {} entr{} in {}", n, if n == 1 { "y" } else { "ies" }, file.display()))
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
            // names already end with '/'; don't double it
            out.push_str(&format!("     {:>10} {:>10}  {}\n", "-", "-", e.name));
            continue;
        }
        n += 1;
        tp += e.compressed_size;
        ts += e.uncompressed_size;
        out.push_str(&format!(
            "{:<4} {:>10} {:>10}  {}\n",
            if e.encrypted { "*" } else { "" },
            human(e.compressed_size),
            human(e.uncompressed_size),
            e.name
        ));
    }
    out.push_str(&format!("\n{} files, {} packed, {} total\n", n, human(tp), human(ts)));
    Ok(out)
}

fn cmd_extract(
    path: &Path,
    dest: &Path,
    password: Option<&str>,
    include: &[String],
    exclude: &[String],
) -> io::Result<String> {
    let report = if include.is_empty() && exclude.is_empty() {
        ops::extract(path, dest, password.map(|s| s.as_bytes()))?
    } else {
        ops::extract_filtered(path, dest, password.map(|s| s.as_bytes()), include, exclude)?
    };
    let mut out = format!("extracted {} files to {}", report.files, dest.display());
    if !include.is_empty() {
        out.push_str(&format!(" (include: {})", include.join(", ")));
    }
    if !exclude.is_empty() {
        out.push_str(&format!(" (exclude: {})", exclude.join(", ")));
    }
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

fn cmd_compress(
    files: Vec<PathBuf>,
    out: &Path,
    password: Option<&str>,
    level: u32,
    format: Option<&str>,
) -> io::Result<String> {
    let fmt = match format {
        None => None,
        Some(s) => Some(ops::OutFormat::parse_out_format(s)?),
    };
    let report = ops::compress_as(&files, out, password.map(|s| s.as_bytes()), level, fmt)?;
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
        aes_inner_method: 8,
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
    mask: Option<&str>,
    dictionary: Option<&Path>,
    threads: usize,
    quiet: bool,
) -> io::Result<String> {
    // Non-ZIP formats: native in-process 7z candidate verification.
    if archive::detect_format(path)? != archive::Format::Zip {
        return crack_via_sevenz(path, dictionary, mask, charset_spec, min_len, max_len, quiet);
    }

    if let Some(pat) = mask {
        let plan = ops::prepare_crack(path)?;
        println!(
            "target: {} [{}] entry `{}`, {} threads, mode: mask `{}`",
            path.display(), plan.kind, plan.entry_name, threads, pat
        );
        println!("space: {} candidates", rosezip_core::charset::MaskGen::parse(pat)
            .map(|m| m.total).unwrap_or(0));
        let opts = CrackOptions { threads, quiet };
        let start = std::time::Instant::now();
        let result = crack::crack_mask(pat, plan.verifier, &opts)?;
        let elapsed = start.elapsed().as_secs_f64();
        return Ok(match &result.password {
            Some(pw) => format!(
                "FOUND password: \"{}\"\ntried {} candidates in {:.2}s ({:.0}/s)",
                String::from_utf8_lossy(pw), result.tried, elapsed,
                result.tried as f64 / elapsed.max(1e-9)
            ),
            None => format!("password not found; tried {} candidates in {:.2}s", result.tried, elapsed),
        });
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
/// (~1-2ms per candidate vs ~50/s with an external binary). Candidates are
/// verified on all CPU threads; dictionary, brute force and mask modes.
fn crack_via_sevenz(
    path: &Path,
    dictionary: Option<&Path>,
    mask: Option<&str>,
    charset_spec: &str,
    min_len: usize,
    max_len: usize,
    quiet: bool,
) -> io::Result<String> {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    use std::sync::{Arc, Mutex};

    if archive::detect_format(path)? != archive::Format::SevenZ {
        return Err(ops::bad("native password attack supports 7z; tar/gz/xz/bz2 have no encryption"));
    }
    let start = std::time::Instant::now();
    let mut result: Option<Vec<u8>> = None;
    let mut tried: u64 = 0;

    // Ticker on the main thread while workers verify candidates.
    let tick = |found_not_empty: bool, handles: &[std::thread::ScopedJoinHandle<'_, ()>], counter: &AtomicU64| {
        let n = counter.load(Ordering::Relaxed);
        if !quiet && n > 0 {
            eprint!("\rtried {} ({:.0}/s)", n, n as f64 / start.elapsed().as_secs_f64().max(1e-9));
        }
        found_not_empty || handles.iter().all(|h| h.is_finished())
    };

    std::thread::scope(|scope| {
        // Each candidate costs a full AES-256 key derivation, so the stream
        // is shared across worker threads with a static split.
        let attempt = |pw: &[u8]| archive::sevenz_test_password(path, pw).unwrap_or(false);

        if let Some(dict) = dictionary {
            // Split at line boundaries; each worker owns a contiguous region.
            let data: &'static [u8] = crack::load_dictionary(dict)?;
            let threads = crack::num_cpus();
            let bounds = line_bounds(data, threads);
            let found: Arc<Mutex<Option<Vec<u8>>>> = Default::default();
            let tried_counter = Arc::new(AtomicU64::new(0));
            let stop = Arc::new(AtomicBool::new(false));
            let mut handles = Vec::new();
            for t in 0..threads {
                let region = &data[bounds[t]..bounds[t + 1]];
                let found = found.clone();
                let tried_counter = tried_counter.clone();
                let stop = stop.clone();
                handles.push(scope.spawn(move || {
                    for word in region.split(|&b| b == b'\n') {
                        if stop.load(Ordering::Relaxed) {
                            break;
                        }
                        let word = word.strip_suffix(b"\r").unwrap_or(word);
                        if word.is_empty() {
                            continue;
                        }
                        tried_counter.fetch_add(1, Ordering::Relaxed);
                        if attempt(word) {
                            let mut g = found.lock().unwrap();
                            if g.is_none() {
                                *g = Some(word.to_vec());
                            }
                            stop.store(true, Ordering::Relaxed);
                            break;
                        }
                    }
                }));
            }
            loop {
                let done = tick(found.lock().unwrap().is_some(), &handles, &tried_counter);
                if done {
                    break;
                }
                std::thread::sleep(std::time::Duration::from_millis(150));
            }
            for h in handles {
                let _ = h.join();
            }
            result = found.lock().unwrap().take();
            tried = tried_counter.load(Ordering::Relaxed);
        } else {
            // Brute force or mask: static split of the index space, workers
            // pull candidates by index and verify in-process. `index_at` maps
            // an index to its candidate; it must be Clone to fan out to the
            // workers (the IndexGen/MaskGen behind it are cheap clones).
            fn run_stream<'scope, 'env, F>(
                scope: &'scope std::thread::Scope<'scope, 'env>,
                gen_total: u64,
                quiet: bool,
                start: &std::time::Instant,
                index_at: F,
                attempt: impl Fn(&[u8]) -> bool + Send + Sync + Copy + 'env,
                result: &mut Option<Vec<u8>>,
                tried: &mut u64,
            ) where
                F: Fn(u64) -> Vec<u8> + Send + Sync + Clone + 'env,
            {
                use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
                use std::sync::{Arc, Mutex};

                let threads = crack::num_cpus();
                let found: Arc<Mutex<Option<Vec<u8>>>> = Default::default();
                let tried_counter = Arc::new(AtomicU64::new(0));
                let stop = Arc::new(AtomicBool::new(false));
                let chunk = gen_total / threads as u64 + 1;
                let mut handles = Vec::new();
                for t in 0..threads {
                    let found = found.clone();
                    let tried_counter = tried_counter.clone();
                    let stop = stop.clone();
                    let index_at = index_at.clone();
                    handles.push(scope.spawn(move || {
                        let lo = (t as u64) * chunk;
                        let hi = (lo + chunk).min(gen_total);
                        for idx in lo..hi {
                            if stop.load(Ordering::Relaxed) {
                                break;
                            }
                            let pw = index_at(idx);
                            tried_counter.fetch_add(1, Ordering::Relaxed);
                            if attempt(&pw) {
                                let mut g = found.lock().unwrap();
                                if g.is_none() {
                                    *g = Some(pw);
                                }
                                stop.store(true, Ordering::Relaxed);
                                break;
                            }
                        }
                    }));
                }
                loop {
                    let n = tried_counter.load(Ordering::Relaxed);
                    if !quiet && n > 0 {
                        eprint!("\rtried {} ({:.0}/s)", n, n as f64 / start.elapsed().as_secs_f64().max(1e-9));
                    }
                    if found.lock().unwrap().is_some() || handles.iter().all(|h| h.is_finished()) {
                        break;
                    }
                    std::thread::sleep(std::time::Duration::from_millis(150));
                }
                for h in handles {
                    let _ = h.join();
                }
                *result = found.lock().unwrap().take();
                *tried = tried_counter.load(Ordering::Relaxed);
            }

            if let Some(pat) = mask {
                let mg = rosezip_core::charset::MaskGen::parse(pat).map_err(|e| ops::bad(&e))?;
                println!("note: 7z = AES-256 + key derivation, native attack is slow; prefer -d <dictionary>");
                println!("space: {} candidates from mask", mg.total);
                run_stream(scope, mg.total, quiet, &start,
                    move |idx| mg.password_at(idx).as_slice().to_vec(),
                    attempt, &mut result, &mut tried);
            } else {
                let gen = ops::make_gen(charset_spec, min_len, max_len)?;
                println!("note: 7z = AES-256 + key derivation, native attack is slow; prefer -d <dictionary>");
                run_stream(scope, gen.total, quiet, &start,
                    move |idx| gen.password_at(idx).as_slice().to_vec(),
                    attempt, &mut result, &mut tried);
            }
        }
        Ok::<(), io::Error>(())
    })?;

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

/// Split a byte slice at `\n` boundaries into `n` roughly equal regions.
fn line_bounds(data: &[u8], n: usize) -> Vec<usize> {
    let mut bounds = Vec::with_capacity(n + 1);
    bounds.push(0usize);
    for _ in 1..n {
        let approx = (bounds.last().unwrap() + data.len() / n).min(data.len());
        let nl = match data[approx..].iter().position(|&b| b == b'\n') {
            Some(p) => approx + p + 1,
            None => data.len(),
        };
        bounds.push(nl);
    }
    bounds.push(data.len());
    bounds
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
