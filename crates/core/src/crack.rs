//! Multi-threaded password cracking engine.
//!
//! Two front ends:
//!  * `crack_bruteforce` / `crack_dictionary` — blocking calls (CLI)
//!  * `spawn_job` — background job with pollable status + cancel (GUI)
//!
//! Work distribution: static chunking of the index space. Each worker takes a
//! slice of the candidate space and processes it independently, so there is
//! no shared mutable state in the hot loop beyond relaxed atomic counters.
//!
//! Dictionary mode: the word list is loaded (mmap on Unix) and split at
//! newline boundaries into contiguous regions per worker.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;

use crate::charset::IndexGen;
use crate::progress::Progress;
use crate::zipcrypt::Verifier;

pub struct CrackResult {
    pub password: Option<Vec<u8>>,
    pub tried: u64,
}

pub struct CrackOptions {
    pub threads: usize,
    pub quiet: bool,
}

impl Default for CrackOptions {
    fn default() -> Self {
        Self { threads: num_cpus(), quiet: false }
    }
}

pub fn num_cpus() -> usize {
    std::thread::available_parallelism().map(|n| n.get()).unwrap_or(1)
}

// ---------------------------------------------------------------------------
// Shared job state (GUI)
// ---------------------------------------------------------------------------

/// Live status snapshot for GUI polling.
#[derive(Clone, Debug)]
pub struct CrackStatus {
    pub done: u64,
    pub total: Option<u64>,
    pub rate_per_sec: f64,
    pub elapsed_secs: f64,
    pub finished: bool,
    pub found: Option<String>,
    pub cancelled: bool,
}

struct JobShared {
    progress: Arc<Progress>,
    cancel: Arc<AtomicBool>,
    found: Mutex<Option<Vec<u8>>>,
    finished: AtomicBool,
}

/// Handle to a running (or finished) background crack job.
pub struct CrackHandle {
    shared: Arc<JobShared>,
    supervisor: Mutex<Option<thread::JoinHandle<()>>>,
}

/// What to attack.
#[derive(Clone)]
pub enum CrackTarget {
    Brute { gen: IndexGen },
    Dictionary { path: PathBuf },
}

/// Spawn a background crack job; poll `status()` from the UI thread.
pub fn spawn_job(target: CrackTarget, verifier: Arc<Verifier>, threads: usize) -> CrackHandle {
    let shared = Arc::new(JobShared {
        progress: Progress::new(match &target {
            CrackTarget::Brute { gen } => Some(gen.total),
            CrackTarget::Dictionary { .. } => None,
        }),
        cancel: Arc::new(AtomicBool::new(false)),
        found: Mutex::new(None),
        finished: AtomicBool::new(false),
    });
    let sup_shared = shared.clone();
    let supervisor = thread::spawn(move || {
        let opts = CrackOptions { threads, quiet: true };
        let found: Arc<Mutex<Option<Vec<u8>>>>;
        match &target {
            CrackTarget::Brute { gen } => {
                found = run_workers(gen, verifier, &opts, &sup_shared.progress, &sup_shared.cancel);
            }
            CrackTarget::Dictionary { path } => {
                match load_dictionary(path) {
                    Ok(data) => {
                        found = run_dict_workers(data, verifier, &opts, &sup_shared.progress, &sup_shared.cancel);
                    }
                    Err(_) => found = Arc::new(Mutex::new(None)),
                }
            }
        }
        // Publish the worker result into the shared slot.
        if let Some(pw) = found.lock().unwrap().take() {
            *sup_shared.found.lock().unwrap() = Some(pw);
        }
        sup_shared.progress.stop();
        sup_shared.finished.store(true, Ordering::Release);
    });
    CrackHandle { shared, supervisor: Mutex::new(Some(supervisor)) }
}

impl CrackHandle {
    pub fn status(&self) -> CrackStatus {
        let p = &self.shared.progress;
        let done = p.done.load(Ordering::Relaxed);
        let elapsed = p.start.elapsed().as_secs_f64();
        CrackStatus {
            done,
            total: p.total,
            rate_per_sec: if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 },
            elapsed_secs: elapsed,
            finished: self.shared.finished.load(Ordering::Acquire),
            found: self
                .shared
                .found
                .lock()
                .unwrap()
                .as_ref()
                .map(|b| String::from_utf8_lossy(b).into_owned()),
            cancelled: self.shared.cancel.load(Ordering::Relaxed),
        }
    }

    pub fn cancel(&self) {
        self.shared.cancel.store(true, Ordering::Relaxed);
    }

    /// Block until the job finishes; returns the final result.
    pub fn join(self) -> CrackResult {
        let handle = self.supervisor.lock().unwrap().take();
        if let Some(h) = handle {
            let _ = h.join();
        }
        CrackResult {
            password: self.shared.found.lock().unwrap().take(),
            tried: self.shared.progress.done.load(Ordering::Relaxed),
        }
    }
}

// ---------------------------------------------------------------------------
// Blocking API (CLI)
// ---------------------------------------------------------------------------

pub fn crack_bruteforce(
    gen: IndexGen,
    verifier: Arc<Verifier>,
    opts: &CrackOptions,
) -> io::Result<CrackResult> {
    let progress = Progress::new(Some(gen.total));
    let printer = printer_for(opts, &progress);
    let cancel = Arc::new(AtomicBool::new(false));
    let found = run_workers(&gen, verifier, opts, &progress, &cancel);
    finish_blocking(progress, printer, found)
}

pub fn crack_dictionary(
    path: &Path,
    verifier: Arc<Verifier>,
    opts: &CrackOptions,
) -> io::Result<CrackResult> {
    let data = load_dictionary(path)?;
    let progress = Progress::new(None);
    let printer = printer_for(opts, &progress);
    let cancel = Arc::new(AtomicBool::new(false));
    let found = run_dict_workers(data, verifier, opts, &progress, &cancel);
    finish_blocking(progress, printer, found)
}

fn printer_for(opts: &CrackOptions, progress: &Arc<Progress>) -> Option<thread::JoinHandle<()>> {
    if opts.quiet {
        None
    } else {
        Some(crate::progress::spawn_printer(progress.clone(), "cracking"))
    }
}

fn finish_blocking(
    progress: Arc<Progress>,
    printer: Option<thread::JoinHandle<()>>,
    found: Arc<Mutex<Option<Vec<u8>>>>,
) -> io::Result<CrackResult> {
    progress.stop();
    if let Some(p) = printer {
        let _ = p.join();
    }
    Ok(CrackResult {
        password: found.lock().unwrap().take(),
        tried: progress.done.load(Ordering::Relaxed),
    })
}

// ---------------------------------------------------------------------------
// Worker orchestration
// ---------------------------------------------------------------------------

fn run_workers(
    gen: &IndexGen,
    verifier: Arc<Verifier>,
    opts: &CrackOptions,
    progress: &Arc<Progress>,
    stop: &Arc<AtomicBool>,
) -> Arc<Mutex<Option<Vec<u8>>>> {
    let total = gen.total;
    let threads = opts.threads.max(1);
    let chunk = total / threads as u64 + 1;
    let found: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let gen = gen.clone();
        let verifier = verifier.clone();
        let progress = progress.clone();
        let found = found.clone();
        let stop = stop.clone();
        handles.push(thread::spawn(move || {
            let start = (t as u64) * chunk;
            let end = (start + chunk).min(total);
            if start >= end {
                return;
            }
            match verifier.as_ref() {
                Verifier::ZipCrypto { .. } => {
                    bruteforce_zipcrypto(&gen, verifier.as_ref(), start, end, &progress, &found, &stop)
                }
                Verifier::WinZipAes { .. } => {
                    bruteforce_generic(&gen, &verifier, start, end, &progress, &found, &stop)
                }
            }
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    found
}

fn run_dict_workers(
    data: &'static [u8],
    verifier: Arc<Verifier>,
    opts: &CrackOptions,
    progress: &Arc<Progress>,
    stop: &Arc<AtomicBool>,
) -> Arc<Mutex<Option<Vec<u8>>>> {
    let threads = opts.threads.max(1);
    let found: Arc<Mutex<Option<Vec<u8>>>> = Arc::new(Mutex::new(None));

    // Split the buffer at newline boundaries into contiguous regions.
    let mut bounds = Vec::with_capacity(threads + 1);
    bounds.push(0usize);
    for _ in 1..threads {
        let approx = (bounds.last().unwrap() + data.len() / threads).min(data.len());
        let nl = match data[approx..].iter().position(|&b| b == b'\n') {
            Some(p) => approx + p + 1,
            None => data.len(),
        };
        bounds.push(nl);
    }
    bounds.push(data.len());

    let mut handles = Vec::with_capacity(threads);
    for t in 0..threads {
        let region: &'static [u8] = &data[bounds[t]..bounds[t + 1]];
        let verifier = verifier.clone();
        let progress = progress.clone();
        let found = found.clone();
        let stop = stop.clone();
        handles.push(thread::spawn(move || {
            let mut local_done = 0u64;
            let mut start = 0usize;
            while start < region.len() {
                if stop.load(Ordering::Relaxed) {
                    break;
                }
                let end = match region[start..].iter().position(|&b| b == b'\n') {
                    Some(p) => start + p,
                    None => region.len(),
                };
                let mut word = &region[start..end];
                if word.last() == Some(&b'\r') {
                    word = &word[..word.len() - 1];
                }
                if !word.is_empty() && verifier.quick_check(word) && verifier.confirm(word) {
                    let mut g = found.lock().unwrap();
                    if g.is_none() {
                        *g = Some(word.to_vec());
                    }
                    progress.found.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    break;
                }
                local_done += 1;
                if local_done >= 4096 {
                    progress.done.fetch_add(local_done, Ordering::Relaxed);
                    local_done = 0;
                }
                start = end + 1;
            }
            progress.done.fetch_add(local_done, Ordering::Relaxed);
        }));
    }
    for h in handles {
        let _ = h.join();
    }
    found
}

// ---------------------------------------------------------------------------
// Hot loops
// ---------------------------------------------------------------------------

/// ZipCrypto hot loop with prefix key-state caching. The outer loop walks
/// every "prefix" (all characters except the last) via an odometer; for each
/// prefix we scan all charset bytes as the final character, reusing the
/// cached prefix key state so only one key update + 12 header bytes of work
/// is needed per candidate.
fn bruteforce_zipcrypto(
    gen: &IndexGen,
    verifier: &Verifier,
    start: u64,
    end: u64,
    progress: &Arc<Progress>,
    found: &Arc<Mutex<Option<Vec<u8>>>>,
    stop: &Arc<AtomicBool>,
) {
    use crate::zipcrypt::ZipCrypto;

    let header = verifier.header().expect("zipcrypto verifier has header");
    let (check_crc, check_time) = verifier.check_bytes();
    let cs: Vec<u8> = gen.charset.clone();
    let n = cs.len() as u64;

    // Translate a flat index into (len, prefix_idx, last_idx).
    let mut idx = start;
    let mut len = gen.min_len;
    while len <= gen.max_len {
        let size = n.pow(len as u32);
        if idx < size {
            break;
        }
        idx -= size;
        len += 1;
    }
    if len > gen.max_len || len == 0 {
        return;
    }

    let prefix_len = len - 1;
    let mut prefix_digits = vec![0usize; prefix_len];
    let mut pw = vec![cs[0]; len];

    {
        let prefix_idx = idx / n;
        let mut v = prefix_idx;
        for d in prefix_digits.iter_mut() {
            *d = (v % n) as usize;
            v /= n;
        }
        for (i, d) in prefix_digits.iter().enumerate() {
            pw[prefix_len - 1 - i] = cs[*d];
        }
    }

    let mut local_done = 0u64;
    let mut cur = start;
    let mut last_start = idx % n;

    'outer: loop {
        // Key state after absorbing the prefix.
        let mut z = ZipCrypto::from_keys([0x12345678, 0x23456789, 0x34567890]);
        for &b in pw[..prefix_len].iter() {
            z.update_password_byte(b);
        }
        let prefix_keys = z.keys();

        let mut last = last_start;
        last_start = 0;
        while last < n {
            if local_done >= 8192 {
                progress.done.fetch_add(local_done, Ordering::Relaxed);
                local_done = 0;
                if stop.load(Ordering::Relaxed) {
                    break 'outer;
                }
            }
            let mut z2 = ZipCrypto::from_keys(prefix_keys);
            z2.update_password_byte(cs[last as usize]);
            let vb = z2.decrypt_header(header);
            if crate::zipcrypt::Verifier::match_check(vb, check_crc, check_time) {
                pw[len - 1] = cs[last as usize];
                if verifier.confirm(&pw) {
                    let mut g = found.lock().unwrap();
                    if g.is_none() {
                        *g = Some(pw.clone());
                    }
                    progress.found.store(true, Ordering::Relaxed);
                    stop.store(true, Ordering::Relaxed);
                    progress.done.fetch_add(local_done, Ordering::Relaxed);
                    return;
                }
            }
            local_done += 1;
            cur += 1;
            last += 1;
            if cur >= end {
                break 'outer;
            }
        }

        // Next prefix (odometer over prefix_digits).
        let mut i = 0usize;
        loop {
            if i >= prefix_len {
                // Exhausted this length; move to the next one.
                len += 1;
                if len > gen.max_len || cur >= end {
                    break 'outer;
                }
                prefix_digits = vec![0usize; len - 1];
                pw = vec![cs[0]; len];
                continue 'outer;
            }
            prefix_digits[i] += 1;
            if prefix_digits[i] < cs.len() {
                pw[prefix_len - 1 - i] = cs[prefix_digits[i]];
                break;
            }
            prefix_digits[i] = 0;
            pw[prefix_len - 1 - i] = cs[0];
            i += 1;
        }
    }
    progress.done.fetch_add(local_done, Ordering::Relaxed);
}

/// Generic path (WinZip AES): per-candidate PBKDF2, no shortcut possible.
fn bruteforce_generic(
    gen: &IndexGen,
    verifier: &Verifier,
    start: u64,
    end: u64,
    progress: &Arc<Progress>,
    found: &Arc<Mutex<Option<Vec<u8>>>>,
    stop: &Arc<AtomicBool>,
) {
    let mut local_done = 0u64;
    for idx in start..end {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        let cand = gen.password_at(idx);
        if verifier.quick_check(cand.as_slice()) && verifier.confirm(cand.as_slice()) {
            let mut g = found.lock().unwrap();
            if g.is_none() {
                *g = Some(cand.as_slice().to_vec());
            }
            progress.found.store(true, Ordering::Relaxed);
            stop.store(true, Ordering::Relaxed);
            break;
        }
        local_done += 1;
        if local_done >= 4096 {
            progress.done.fetch_add(local_done, Ordering::Relaxed);
            local_done = 0;
        }
    }
    progress.done.fetch_add(local_done, Ordering::Relaxed);
}

// ---------------------------------------------------------------------------
// Dictionary loading
// ---------------------------------------------------------------------------

/// Load a word list as a full-lifetime byte slice.
/// mmap on Unix, plain read elsewhere.
fn load_dictionary(path: &Path) -> io::Result<&'static [u8]> {
    #[cfg(unix)]
    {
        unsafe { mmap_file(path) }
    }
    #[cfg(not(unix))]
    {
        Ok(Box::leak(fs::read(path)?.into_boxed_slice()))
    }
}

/// mmap a file read-only (Unix). Uses libc directly to avoid a dependency.
#[cfg(unix)]
unsafe fn mmap_file(path: &Path) -> io::Result<&'static [u8]> {
    use std::os::fd::AsRawFd;

    let file = fs::File::open(path)?;
    let len = file.metadata()?.len() as usize;
    if len == 0 {
        return Ok(&[]);
    }
    extern "C" {
        fn mmap(addr: *mut u8, len: usize, prot: i32, flags: i32, fd: i32, off: i64) -> *mut u8;
    }
    const PROT_READ: i32 = 1;
    const MAP_PRIVATE: i32 = 2;
    const MAP_FAILED: *mut u8 = usize::MAX as *mut u8;

    let fd = file.as_raw_fd();
    let ptr = mmap(std::ptr::null_mut(), len, PROT_READ, MAP_PRIVATE, fd, 0);
    if ptr == MAP_FAILED {
        return Err(io::Error::last_os_error());
    }
    let slice = std::slice::from_raw_parts(ptr, len);
    // Leak the mapping and the File; process-lifetime is fine for our use.
    std::mem::forget(file);
    Ok(slice)
}

#[cfg(test)]
mod job_tests {
    use super::*;
    use crate::archive::ZipEntry;
    use crate::zipcrypt::Verifier;
    use std::io::Write;

    /// End-to-end: spawn_job (the GUI path) against a real encrypted zip.
    #[test]
    fn gui_job_finds_password() {
        let dir = std::env::temp_dir().join("rosezip_job_test");
        std::fs::create_dir_all(&dir).unwrap();
        let src = dir.join("data.txt");
        std::fs::write(&src, "gui job test payload - repeat ".repeat(8)).unwrap();

        let zip = dir.join("t.zip");
        // Native encrypted writer — no external `zip` binary needed.
        crate::ops::compress(&[src], &zip, Some(b"job42"), 6).unwrap();

        let plan = crate::ops::prepare_crack(&zip).unwrap();
        let gen = crate::ops::make_gen("lower+digits", 1, 5).unwrap();
        let handle = spawn_job(
            CrackTarget::Brute { gen },
            plan.verifier.clone(),
            std::thread::available_parallelism().map(|n| n.get()).unwrap_or(2),
        );
        // Poll like a GUI would.
        let mut final_st = None;
        for _ in 0..200 {
            let st = handle.status();
            if st.finished {
                final_st = Some(st);
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        let res = handle.join();
        assert_eq!(res.password.as_deref(), Some(b"job42".as_slice()));
        assert!(final_st.map(|s| s.found.is_some()).unwrap_or(false));
        let _ = std::fs::remove_dir_all(&dir);
        let _: Option<()> = None;
    }

    #[test]
    fn cancel_works() {
        let entry = ZipEntry {
            name: "x".into(),
            encrypted: true,
            header_offset: 0,
            compressed_size: 32,
            uncompressed_size: 32,
            method: 8,
            crc32: 0x11223344,
            is_dir: false,
            dos_time: 0x098b,
            dos_date: 0x5B99,
        };
        let v = std::sync::Arc::new(
            Verifier::prepare(&entry, &vec![0u8; 32], None, Some(0x098b)).unwrap(),
        );
        let gen = crate::ops::make_gen("lower", 1, 9).unwrap(); // huge space
        let handle = spawn_job(CrackTarget::Brute { gen }, v, 2);
        std::thread::sleep(std::time::Duration::from_millis(300));
        handle.cancel();
        let mut finished = false;
        for _ in 0..100 {
            let st = handle.status();
            if st.finished {
                finished = true;
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
        assert!(finished, "job should finish after cancel");
        let _ = std::io::sink().write(b"");
    }
}
