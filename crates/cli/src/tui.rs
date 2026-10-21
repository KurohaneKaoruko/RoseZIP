//! Minimal zero-dependency TUI: raw mode, menu-driven, arrow-key navigation.
//!
//! Layout: header, numbered menu, contextual input prompts, live progress
//! for crack jobs. Works over plain ANSI terminals (Linux/macOS/WSL).

use std::fs;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, Instant};

use rosezip_core::crack::{self, CrackTarget};
use rosezip_core::ops;

pub fn run() -> io::Result<()> {
    let mut tui = Tui::new()?;
    let result = main_loop(&mut tui);
    tui.restore();
    result
}

// ---------------------------------------------------------------------------
// Terminal plumbing (raw mode via termios, no external crates)
// ---------------------------------------------------------------------------

#[cfg(unix)]
mod raw {
    use std::io;

    pub struct RawGuard {
        orig: libc_termios,
        set: bool,
    }

    #[repr(C)]
    #[derive(Clone, Copy)]
    pub struct libc_termios {
        c_iflag: u32,
        c_oflag: u32,
        c_cflag: u32,
        c_lflag: u32,
        c_line: u8,
        c_cc: [u8; 32],
        c_ispeed: u32,
        c_ospeed: u32,
    }

    extern "C" {
        fn tcgetattr(fd: i32, termios_p: *mut libc_termios) -> i32;
        fn tcsetattr(fd: i32, optional_actions: i32, termios_p: *const libc_termios) -> i32;
    }

    const TCSANOW: i32 = 0;

    impl RawGuard {
        pub fn enable() -> io::Result<Self> {
            unsafe {
                let mut t: libc_termios = std::mem::zeroed();
                if tcgetattr(0, &mut t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                let orig = t;
                // cfmakeraw equivalent (minimal): turn off canonical echo etc.
                t.c_lflag &= !(0o10 | 0o2 | 0o1 | 0o100000); // ICANON|ECHO|ISIG|IEXTEN
                t.c_iflag &= !(0o400 | 0o2000 | 0o20000); // IXON|ICRNL|INPCK-ish
                t.c_cc[6] = 1; // VMIN
                t.c_cc[5] = 0; // VTIME
                if tcsetattr(0, TCSANOW, &t) != 0 {
                    return Err(io::Error::last_os_error());
                }
                Ok(RawGuard { orig, set: true })
            }
        }

        pub fn disable(&mut self) {
            if self.set {
                unsafe {
                    tcsetattr(0, TCSANOW, &self.orig);
                }
                self.set = false;
            }
        }
    }

    impl Drop for RawGuard {
        fn drop(&mut self) {
            self.disable();
        }
    }
}

#[cfg(unix)]
use raw::RawGuard;

#[cfg(not(unix))]
mod raw {
    use std::io;
    pub struct RawGuard;
    impl RawGuard {
        pub fn enable() -> io::Result<Self> {
            Err(io::Error::new(io::ErrorKind::Unsupported, "TUI needs a Unix terminal"))
        }
        pub fn disable(&mut self) {}
    }
}

#[cfg(not(unix))]
use raw::RawGuard;

struct Tui {
    _guard: RawGuard,
    out: io::Stdout,
}

enum Key {
    Up,
    Down,
    Enter,
    Esc,
    Char(char),
    Backspace,
    Other,
}

impl Tui {
    fn new() -> io::Result<Self> {
        Ok(Tui { _guard: RawGuard::enable()?, out: io::stdout() })
    }

    fn restore(&mut self) {
        self._guard.disable();
        let mut o = io::stdout();
        let _ = write!(o, "\x1b[?25h\x1b[0m\r\n");
        let _ = o.flush();
    }

    fn read_key(&mut self) -> io::Result<Key> {
        let mut b = [0u8; 1];
        if io::stdin().read(&mut b)? == 0 {
            return Ok(Key::Esc);
        }
        match b[0] {
            0x1b => {
                // try to read the rest of an escape sequence (non-blocking-ish)
                let mut seq = [0u8; 2];
                set_nonblocking(true);
                let n = io::stdin().read(&mut seq).unwrap_or(0);
                set_nonblocking(false);
                if n >= 2 && seq[0] == b'[' {
                    match seq[1] {
                        b'A' => Ok(Key::Up),
                        b'B' => Ok(Key::Down),
                        _ => Ok(Key::Other),
                    }
                } else {
                    Ok(Key::Esc)
                }
            }
            b'\r' | b'\n' => Ok(Key::Enter),
            127 | 8 => Ok(Key::Backspace),
            c if c.is_ascii_graphic() || c == b' ' => Ok(Key::Char(c as char)),
            _ => Ok(Key::Other),
        }
    }

    fn print(&mut self, s: &str) {
        let _ = self.out.write_all(s.as_bytes());
        let _ = self.out.flush();
    }
}

#[cfg(unix)]
fn set_nonblocking(on: bool) {
    extern "C" {
        fn fcntl(fd: i32, cmd: i32, arg: i32) -> i32;
    }
    const F_GETFL: i32 = 3;
    const F_SETFL: i32 = 4;
    const O_NONBLOCK: i32 = 0o4000;
    unsafe {
        let flags = fcntl(0, F_GETFL, 0);
        if flags >= 0 {
            let nf = if on { flags | O_NONBLOCK } else { flags & !O_NONBLOCK };
            fcntl(0, F_SETFL, nf);
        }
    }
}

#[cfg(not(unix))]
fn set_nonblocking(_on: bool) {}

// ---------------------------------------------------------------------------
// Main loop
// ---------------------------------------------------------------------------

const MENU: &[&str] = &[
    "List / inspect archive",
    "Extract archive",
    "Compress to ZIP",
    "Crack password",
    "Benchmark",
    "Quit",
];

fn main_loop(tui: &mut Tui) -> io::Result<()> {
    let mut sel: usize = 0;
    let mut status = String::from("Welcome to RoseZIP — ↑/↓ select, Enter confirm");

    loop {
        // screen
        tui.print("\x1b[2J\x1b[H");
        tui.print("\x1b[1;35m╭──────────────────────────────╮\x1b[0m\r\n");
        tui.print("\x1b[1;35m│  🌹 RoseZIP  ·  archive tool │\x1b[0m\r\n");
        tui.print("\x1b[1;35m╰──────────────────────────────╯\x1b[0m\r\n\r\n");
        for (i, item) in MENU.iter().enumerate() {
            if i == sel {
                tui.print(&format!("\x1b[1;36m ❯ {} \x1b[0m\r\n", item));
            } else {
                tui.print(&format!("   {}\r\n", item));
            }
        }
        tui.print(&format!("\r\n\x1b[2m{}\x1b[0m\r\n", status));

        match tui.read_key()? {
            Key::Up => sel = (sel + MENU.len() - 1) % MENU.len(),
            Key::Down => sel = (sel + 1) % MENU.len(),
            Key::Esc => return Ok(()),
            Key::Enter => {
                status = match sel {
                    0 => action_list(tui)?,
                    1 => action_extract(tui)?,
                    2 => action_compress(tui)?,
                    3 => action_crack(tui)?,
                    4 => action_bench(tui)?,
                    _ => return Ok(()),
                };
            }
            Key::Char('q') => return Ok(()),
            _ => {}
        }
    }
}

// ---------------------------------------------------------------------------
// Input helpers (line editing in raw mode)
// ---------------------------------------------------------------------------

fn prompt_line(tui: &mut Tui, label: &str) -> io::Result<String> {
    prompt_line_default(tui, label, "")
}

fn prompt_line_default(tui: &mut Tui, label: &str, default: &str) -> io::Result<String> {
    tui.print(&format!("\x1b[1m{}\x1b[0m", label));
    let mut buf: Vec<char> = default.chars().collect();
    tui.print(default);
    loop {
        match tui.read_key()? {
            Key::Enter => {
                tui.print("\r\n");
                return Ok(buf.into_iter().collect());
            }
            Key::Backspace => {
                if buf.pop().is_some() {
                    tui.print("\x08 \x08");
                }
            }
            Key::Char(c) => {
                buf.push(c);
                tui.print(&c.to_string());
            }
            Key::Esc => {
                tui.print("\r\n");
                return Ok(String::new());
            }
            _ => {}
        }
    }
}

fn pause(tui: &mut Tui) -> io::Result<()> {
    tui.print("\x1b[2m[press any key]\x1b[0m");
    let _ = tui.read_key();
    tui.print("\r\n");
    Ok(())
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

fn action_list(tui: &mut Tui) -> io::Result<String> {
    let path = prompt_line(tui, "archive path: ")?;
    if path.is_empty() {
        return Ok("cancelled".into());
    }
    match ops::inspect(PathBuf::from(&path).as_path()) {
        Ok(view) => {
            tui.print("\r\n");
            tui.print(&format!("format: {:?}\r\n", view.format));
            if let Some(e) = view.encryption {
                tui.print(&format!("encryption: {}\r\n", e));
            }
            tui.print(&format!("{:<4} {:>10} {:>10}  name\r\n", "enc", "packed", "size"));
            let mut n = 0;
            for e in &view.entries {
                if e.is_dir {
                    tui.print(&format!("     {:>10} {:>10}  {}/\r\n", "-", "-", e.name));
                } else {
                    n += 1;
                    tui.print(&format!(
                        "{:<4} {:>10} {:>10}  {}\r\n",
                        if e.encrypted { "*" } else { "" },
                        human(e.compressed_size),
                        human(e.uncompressed_size),
                        e.name
                    ));
                }
            }
            tui.print(&format!("\r\n{} files\r\n", n));
            pause(tui)?;
            Ok(format!("listed {}", path))
        }
        Err(e) => Ok(format!("error: {}", e)),
    }
}

fn action_extract(tui: &mut Tui) -> io::Result<String> {
    let path = prompt_line(tui, "archive path: ")?;
    if path.is_empty() {
        return Ok("cancelled".into());
    }
    let dest = prompt_line_default(tui, "output dir [./out]: ", "./out")?;
    let pw = prompt_line(tui, "password (empty = none): ")?;
    match ops::extract(
        PathBuf::from(&path).as_path(),
        PathBuf::from(&dest).as_path(),
        if pw.is_empty() { None } else { Some(pw.as_bytes()) },
    ) {
        Ok(report) => {
            let msg = format!(
                "extracted {} files to {} ({} errors)",
                report.files,
                dest,
                report.errors.len()
            );
            tui.print(&format!("\r\n{}\r\n", msg));
            for e in report.errors.iter().take(5) {
                tui.print(&format!("  {}\r\n", e));
            }
            pause(tui)?;
            Ok(msg)
        }
        Err(e) => Ok(format!("error: {}", e)),
    }
}

fn action_compress(tui: &mut Tui) -> io::Result<String> {
    let inputs = prompt_line(tui, "files/dirs (space separated): ")?;
    if inputs.is_empty() {
        return Ok("cancelled".into());
    }
    let out = prompt_line_default(tui, "output zip [out.zip]: ", "out.zip")?;
    let pw = prompt_line(tui, "password (empty = none): ")?;
    let level: u32 =
        prompt_line_default(tui, "deflate level 0-9 [6]: ", "6")?.parse().unwrap_or(6);
    let files: Vec<PathBuf> = inputs.split_whitespace().map(PathBuf::from).collect();
    match ops::compress(&files, PathBuf::from(&out).as_path(), if pw.is_empty() { None } else { Some(pw.as_bytes()) }, level) {
        Ok(report) => {
            let msg = format!("added {} files, {} -> {}", report.files, human(report.bytes), out);
            tui.print(&format!("\r\n{}\r\n", msg));
            pause(tui)?;
            Ok(msg)
        }
        Err(e) => Ok(format!("error: {}", e)),
    }
}

fn action_crack(tui: &mut Tui) -> io::Result<String> {
    let path = prompt_line(tui, "archive path: ")?;
    if path.is_empty() {
        return Ok("cancelled".into());
    }
    let p = PathBuf::from(&path);
    if !p.exists() {
        return Ok(format!("error: file not found: {}", path));
    }

    // non-ZIP → native 7z dictionary attack
    if rosezip_core::archive::detect_format(&p)? != rosezip_core::archive::Format::Zip {
        let dict = prompt_line(tui, "dictionary path (required for 7z): ")?;
        if dict.is_empty() {
            return Ok("7z format needs a dictionary".into());
        }
        return crack_via_7z_tui(tui, &p, &dict);
    }

    let plan = match ops::prepare_crack(&p) {
        Ok(plan) => plan,
        Err(e) => return Ok(format!("error: {}", e)),
    };
    tui.print(&format!(
        "\r\ntarget entry `{}` — {}\r\n\r\n", plan.entry_name, plan.kind
    ));
    tui.print("1) dictionary  2) brute force\r\n");
    let mode = prompt_line_default(tui, "mode [2]: ", "2")?;
    let mode = if mode.is_empty() { "2".to_string() } else { mode };

    let threads = crack::num_cpus();

    if mode == "1" {
        let dict = prompt_line(tui, "dictionary path: ")?;
        if dict.is_empty() {
            return Ok("cancelled".into());
        }
        let target = CrackTarget::Dictionary { path: PathBuf::from(dict) };
        run_job_ui(tui, target, plan.verifier.clone(), threads)
    } else {
        let cs = prompt_line_default(tui, "charset (lower/digits/…, or lower+digits) [lower]: ", "lower")?;
        let cs = if cs.is_empty() { "lower".to_string() } else { cs };
        let min_len: usize =
            prompt_line_default(tui, "min length [1]: ", "1")?.parse().unwrap_or(1);
        let max_len: usize =
            prompt_line_default(tui, "max length [6]: ", "6")?.parse().unwrap_or(6);
        let gen = match ops::make_gen(&cs, min_len, max_len) {
            Ok(g) => g,
            Err(e) => return Ok(format!("error: {}", e)),
        };
        tui.print(&format!(
            "space: {}\r\n",
            human_count(gen.total)
        ));
        let target = CrackTarget::Brute { gen };
        run_job_ui(tui, target, plan.verifier.clone(), threads)
    }
}

fn run_job_ui(
    tui: &mut Tui,
    target: CrackTarget,
    verifier: Arc<rosezip_core::zipcrypt::Verifier>,
    threads: usize,
) -> io::Result<String> {
    let handle = crack::spawn_job(target, verifier, threads);
    let start = Instant::now();
    loop {
        let st = handle.status();
        let pct = st.total.map(|t| st.done as f64 * 100.0 / t.max(1) as f64);
        let line = match (pct, &st.found) {
            (Some(p), _) => format!(
                "\r{:>6.2}%  {:>12} tried  {:>8}/s  {:>6.1}s  ",
                p,
                human_count(st.done),
                human_count(st.rate_per_sec as u64),
                st.elapsed_secs
            ),
            (None, _) => format!(
                "\r{:>12} tried  {:>8}/s  {:>6.1}s  ",
                human_count(st.done),
                human_count(st.rate_per_sec as u64),
                st.elapsed_secs
            ),
        };
        tui.print(&line);
        if st.finished {
            tui.print("\r\n");
            let elapsed = start.elapsed().as_secs_f64();
            let res = handle.join();
            let msg = match res.password {
                Some(pw) => format!("✓ FOUND password: \"{}\"", String::from_utf8_lossy(&pw)),
                None => format!("not found ({} tried in {:.1}s)", res.tried, elapsed),
            };
            tui.print(&format!("\x1b[1;32m{}\x1b[0m\r\n", msg));
            pause(tui)?;
            return Ok(msg);
        }
        std::thread::sleep(Duration::from_millis(100));
    }
}

fn crack_via_7z_tui(tui: &mut Tui, path: &PathBuf, dict: &str) -> io::Result<String> {
    let words = fs::read_to_string(dict)?;
    let start = Instant::now();
    let mut tried: u64 = 0;
    for line in words.lines() {
        let pw = line.trim_end_matches('\r');
        tried += 1;
        if tried % 10 == 0 {
            tui.print(&format!(
                "\r{:>8} tried  {:>5.1}s  ",
                tried,
                start.elapsed().as_secs_f64()
            ));
        }
        if rosezip_core::archive::sevenz_test_password(path, pw.as_bytes())? {
            let msg = format!("✓ FOUND password: \"{}\"", pw);
            tui.print(&format!("\r\n\x1b[1;32m{}\x1b[0m\r\n", msg));
            pause(tui)?;
            return Ok(msg);
        }
    }
    let msg = format!("not found ({} tried)", tried);
    tui.print(&format!("\r\n{}\r\n", msg));
    pause(tui)?;
    Ok(msg)
}

fn action_bench(tui: &mut Tui) -> io::Result<String> {
    tui.print("\r\nbenchmarking...\r\n");
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
        rosezip_core::zipcrypt::Verifier::prepare(&entry, &vec![0u8; 32], None, Some(0x98b))
            .ok_or_else(|| ops::bad("bench setup failed"))?,
    );
    let threads = crack::num_cpus();
    let per = 4_000_000u64;
    let start = Instant::now();
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
    let msg = format!(
        "ZipCrypto: {:.2}M/s on {} threads ({:.2}M/s per thread)",
        rate / 1e6,
        threads,
        rate / 1e6 / threads as f64
    );
    tui.print(&format!("{}\r\n", msg));
    pause(tui)?;
    Ok(msg)
}

// ---------------------------------------------------------------------------
// formatting
// ---------------------------------------------------------------------------

fn human(n: u64) -> String {
    const U: [&str; 6] = ["B", "K", "MB", "GB", "TB", "PB"];
    let mut n = n as f64;
    let mut i = 0;
    while n >= 1024.0 && i < U.len() - 1 {
        n /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{}{}", n as u64, U[0])
    } else {
        format!("{:.1}{}", n, U[i])
    }
}

fn human_count(n: u64) -> String {
    if n >= 1_000_000_000 {
        format!("{:.2}G", n as f64 / 1e9)
    } else if n >= 1_000_000 {
        format!("{:.2}M", n as f64 / 1e6)
    } else if n >= 1_000 {
        format!("{:.1}K", n as f64 / 1e3)
    } else {
        format!("{}", n)
    }
}
