//! Terminal progress display for long-running cracking jobs.
//! Single-line refresh, no external deps, flushes are cheap.

use std::io::{self, Write};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

pub struct Progress {
    pub total: Option<u64>,
    pub done: AtomicU64,
    pub found: AtomicBool,
    running: AtomicBool,
    pub start: Instant,
}

impl Progress {
    pub fn new(total: Option<u64>) -> Arc<Self> {
        Arc::new(Self {
            total,
            done: AtomicU64::new(0),
            found: AtomicBool::new(false),
            running: AtomicBool::new(true),
            start: Instant::now(),
        })
    }

    pub fn stop(&self) {
        self.running.store(false, Ordering::Relaxed);
    }
}

/// Spawn a thread that repaints a single progress line roughly 5x/second.
pub fn spawn_printer(progress: Arc<Progress>, what: &'static str) -> std::thread::JoinHandle<()> {
    std::thread::spawn(move || {
        let mut out = io::stdout();
        let mut last_len = 0usize;
        while progress.running.load(Ordering::Relaxed) {
            let done = progress.done.load(Ordering::Relaxed);
            let elapsed = progress.start.elapsed().as_secs_f64();
            let rate = if elapsed > 0.0 { done as f64 / elapsed } else { 0.0 };
            let line = match progress.total {
                Some(total) => format!(
                    "\r{} {}/{} ({:.1}%)  {}/s  elapsed {}",
                    what,
                    done,
                    total,
                    done as f64 * 100.0 / total as f64,
                    human_rate(rate),
                    fmt_elapsed(elapsed)
                ),
                None => format!(
                    "\r{} {} tried  {}/s  elapsed {}",
                    what,
                    done,
                    human_rate(rate),
                    fmt_elapsed(elapsed)
                ),
            };
            let _ = write!(out, "{}", line);
            let _ = out.flush();
            // Pad over leftovers from a previously longer line.
            let pad = line.len().saturating_sub(last_len);
            let _ = write!(out, "{}", " ".repeat(pad));
            last_len = line.len();
            std::thread::sleep(Duration::from_millis(200));
        }
        let _ = writeln!(out);
        let _ = out.flush();
    })
}

fn human_rate(rate: f64) -> String {
    if rate >= 1_000_000.0 {
        format!("{:.2}M", rate / 1_000_000.0)
    } else if rate >= 1_000.0 {
        format!("{:.1}K", rate / 1_000.0)
    } else {
        format!("{:.0}", rate)
    }
}

fn fmt_elapsed(secs: f64) -> String {
    let s = secs as u64;
    if s >= 3600 {
        format!("{}:{:02}:{:02}", s / 3600, (s % 3600) / 60, s % 60)
    } else if s >= 60 {
        format!("{}:{:02}", s / 60, s % 60)
    } else {
        format!("{}s", s)
    }
}
