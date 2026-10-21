//! RoseZIP CLI.
//!
//! No arguments → interactive TUI. Arguments → direct execution.
//!
//! SPDX-License-Identifier: GPL-3.0-only

mod cmd;
mod tui;

use clap::Parser;

#[derive(Parser)]
#[command(
    name = "rosezip",
    version,
    about = "High-performance archive tool (ZIP/7z) with fast password recovery — no args for TUI"
)]
struct Cli {
    #[command(subcommand)]
    cmd: Option<Cmd>,
}

#[derive(clap::Subcommand)]
enum Cmd {
    /// List archive contents
    List { file: std::path::PathBuf },
    /// Extract an archive
    Extract {
        file: std::path::PathBuf,
        #[arg(short, long)]
        out_dir: Option<std::path::PathBuf>,
        #[arg(short, long)]
        password: Option<String>,
    },
    /// Create a ZIP archive (native ZipCrypto encryption with -p)
    Compress {
        files: Vec<std::path::PathBuf>,
        #[arg(short, long)]
        out: std::path::PathBuf,
        #[arg(short, long)]
        password: Option<String>,
        #[arg(short, long, default_value = "6")]
        level: u32,
    },
    /// Show archive info and encryption type
    Check { file: std::path::PathBuf },
    /// Benchmark password verification speed
    Bench,
    /// Crack a password-protected archive
    Crack {
        file: std::path::PathBuf,
        #[arg(short, long, default_value = "lower")]
        charset: String,
        #[arg(short = 'n', long, default_value = "1")]
        min_len: usize,
        #[arg(short = 'x', long, default_value = "6")]
        max_len: usize,
        #[arg(short, long)]
        dictionary: Option<std::path::PathBuf>,
        #[arg(short = 'P', long, default_value_t = rosezip_core::crack::num_cpus())]
        threads: usize,
        #[arg(short, long)]
        quiet: bool,
    },
    /// Test archive integrity (decode everything, verify checksums)
    Test {
        file: std::path::PathBuf,
        #[arg(short, long)]
        password: Option<String>,
    },
}

fn main() {
    let cli = Cli::parse();
    match cli.cmd {
        None => {
            if let Err(e) = tui::run() {
                eprintln!("tui error: {}", e);
                std::process::exit(1);
            }
        }
        Some(cmd) => {
            let start = std::time::Instant::now();
            match cmd::dispatch(cmd) {
                Ok(msg) => {
                    if !msg.is_empty() {
                        println!("{}", msg);
                    }
                    println!("(took {:.2}s)", start.elapsed().as_secs_f64());
                }
                Err(e) => {
                    eprintln!("error: {}", e);
                    std::process::exit(1);
                }
            }
        }
    }
}
