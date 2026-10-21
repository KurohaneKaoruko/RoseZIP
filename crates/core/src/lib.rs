//! RoseZIP engine: fully native archive handling (ZIP/7z/tar/gz/xz/bz2) and
//! multi-threaded password recovery. No external binaries required.
//!
//! SPDX-License-Identifier: GPL-3.0-only

pub mod archive;
pub mod charset;
pub mod crack;
pub mod ops;
pub mod progress;
pub mod zipcrypt;

pub use crack::{spawn_job, CrackHandle, CrackOptions, CrackResult, CrackStatus, CrackTarget};
