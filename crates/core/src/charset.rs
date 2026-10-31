//! Charset / candidate-word utilities shared by the brute-forcer.

use std::fmt;

pub const LOWER: &str = "abcdefghijklmnopqrstuvwxyz";
pub const UPPER: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
pub const DIGITS: &str = "0123456789";
pub const SYMBOLS: &str = "!@#$%^&*()-_=+[]{};:,.<>?/|~";

/// Named charset shortcuts usable from the CLI (`-c lower+digits`).
pub fn charset_by_name(name: &str) -> Option<&'static str> {
    match name.to_ascii_lowercase().as_str() {
        "lower" => Some(LOWER),
        "upper" => Some(UPPER),
        "digits" | "num" | "numbers" => Some(DIGITS),
        "symbols" => Some(SYMBOLS),
        "letters" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"),
        "alnum" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"),
        "all" => Some("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{};:,.<>?/|~"),
        _ => None,
    }
}

/// Resolve a spec like `lower+digits` or a literal set `abc123`.
pub fn resolve_charset(spec: &str) -> Result<Vec<u8>, String> {
    if spec.contains('+') {
        let mut set = Vec::new();
        for part in spec.split('+') {
            let s = charset_by_name(part)
                .ok_or_else(|| format!("unknown charset name: `{}`", part))?;
            for &b in s.as_bytes() {
                if !set.contains(&b) {
                    set.push(b);
                }
            }
        }
        Ok(set)
    } else if let Some(s) = charset_by_name(spec) {
        Ok(s.as_bytes().to_vec())
    } else {
        let set = spec.as_bytes().to_vec();
        if set.is_empty() {
            return Err("charset must not be empty".into());
        }
        Ok(set)
    }
}

/// One candidate password currently being tried.
#[derive(Clone)]
pub struct Candidate {
    pub bytes: [u8; 32],
    pub len: u8,
}

impl Candidate {
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..self.len as usize]
    }
}

impl fmt::Display for Candidate {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", String::from_utf8_lossy(self.as_slice()))
    }
}

/// Incremental index-based generator: treat each password as a number
/// in base `charset.len()` with variable digit count (little-endian digits).
#[derive(Clone)]
pub struct IndexGen {
    pub charset: Vec<u8>,
    /// inclusive lower bound for password length
    pub min_len: usize,
    /// inclusive upper bound for password length
    pub max_len: usize,
    /// total candidates = sum charset.len()^len for len in [min, max]
    pub total: u64,
}

impl IndexGen {
    pub fn new(charset: Vec<u8>, min_len: usize, max_len: usize) -> Result<Self, String> {
        let base = charset.len() as u64;
        let mut total: u64 = 0;
        for len in min_len..=max_len {
            let n = base.checked_pow(len as u32).and_then(|p| total.checked_add(p));
            match n {
                Some(v) => total = v,
                None => return Err("search space too large for u64 indexing".into()),
            }
        }
        if total == 0 {
            return Err("empty search space".into());
        }
        Ok(Self { charset, min_len, max_len, total })
    }

    /// Map an integer in [0, total) to its password bytes.
    pub fn password_at(&self, mut idx: u64) -> Candidate {
        for len in self.min_len..=self.max_len {
            let size = (self.charset.len() as u64).pow(len as u32);
            if idx < size {
                let mut buf = [0u8; 32];
                for i in (0..len).rev() {
                    buf[i] = self.charset[(idx % self.charset.len() as u64) as usize];
                    idx /= self.charset.len() as u64;
                }
                return Candidate { bytes: buf, len: len as u8 };
            }
            idx -= size;
        }
        unreachable!("index out of range")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gen_order() {
        let g = IndexGen::new(b"ab".to_vec(), 1, 2).unwrap();
        assert_eq!(g.total, 6);
        assert_eq!(g.password_at(0).as_slice(), b"a");
        assert_eq!(g.password_at(1).as_slice(), b"b");
        assert_eq!(g.password_at(2).as_slice(), b"aa");
    }

    #[test]
    fn resolve() {
        assert_eq!(resolve_charset("lower+digits").unwrap().len(), 36);
        assert_eq!(resolve_charset("abc").unwrap(), b"abc".to_vec());
    }

    #[test]
    fn resolve_unknown_name_errors() {
        // `nope` is a legal literal charset (chars n-o-p-e); only '+'-composed
        // unknown names are rejected.
        assert!(resolve_charset("lower+nope").is_err());
        assert!(resolve_charset("").is_err());
        // duplicate chars in combined sets collapse
        assert_eq!(resolve_charset("digits+digits").unwrap(), b"0123456789".to_vec());
        assert_eq!(resolve_charset("digits").unwrap(), b"0123456789".to_vec());
    }

    #[test]
    fn gen_total_and_length_bounds() {
        let g = IndexGen::new(b"ab".to_vec(), 2, 2).unwrap();
        assert_eq!(g.total, 4);
        assert_eq!(g.password_at(3).as_slice(), b"bb");
        // full range 1..=2
        let g = IndexGen::new(b"ab".to_vec(), 1, 2).unwrap();
        assert_eq!(g.password_at(g.total - 1).as_slice(), b"bb");
        // an impossibly large space must error instead of wrapping
        assert!(IndexGen::new(b"ab".to_vec(), 1, 200).is_err());
        assert!(IndexGen::new(vec![], 1, 4).is_err());
    }

    #[test]
    fn candidate_display() {
        let c = IndexGen::new(b"ab".to_vec(), 1, 1).unwrap().password_at(0);
        assert_eq!(c.len, 1);
        assert_eq!(c.as_slice(), b"a");
        assert_eq!(c.to_string(), "a");
    }
}
