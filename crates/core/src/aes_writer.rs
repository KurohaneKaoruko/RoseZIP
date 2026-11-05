//! WinZip AES encryption write path (AE-1 / AE-2).
//!
//! Symmetric to the reader in [`crate::zipcrypt`] and `ops::decrypt_winzip_aes`:
//! PBKDF2-HMAC-SHA1 derives `aes_key || hmac_key || pw_verify`, the payload is
//! encrypted with AES-CTR (little-endian counter starting at 1), and an
//! HMAC-SHA1 over the ciphertext (first 10 bytes) is appended.
//!
//! SPDX-License-Identifier: GPL-3.0-only

use crate::zipcrypt::{aes_iterations, hmac_sha1, pbkdf2_hmac_sha1_multi, Aes, AesCtr, AesStrength};

/// WinZip AES vendor version numbers (extra field 0x9901).
pub const AE_VERSION_1: u16 = 1; // AE-1: authenticates the CRC
pub const AE_VERSION_2: u16 = 2; // AE-2: CRC field must be written as 0

/// Derived key material for one entry.
pub struct AesKeys {
    pub aes_key: Vec<u8>,
    pub hmac_key: Vec<u8>,
    pub pw_verify: [u8; 2],
}

/// Derive the per-entry key material: `PBKDF2-HMAC-SHA1(pw, salt) =
/// aes_key || hmac_key || pw_verify`.
pub fn derive_keys(password: &[u8], salt: &[u8], strength: AesStrength) -> AesKeys {
    let key_len = strength.key_len();
    let mut dk = vec![0u8; key_len * 2 + 2];
    pbkdf2_hmac_sha1_multi(password, salt, aes_iterations(strength), &mut dk);
    let mut pw_verify = [0u8; 2];
    pw_verify.copy_from_slice(&dk[key_len * 2..]);
    AesKeys {
        aes_key: dk[..key_len].to_vec(),
        hmac_key: dk[key_len..key_len * 2].to_vec(),
        pw_verify,
    }
}

/// One-shot encryption of a payload: CTR encrypt, then HMAC over the
/// ciphertext, truncated to the 10-byte authentication code.
///
/// `salt` and `keys` are produced per entry by the caller (fresh salt per
/// entry, exactly like 7-Zip/pyzipper/WinZip).
pub fn encrypt_payload(keys: &AesKeys, payload: &mut Vec<u8>) -> [u8; 10] {
    // WinZip AES-CTR: counter block starts at 1; pyzipper and 7-Zip use the
    // little-endian increment, which our reader accepts (tried first).
    let mut iv = [0u8; 16];
    iv[0] = 1;
    let mut ctr = AesCtr::new_little_endian(Aes::new(&keys.aes_key), iv);
    ctr.apply(payload);
    let mac = hmac_sha1(&keys.hmac_key, payload);
    let mut tag = [0u8; 10];
    tag.copy_from_slice(&mac[..10]);
    tag
}

/// Build the 0x9901 extra field: header id + size + version + "AE" +
/// strength id + inner compression method (all LE, 7 bytes of body).
pub fn extra_field(version: u16, strength: AesStrength, inner_method: u16) -> Vec<u8> {
    let strength_id = match strength {
        AesStrength::Aes128 => 1u8,
        AesStrength::Aes192 => 2u8,
        AesStrength::Aes256 => 3u8,
    };
    let mut out = Vec::with_capacity(11);
    out.extend_from_slice(&0x9901u16.to_le_bytes());
    out.extend_from_slice(&7u16.to_le_bytes());
    out.extend_from_slice(&version.to_le_bytes());
    out.extend_from_slice(b"AE");
    out.push(strength_id);
    out.extend_from_slice(&inner_method.to_le_bytes());
    out
}

/// Random salt / salt length per strength (8/12/16 bytes for 128/192/256).
pub fn salt_len(strength: AesStrength) -> usize {
    strength.salt_len()
}

/// Fill `buf` with OS random bytes. Falls back to a time-seeded pool when
/// `/dev/urandom` is unavailable (all real targets have it).
pub fn random_bytes(buf: &mut [u8]) {
    use std::io::Read;
    if let Ok(mut f) = std::fs::File::open("/dev/urandom") {
        if f.read_exact(buf).is_ok() {
            return;
        }
    }
    // Fallback: splitmix over a time-seeded state. Not cryptographically
    // ideal, but strictly better than a fixed salt and always available.
    let mut state = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as u64)
        .unwrap_or(0x9E3779B97F4A7C15)
        | 1;
    for b in buf.iter_mut() {
        state = state.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = state;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z ^= z >> 31;
        *b = z as u8;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn extra_field_layout() {
        // 01 99 07 00 02 00 41 45 03 08 00 — exactly what 7-Zip writes for
        // AE-2 + AES-256 + deflate inner (observed interop fixture).
        let f = extra_field(AE_VERSION_2, AesStrength::Aes256, 8);
        assert_eq!(f.len(), 11);
        assert_eq!(f[0], 0x01);
        assert_eq!(f[1], 0x99);
        assert_eq!(&f[2..4], &7u16.to_le_bytes());
        assert_eq!(&f[4..6], &AE_VERSION_2.to_le_bytes());
        assert_eq!(&f[6..8], b"AE");
        assert_eq!(f[8], 3);
        assert_eq!(&f[9..11], &8u16.to_le_bytes());
        let hex: String = f.iter().map(|b| format!("{:02x}", b)).collect();
        assert_eq!(hex, "0199070002004145030800");

        // AE-1 + AES-128 + Store
        let f = extra_field(AE_VERSION_1, AesStrength::Aes128, 0);
        assert_eq!(&f[4..6], &AE_VERSION_1.to_le_bytes());
        assert_eq!(f[8], 1);
        assert_eq!(&f[9..11], &0u16.to_le_bytes());
    }

    #[test]
    fn keys_split_correctly() {
        let salt = [0u8; 16];
        let k = derive_keys(b"pw", &salt, AesStrength::Aes256);
        assert_eq!(k.aes_key.len(), 32);
        assert_eq!(k.hmac_key.len(), 32);
        // pw_verify is the last two derived bytes
        let mut full = vec![0u8; 66];
        crate::zipcrypt::pbkdf2_hmac_sha1_multi(b"pw", &salt, aes_iterations(AesStrength::Aes256), &mut full);
        assert_eq!(&k.aes_key[..], &full[..32]);
        assert_eq!(&k.hmac_key[..], &full[32..64]);
        assert_eq!(k.pw_verify, [full[64], full[65]]);
    }
}
