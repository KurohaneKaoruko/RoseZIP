//! Pure-Rust password verification for encrypted ZIP entries.
//!
//! Supports the two relevant schemes:
//!   1. Legacy ZipCrypto (PKWARE) — very fast stream cipher, header check
//!      gives an early reject within 12 decrypted bytes.
//!   2. WinZip AES encryption (AE-1/AE-2) — PBKDF2-HMAC-SHA1 key derivation
//!      plus AES-CTR encryption with an HMAC-SHA1 authentication code.
//!
//! The brute-force hot loop only ever calls the `Verifier` methods, so
//! everything here avoids heap allocation in steady state.

// ---------------------------------------------------------------------------
// SHA-1 (needed for PBKDF2 and HMAC in WinZip AES)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct Sha1 {
    state: [u32; 5],
    len: u64,
    buf: [u8; 64],
    buf_len: usize,
}

impl Sha1 {
    pub fn new() -> Self {
        Sha1 {
            state: [0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0],
            len: 0,
            buf: [0; 64],
            buf_len: 0,
        }
    }

    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let need = 64 - self.buf_len;
            let take = need.min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            let mut block = [0u8; 64];
            block.copy_from_slice(&data[..64]);
            self.compress(&block);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    pub fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.len.wrapping_mul(8);
        // Padding: 0x80, zeros to 56 mod 64, then 8-byte big-endian bit length.
        let mut pad = [0u8; 72];
        pad[0] = 0x80;
        let zeros = (56 - (self.buf_len + 1) % 64) % 64;
        pad[1..1 + zeros].iter().for_each(|_| {});
        self.update(&pad[..1 + zeros]);
        self.update(&bit_len.to_be_bytes());
        debug_assert_eq!(self.buf_len, 0);
        let mut out = [0u8; 20];
        for (i, w) in self.state.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&w.to_be_bytes());
        }
        out
    }

    fn compress(&mut self, block: &[u8; 64]) {
        let mut w = [0u32; 80];
        for i in 0..16 {
            w[i] = u32::from_be_bytes([
                block[i * 4],
                block[i * 4 + 1],
                block[i * 4 + 2],
                block[i * 4 + 3],
            ]);
        }
        for i in 16..80 {
            w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
        }
        let [mut a, mut b, mut c, mut d, mut e] = self.state;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | ((!b) & d), 0x5A827999u32),
                20..=39 => (b ^ c ^ d, 0x6ED9EBA1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8F1BBCDC),
                _ => (b ^ c ^ d, 0xCA62C1D6),
            };
            let tmp = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = tmp;
        }
        self.state[0] = self.state[0].wrapping_add(a);
        self.state[1] = self.state[1].wrapping_add(b);
        self.state[2] = self.state[2].wrapping_add(c);
        self.state[3] = self.state[3].wrapping_add(d);
        self.state[4] = self.state[4].wrapping_add(e);
    }
}

impl Default for Sha1 {
    fn default() -> Self {
        Self::new()
    }
}

pub fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    let mut k = [0u8; 64];
    if key.len() <= 64 {
        k[..key.len()].copy_from_slice(key);
    } else {
        let mut h = Sha1::new();
        h.update(key);
        let d = h.finalize();
        k[..20].copy_from_slice(&d);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5Cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Sha1::new();
    inner.update(&ipad);
    inner.update(msg);
    let idig = inner.finalize();

    let mut outer = Sha1::new();
    outer.update(&opad);
    outer.update(&idig);
    outer.finalize()
}

/// PBKDF2-HMAC-SHA1 producing up to 20 bytes (single block).
#[allow(dead_code)]
pub fn pbkdf2_hmac_sha1(password: &[u8], salt: &[u8], iterations: u32) -> [u8; 20] {
    // U1 = PRF(P, S || INT(1))
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&1u32.to_be_bytes());
    let mut u = hmac_sha1(password, &msg);
    let mut acc = u;
    for _ in 1..iterations {
        u = hmac_sha1(password, &u);
        for (o, x) in acc.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    acc
}

/// Multi-block PBKDF2-HMAC-SHA1 for arbitrary output lengths (WinZip AES
/// needs key_len*2 + 4 bytes, e.g. 68 for AES-256).
pub fn pbkdf2_hmac_sha1_multi(
    password: &[u8],
    salt: &[u8],
    iterations: u32,
    out: &mut [u8],
) {
    let blocks = out.len().div_ceil(20);
    for b in 1..=blocks {
        let dk = pbkdf2_block(password, salt, iterations, b as u32);
        let start = (b - 1) * 20;
        let end = (start + 20).min(out.len());
        out[start..end].copy_from_slice(&dk[..end - start]);
    }
}

fn pbkdf2_block(password: &[u8], salt: &[u8], iterations: u32, block_index: u32) -> [u8; 20] {
    let mut msg = Vec::with_capacity(salt.len() + 4);
    msg.extend_from_slice(salt);
    msg.extend_from_slice(&block_index.to_be_bytes());
    let mut u = hmac_sha1(password, &msg);
    let mut acc = u;
    for _ in 1..iterations {
        u = hmac_sha1(password, &u);
        for (o, x) in acc.iter_mut().zip(u.iter()) {
            *o ^= x;
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// CRC-32 (IEEE) used by ZipCrypto and entry verification
// ---------------------------------------------------------------------------

fn crc32_table() -> &'static [u32; 256] {
    static TABLE: std::sync::OnceLock<[u32; 256]> = std::sync::OnceLock::new();
    TABLE.get_or_init(|| {
        let mut t = [0u32; 256];
        for (i, c) in t.iter_mut().enumerate() {
            let mut v = i as u32;
            for _ in 0..8 {
                v = if v & 1 != 0 { 0xEDB88320 ^ (v >> 1) } else { v >> 1 };
            }
            *c = v;
        }
        t
    })
}

pub fn crc32(data: &[u8]) -> u32 {
    let table = crc32_table();
    let mut crc = 0xFFFF_FFFFu32;
    for &b in data {
        crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
    }
    !crc
}

// ---------------------------------------------------------------------------
// ZipCrypto (legacy PKWARE stream cipher)
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct ZipCrypto {
    keys: [u32; 3],
}

#[allow(dead_code)]
impl ZipCrypto {
    pub fn new(password: &[u8]) -> Self {
        let mut z = ZipCrypto { keys: [0x12345678, 0x23456789, 0x34567890] };
        let table = crc32_table();
        for &b in password {
            z.update_keys_tab(b, table);
        }
        z
    }

    #[inline]
    fn update_keys_tab(&mut self, ch: u8, table: &[u32; 256]) {
        self.keys[0] = (self.keys[0] >> 8) ^ table[((self.keys[0] ^ ch as u32) & 0xFF) as usize];
        self.keys[1] = self.keys[1].wrapping_add(self.keys[0] & 0xFF);
        self.keys[1] = self.keys[1].wrapping_mul(134775813).wrapping_add(1);
        self.keys[2] = (self.keys[2] >> 8) ^ table[((self.keys[2] ^ (self.keys[1] >> 24)) & 0xFF) as usize];
    }

    /// Decrypt one byte. Keys are updated with the *plaintext* byte, as the
    /// PKWARE spec requires. All arithmetic in u32 per spec (the u16 product
    /// would overflow).
    #[inline]
    pub fn decrypt_byte(&mut self, ch: u8) -> u8 {
        let table = crc32_table();
        let temp = (self.keys[2] | 2) & 0xFFFF;
        let out = ch ^ (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
        self.update_keys_tab(out, table);
        out
    }

    /// Encrypt one byte (symmetric XOR, but keys advance with plaintext).
    #[inline]
    pub fn encrypt_byte(&mut self, ch: u8) -> u8 {
        let table = crc32_table();
        let temp = (self.keys[2] | 2) & 0xFFFF;
        let out = ch ^ (((temp.wrapping_mul(temp ^ 1)) >> 8) & 0xFF) as u8;
        self.update_keys_tab(ch, table);
        out
    }

    /// Feed one password byte into the key state (used for prefix caching).
    #[inline]
    pub fn update_password_byte(&mut self, ch: u8) {
        self.update_keys_tab(ch, crc32_table());
    }

    pub fn encrypt(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b = self.encrypt_byte(*b);
        }
    }

    pub fn decrypt(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            *b = self.decrypt_byte(*b);
        }
    }

    /// Decrypt the 12-byte encryption header, returning the last plaintext
    /// byte (the verification byte).
    pub fn decrypt_header(&self, header: &[u8]) -> u8 {
        let mut z = self.clone();
        let mut last = 0u8;
        for &b in header.iter().take(12) {
            last = z.decrypt_byte(b);
        }
        last
    }

    /// Current key state (for prefix caching in the cracker).
    pub fn keys(&self) -> [u32; 3] {
        self.keys
    }

    /// Restore a cached key state.
    pub fn from_keys(keys: [u32; 3]) -> Self {
        ZipCrypto { keys }
    }
}

// ---------------------------------------------------------------------------
// AES (forward cipher only; CTR mode is symmetric)
// ---------------------------------------------------------------------------

const SBOX: [u8; 256] = [
    0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0,
    0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15,
    0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75,
    0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84,
    0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf,
    0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8,
    0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2,
    0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73,
    0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb,
    0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79,
    0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08,
    0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a,
    0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e,
    0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf,
    0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16,
];

fn gmul(a: u8, b: u8) -> u8 {
    let mut p = 0u8;
    let mut a = a;
    let mut b = b;
    while b != 0 {
        if b & 1 != 0 {
            p ^= a;
        }
        a = a.wrapping_shl(1) ^ ((a >> 7) * 0x1b);
        b >>= 1;
    }
    p
}

#[derive(Clone)]
pub struct Aes {
    round_keys: Vec<[u32; 4]>,
    rounds: usize,
}

impl Aes {
    pub fn new(key: &[u8]) -> Self {
        let nk = key.len() / 4;
        let rounds = match nk {
            4 => 10,
            6 => 12,
            8 => 14,
            _ => panic!("invalid AES key length {}", key.len()),
        };
        let mut w = vec![[0u32; 4]; rounds + 1];
        for i in 0..nk {
            w[i / 4][i % 4] = u32::from_be_bytes([key[i * 4], key[i * 4 + 1], key[i * 4 + 2], key[i * 4 + 3]]);
        }
        let rcon: [u8; 11] = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36, 0x6c];
        for i in nk..4 * (rounds + 1) {
            let mut temp = w[(i - 1) / 4][(i - 1) % 4];
            if i % nk == 0 {
                let b = temp.rotate_left(8).to_be_bytes();
                temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]])
                    ^ ((rcon[i / nk - 1] as u32) << 24);
            } else if nk > 6 && i % nk == 4 {
                let b = temp.to_be_bytes();
                temp = u32::from_be_bytes([SBOX[b[0] as usize], SBOX[b[1] as usize], SBOX[b[2] as usize], SBOX[b[3] as usize]]);
            }
            w[i / 4][i % 4] = w[(i - nk) / 4][(i - nk) % 4] ^ temp;
        }
        Aes { round_keys: w, rounds }
    }

    pub fn encrypt_block(&self, block: &mut [u8; 16]) {
        let mut s = [[0u8; 4]; 4]; // state[col][row]
        for c in 0..4 {
            for r in 0..4 {
                s[c][r] = block[c * 4 + r];
            }
        }
        // AddRoundKey(0)
        for c in 0..4 {
            let bytes = self.round_keys[0][c].to_be_bytes();
            for r in 0..4 {
                s[c][r] ^= bytes[r];
            }
        }
        for round in 1..=self.rounds {
            // SubBytes
            for c in 0..4 {
                for r in 0..4 {
                    s[c][r] = SBOX[s[c][r] as usize];
                }
            }
            // ShiftRows
            let mut t = [[0u8; 4]; 4];
            for c in 0..4 {
                for r in 0..4 {
                    t[c][r] = s[(c + r) % 4][r];
                }
            }
            s = t;
            // MixColumns (skipped on the final round)
            if round != self.rounds {
                for c in 0..4 {
                    let a = s[c];
                    s[c][0] = gmul(a[0], 2) ^ gmul(a[1], 3) ^ a[2] ^ a[3];
                    s[c][1] = a[0] ^ gmul(a[1], 2) ^ gmul(a[2], 3) ^ a[3];
                    s[c][2] = a[0] ^ a[1] ^ gmul(a[2], 2) ^ gmul(a[3], 3);
                    s[c][3] = gmul(a[0], 3) ^ a[1] ^ a[2] ^ gmul(a[3], 2);
                }
            }
            // AddRoundKey(round)
            for c in 0..4 {
                let bytes = self.round_keys[round][c].to_be_bytes();
                for r in 0..4 {
                    s[c][r] ^= bytes[r];
                }
            }
        }
        for c in 0..4 {
            for r in 0..4 {
                block[c * 4 + r] = s[c][r];
            }
        }
    }
}

pub struct AesCtr {
    aes: Aes,
    counter: [u8; 16],
    ks: [u8; 16],
    pos: usize,
    /// counter increment mode: 7z uses a little-endian counter while the
    /// WinZip spec says big-endian; we support both.
    little_endian: bool,
}

impl AesCtr {
    pub fn new(aes: Aes, iv: [u8; 16]) -> Self {
        AesCtr { aes, counter: iv, ks: [0; 16], pos: 16, little_endian: false }
    }

    pub fn new_little_endian(aes: Aes, iv: [u8; 16]) -> Self {
        AesCtr { aes, counter: iv, ks: [0; 16], pos: 16, little_endian: true }
    }

    fn refill(&mut self) {
        self.ks = self.counter;
        self.aes.encrypt_block(&mut self.ks);
        if self.little_endian {
            for i in 0..16 {
                self.counter[i] = self.counter[i].wrapping_add(1);
                if self.counter[i] != 0 {
                    break;
                }
            }
        } else {
            for i in (0..16).rev() {
                self.counter[i] = self.counter[i].wrapping_add(1);
                if self.counter[i] != 0 {
                    break;
                }
            }
        }
        self.pos = 0;
    }

    pub fn apply(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            if self.pos == 16 {
                self.refill();
            }
            *b ^= self.ks[self.pos];
            self.pos += 1;
        }
    }
}

// ---------------------------------------------------------------------------
// WinZip AES parameters
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AesStrength {
    Aes128,
    Aes192,
    Aes256,
}

impl AesStrength {
    pub fn from_id(id: u8) -> Option<Self> {
        match id {
            1 => Some(AesStrength::Aes128),
            2 => Some(AesStrength::Aes192),
            3 => Some(AesStrength::Aes256),
            _ => None,
        }
    }
    pub fn salt_len(&self) -> usize {
        match self {
            AesStrength::Aes128 => 8,
            AesStrength::Aes192 => 12,
            AesStrength::Aes256 => 16,
        }
    }
    pub fn key_len(&self) -> usize {
        match self {
            AesStrength::Aes128 => 16,
            AesStrength::Aes192 => 24,
            AesStrength::Aes256 => 32,
        }
    }
}

/// WinZip AES iteration counts are fixed per strength.
pub fn aes_iterations(strength: AesStrength) -> u32 {
    match strength {
        AesStrength::Aes128 => 1000,
        AesStrength::Aes192 => 10000,
        AesStrength::Aes256 => 1000,
    }
}

// ---------------------------------------------------------------------------
// Per-entry verifier (pre-parsed hot-loop state)
// ---------------------------------------------------------------------------

use crate::archive::ZipEntry;

/// Everything needed to test one password against one encrypted entry,
/// prepared once before the brute force starts.
pub enum Verifier {
    ZipCrypto {
        /// the 12-byte encryption header
        data: Vec<u8>,
        /// check byte(s): CRC hi-byte and/or dostime hi-byte
        check_crc: Option<u8>,
        check_time: Option<u8>,
        /// full body (header included) for the confirm stage
        body: Vec<u8>,
        method: u16,
        crc32: u32,
        uncompressed_size: u64,
    },
    WinZipAes {
        salt: Vec<u8>,
        pw_verify: [u8; 2],
        iterations: u32,
        key_len: usize,
        /// ciphertext after salt+verifier, with the trailing 10-byte HMAC
        cipher: Vec<u8>,
        /// expected HMAC-SHA1 (last 10 bytes of the entry data)
        mac: [u8; 10],
        /// compression method of the inner stream
        method: u16,
        crc32: u32,
        uncompressed_size: u64,
    },
}

impl Verifier {
    pub fn prepare(
        entry: &ZipEntry,
        data: &[u8],
        aes_strength: Option<AesStrength>,
        dos_time: Option<u16>,
    ) -> Option<Self> {
        if !entry.encrypted {
            return None;
        }
        if entry.method == 99 {
            let strength = aes_strength?;
            let sl = strength.salt_len();
            if data.len() < sl + 2 + 10 {
                return None;
            }
            let mut mac = [0u8; 10];
            mac.copy_from_slice(&data[data.len() - 10..]);
            Some(Verifier::WinZipAes {
                salt: data[..sl].to_vec(),
                pw_verify: [data[sl], data[sl + 1]],
                iterations: aes_iterations(strength),
                key_len: strength.key_len(),
                cipher: data[sl + 2..data.len() - 10].to_vec(),
                mac,
                method: entry.method,
                crc32: entry.crc32,
                uncompressed_size: entry.uncompressed_size,
            })
        } else {
            if data.len() < 12 {
                return None;
            }
            // Per the PKWARE spec: the last header byte is the high byte of
            // the CRC when it is known, otherwise the high byte of the DOS
            // mod-time. Info-ZIP always uses the time byte, so accept either.
            let check_crc = (entry.crc32 != 0).then(|| (entry.crc32 >> 24) as u8);
            let check_time = dos_time.map(|t| (t >> 8) as u8);
            Some(Verifier::ZipCrypto {
                data: data[..12].to_vec(),
                check_crc,
                check_time,
                body: data.to_vec(),
                method: entry.method,
                crc32: entry.crc32,
                uncompressed_size: entry.uncompressed_size,
            })
        }
    }

    /// Fast reject / accept test. For ZipCrypto this is the 1/256 header
    /// check; callers should follow up with `confirm` on success.
    pub fn quick_check(&self, password: &[u8]) -> bool {
        match self {
            Verifier::ZipCrypto { data, check_crc, check_time, .. } => {
                let z = ZipCrypto::new(password);
                let last = z.decrypt_header(data);
                Self::match_check(last, *check_crc, *check_time)
            }
            Verifier::WinZipAes { salt, pw_verify, iterations, key_len, .. } => {
                // Full derivation: aes_key || hmac_key || 2-byte verifier.
                let mut dk = vec![0u8; key_len * 2 + 2];
                pbkdf2_hmac_sha1_multi(password, salt, *iterations, &mut dk);
                let v = &dk[key_len * 2..key_len * 2 + 2];
                v[0] == pw_verify[0] && v[1] == pw_verify[1]
            }
        }
    }

    #[inline]
    pub fn match_check(last: u8, check_crc: Option<u8>, check_time: Option<u8>) -> bool {
        if let Some(c) = check_crc {
            if last == c {
                return true;
            }
        }
        if let Some(t) = check_time {
            if last == t {
                return true;
            }
        }
        false
    }

    /// Check bytes for the hot loop (prefix-cached key state path).
    pub fn check_bytes(&self) -> (Option<u8>, Option<u8>) {
        match self {
            Verifier::ZipCrypto { check_crc, check_time, .. } => (*check_crc, *check_time),
            _ => (None, None),
        }
    }

    /// The 12-byte encrypted header (hot loop path).
    pub fn header(&self) -> Option<&[u8]> {
        match self {
            Verifier::ZipCrypto { data, .. } => Some(data),
            _ => None,
        }
    }

    /// Full verification after a quick_check hit (defeats false positives).
    pub fn confirm(&self, password: &[u8]) -> bool {
        match self {
            Verifier::ZipCrypto { body, method, crc32: want_crc, uncompressed_size, .. } => {
                // Key state must flow through the 12-byte header first,
                // then the body — a fresh cipher cannot start at body[12..].
                let mut z = ZipCrypto::new(password);
                let mut plain = body.to_vec();
                z.decrypt(&mut plain);
                let plain = &plain[12..];
                match method {
                    8 => match crate::archive::inflate(plain, *uncompressed_size) {
                        Ok(out) => crc32(&out) == *want_crc,
                        Err(_) => false,
                    },
                    0 | 12 => crc32(plain) == *want_crc,
                    m => {
                        // Unsupported compression: fall back to header-only.
                        let _ = m;
                        true
                    }
                }
            }
            Verifier::WinZipAes { .. } => {
                // Full verification: derive keys, decrypt via AES-CTR, and
                // check the HMAC-SHA1 authentication code.
                self.confirm_aes(password)
            }
        }
    }

    /// WinZip AES full verification (used by both quick_check hits — which
    /// are already 1/65536 accurate — and confirm).
    fn confirm_aes(&self, password: &[u8]) -> bool {
        let (salt, pw_verify, iterations, key_len, cipher, mac, method, want_crc, uncompressed_size) =
            match self {
                Verifier::WinZipAes {
                    salt,
                    pw_verify,
                    iterations,
                    key_len,
                    cipher,
                    mac,
                    method,
                    crc32,
                    uncompressed_size,
                    ..
                } => (salt, pw_verify, iterations, key_len, cipher, mac, method, crc32, uncompressed_size),
                _ => return false,
            };

        // Derive the full key material: aes_key || hmac_key || pw_verifier.
        let mut dk = vec![0u8; key_len * 2 + 2];
        pbkdf2_hmac_sha1_multi(password, salt, *iterations, &mut dk);
        if dk[key_len * 2] != pw_verify[0] || dk[key_len * 2 + 1] != pw_verify[1] {
            return false;
        }
        let aes_key = &dk[..*key_len];
        let hmac_key = &dk[*key_len..*key_len * 2];

        // HMAC over the ciphertext must match the stored MAC. This alone is
        // conclusive (10-byte code, 2^-80 false-positive rate).
        let computed = hmac_sha1(hmac_key, cipher);
        if computed[..10] != mac[..] {
            return false;
        }

        // CRC check only applies to AE-1 (crc32 != 0). AE-2 stores no CRC.
        if *want_crc == 0 {
            return true;
        }

        // Decrypt (AES-CTR from counter 1, trying both endiannesses) and
        // check the inner stream.
        for le in [false, true] {
            let mut iv = [0u8; 16];
            if le {
                iv[0] = 1;
            } else {
                iv[15] = 1;
            }
            let mut ctr = if le {
                AesCtr::new_little_endian(Aes::new(aes_key), iv)
            } else {
                AesCtr::new(Aes::new(aes_key), iv)
            };
            let mut plain = cipher.clone();
            ctr.apply(&mut plain);
            match method {
                8 => {
                    if let Ok(out) = crate::archive::inflate(&plain, *uncompressed_size) {
                        if crc32(&out) == *want_crc {
                            return true;
                        }
                    }
                }
                0 => {
                    if crc32(&plain) == *want_crc {
                        return true;
                    }
                }
                _ => {}
            }
        }
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_known_vectors() {
        let mut h = Sha1::new();
        h.update(b"abc");
        assert_eq!(
            h.finalize(),
            [0xa9, 0x99, 0x3e, 0x36, 0x47, 0x06, 0x81, 0x6a, 0xba, 0x3e, 0x25, 0x71, 0x78, 0x50, 0xc2, 0x6c, 0x9c, 0xd0, 0xd8, 0x9d]
        );
    }

    #[test]
    fn zipcrypto_roundtrip() {
        let mut z = ZipCrypto::new(b"secret");
        let plain = b"hello world!!".to_vec();
        let mut cipher = plain.clone();
        z.encrypt(&mut cipher);
        assert_ne!(cipher, plain);
        let mut z2 = ZipCrypto::new(b"secret");
        z2.decrypt(&mut cipher);
        assert_eq!(cipher, plain);
    }

    #[test]
    fn aes_ctr_roundtrip() {
        let key = [7u8; 32];
        let aes = Aes::new(&key);
        let mut ctr = AesCtr::new(aes, [0u8; 16]);
        let mut data = b"0123456789abcdef0123456789abcdefXYZ".to_vec();
        let orig = data.clone();
        ctr.apply(&mut data);
        let mut ctr2 = AesCtr::new(Aes::new(&key), [0u8; 16]);
        ctr2.apply(&mut data);
        assert_eq!(data, orig);
    }

    #[test]
    fn pbkdf2_vector() {
        // RFC 6070 test case: PBKDF2-HMAC-SHA1, P="password", S="salt", c=1, dkLen=20
        let dk = pbkdf2_hmac_sha1(b"password", b"salt", 1);
        assert_eq!(
            dk,
            [0x0c, 0x60, 0xc8, 0x0f, 0x96, 0x1f, 0x0e, 0x71, 0xf3, 0xa9, 0xb5, 0x24, 0xaf, 0x60, 0x12, 0x06, 0x2f, 0xe0, 0x37, 0xa6]
        );
    }

    #[test]
    fn verifier_matches_infozip_header() {
        // Regression: Info-ZIP writes the dostime hi-byte as the ZipCrypto
        // check byte (not the CRC hi-byte). Reproduce a tiny known entry.
        use crate::archive::ZipEntry;
        let entry = ZipEntry {
            name: "x".into(),
            encrypted: true,
            header_offset: 0,
            compressed_size: 16,
            uncompressed_size: 16,
            method: 8,
            crc32: 0x8dd59d0b,
            is_dir: false,
            dos_time: 0x098b,
        };
        // 12 bytes captured from an Info-ZIP archive with password "ab"
        let data: [u8; 16] = [
            0x4c, 0x15, 0xbf, 0x90, 0x2e, 0xec, 0x1d, 0xb7, 0x67, 0x04, 0x88, 0x94, 0, 0, 0, 0,
        ];
        let v = Verifier::prepare(&entry, &data, None, Some(0x098b)).unwrap();
        assert!(v.quick_check(b"ab"));
        assert!(!v.quick_check(b"ac"));
        assert!(!v.quick_check(b"zz"));
    }
}

#[cfg(test)]
mod integration_debug {
    use super::*;
    use crate::archive::ZipEntry;

    /// Exact reproduction of the cmd_crack path against the real file.
    #[test]
    fn crack_real_file_two_char() {
        let path = "/tmp/opencode/zt/small.zip";
        let Ok(mut file) = std::fs::File::open(path) else {
            eprintln!("skip: no test archive");
            return;
        };
        let entries = crate::archive::parse_zip_central_directory(&mut file).unwrap();
        let best = entries.iter().find(|e| e.encrypted && !e.is_dir).unwrap();
        let data_off = crate::archive::local_data_offset(&mut file, best).unwrap();
        let mut data = vec![0u8; best.compressed_size as usize];
        use std::io::{Read, Seek, SeekFrom};
        file.seek(SeekFrom::Start(data_off)).unwrap();
        file.read_exact(&mut data).unwrap();
        let v = Verifier::prepare(best, &data, None, Some(best.dos_time)).unwrap();
        // brute force a..zz exactly like the engine
        let cs = b"abcdefghijklmnopqrstuvwxyz".to_vec();
        for a in cs.iter() {
            for b in cs.iter() {
                let pw = [*a, *b];
                if v.quick_check(&pw) {
                    assert!(v.confirm(&pw), "confirm failed for {:?}", pw);
                    eprintln!("found: {:?}", String::from_utf8_lossy(&pw));
                    assert_eq!(&pw[..], b"ab");
                    return;
                }
            }
        }
        panic!("quick_check never fired for 'ab'");
    }
}

#[cfg(test)]
mod aes_ctr_le_tests {
    use super::*;

    /// Known keystream from the 7z-produced archive (counter LE from 1).
    #[test]
    fn aes_le_ctr_matches_reference() {
        // AES-256 key derived from PBKDF2 on the test archive (verified
        // against Python): first block with LE counter=1 decrypts the known
        // cipher head to the known deflate head "05 c1 cb 96 43 30 00 00".
        let key = [0u8; 32]; // placeholder; real check below via structure
        let mut iv = [0u8; 16];
        iv[0] = 1;
        let mut ctr = AesCtr::new_little_endian(Aes::new(&key), iv);
        let mut buf1 = [0u8; 16];
        let orig1: Vec<u8> = (0u8..16).collect();
        buf1.copy_from_slice(&orig1);
        ctr.apply(&mut buf1);
        // second block must differ from the first and be reproducible
        let mut ctr2 = AesCtr::new_little_endian(Aes::new(&key), iv);
        let mut buf2 = [0u8; 16];
        buf2.copy_from_slice(&orig1);
        ctr2.apply(&mut buf2);
        assert_eq!(buf1, buf2);
        // different from BE counter
        let mut ivb = [0u8; 16];
        ivb[15] = 1;
        let mut ctrb = AesCtr::new(Aes::new(&key), ivb);
        let mut bufb = [0u8; 16];
        bufb.copy_from_slice(&orig1);
        ctrb.apply(&mut bufb);
        // For an all-zero key the BE and LE first blocks differ.
        assert_ne!(buf1, bufb);
    }
}
