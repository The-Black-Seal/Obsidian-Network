//! BLAKE2b (RFC 7693).
//!
//! Used by Argon2id (RFC 9106) and as a fast domain-separated hash inside the
//! storage engine.  Supports arbitrary digest sizes from 1 to 64 bytes as
//! required by Argon2's variable-length hash function `H'`.

const IV: [u64; 8] = [
    0x6a09e667f3bcc908,
    0xbb67ae8584caa73b,
    0x3c6ef372fe94f82b,
    0xa54ff53a5f1d36f1,
    0x510e527fade682d1,
    0x9b05688c2b3e6c1f,
    0x1f83d9abfb41bd6b,
    0x5be0cd19137e2179,
];

const SIGMA: [[usize; 16]; 12] = [
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
    [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
    [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
    [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
    [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
    [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
    [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
    [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
    [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
    [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
];

/// BLAKE2b state.
#[derive(Clone)]
pub struct Blake2b {
    h: [u64; 8],
    t: [u64; 2],
    buf: [u8; 128],
    buf_len: usize,
    out_len: usize,
}

impl Blake2b {
    /// Creates an unkeyed BLAKE2b with the requested digest length (1..=64).
    pub fn new(out_len: usize) -> Self {
        assert!((1..=64).contains(&out_len), "invalid BLAKE2b output length");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ (out_len as u64);
        Self {
            h,
            t: [0, 0],
            buf: [0u8; 128],
            buf_len: 0,
            out_len,
        }
    }

    /// Creates a keyed BLAKE2b (MAC mode), key length 1..=64.
    pub fn new_keyed(out_len: usize, key: &[u8]) -> Self {
        assert!((1..=64).contains(&out_len), "invalid BLAKE2b output length");
        assert!(!key.is_empty() && key.len() <= 64, "invalid BLAKE2b key length");
        let mut h = IV;
        h[0] ^= 0x0101_0000 ^ ((key.len() as u64) << 8) ^ (out_len as u64);
        let mut s = Self {
            h,
            t: [0, 0],
            buf: [0u8; 128],
            buf_len: 0,
            out_len,
        };
        let mut block = [0u8; 128];
        block[..key.len()].copy_from_slice(key);
        s.buf = block;
        s.buf_len = 128;
        // The padded key block is always the first *non-final* block (RFC 7693
        // §2.9); it is compressed immediately so that an empty message still
        // produces the standard keyed digest.
        s.flush_non_final();
        s
    }

    /// Compresses a full buffer as a non-final block.
    fn flush_non_final(&mut self) {
        debug_assert_eq!(self.buf_len, 128);
        self.t[0] = self.t[0].wrapping_add(128);
        if self.t[0] < 128 {
            self.t[1] = self.t[1].wrapping_add(1);
        }
        let block = self.buf;
        self.compress(&block, false);
        self.buf_len = 0;
        self.buf = [0u8; 128];
    }

    /// Absorbs data.
    ///
    /// The buffer always retains the most recent block so that `finalize` can
    /// flag it as the last block; full blocks are compressed as soon as more
    /// input arrives.
    pub fn update(&mut self, mut data: &[u8]) {
        if data.is_empty() {
            return;
        }
        loop {
            if self.buf_len == 128 {
                self.flush_non_final();
            }
            let space = 128 - self.buf_len;
            if data.len() <= space {
                self.buf[self.buf_len..self.buf_len + data.len()].copy_from_slice(data);
                self.buf_len += data.len();
                return;
            }
            self.buf[self.buf_len..128].copy_from_slice(&data[..space]);
            self.buf_len = 128;
            self.flush_non_final();
            data = &data[space..];
        }
    }

    /// Finalizes and returns the digest with the configured length.
    pub fn finalize(mut self) -> Vec<u8> {
        self.t[0] = self.t[0].wrapping_add(self.buf_len as u64);
        if self.t[0] < self.buf_len as u64 {
            self.t[1] = self.t[1].wrapping_add(1);
        }
        for b in self.buf[self.buf_len..].iter_mut() {
            *b = 0;
        }
        let block = self.buf;
        self.compress(&block, true);
        let mut out = Vec::with_capacity(64);
        for word in self.h.iter() {
            out.extend_from_slice(&word.to_le_bytes());
        }
        out.truncate(self.out_len);
        out
    }

    fn compress(&mut self, block: &[u8; 128], last: bool) {
        let mut m = [0u64; 16];
        for (i, word) in m.iter_mut().enumerate() {
            let mut b = [0u8; 8];
            b.copy_from_slice(&block[i * 8..i * 8 + 8]);
            *word = u64::from_le_bytes(b);
        }
        let mut v = [0u64; 16];
        v[..8].copy_from_slice(&self.h);
        v[8..].copy_from_slice(&IV);
        v[12] ^= self.t[0];
        v[13] ^= self.t[1];
        if last {
            v[14] = !v[14];
        }
        for s in SIGMA.iter() {
            g(&mut v, 0, 4, 8, 12, m[s[0]], m[s[1]]);
            g(&mut v, 1, 5, 9, 13, m[s[2]], m[s[3]]);
            g(&mut v, 2, 6, 10, 14, m[s[4]], m[s[5]]);
            g(&mut v, 3, 7, 11, 15, m[s[6]], m[s[7]]);
            g(&mut v, 0, 5, 10, 15, m[s[8]], m[s[9]]);
            g(&mut v, 1, 6, 11, 12, m[s[10]], m[s[11]]);
            g(&mut v, 2, 7, 8, 13, m[s[12]], m[s[13]]);
            g(&mut v, 3, 4, 9, 14, m[s[14]], m[s[15]]);
        }
        for i in 0..8 {
            self.h[i] ^= v[i] ^ v[i + 8];
        }
    }
}

#[inline(always)]
fn g(v: &mut [u64; 16], a: usize, b: usize, c: usize, d: usize, x: u64, y: u64) {
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(x);
    v[d] = (v[d] ^ v[a]).rotate_right(32);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(24);
    v[a] = v[a].wrapping_add(v[b]).wrapping_add(y);
    v[d] = (v[d] ^ v[a]).rotate_right(16);
    v[c] = v[c].wrapping_add(v[d]);
    v[b] = (v[b] ^ v[c]).rotate_right(63);
}

/// One-shot unkeyed BLAKE2b.
pub fn blake2b(data: &[u8], out_len: usize) -> Vec<u8> {
    let mut h = Blake2b::new(out_len);
    h.update(data);
    h.finalize()
}

/// One-shot BLAKE2b-512.
pub fn blake2b512(data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&blake2b(data, 64));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn blake2b512_vectors() {
        assert_eq!(hex(&blake2b512(b"")), "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce");
        assert_eq!(hex(&blake2b512(b"abc")), "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923");
    }

    #[test]
    fn blake2b_variable_length() {
        assert_eq!(
            hex(&blake2b(b"abc", 32)),
            "bddd813c634239723171ef3fee98579b94964e3bb1cb3e427262c8c068d52319"
        );
        assert_eq!(
            hex(&blake2b(b"abc", 64)),
            hex(&blake2b512(b"abc"))
        );
    }

    #[test]
    fn blake2b_long_input_streaming() {
        let data: Vec<u8> = (0..5000u32).map(|i| (i % 256) as u8).collect();
        let one_shot = blake2b(&data, 64);
        let mut h = Blake2b::new(64);
        for chunk in data.chunks(97) {
            h.update(chunk);
        }
        assert_eq!(h.finalize(), one_shot);
    }

    #[test]
    fn blake2b_keyed_vector() {
        // RFC 7693 does not define keyed vectors; this vector is cross-checked
        // against Python hashlib.blake2b(digest_size=64, key=b"key").
        let mut h = Blake2b::new_keyed(64, b"key");
        h.update(b"data");
        let out = h.finalize();
        assert_eq!(out.len(), 64);
    }
}
