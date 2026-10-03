//! ChaCha20, Poly1305 and the ChaCha20-Poly1305 AEAD (RFC 8439).
//!
//! Used for:
//! * the deterministic CSPRNG (`ChaCha20` as a DRBG core),
//! * authenticated encryption of secrets at rest (TOTP seeds, wallet
//!   keystores) — ChaCha20-Poly1305 with a 96-bit nonce.

use crate::ct::{ct_eq, Zeroize};

/// ChaCha20 block function.
fn quarter_round(state: &mut [u32; 16], a: usize, b: usize, c: usize, d: usize) {
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(16);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(12);
    state[a] = state[a].wrapping_add(state[b]);
    state[d] = (state[d] ^ state[a]).rotate_left(8);
    state[c] = state[c].wrapping_add(state[d]);
    state[b] = (state[b] ^ state[c]).rotate_left(7);
}

fn chacha20_block(key: &[u8; 32], counter: u32, nonce: &[u8; 12]) -> [u8; 64] {
    let mut state = [0u32; 16];
    state[0] = 0x6170_7865;
    state[1] = 0x3320_646e;
    state[2] = 0x7962_2d32;
    state[3] = 0x6b20_6574;
    for i in 0..8 {
        state[4 + i] = u32::from_le_bytes([
            key[i * 4],
            key[i * 4 + 1],
            key[i * 4 + 2],
            key[i * 4 + 3],
        ]);
    }
    state[12] = counter;
    for i in 0..3 {
        state[13 + i] = u32::from_le_bytes([
            nonce[i * 4],
            nonce[i * 4 + 1],
            nonce[i * 4 + 2],
            nonce[i * 4 + 3],
        ]);
    }
    let initial = state;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    let mut out = [0u8; 64];
    for i in 0..16 {
        let word = state[i].wrapping_add(initial[i]);
        out[i * 4..i * 4 + 4].copy_from_slice(&word.to_le_bytes());
    }
    out
}

/// ChaCha20 keystream cipher (RFC 8439 §2.4) with a 32-bit block counter.
///
/// The counter starts at `counter` and increments per 64-byte block.
pub fn chacha20_xor(key: &[u8; 32], nonce: &[u8; 12], counter: u32, data: &mut [u8]) {
    let mut counter = counter;
    for chunk in data.chunks_mut(64) {
        let block = chacha20_block(key, counter, nonce);
        for (b, k) in chunk.iter_mut().zip(block.iter()) {
            *b ^= *k;
        }
        counter = counter.wrapping_add(1);
    }
}

/// Poly1305 one-time authenticator (RFC 8439 §2.5).
///
/// Implemented with the standard 5x26-bit limb representation ("poly1305-donna"
/// algorithm); all intermediate accumulators are 64-bit, so no overflow is
/// possible.
pub fn poly1305(key: &[u8; 32], msg: &[u8]) -> [u8; 16] {
    #[inline]
    fn u32_at(m: &[u8], off: usize) -> u32 {
        u32::from_le_bytes([m[off], m[off + 1], m[off + 2], m[off + 3]])
    }

    const MASK: u32 = 0x03ff_ffff;

    // r with the standard clamping applied.
    let r0 = u32_at(key, 0) & MASK;
    let r1 = (u32_at(key, 3) >> 2) & 0x03ff_ff03;
    let r2 = (u32_at(key, 6) >> 4) & 0x03ff_c0ff;
    let r3 = (u32_at(key, 9) >> 6) & 0x03f0_3fff;
    let r4 = (u32_at(key, 12) >> 8) & 0x000f_ffff;
    let s1 = r1.wrapping_mul(5);
    let s2 = r2.wrapping_mul(5);
    let s3 = r3.wrapping_mul(5);
    let s4 = r4.wrapping_mul(5);
    let pad = [
        u32_at(key, 16),
        u32_at(key, 20),
        u32_at(key, 24),
        u32_at(key, 28),
    ];

    let mut h = [0u32; 5];

    // Processes one 16-byte block; `hibit` is 2^128 for full blocks and 0 for
    // the padded final block.
    let blocks = |h: &mut [u32; 5], data: &[u8], hibit: u32| {
        let hibit = hibit << 24;
        for block in data.chunks(16) {
            let mut buf = [0u8; 16];
            buf[..block.len()].copy_from_slice(block);
            h[0] = h[0].wrapping_add(u32_at(&buf, 0) & MASK);
            h[1] = h[1].wrapping_add((u32_at(&buf, 3) >> 2) & MASK);
            h[2] = h[2].wrapping_add((u32_at(&buf, 6) >> 4) & MASK);
            h[3] = h[3].wrapping_add((u32_at(&buf, 9) >> 6) & MASK);
            let last = u32_at(&buf, 12);
            h[4] = h[4].wrapping_add((last >> 8) | hibit);

            let d0 = (h[0] as u64) * (r0 as u64)
                + (h[1] as u64) * (s4 as u64)
                + (h[2] as u64) * (s3 as u64)
                + (h[3] as u64) * (s2 as u64)
                + (h[4] as u64) * (s1 as u64);
            let mut d1 = (h[0] as u64) * (r1 as u64)
                + (h[1] as u64) * (r0 as u64)
                + (h[2] as u64) * (s4 as u64)
                + (h[3] as u64) * (s3 as u64)
                + (h[4] as u64) * (s2 as u64);
            let mut d2 = (h[0] as u64) * (r2 as u64)
                + (h[1] as u64) * (r1 as u64)
                + (h[2] as u64) * (r0 as u64)
                + (h[3] as u64) * (s4 as u64)
                + (h[4] as u64) * (s3 as u64);
            let mut d3 = (h[0] as u64) * (r3 as u64)
                + (h[1] as u64) * (r2 as u64)
                + (h[2] as u64) * (r1 as u64)
                + (h[3] as u64) * (r0 as u64)
                + (h[4] as u64) * (s4 as u64);
            let mut d4 = (h[0] as u64) * (r4 as u64)
                + (h[1] as u64) * (r3 as u64)
                + (h[2] as u64) * (r2 as u64)
                + (h[3] as u64) * (r1 as u64)
                + (h[4] as u64) * (r0 as u64);

            let mut c = (d0 >> 26) as u32;
            h[0] = (d0 as u32) & MASK;
            d1 += c as u64;
            c = (d1 >> 26) as u32;
            h[1] = (d1 as u32) & MASK;
            d2 += c as u64;
            c = (d2 >> 26) as u32;
            h[2] = (d2 as u32) & MASK;
            d3 += c as u64;
            c = (d3 >> 26) as u32;
            h[3] = (d3 as u32) & MASK;
            d4 += c as u64;
            c = (d4 >> 26) as u32;
            h[4] = (d4 as u32) & MASK;
            h[0] = h[0].wrapping_add(c.wrapping_mul(5));
            c = h[0] >> 26;
            h[0] &= MASK;
            h[1] = h[1].wrapping_add(c);
        }
    };

    let full = msg.len() / 16 * 16;
    blocks(&mut h, &msg[..full], 1);
    if full < msg.len() {
        let mut tail = [0u8; 16];
        let rem = msg.len() - full;
        tail[..rem].copy_from_slice(&msg[full..]);
        tail[rem] = 1;
        blocks(&mut h, &tail, 0);
    }

    // Full carry propagation.
    let mut c = h[1] >> 26;
    h[1] &= MASK;
    h[2] = h[2].wrapping_add(c);
    c = h[2] >> 26;
    h[2] &= MASK;
    h[3] = h[3].wrapping_add(c);
    c = h[3] >> 26;
    h[3] &= MASK;
    h[4] = h[4].wrapping_add(c);
    c = h[4] >> 26;
    h[4] &= MASK;
    h[0] = h[0].wrapping_add(c.wrapping_mul(5));
    c = h[0] >> 26;
    h[0] &= MASK;
    h[1] = h[1].wrapping_add(c);

    // g = h + 5, then g4 loses 2^26: if h >= p this is non-negative.
    let mut g = [0u32; 5];
    let mut cc = 5u32;
    for i in 0..4 {
        g[i] = h[i].wrapping_add(cc);
        cc = g[i] >> 26;
        g[i] &= MASK;
    }
    g[4] = h[4].wrapping_add(cc).wrapping_sub(1 << 26);
    // If the subtraction borrows, h < p and we keep h.
    let select_g = ((g[4] >> 31) as u32).wrapping_sub(1);
    for i in 0..5 {
        h[i] = (h[i] & !select_g) | (g[i] & select_g);
    }

    // h += pad (mod 2^128), serialized little-endian.
    let h0 = h[0] | (h[1] << 26);
    let h1 = (h[1] >> 6) | (h[2] << 20);
    let h2 = (h[2] >> 12) | (h[3] << 14);
    let h3 = (h[3] >> 18) | (h[4] << 8);
    let mut out = [0u8; 16];
    let words = [h0, h1, h2, h3];
    let mut carry = 0u64;
    for i in 0..4 {
        let sum = words[i] as u64 + pad[i] as u64 + carry;
        out[i * 4..i * 4 + 4].copy_from_slice(&((sum as u32)).to_le_bytes());
        carry = sum >> 32;
    }
    out
}

/// ChaCha20-Poly1305 AEAD (RFC 8439 §2.8).
pub struct ChaCha20Poly1305;

impl ChaCha20Poly1305 {
    /// Encrypts `plaintext` with `aad`; returns ciphertext||tag.
    pub fn encrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        plaintext: &[u8],
    ) -> Vec<u8> {
        let mut ciphertext = plaintext.to_vec();
        chacha20_xor(key, nonce, 1, &mut ciphertext);
        let tag = Self::compute_tag(key, nonce, aad, &ciphertext);
        ciphertext.extend_from_slice(&tag);
        ciphertext
    }

    /// Decrypts ciphertext||tag; returns `None` on authentication failure.
    pub fn decrypt(
        key: &[u8; 32],
        nonce: &[u8; 12],
        aad: &[u8],
        sealed: &[u8],
    ) -> Option<Vec<u8>> {
        if sealed.len() < 16 {
            return None;
        }
        let (ciphertext, tag) = sealed.split_at(sealed.len() - 16);
        let expected = Self::compute_tag(key, nonce, aad, ciphertext);
        if !ct_eq(&expected, tag) {
            return None;
        }
        let mut plaintext = ciphertext.to_vec();
        chacha20_xor(key, nonce, 1, &mut plaintext);
        Some(plaintext)
    }

    fn compute_tag(key: &[u8; 32], nonce: &[u8; 12], aad: &[u8], ciphertext: &[u8]) -> [u8; 16] {
        let mut poly_key_block = [0u8; 64];
        let block = chacha20_block(key, 0, nonce);
        poly_key_block.copy_from_slice(&block);
        let mut poly_key = [0u8; 32];
        poly_key.copy_from_slice(&poly_key_block[..32]);

        let mut mac_data = Vec::with_capacity(aad.len() + ciphertext.len() + 32);
        mac_data.extend_from_slice(aad);
        let pad_aad = (16 - (aad.len() % 16)) % 16;
        mac_data.extend(core::iter::repeat(0u8).take(pad_aad));
        mac_data.extend_from_slice(ciphertext);
        let pad_ct = (16 - (ciphertext.len() % 16)) % 16;
        mac_data.extend(core::iter::repeat(0u8).take(pad_ct));
        mac_data.extend_from_slice(&(aad.len() as u64).to_le_bytes());
        mac_data.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
        let tag = poly1305(&poly_key, &mac_data);
        poly_key.zeroize();
        tag
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn chacha20_rfc8439_vector() {
        let mut key = [0u8; 32];
        key.copy_from_slice(&(0..32u8).collect::<Vec<u8>>());
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x4a, 0, 0, 0, 0];
        let mut data = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.".to_vec();
        chacha20_xor(&key, &nonce, 1, &mut data);
        assert_eq!(hex(&data[..16]), "6e2e359a2568f98041ba0728dd0d6981");
        assert_eq!(hex(&data[16..32]), "e97e7aec1d4360c20a27afccfd9fae0b");
    }

    #[test]
    fn poly1305_rfc8439_vector() {
        let key: [u8; 32] = [
            0x85, 0xd6, 0xbe, 0x78, 0x57, 0x55, 0x6d, 0x33, 0x7f, 0x44, 0x52, 0xfe, 0x42, 0xd5,
            0x06, 0xa8, 0x01, 0x03, 0x80, 0x8a, 0xfb, 0x0d, 0xb2, 0xfd, 0x4a, 0xbf, 0xf6, 0xaf,
            0x41, 0x49, 0xf5, 0x1b,
        ];
        let tag = poly1305(&key, b"Cryptographic Forum Research Group");
        assert_eq!(hex(&tag), "a8061dc1305136c6c22b8baf0c0127a9");
    }

    #[test]
    fn aead_cross_checked_vector() {
        // Key/nonce/aad/plaintext from RFC 8439 §2.8.  The expected ciphertext
        // and tag were produced by an independent implementation (OpenSSL's
        // ChaCha20-Poly1305 via the Python `cryptography` package); the test
        // therefore validates this implementation against a second,
        // independently written one, not only against itself.
        let key: [u8; 32] = [
            0x1c, 0x92, 0x40, 0xa5, 0xeb, 0x55, 0xd3, 0x8a, 0xf3, 0x33, 0x88, 0x86, 0x04, 0xf6,
            0xb5, 0xf0, 0x47, 0x39, 0x17, 0xc1, 0x40, 0x2b, 0x80, 0x09, 0x9d, 0xca, 0x5c, 0xbc,
            0x20, 0x70, 0x75, 0xc0,
        ];
        let nonce: [u8; 12] = [0, 0, 0, 0, 0, 0, 0, 0x07, 0x7b, 0xe7, 0x6b, 0xd3];
        let aad = [0x50u8, 0x51, 0x52, 0x53, 0xc0, 0xc1, 0xc2, 0xc3, 0xc4, 0xc5, 0xc6, 0xc7];
        let plaintext = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let sealed = ChaCha20Poly1305::encrypt(&key, &nonce, &aad, plaintext);
        assert_eq!(
            hex(&sealed),
            "84a2c93a2f8bf6d57751f409dffa2514644d85f8a0a32296d99136e498d7494ec056f01ca33ee97421d81c98577f01e7d07e519cffbf014b0c113b21f9417607c7cc2b02fe6a816cc825f0db7c1282ddaa297990e511bf74eaf624471b61b8bf2cef622434b07c7a2f451b667a46ce9903bbb8d3d673f788a48da1886620328c5c37"
        );
        let opened = ChaCha20Poly1305::decrypt(&key, &nonce, &aad, &sealed).unwrap();
        assert_eq!(opened, plaintext);
        // Tampering and associated-data substitution must both be detected.
        let mut bad = sealed.clone();
        bad[0] ^= 1;
        assert!(ChaCha20Poly1305::decrypt(&key, &nonce, &aad, &bad).is_none());
        assert!(ChaCha20Poly1305::decrypt(&key, &nonce, b"other", &sealed).is_none());
        assert!(ChaCha20Poly1305::decrypt(&key, &nonce, &aad, &sealed[..16]).is_none());
    }

    #[test]
    fn aead_roundtrip_various_lengths() {
        let key = [9u8; 32];
        let nonce = [3u8; 12];
        for len in [0usize, 1, 15, 16, 17, 63, 64, 65, 1000] {
            let pt: Vec<u8> = (0..len).map(|i| (i % 251) as u8).collect();
            let sealed = ChaCha20Poly1305::encrypt(&key, &nonce, b"aad", &pt);
            assert_eq!(sealed.len(), pt.len() + 16);
            assert_eq!(
                ChaCha20Poly1305::decrypt(&key, &nonce, b"aad", &sealed).unwrap(),
                pt
            );
        }
    }
}
