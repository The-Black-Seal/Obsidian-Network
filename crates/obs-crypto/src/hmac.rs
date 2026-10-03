//! HMAC (RFC 2104), HKDF (RFC 5869) and PBKDF2 (RFC 8018).

use crate::ct::ct_eq;
use crate::sha2::{Sha256, Sha512};
use crate::sha1::Sha1;

/// Minimal hashing interface used by the MAC/KDF constructions.
pub trait Digest: Clone {
    /// Digest output size in bytes.
    const OUT_LEN: usize;
    /// Internal block size in bytes.
    const BLOCK_LEN: usize;
    /// Creates an empty hasher state.
    fn new_state() -> Self;
    /// Absorbs data.
    fn absorb(&mut self, data: &[u8]);
    /// Produces the digest.
    fn finish(self) -> Vec<u8>;
}

impl Digest for Sha256 {
    const OUT_LEN: usize = 32;
    const BLOCK_LEN: usize = 64;
    fn new_state() -> Self {
        Sha256::new()
    }
    fn absorb(&mut self, data: &[u8]) {
        self.update(data)
    }
    fn finish(self) -> Vec<u8> {
        Sha256::finalize(self).to_vec()
    }
}

impl Digest for Sha512 {
    const OUT_LEN: usize = 64;
    const BLOCK_LEN: usize = 128;
    fn new_state() -> Self {
        Sha512::new()
    }
    fn absorb(&mut self, data: &[u8]) {
        self.update(data)
    }
    fn finish(self) -> Vec<u8> {
        Sha512::finalize(self).to_vec()
    }
}

impl Digest for Sha1 {
    const OUT_LEN: usize = 20;
    const BLOCK_LEN: usize = 64;
    fn new_state() -> Self {
        Sha1::new()
    }
    fn absorb(&mut self, data: &[u8]) {
        self.update(data)
    }
    fn finish(self) -> Vec<u8> {
        Sha1::finalize(self).to_vec()
    }
}

/// HMAC over a [`Digest`].
pub fn hmac<D: Digest>(key: &[u8], data: &[u8]) -> Vec<u8> {
    let mut k = vec![0u8; D::BLOCK_LEN];
    if key.len() > D::BLOCK_LEN {
        let mut h = D::new_state();
        h.absorb(key);
        let d = h.finish();
        k[..d.len()].copy_from_slice(&d);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut inner = D::new_state();
    let ipad: Vec<u8> = k.iter().map(|b| b ^ 0x36).collect();
    inner.absorb(&ipad);
    inner.absorb(data);
    let inner_digest = inner.finish();
    let mut outer = D::new_state();
    let opad: Vec<u8> = k.iter().map(|b| b ^ 0x5c).collect();
    outer.absorb(&opad);
    outer.absorb(&inner_digest);
    outer.finish()
}

/// HMAC-SHA-256 one-shot.
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; 32] {
    let mut out = [0u8; 32];
    out.copy_from_slice(&hmac::<Sha256>(key, data));
    out
}

/// HMAC-SHA-512 one-shot.
pub fn hmac_sha512(key: &[u8], data: &[u8]) -> [u8; 64] {
    let mut out = [0u8; 64];
    out.copy_from_slice(&hmac::<Sha512>(key, data));
    out
}

/// Constant-time HMAC-SHA-256 verification.
pub fn hmac_sha256_verify(key: &[u8], data: &[u8], tag: &[u8]) -> bool {
    ct_eq(&hmac_sha256(key, data), tag)
}

/// HKDF-Extract (RFC 5869).
pub fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> [u8; 32] {
    hmac_sha256(salt, ikm)
}

/// HKDF-Expand (RFC 5869).
///
/// `okm.len()` must be at most `255 * 32` bytes.
pub fn hkdf_expand(prk: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    assert!(okm_len <= 255 * 32, "HKDF output too long");
    let mut okm = Vec::with_capacity(okm_len);
    let mut t: Vec<u8> = Vec::new();
    let mut counter: u8 = 1;
    while okm.len() < okm_len {
        let mut input = Vec::with_capacity(t.len() + info.len() + 1);
        input.extend_from_slice(&t);
        input.extend_from_slice(info);
        input.push(counter);
        t = hmac_sha256(prk, &input).to_vec();
        let take = core::cmp::min(okm_len - okm.len(), t.len());
        okm.extend_from_slice(&t[..take]);
        counter = counter.checked_add(1).expect("HKDF counter overflow");
    }
    okm
}

/// HKDF-SHA-256 (extract-then-expand).
pub fn hkdf(salt: &[u8], ikm: &[u8], info: &[u8], okm_len: usize) -> Vec<u8> {
    let prk = hkdf_extract(salt, ikm);
    hkdf_expand(&prk, info, okm_len)
}

/// PBKDF2-HMAC-SHA-512 (RFC 8018).  Used for BIP-39 seed derivation.
pub fn pbkdf2_hmac_sha512(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    pbkdf2::<Sha512>(password, salt, iterations, out_len)
}

/// PBKDF2-HMAC with a generic digest.
pub fn pbkdf2<D: Digest>(password: &[u8], salt: &[u8], iterations: u32, out_len: usize) -> Vec<u8> {
    assert!(iterations >= 1, "PBKDF2 requires at least one iteration");
    let h_len = D::OUT_LEN;
    let blocks = out_len.div_ceil(h_len);
    let mut out = Vec::with_capacity(blocks * h_len);
    for block_index in 1..=blocks {
        let mut salt_block = salt.to_vec();
        salt_block.extend_from_slice(&(block_index as u32).to_be_bytes());
        let mut u = hmac::<D>(password, &salt_block);
        let mut t = u.clone();
        for _ in 1..iterations {
            u = hmac::<D>(password, &u);
            for (ti, ui) in t.iter_mut().zip(u.iter()) {
                *ti ^= *ui;
            }
        }
        out.extend_from_slice(&t);
    }
    out.truncate(out_len);
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    #[test]
    fn hmac_sha256_rfc4231_vectors() {
        // RFC 4231 test case 1 and 2.
        assert_eq!(
            hex(&hmac_sha256(&[0x0b; 20], b"Hi There")),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
        assert_eq!(
            hex(&hmac_sha256(b"Jefe", b"what do ya want for nothing?")),
            "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843"
        );
    }

    #[test]
    fn hmac_sha512_rfc4231_vectors() {
        assert_eq!(
            hex(&hmac_sha512(&[0x0b; 20], b"Hi There")),
            "87aa7cdea5ef619d4ff0b4241a1d6cb02379f4e2ce4ec2787ad0b30545e17cdedaa833b7d6b8a702038b274eaea3f4e4be9d914eeb61f1702e696c203a126854"
        );
    }

    #[test]
    fn hkdf_rfc5869_case1() {
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0..13u8).collect();
        let info: Vec<u8> = (0xf0..0xfa).collect();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex(&prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let okm = hkdf_expand(&prk, &info, 42);
        assert_eq!(hex(&okm), "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865");
    }

    #[test]
    fn hkdf_rfc5869_case3_empty_salt() {
        let ikm = [0x0bu8; 22];
        let prk = hkdf_extract(&[], &ikm);
        let okm = hkdf_expand(&prk, &[], 42);
        assert_eq!(hex(&okm), "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8");
    }

    #[test]
    fn pbkdf2_sha512_vector() {
        // RFC 6070 style vector for PBKDF2-HMAC-SHA512: P="password", S="salt", c=1, dkLen=64
        assert_eq!(
            hex(&pbkdf2_hmac_sha512(b"password", b"salt", 1, 64)),
            "867f70cf1ade02cff3752599a3a53dc4af34c7a669815ae5d513554e1c8cf252c02d470a285a0501bad999bfe943c08f050235d7d68b1da55e63f73b60a57fce"
        );
        assert_eq!(
            hex(&pbkdf2_hmac_sha512(b"password", b"salt", 4096, 64)),
            "d197b1b33db0143e018b12f3d1d1479e6cdebdcc97c5c0f87f6902e072f457b5143f30602641b3d55cd335988cb36b84376060ecd532e039b742a239434af2d5"
        );
    }
}
