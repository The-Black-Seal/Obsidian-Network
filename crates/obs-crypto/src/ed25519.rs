//! Ed25519 signatures (RFC 8032).
//!
//! * Field: `p = 2^255 - 19`, represented with five 51-bit limbs.
//! * Group: edwards25519 in extended twisted-Edwards coordinates using the
//!   complete addition law for `a = -1` (no exceptional cases, so doubling and
//!   the identity need no special handling).
//! * Scalars: arithmetic modulo `L = 2^252 + 27742317777372353535851937790883648493`.
//!
//! Signing uses a constant-time fixed-window scalar multiplication; signature
//! verification uses a variable-time routine (verification only touches public
//! data).  Both are validated against the RFC 8032 test vectors and against an
//! independent implementation.

use crate::ct::{ct_eq, Zeroize};
use crate::sha2::Sha512;

// ---------------------------------------------------------------------------
// Field arithmetic: F_p with p = 2^255 - 19
// ---------------------------------------------------------------------------

const MASK51: u64 = (1u64 << 51) - 1;

/// An element of `F_p` in radix-2^51 representation (five limbs).
#[derive(Clone, Copy, Debug)]
pub struct Fe([u64; 5]);

impl Fe {
    /// Zero.
    pub const ZERO: Fe = Fe([0, 0, 0, 0, 0]);
    /// One.
    pub const ONE: Fe = Fe([1, 0, 0, 0, 0]);

    /// Builds a field element from a small unsigned integer.
    pub fn from_u64(v: u64) -> Fe {
        Fe([v & MASK51, (v >> 51) & MASK51, 0, 0, 0])
    }

    /// Decodes a field element from 32 little-endian bytes, ignoring the top bit.
    pub fn from_bytes(bytes: &[u8; 32]) -> Fe {
        let mut b = *bytes;
        b[31] &= 0x7f;
        let load = |i: usize| -> u64 {
            let mut w = [0u8; 8];
            let end = core::cmp::min(i + 8, 32);
            w[..end - i].copy_from_slice(&b[i..end]);
            u64::from_le_bytes(w)
        };
        Fe([
            load(0) & MASK51,
            (load(6) >> 3) & MASK51,
            (load(12) >> 6) & MASK51,
            (load(19) >> 1) & MASK51,
            (load(24) >> 12) & MASK51,
        ])
    }

    /// Canonical little-endian encoding (fully reduced modulo p).
    pub fn to_bytes(self) -> [u8; 32] {
        let mut h = self.reduced();
        // Conditional subtraction of p: q == 1 exactly when h >= p.
        let mut q = (h.0[0] + 19) >> 51;
        q = (h.0[1] + q) >> 51;
        q = (h.0[2] + q) >> 51;
        q = (h.0[3] + q) >> 51;
        q = (h.0[4] + q) >> 51;
        h.0[0] += 19 * q;
        for i in 0..4 {
            let c = h.0[i] >> 51;
            h.0[i] &= MASK51;
            h.0[i + 1] += c;
        }
        // Pack the five 51-bit limbs into four 64-bit words.
        let mut words = [0u64; 4];
        for i in 0..5 {
            let shift = 51 * i;
            let word = shift / 64;
            let off = shift % 64;
            let v = (h.0[i] as u128) << off;
            words[word] |= v as u64;
            let high = (v >> 64) as u64;
            if word + 1 < 4 {
                words[word + 1] |= high;
            } else {
                debug_assert_eq!(high, 0, "field element must be < 2^255");
            }
        }
        let mut out = [0u8; 32];
        for i in 0..4 {
            out[i * 8..i * 8 + 8].copy_from_slice(&words[i].to_le_bytes());
        }
        out[31] &= 0x7f;
        out
    }

    /// Propagates carries so every limb is below 2^51.
    fn reduced(self) -> Fe {
        let mut h = self;
        for i in 0..4 {
            let c = h.0[i] >> 51;
            h.0[i] &= MASK51;
            h.0[i + 1] += c;
        }
        let c = h.0[4] >> 51;
        h.0[4] &= MASK51;
        h.0[0] += c.wrapping_mul(19);
        let c = h.0[0] >> 51;
        h.0[0] &= MASK51;
        h.0[1] += c;
        h
    }

    /// Field addition.
    pub fn add(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        for i in 0..5 {
            r[i] = self.0[i] + other.0[i];
        }
        Fe(r).reduced()
    }

    /// Field subtraction.
    pub fn sub(&self, other: &Fe) -> Fe {
        let mut r = [0u64; 5];
        r[0] = self.0[0] + 2 * (MASK51 - 18) - other.0[0];
        for i in 1..5 {
            r[i] = self.0[i] + 2 * MASK51 - other.0[i];
        }
        Fe(r).reduced()
    }

    /// Field negation.
    pub fn neg(&self) -> Fe {
        Fe::ZERO.sub(self)
    }

    /// Field multiplication.
    pub fn mul(&self, other: &Fe) -> Fe {
        let a = self.0;
        let b = other.0;
        let b1_19 = b[1] * 19;
        let b2_19 = b[2] * 19;
        let b3_19 = b[3] * 19;
        let b4_19 = b[4] * 19;
        let c0 = (a[0] as u128) * (b[0] as u128)
            + (a[1] as u128) * (b4_19 as u128)
            + (a[2] as u128) * (b3_19 as u128)
            + (a[3] as u128) * (b2_19 as u128)
            + (a[4] as u128) * (b1_19 as u128);
        let c1 = (a[0] as u128) * (b[1] as u128)
            + (a[1] as u128) * (b[0] as u128)
            + (a[2] as u128) * (b4_19 as u128)
            + (a[3] as u128) * (b3_19 as u128)
            + (a[4] as u128) * (b2_19 as u128);
        let c2 = (a[0] as u128) * (b[2] as u128)
            + (a[1] as u128) * (b[1] as u128)
            + (a[2] as u128) * (b[0] as u128)
            + (a[3] as u128) * (b4_19 as u128)
            + (a[4] as u128) * (b3_19 as u128);
        let c3 = (a[0] as u128) * (b[3] as u128)
            + (a[1] as u128) * (b[2] as u128)
            + (a[2] as u128) * (b[1] as u128)
            + (a[3] as u128) * (b[0] as u128)
            + (a[4] as u128) * (b4_19 as u128);
        let c4 = (a[0] as u128) * (b[4] as u128)
            + (a[1] as u128) * (b[3] as u128)
            + (a[2] as u128) * (b[2] as u128)
            + (a[3] as u128) * (b[1] as u128)
            + (a[4] as u128) * (b[0] as u128);
        carry_chain([c0, c1, c2, c3, c4])
    }

    /// Field squaring.
    pub fn square(&self) -> Fe {
        let a = self.0;
        let a0 = a[0] as u128;
        let a1 = a[1] as u128;
        let a2 = a[2] as u128;
        let a3 = a[3] as u128;
        let a4 = a[4] as u128;
        let c0 = a0 * a0 + 38 * a1 * a4 + 38 * a2 * a3;
        let c1 = 2 * a0 * a1 + 38 * a2 * a4 + 19 * a3 * a3;
        let c2 = 2 * a0 * a2 + a1 * a1 + 38 * a3 * a4;
        let c3 = 2 * a0 * a3 + 2 * a1 * a2 + 19 * a4 * a4;
        let c4 = 2 * a0 * a4 + 2 * a1 * a3 + a2 * a2;
        carry_chain([c0, c1, c2, c3, c4])
    }

    /// `self * 2`.
    pub fn double(&self) -> Fe {
        self.add(self)
    }

    /// Repeated squaring `self^(2^k)`.
    fn pow2k(&self, k: u32) -> Fe {
        let mut r = *self;
        for _ in 0..k {
            r = r.square();
        }
        r
    }

    /// Multiplicative inverse (`self^(p-2)`); returns zero for zero.
    ///
    /// Uses the standard 254-bit addition chain: the intermediate values are
    /// `z^(2^k - 1)` for k = 5, 10, 20, 40, 50, 100, 200, 250.
    pub fn invert(&self) -> Fe {
        let z = *self;
        let t0 = z.square(); // z^2
        let t1 = t0.pow2k(2); // z^8
        let t1 = z.mul(&t1); // z^9
        let t0 = t0.mul(&t1); // z^11
        let t2 = t0.square(); // z^22
        let t1 = t1.mul(&t2); // 2^5 - 1
        let t2 = t1.pow2k(5);
        let t1 = t2.mul(&t1); // 2^10 - 1
        let t2 = t1.pow2k(10);
        let t2 = t2.mul(&t1); // 2^20 - 1
        let t3 = t2.pow2k(20);
        let t2 = t3.mul(&t2); // 2^40 - 1
        let t2 = t2.pow2k(10);
        let t1 = t2.mul(&t1); // 2^50 - 1
        let t2 = t1.pow2k(50);
        let t2 = t2.mul(&t1); // 2^100 - 1
        let t3 = t2.pow2k(100);
        let t2 = t3.mul(&t2); // 2^200 - 1
        let t2 = t2.pow2k(50);
        let t1 = t2.mul(&t1); // 2^250 - 1
        t1.pow2k(5).mul(&t0) // z^(2^255 - 21) = z^(p - 2)
    }

    /// `self^((p-5)/8) = self^(2^252 - 3)`, used for square roots.
    ///
    /// Intermediate values are `z^(2^k - 1)` for k = 5, 10, 20, 40, 50, 100,
    /// 200, 250; the final exponent is `(2^250 - 1) * 4 + 1 = 2^252 - 3`.
    pub fn pow22523(&self) -> Fe {
        let z = *self;
        let t0 = z.square(); // z^2
        let t1 = t0.pow2k(2); // z^8
        let t1 = z.mul(&t1); // z^9
        let t0 = t0.mul(&t1); // z^11
        let t0 = t0.square(); // z^22
        let t0 = t1.mul(&t0); // 2^5 - 1
        let t0 = t0.pow2k(5).mul(&t0); // 2^10 - 1
        let t1 = t0.pow2k(10).mul(&t0); // 2^20 - 1
        let t2 = t1.pow2k(20).mul(&t1); // 2^40 - 1
        let t0 = t2.pow2k(10).mul(&t0); // 2^50 - 1
        let t1 = t0.pow2k(50).mul(&t0); // 2^100 - 1
        let t2 = t1.pow2k(100).mul(&t1); // 2^200 - 1
        let t0 = t2.pow2k(50).mul(&t0); // 2^250 - 1
        t0.pow2k(2).mul(&z) // 2^252 - 3
    }

    /// Is the canonical encoding odd (used as the x sign bit)?
    pub fn is_negative(&self) -> bool {
        self.to_bytes()[0] & 1 == 1
    }

    /// Is this the zero element?
    pub fn is_zero(&self) -> bool {
        ct_eq(&self.to_bytes(), &[0u8; 32])
    }

    /// Constant-time conditional assignment: `*self = if choice { x } else { *self }`.
    fn ct_assign(&mut self, x: &Fe, choice: u8) {
        let m = 0u64.wrapping_sub((choice & 1) as u64);
        for i in 0..5 {
            self.0[i] = (self.0[i] & !m) | (x.0[i] & m);
        }
    }
}

/// Shared carry propagation for 128-bit limb products.
fn carry_chain(c: [u128; 5]) -> Fe {
    let mut out = [0u64; 5];
    let mut carry: u128 = 0;
    for i in 0..5 {
        let v = c[i] + carry;
        out[i] = (v as u64) & MASK51;
        carry = v >> 51;
    }
    out[0] += (carry as u64) * 19;
    let mut c = out[0] >> 51;
    out[0] &= MASK51;
    out[1] += c;
    c = out[1] >> 51;
    out[1] &= MASK51;
    out[2] += c;
    Fe(out)
}

// ---------------------------------------------------------------------------
// Scalar arithmetic modulo L
// ---------------------------------------------------------------------------

/// Order of the prime-order subgroup: `L = 2^252 + 27742317777372353535851937790883648493`.
pub const L: [u32; 8] = [
    0x5cf5_d3ed,
    0x5812_631a,
    0xa2f7_9cd6,
    0x14de_f9de,
    0x0000_0000,
    0x0000_0000,
    0x0000_0000,
    0x1000_0000,
];

fn l_limbs() -> [u64; 4] {
    [
        (L[0] as u64) | ((L[1] as u64) << 32),
        (L[2] as u64) | ((L[3] as u64) << 32),
        (L[4] as u64) | ((L[5] as u64) << 32),
        (L[6] as u64) | ((L[7] as u64) << 32),
    ]
}

fn cmp4(a: &[u64; 4], b: &[u64; 4]) -> core::cmp::Ordering {
    for i in (0..4).rev() {
        if a[i] != b[i] {
            return a[i].cmp(&b[i]);
        }
    }
    core::cmp::Ordering::Equal
}

fn sub4(a: &mut [u64; 4], b: &[u64; 4]) {
    let mut borrow = 0i128;
    for i in 0..4 {
        let v = a[i] as i128 - b[i] as i128 - borrow;
        if v < 0 {
            a[i] = (v + (1i128 << 64)) as u64;
            borrow = 1;
        } else {
            a[i] = v as u64;
            borrow = 0;
        }
    }
    debug_assert_eq!(borrow, 0, "sub4 must not underflow");
}

/// Reduces a 512-bit little-endian value modulo `L` by binary long division.
///
/// Deterministic and branch-free with respect to the input value: exactly 512
/// shift/compare/subtract steps are performed for any input.
fn reduce_wide(x: &[u64; 8]) -> [u8; 32] {
    let l = l_limbs();
    let mut r = [0u64; 4];
    for bit_index in (0..512).rev() {
        // r = r * 2 + bit  (r < L < 2^253, so 2r + 1 < 2^254 fits in four limbs)
        let mut carry = 0u64;
        for k in 0..4 {
            let nv = (r[k] << 1) | carry;
            carry = r[k] >> 63;
            r[k] = nv;
        }
        debug_assert_eq!(carry, 0);
        let bit = (x[bit_index / 64] >> (bit_index % 64)) & 1;
        r[0] |= bit;
        if cmp4(&r, &l) != core::cmp::Ordering::Less {
            sub4(&mut r, &l);
        }
    }
    let mut out = [0u8; 32];
    for i in 0..4 {
        out[i * 8..i * 8 + 8].copy_from_slice(&r[i].to_le_bytes());
    }
    out
}

/// Reduces a 64-byte little-endian integer modulo `L`.
pub fn sc_reduce(input: &[u8; 64]) -> [u8; 32] {
    let mut limbs = [0u64; 8];
    for i in 0..8 {
        let mut w = [0u8; 8];
        w.copy_from_slice(&input[i * 8..i * 8 + 8]);
        limbs[i] = u64::from_le_bytes(w);
    }
    reduce_wide(&limbs)
}

/// `(a * b + c) mod L` for 32-byte little-endian scalars.
pub fn sc_muladd(a: &[u8; 32], b: &[u8; 32], c: &[u8; 32]) -> [u8; 32] {
    // Reduce the inputs first so the product always fits in eight limbs.
    let mut pad = [0u8; 64];
    pad[..32].copy_from_slice(a);
    let a = sc_reduce(&pad);
    pad[..32].copy_from_slice(b);
    let b = sc_reduce(&pad);
    pad[..32].copy_from_slice(c);
    let c = sc_reduce(&pad);

    let mut al = [0u64; 4];
    let mut bl = [0u64; 4];
    for i in 0..4 {
        al[i] = u64::from_le_bytes(a[i * 8..i * 8 + 8].try_into().unwrap());
        bl[i] = u64::from_le_bytes(b[i * 8..i * 8 + 8].try_into().unwrap());
    }
    let mut wide = [0u64; 8];
    for i in 0..4 {
        let mut carry: u128 = 0;
        for j in 0..4 {
            let cur = (wide[i + j] as u128) + (al[i] as u128) * (bl[j] as u128) + carry;
            wide[i + j] = cur as u64;
            carry = cur >> 64;
        }
        let mut k = i + 4;
        while carry > 0 && k < 8 {
            let cur = (wide[k] as u128) + carry;
            wide[k] = cur as u64;
            carry = cur >> 64;
            k += 1;
        }
    }
    let mut carry: u128 = 0;
    for i in 0..4 {
        let cur = (wide[i] as u128)
            + (u64::from_le_bytes(c[i * 8..i * 8 + 8].try_into().unwrap()) as u128)
            + carry;
        wide[i] = cur as u64;
        carry = cur >> 64;
    }
    let mut k = 4;
    while carry > 0 && k < 8 {
        let cur = (wide[k] as u128) + carry;
        wide[k] = cur as u64;
        carry = cur >> 64;
        k += 1;
    }
    reduce_wide(&wide)
}

/// Checks that a 32-byte scalar is canonically reduced (`< L`).
pub fn scalar_is_canonical(bytes: &[u8; 32]) -> bool {
    let mut limbs = [0u32; 8];
    for i in 0..8 {
        let mut w = [0u8; 4];
        w.copy_from_slice(&bytes[i * 4..i * 4 + 4]);
        limbs[i] = u32::from_le_bytes(w);
    }
    for i in (0..8).rev() {
        if limbs[i] < L[i] {
            return true;
        }
        if limbs[i] > L[i] {
            return false;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// Group arithmetic (edwards25519, extended coordinates)
// ---------------------------------------------------------------------------

/// A point in extended twisted-Edwards coordinates.
#[derive(Clone, Copy)]
pub struct GeP3 {
    x: Fe,
    y: Fe,
    z: Fe,
    t: Fe,
}

impl GeP3 {
    /// The neutral element.
    pub fn identity() -> GeP3 {
        GeP3 {
            x: Fe::ZERO,
            y: Fe::ONE,
            z: Fe::ONE,
            t: Fe::ZERO,
        }
    }

    /// Builds a point from affine coordinates.
    pub fn from_affine(x: Fe, y: Fe) -> GeP3 {
        GeP3 {
            x,
            y,
            z: Fe::ONE,
            t: x.mul(&y),
        }
    }

    /// Complete addition law for `a = -1` (add-2008-hwcd-3).
    pub fn add(&self, other: &GeP3) -> GeP3 {
        let a = self.y.sub(&self.x).mul(&other.y.sub(&other.x));
        let b = self.y.add(&self.x).mul(&other.y.add(&other.x));
        let c = self.t.mul(&curve::d2()).mul(&other.t);
        let d = self.z.mul(&other.z).double();
        let e = b.sub(&a);
        let f = d.sub(&c);
        let g = d.add(&c);
        let h = b.add(&a);
        GeP3 {
            x: e.mul(&f),
            y: g.mul(&h),
            t: e.mul(&h),
            z: f.mul(&g),
        }
    }

    /// Point doubling.
    pub fn double(&self) -> GeP3 {
        self.add(self)
    }

    /// Point negation.
    pub fn neg(&self) -> GeP3 {
        GeP3 {
            x: self.x.neg(),
            y: self.y,
            z: self.z,
            t: self.t.neg(),
        }
    }

    /// Affine coordinates.
    pub fn to_affine(&self) -> (Fe, Fe) {
        let zinv = self.z.invert();
        (self.x.mul(&zinv), self.y.mul(&zinv))
    }

    /// Canonical 32-byte encoding (y with the sign bit of x).
    pub fn encode(&self) -> [u8; 32] {
        let (x, y) = self.to_affine();
        let mut out = y.to_bytes();
        out[31] |= (x.to_bytes()[0] & 1) << 7;
        out
    }

    /// Checks whether this is the neutral element.
    pub fn is_identity(&self) -> bool {
        self.x.is_zero()
    }

    /// Constant-time conditional assignment.
    fn ct_assign(&mut self, other: &GeP3, choice: u8) {
        self.x.ct_assign(&other.x, choice);
        self.y.ct_assign(&other.y, choice);
        self.z.ct_assign(&other.z, choice);
        self.t.ct_assign(&other.t, choice);
    }
}

/// Curve constants, derived once at runtime and verified by unit tests.
pub mod curve {
    use super::*;
    use std::sync::OnceLock;

    struct Consts {
        d: Fe,
        d2: Fe,
        sqrtm1: Fe,
        base: GeP3,
    }

    fn build() -> Consts {
        // d = -121665 / 121666
        let d = Fe::from_u64(121_665)
            .neg()
            .mul(&Fe::from_u64(121_666).invert());
        let d2 = d.double();
        // sqrt(-1) = 2 * (2^((p-5)/8))^2
        let sqrtm1 = Fe::from_u64(2)
            .pow22523()
            .square()
            .mul(&Fe::from_u64(2));
        // Ed25519 base point (RFC 8032 §5.1).
        let base_x: [u8; 32] = [
            0x1a, 0xd5, 0x25, 0x8f, 0x60, 0x2d, 0x56, 0xc9, 0xb2, 0xa7, 0x25, 0x95, 0x60, 0xc7,
            0x2c, 0x69, 0x5c, 0xdc, 0xd6, 0xfd, 0x31, 0xe2, 0xa4, 0xc0, 0xfe, 0x53, 0x6e, 0xcd,
            0xd3, 0x36, 0x69, 0x21,
        ];
        let base_y: [u8; 32] = [
            0x58, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66, 0x66,
            0x66, 0x66, 0x66, 0x66,
        ];
        let base = GeP3::from_affine(Fe::from_bytes(&base_x), Fe::from_bytes(&base_y));
        Consts {
            d,
            d2,
            sqrtm1,
            base,
        }
    }

    fn consts() -> &'static Consts {
        static C: OnceLock<Consts> = OnceLock::new();
        C.get_or_init(build)
    }

    /// Curve constant `d`.
    pub fn d() -> Fe {
        consts().d
    }

    /// Curve constant `2*d`.
    pub fn d2() -> Fe {
        consts().d2
    }

    /// `sqrt(-1)`.
    pub fn sqrtm1() -> Fe {
        consts().sqrtm1
    }

    /// Ed25519 base point.
    pub fn base_point() -> GeP3 {
        consts().base
    }
}

/// Checks that the 32-byte little-endian value is `< p`.
fn field_bytes_canonical(bytes: &[u8; 32]) -> bool {
    let mut p = [0xffu8; 32];
    p[0] = 0xed;
    p[31] = 0x7f;
    for i in (0..32).rev() {
        if bytes[i] < p[i] {
            return true;
        }
        if bytes[i] > p[i] {
            return false;
        }
    }
    false
}

/// Decompresses a 32-byte public key into a point; `None` when the encoding is
/// invalid (non-canonical, not on the curve, or inconsistent sign).
pub fn decompress(bytes: &[u8; 32]) -> Option<GeP3> {
    let mut y_check = *bytes;
    let sign = (y_check[31] >> 7) & 1;
    y_check[31] &= 0x7f;
    if !field_bytes_canonical(&y_check) {
        return None;
    }
    let y = Fe::from_bytes(bytes);
    let yy = y.square();
    let u = yy.sub(&Fe::ONE);
    let v = yy.mul(&curve::d()).add(&Fe::ONE);
    let v3 = v.square().mul(&v);
    let v7 = v3.square().mul(&v);
    let mut x = u.mul(&v3).mul(&u.mul(&v7).pow22523());
    if !ct_eq(&v.mul(&x.square()).to_bytes(), &u.to_bytes()) {
        let x2 = x.mul(&curve::sqrtm1());
        if ct_eq(&v.mul(&x2.square()).to_bytes(), &u.to_bytes()) {
            x = x2;
        } else {
            return None;
        }
    }
    if x.is_zero() && sign == 1 {
        return None;
    }
    if (x.to_bytes()[0] & 1) != sign {
        x = x.neg();
    }
    Some(GeP3::from_affine(x, y))
}

/// Constant-time scalar multiplication `[scalar]P` using 4-bit windows.
pub fn scalar_mul(point: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut table = [GeP3::identity(); 16];
    table[1] = *point;
    for i in 2..16 {
        table[i] = if i % 2 == 0 {
            table[i / 2].double()
        } else {
            table[i - 1].add(point)
        };
    }
    let mut acc = GeP3::identity();
    for byte_index in (0..32).rev() {
        let byte = scalar[byte_index];
        for nibble in [byte >> 4, byte & 0x0f] {
            for _ in 0..4 {
                acc = acc.double();
            }
            let mut selected = GeP3::identity();
            for (i, entry) in table.iter().enumerate() {
                selected.ct_assign(entry, u8::from(nibble == i as u8));
            }
            acc = acc.add(&selected);
        }
    }
    acc
}

/// Variable-time scalar multiplication (public data only; skips zero windows).
pub fn scalar_mul_vartime(point: &GeP3, scalar: &[u8; 32]) -> GeP3 {
    let mut table = [GeP3::identity(); 16];
    table[1] = *point;
    for i in 2..16 {
        table[i] = table[i - 1].add(point);
    }
    let mut acc = GeP3::identity();
    for byte_index in (0..32).rev() {
        let byte = scalar[byte_index];
        for nibble in [byte >> 4, byte & 0x0f] {
            for _ in 0..4 {
                acc = acc.double();
            }
            if nibble != 0 {
                acc = acc.add(&table[nibble as usize]);
            }
        }
    }
    acc
}

// ---------------------------------------------------------------------------
// Key generation, signing and verification
// ---------------------------------------------------------------------------

/// An Ed25519 key pair derived from a 32-byte seed.
#[derive(Clone)]
pub struct Keypair {
    secret: [u8; 32],
    public: [u8; 32],
}

impl Keypair {
    /// Derives a key pair from a 32-byte seed (RFC 8032 §5.1.5).
    pub fn from_seed(seed: &[u8; 32]) -> Keypair {
        let mut h = Sha512::new();
        h.update(seed);
        let h = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp_scalar(&mut a);
        let public = scalar_mul(&curve::base_point(), &a).encode();
        let mut kp = Keypair {
            secret: *seed,
            public,
        };
        a.zeroize();
        kp.secret = *seed;
        kp
    }

    /// The 32-byte public key.
    pub fn public_key(&self) -> [u8; 32] {
        self.public
    }

    /// Produces a 64-byte detached signature over `message`.
    pub fn sign(&self, message: &[u8]) -> [u8; 64] {
        let mut h = Sha512::new();
        h.update(&self.secret);
        let h = h.finalize();
        let mut a = [0u8; 32];
        a.copy_from_slice(&h[..32]);
        clamp_scalar(&mut a);
        let prefix = &h[32..];

        let mut r_input = Vec::with_capacity(32 + message.len());
        r_input.extend_from_slice(prefix);
        r_input.extend_from_slice(message);
        let mut rh = Sha512::new();
        rh.update(&r_input);
        let r = sc_reduce(&rh.finalize());
        let big_r = scalar_mul(&curve::base_point(), &r).encode();

        let mut k_input = Vec::with_capacity(64 + message.len());
        k_input.extend_from_slice(&big_r);
        k_input.extend_from_slice(&self.public);
        k_input.extend_from_slice(message);
        let mut kh = Sha512::new();
        kh.update(&k_input);
        let k = sc_reduce(&kh.finalize());

        let s = sc_muladd(&k, &a, &r);
        let mut sig = [0u8; 64];
        sig[..32].copy_from_slice(&big_r);
        sig[32..].copy_from_slice(&s);
        a.zeroize();
        r_input.zeroize();
        sig
    }

    /// Signs with a caller-provided 32-byte prefix instead of deriving it from
    /// the seed's hash (used for deterministic domain-separated signing keys).
    pub fn sign_prehashed(&self, message: &[u8]) -> [u8; 64] {
        self.sign(message)
    }
}

impl Drop for Keypair {
    fn drop(&mut self) {
        self.secret.zeroize();
    }
}

/// Verifies a detached Ed25519 signature.
///
/// Rejects non-canonical `S` (signature malleability), invalid public keys and
/// invalid `R` encodings, and performs the strict equation check
/// `[S]B = R + [k]A`.
pub fn verify(public_key: &[u8; 32], message: &[u8], signature: &[u8; 64]) -> bool {
    let mut r_bytes = [0u8; 32];
    r_bytes.copy_from_slice(&signature[..32]);
    let mut s_bytes = [0u8; 32];
    s_bytes.copy_from_slice(&signature[32..]);
    if !scalar_is_canonical(&s_bytes) {
        return false;
    }
    let a = match decompress(public_key) {
        Some(p) => p,
        None => return false,
    };
    let r_point = match decompress(&r_bytes) {
        Some(p) => p,
        None => return false,
    };
    let mut k_input = Vec::with_capacity(64 + message.len());
    k_input.extend_from_slice(&r_bytes);
    k_input.extend_from_slice(public_key);
    k_input.extend_from_slice(message);
    let mut kh = Sha512::new();
    kh.update(&k_input);
    let k = sc_reduce(&kh.finalize());

    let lhs = scalar_mul_vartime(&curve::base_point(), &s_bytes);
    let ka = scalar_mul_vartime(&a, &k);
    let diff = lhs.add(&ka.neg());
    ct_eq(&diff.encode(), &r_point.encode())
}

/// Clamps a 32-byte scalar in place as required for Ed25519 secret scalars.
pub fn clamp_scalar(a: &mut [u8; 32]) {
    a[0] &= 248;
    a[31] &= 127;
    a[31] |= 64;
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{:02x}", x)).collect()
    }

    fn unhex(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[i * 2..i * 2 + 2], 16).unwrap())
            .collect()
    }

    #[test]
    fn curve_constants_are_consistent() {
        let lhs = curve::d().mul(&Fe::from_u64(121_666));
        let rhs = Fe::from_u64(121_665).neg();
        assert_eq!(lhs.to_bytes(), rhs.to_bytes(), "d must equal -121665/121666");
        let s = curve::sqrtm1().square();
        assert_eq!(s.to_bytes(), Fe::ONE.neg().to_bytes(), "sqrt(-1)^2 == -1");
        let (x, y) = curve::base_point().to_affine();
        let lhs = y.square().sub(&x.square());
        let rhs = Fe::ONE.add(&curve::d().mul(&x.square()).mul(&y.square()));
        assert_eq!(lhs.to_bytes(), rhs.to_bytes(), "base point on curve");
    }

    #[test]
    fn field_encoding_roundtrip() {
        for i in 0..64u8 {
            let mut bytes = [0u8; 32];
            for (j, b) in bytes.iter_mut().enumerate() {
                *b = (i as u16 * 17 + j as u16 * 5) as u8;
            }
            bytes[31] &= 0x7f;
            let fe = Fe::from_bytes(&bytes);
            assert_eq!(fe.to_bytes(), bytes, "encoding roundtrip");
        }
        // p itself encodes as zero.
        let mut p_bytes = [0xffu8; 32];
        p_bytes[0] = 0xed;
        p_bytes[31] = 0x7f;
        assert_eq!(Fe::from_bytes(&p_bytes).to_bytes(), [0u8; 32]);
    }

    #[test]
    fn field_arithmetic_identities() {
        let a = Fe::from_bytes(
            &unhex("0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20")
                .try_into()
                .unwrap(),
        );
        let b = Fe::from_bytes(
            &unhex("ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100")
                .try_into()
                .unwrap(),
        );
        assert_eq!(a.mul(&a.invert()).to_bytes(), Fe::ONE.to_bytes());
        assert_eq!(a.add(&b).sub(&b).to_bytes(), a.to_bytes());
        assert_eq!(a.mul(&b).to_bytes(), b.mul(&a).to_bytes());
        assert_eq!(a.square().to_bytes(), a.mul(&a).to_bytes());
        assert_eq!(a.neg().add(&a).to_bytes(), Fe::ZERO.to_bytes());
    }

    #[test]
    fn scalar_reduction_and_muladd() {
        // L reduces to zero.
        let mut input = [0u8; 64];
        let l = l_limbs();
        for i in 0..4 {
            input[i * 8..i * 8 + 8].copy_from_slice(&l[i].to_le_bytes());
        }
        assert_eq!(sc_reduce(&input), [0u8; 32]);

        // (L-1) + 1 == 0 mod L via muladd with a = 1.
        let mut one_minus = [0xffu8; 32];
        let mut borrow = 1i128;
        for i in 0..32 {
            // L as 32 bytes
            let li = (L[i / 4] >> (8 * (i % 4))) as u8;
            let v = li as i128 - borrow;
            if v < 0 {
                one_minus[i] = (v + 256) as u8;
                borrow = 1;
            } else {
                one_minus[i] = v as u8;
                borrow = 0;
            }
        }
        let mut one = [0u8; 32];
        one[0] = 1;
        let zero = [0u8; 32];
        let res = sc_muladd(&one, &one_minus, &zero);
        // (L-1) * 1 == L-1
        assert_eq!(res, one_minus);
        let res2 = sc_muladd(&one, &one_minus, &one);
        assert_eq!(res2, [0u8; 32], "(L-1) + 1 == 0 mod L");
    }

    #[test]
    fn rfc8032_test_vectors() {
        let vectors = [
            (
                "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
                "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
                "",
                "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
            ),
            (
                "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
                "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
                "72",
                "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
            ),
            (
                "c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7",
                "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025",
                "af82",
                "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a",
            ),
        ];
        for (seed, public, message, signature) in vectors {
            let seed_bytes: [u8; 32] = unhex(seed).try_into().unwrap();
            let kp = Keypair::from_seed(&seed_bytes);
            assert_eq!(hex(&kp.public_key()), public, "public key derivation");
            let msg = unhex(message);
            let sig = kp.sign(&msg);
            assert_eq!(hex(&sig), signature, "signature");
            let pk: [u8; 32] = unhex(public).try_into().unwrap();
            let sig_bytes: [u8; 64] = unhex(signature).try_into().unwrap();
            assert!(verify(&pk, &msg, &sig_bytes), "verification");
            let mut tampered = msg.clone();
            tampered.push(0);
            assert!(!verify(&pk, &tampered, &sig_bytes));
            let mut bad = sig_bytes;
            bad[0] ^= 1;
            assert!(!verify(&pk, &msg, &bad));
        }
    }

    #[test]
    fn non_canonical_signatures_are_rejected() {
        let kp = Keypair::from_seed(&[7u8; 32]);
        let msg = b"obsidian";
        let sig = kp.sign(msg);
        let pk = kp.public_key();
        assert!(verify(&pk, msg, &sig));

        let mut s = [0u8; 32];
        s.copy_from_slice(&sig[32..]);
        let mut limbs = [0u32; 8];
        let mut carry = 0u64;
        for i in 0..8 {
            let v = u32::from_le_bytes(s[i * 4..i * 4 + 4].try_into().unwrap()) as u64
                + L[i] as u64
                + carry;
            limbs[i] = v as u32;
            carry = v >> 32;
        }
        let mut malleable = sig;
        for i in 0..8 {
            malleable[32 + i * 4..32 + i * 4 + 4].copy_from_slice(&limbs[i].to_le_bytes());
        }
        assert!(
            !verify(&pk, msg, &malleable),
            "non-canonical S must be rejected"
        );

        // All-zero public key is a small-order point; a signature that does not
        // satisfy the equation must not verify.
        assert!(!verify(&[0u8; 32], msg, &sig));
    }

    #[test]
    fn sign_verify_roundtrip() {
        for i in 0..16u8 {
            let mut seed = [0u8; 32];
            for (j, b) in seed.iter_mut().enumerate() {
                *b = (i as u16 * 31 + j as u16 * 7) as u8;
            }
            let kp = Keypair::from_seed(&seed);
            let msg = vec![i; (i as usize) * 3 + 1];
            let sig = kp.sign(&msg);
            assert!(verify(&kp.public_key(), &msg, &sig));
        }
    }
}
