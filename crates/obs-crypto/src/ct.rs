//! Constant-time helpers.
//!
//! These primitives are used by every secret-dependent code path (signature
//! generation, MAC verification, password verification, code comparison).
//! They must never be replaced by `==` on secret data.

use core::sync::atomic::{compiler_fence, Ordering};

/// Constant-time equality for byte slices of equal length.
///
/// Returns `true` when both slices have identical content.  The running time
/// depends only on the (public) length, never on the content.
#[inline]
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for i in 0..a.len() {
        diff |= a[i] ^ b[i];
    }
    compiler_fence(Ordering::SeqCst);
    diff == 0
}

/// Constant-time equality for fixed-size arrays.
#[inline]
pub fn ct_eq_array<const N: usize>(a: &[u8; N], b: &[u8; N]) -> bool {
    ct_eq(a, b)
}

/// Returns `true` if all bytes are zero, without branching on the content.
#[inline]
pub fn ct_is_zero(bytes: &[u8]) -> bool {
    let mut acc = 0u8;
    for b in bytes {
        acc |= *b;
    }
    compiler_fence(Ordering::SeqCst);
    acc == 0
}

/// Constant-time conditional select over byte slices of equal length.
///
/// `if choice == 1 { out = a } else { out = b }` without a branch on `choice`.
#[inline]
pub fn ct_select(choice: u8, a: &[u8], b: &[u8], out: &mut [u8]) {
    debug_assert_eq!(a.len(), b.len());
    debug_assert_eq!(a.len(), out.len());
    let mask = 0u8.wrapping_sub(choice & 1);
    for i in 0..out.len() {
        out[i] = (a[i] & mask) | (b[i] & !mask);
    }
    compiler_fence(Ordering::SeqCst);
}

/// Constant-time conditional swap of two equal-length byte buffers.
#[inline]
pub fn ct_swap(choice: u8, a: &mut [u8], b: &mut [u8]) {
    debug_assert_eq!(a.len(), b.len());
    let mask = 0u8.wrapping_sub(choice & 1);
    for i in 0..a.len() {
        let t = mask & (a[i] ^ b[i]);
        a[i] ^= t;
        b[i] ^= t;
    }
    compiler_fence(Ordering::SeqCst);
}

/// A wrapper that zeroizes its contents on drop.
///
/// Used for seeds, private keys, password hashes and derived key material so
/// that secrets do not linger in freed memory.
pub struct Zeroizing<T: Zeroize>(pub T);

impl<T: Zeroize> Drop for Zeroizing<T> {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl<T: Zeroize> core::ops::Deref for Zeroizing<T> {
    type Target = T;
    fn deref(&self) -> &T {
        &self.0
    }
}

impl<T: Zeroize> core::ops::DerefMut for Zeroizing<T> {
    fn deref_mut(&mut self) -> &mut T {
        &mut self.0
    }
}

/// Types that can securely erase their contents.
pub trait Zeroize {
    /// Overwrites the value with zeros using volatile writes.
    fn zeroize(&mut self);
}

impl Zeroize for [u8] {
    #[inline]
    fn zeroize(&mut self) {
        for b in self.iter_mut() {
            unsafe { core::ptr::write_volatile(b, 0u8) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl Zeroize for Vec<u8> {
    #[inline]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<const N: usize> Zeroize for [u64; N] {
    #[inline]
    fn zeroize(&mut self) {
        for w in self.iter_mut() {
            unsafe { core::ptr::write_volatile(w, 0u64) };
        }
        compiler_fence(Ordering::SeqCst);
    }
}

impl<const N: usize> Zeroize for [u8; N] {
    #[inline]
    fn zeroize(&mut self) {
        self.as_mut_slice().zeroize();
    }
}

impl<T: Zeroize> Zeroize for Option<T> {
    #[inline]
    fn zeroize(&mut self) {
        if let Some(v) = self.as_mut() {
            v.zeroize();
        }
    }
}

impl<T: Zeroize> Zeroize for &mut T {
    #[inline]
    fn zeroize(&mut self) {
        (**self).zeroize();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn eq_works() {
        assert!(ct_eq(b"abc", b"abc"));
        assert!(!ct_eq(b"abc", b"abd"));
        assert!(!ct_eq(b"abc", b"ab"));
    }

    #[test]
    fn select_works() {
        let a = [1u8, 2, 3];
        let b = [9u8, 8, 7];
        let mut out = [0u8; 3];
        ct_select(1, &a, &b, &mut out);
        assert_eq!(out, a);
        ct_select(0, &a, &b, &mut out);
        assert_eq!(out, b);
    }

    #[test]
    fn swap_works() {
        let mut a = [1u8, 2];
        let mut b = [3u8, 4];
        ct_swap(1, &mut a, &mut b);
        assert_eq!(a, [3, 4]);
        assert_eq!(b, [1, 2]);
        ct_swap(0, &mut a, &mut b);
        assert_eq!(a, [3, 4]);
    }

    #[test]
    fn zeroizing_clears() {
        let mut buf = vec![7u8; 32];
        buf.zeroize();
        assert_eq!(buf, vec![0u8; 32]);
    }
}
