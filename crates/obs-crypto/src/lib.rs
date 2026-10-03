//! # obs-crypto
//!
//! Cryptographic primitives for Obsidian Network, implemented from published
//! specifications with **no third-party dependencies**.
//!
//! | Primitive | Specification | Used for |
//! |-----------|---------------|----------|
//! | SHA-256 / SHA-512 | FIPS 180-4 | state & transaction roots, block hashes |
//! | SHA-1 | FIPS 180-4 | HMAC-SHA-1 TOTP interoperability **only** |
//! | BLAKE2b | RFC 7693 | Argon2 core, storage checksums |
//! | HMAC | RFC 2104 | sessions, TOTP, HKDF, PBKDF2 |
//! | HKDF | RFC 5869 | key separation (server master key, API keys) |
//! | PBKDF2 | RFC 8018 | BIP-39 seed derivation |
//! | Argon2id | RFC 9106 | passwords, recovery codes, API secrets |
//! | ChaCha20-Poly1305 | RFC 8439 | encryption of secrets at rest |
//! | Ed25519 | RFC 8032 | wallet keys, validator node identity |
//! | BIP-39 | BIP-39 | 24-word wallet recovery phrases |
//! | SLIP-0010 | SLIP-0010 | deterministic hardened key derivation |
//!
//! Every primitive is tested against its published test vectors, and the
//! signature/derivation layers are additionally cross-checked against
//! independent reference implementations (see `tests/vectors.rs` and
//! `docs/security/crypto.md`).
//!
//! ## Constant-time discipline
//!
//! Secret-dependent code paths use [`ct`] helpers and avoid data-dependent
//! branches: scalar multiplication for signing, MAC comparison, password hash
//! verification and code comparison are all constant-time.  Verification of
//! public-key signatures uses variable-time arithmetic, which is safe because
//! the inputs are public.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod argon2;
pub mod blake2b;
pub mod chacha;
pub mod ct;
pub mod ed25519;
pub mod encoding;
pub mod hmac;
pub mod mnemonic;
pub mod rand;
pub mod sha1;
pub mod sha2;
pub mod totp;

/// Version of the cryptographic suite, reported in release metadata.
pub const CRYPTO_SUITE_VERSION: &str = "obsidian-crypto/1.0.0";

/// AES is deliberately **not** implemented: ChaCha20-Poly1305 is used
/// everywhere, which is constant-time in software and needs no hardware
/// acceleration to be safe.
pub const AEAD_ALGORITHM: &str = "ChaCha20-Poly1305";

/// Signature algorithm used by wallets and validator node identities.
pub const SIGNATURE_ALGORITHM: &str = "Ed25519";

/// Wallet entropy strength in bits (protocol minimum for wallet generation).
pub const WALLET_ENTROPY_BITS: usize = 256;

// ---------------------------------------------------------------------------
// Minimal wasm ABI (feature `wasm-abi`)
// ---------------------------------------------------------------------------

#[cfg(all(feature = "wasm-abi", target_arch = "wasm32"))]
mod wasm_abi {
    //! A tiny, allocation-aware C ABI used by the browser wallet.
    //!
    //! The JavaScript host allocates a buffer with [`obs_alloc`], fills it with
    //! input data, calls a function, and releases buffers with [`obs_free`].
    //! Only public wallet operations are exposed; private keys never leave the
    //! module.

    use crate::ed25519::Keypair;

    /// Allocates `len` bytes and returns a pointer the host can write to.
    #[no_mangle]
    pub extern "C" fn obs_alloc(len: usize) -> *mut u8 {
        let mut v = vec![0u8; len];
        let ptr = v.as_mut_ptr();
        core::mem::forget(v);
        ptr
    }

    /// Frees a buffer previously returned by [`obs_alloc`].
    ///
    /// # Safety
    /// `ptr` must come from [`obs_alloc`] with the same `len`.
    #[no_mangle]
    pub unsafe extern "C" fn obs_free(ptr: *mut u8, len: usize) {
        if ptr.is_null() {
            return;
        }
        unsafe {
            drop(Vec::from_raw_parts(ptr, len, len));
        }
    }

    /// Signs a message with a 32-byte seed.  `out` receives 64 bytes.
    ///
    /// # Safety
    /// All pointers must be valid for the stated lengths.
    #[no_mangle]
    pub unsafe extern "C" fn obs_ed25519_sign(
        seed: *const u8,
        msg: *const u8,
        msg_len: usize,
        out: *mut u8,
    ) -> i32 {
        if seed.is_null() || out.is_null() || (msg.is_null() && msg_len > 0) {
            return -1;
        }
        let seed_slice = unsafe { core::slice::from_raw_parts(seed, 32) };
        let msg_slice = if msg_len == 0 {
            &[][..]
        } else {
            unsafe { core::slice::from_raw_parts(msg, msg_len) }
        };
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(seed_slice);
        let kp = Keypair::from_seed(&seed_arr);
        let sig = kp.sign(msg_slice);
        unsafe {
            core::ptr::copy_nonoverlapping(sig.as_ptr(), out, 64);
        }
        0
    }

    /// Derives the 32-byte public key from a 32-byte seed.
    ///
    /// # Safety
    /// Pointers must be valid for the stated lengths.
    #[no_mangle]
    pub unsafe extern "C" fn obs_ed25519_public_key(seed: *const u8, out: *mut u8) -> i32 {
        if seed.is_null() || out.is_null() {
            return -1;
        }
        let mut seed_arr = [0u8; 32];
        seed_arr.copy_from_slice(unsafe { core::slice::from_raw_parts(seed, 32) });
        let kp = Keypair::from_seed(&seed_arr);
        let pk = kp.public_key();
        unsafe {
            core::ptr::copy_nonoverlapping(pk.as_ptr(), out, 32);
        }
        0
    }
}
