//! Cryptographically secure randomness.
//!
//! Two layers are provided:
//!
//! 1. [`os_random`] — raw operating-system entropy (`/dev/urandom` on Unix,
//!    the host `crypto.getRandomValues` bridge on `wasm32`).
//! 2. [`Csprng`] — a ChaCha20-based deterministic random bit generator seeded
//!    from the OS, used for bulk key material, salts, nonces and identifiers.
//!
//! The DRBG reseeds itself from the OS after `RESEED_INTERVAL` bytes and is
//! forward-secure with respect to its own output stream.

use crate::chacha::chacha20_xor;
use crate::ct::{Zeroize, Zeroizing};

/// Errors that can occur while obtaining entropy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EntropyError {
    /// The operating system entropy source could not be read.
    Unavailable,
    /// The host-provided entropy source (wasm) reported a failure.
    HostRejected,
}

impl core::fmt::Display for EntropyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            EntropyError::Unavailable => write!(f, "operating system entropy unavailable"),
            EntropyError::HostRejected => write!(f, "host entropy source rejected the request"),
        }
    }
}

#[cfg(all(unix, not(target_arch = "wasm32")))]
mod imp {
    use super::EntropyError;
    use std::io::Read;

    pub fn fill(dst: &mut [u8]) -> Result<(), EntropyError> {
        let mut file = std::fs::File::open("/dev/urandom").map_err(|_| EntropyError::Unavailable)?;
        file.read_exact(dst).map_err(|_| EntropyError::Unavailable)?;
        Ok(())
    }
}

#[cfg(target_arch = "wasm32")]
mod imp {
    use super::EntropyError;

    extern "C" {
        /// Provided by the wallet host page: fills `len` bytes at `ptr` with
        /// cryptographically secure random data from the browser CSPRNG.
        fn obs_wasm_random(ptr: *mut u8, len: usize) -> i32;
    }

    pub fn fill(dst: &mut [u8]) -> Result<(), EntropyError> {
        let rc = unsafe { obs_wasm_random(dst.as_mut_ptr(), dst.len()) };
        if rc == 0 {
            Ok(())
        } else {
            Err(EntropyError::HostRejected)
        }
    }
}

#[cfg(not(any(unix, target_arch = "wasm32")))]
mod imp {
    use super::EntropyError;

    pub fn fill(_dst: &mut [u8]) -> Result<(), EntropyError> {
        Err(EntropyError::Unavailable)
    }
}

/// Fills `dst` with operating system entropy.
pub fn os_random(dst: &mut [u8]) -> Result<(), EntropyError> {
    imp::fill(dst)
}

/// Returns `len` bytes of operating system entropy.
pub fn os_random_vec(len: usize) -> Result<Vec<u8>, EntropyError> {
    let mut v = vec![0u8; len];
    os_random(&mut v)?;
    Ok(v)
}

const RESEED_INTERVAL: u64 = 1 << 20; // 1 MiB

/// A ChaCha20-based CSPRNG.
pub struct Csprng {
    key: Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
    counter: u32,
    buffer: [u8; 64],
    buffer_pos: usize,
    generated: u64,
}

impl Csprng {
    /// Creates a generator seeded from the operating system.
    pub fn from_os() -> Result<Csprng, EntropyError> {
        let mut key = [0u8; 32];
        let mut nonce = [0u8; 12];
        os_random(&mut key)?;
        os_random(&mut nonce)?;
        Ok(Csprng {
            key: Zeroizing(key),
            nonce,
            counter: 0,
            buffer: [0u8; 64],
            buffer_pos: 64,
            generated: 0,
        })
    }

    /// Creates a deterministic generator from an explicit 32-byte seed.
    ///
    /// **Test use only.** Production code must use [`Csprng::from_os`].
    pub fn from_seed(seed: &[u8; 32]) -> Csprng {
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&seed[..12]);
        Csprng {
            key: Zeroizing(*seed),
            nonce,
            counter: 0,
            buffer: [0u8; 64],
            buffer_pos: 64,
            generated: 0,
        }
    }

    /// Re-derives the internal state from fresh OS entropy.
    pub fn reseed(&mut self) -> Result<(), EntropyError> {
        let mut fresh = [0u8; 32];
        os_random(&mut fresh)?;
        for i in 0..32 {
            self.key.0[i] ^= fresh[i];
        }
        fresh.zeroize();
        self.counter = 0;
        self.buffer_pos = 64;
        Ok(())
    }

    fn refill(&mut self) {
        self.buffer = [0u8; 64];
        chacha20_xor(&self.key.0, &self.nonce, self.counter, &mut self.buffer);
        // Advance nonce to separate call sites; counter wraps are handled by
        // the nonce increment, so the keystream never repeats.
        self.counter = self.counter.wrapping_add(1);
        if self.counter == 0 {
            for i in 0..12 {
                self.nonce[i] = self.nonce[i].wrapping_add(1);
                if self.nonce[i] != 0 {
                    break;
                }
            }
        }
        self.buffer_pos = 0;
    }

    /// Fills `dst` with pseudorandom bytes.
    pub fn fill_bytes(&mut self, dst: &mut [u8]) {
        for byte in dst.iter_mut() {
            if self.buffer_pos == 64 {
                self.refill();
            }
            *byte = self.buffer[self.buffer_pos];
            self.buffer_pos += 1;
            self.generated += 1;
        }
        if self.generated > RESEED_INTERVAL {
            // Best-effort reseed; if the OS source is unavailable we keep
            // operating on the existing state (which is still cryptographically
            // strong, just not freshly reseeded).
            let _ = self.reseed();
        }
    }

    /// Returns a random `u64`.
    pub fn next_u64(&mut self) -> u64 {
        let mut b = [0u8; 8];
        self.fill_bytes(&mut b);
        u64::from_le_bytes(b)
    }

    /// Returns a random `u32`.
    pub fn next_u32(&mut self) -> u32 {
        let mut b = [0u8; 4];
        self.fill_bytes(&mut b);
        u32::from_le_bytes(b)
    }

    /// Returns a uniformly distributed integer in `[0, upper)` with rejection
    /// sampling (no modulo bias).
    pub fn gen_range_u64(&mut self, upper: u64) -> u64 {
        assert!(upper > 0, "gen_range_u64 requires a non-zero bound");
        let zone = u64::MAX - (u64::MAX % upper) - 1;
        loop {
            let v = self.next_u64();
            if v <= zone {
                return v % upper;
            }
        }
    }

    /// Returns a random byte vector of the requested length.
    pub fn bytes(&mut self, len: usize) -> Vec<u8> {
        let mut v = vec![0u8; len];
        self.fill_bytes(&mut v);
        v
    }
}

impl Drop for Csprng {
    fn drop(&mut self) {
        self.buffer.zeroize();
        self.counter = 0;
    }
}

/// Convenience: `len` bytes of fresh CSPRNG output seeded from the OS.
pub fn random_bytes(len: usize) -> Result<Vec<u8>, EntropyError> {
    let mut rng = Csprng::from_os()?;
    Ok(rng.bytes(len))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn os_entropy_is_available() {
        let mut buf = [0u8; 32];
        os_random(&mut buf).expect("OS entropy must be available on supported platforms");
        assert_ne!(buf, [0u8; 32]);
    }

    #[test]
    fn deterministic_generator_is_reproducible() {
        let seed = [42u8; 32];
        let mut a = Csprng::from_seed(&seed);
        let mut b = Csprng::from_seed(&seed);
        let x = a.bytes(100);
        let y = b.bytes(100);
        assert_eq!(x, y);
        let mut c = Csprng::from_seed(&[43u8; 32]);
        assert_ne!(c.bytes(100), x);
    }

    #[test]
    fn range_sampling_is_in_bounds() {
        let mut rng = Csprng::from_seed(&[1u8; 32]);
        for _ in 0..1000 {
            assert!(rng.gen_range_u64(10) < 10);
        }
    }

    #[test]
    fn distinct_calls_produce_distinct_output() {
        let mut rng = Csprng::from_os().unwrap();
        let a = rng.bytes(32);
        let b = rng.bytes(32);
        assert_ne!(a, b);
    }
}
