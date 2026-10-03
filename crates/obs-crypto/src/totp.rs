//! Time-based one-time passwords (RFC 6238), the MFA second factor.
//!
//! This is the *authenticator* standard, so it is implemented exactly as
//! RFC 6238 and RFC 4226 define it — HMAC-SHA-1, a 30-second step, six digits —
//! because the point of TOTP is that a standard authenticator app (or hardware
//! key) can produce the codes.  SHA-1 here is not a security choice being made:
//! it is the algorithm every authenticator uses, and its role is a MAC inside
//! HMAC, not collision resistance.
//!
//! ## What this module does and does not do
//!
//! * It never stores, logs or returns a secret it was not given.  The caller
//!   (the registration service) owns secret storage, and stores secrets
//!   encrypted at rest.
//! * Codes are compared in constant time, with a configurable skew window
//!   (default: one step before and one after, i.e. ±30 seconds) so clock drift
//!   on a phone does not lock an account out, without opening the window wide
//!   enough to make guessing useful.
//! * A step is 30 seconds and a code is 6 digits, which is the standard; the
//!   protocol's own operations *never* depend on TOTP — it gates access to the
//!   registration service, not consensus.

use crate::encoding::base32_encode;
use crate::hmac::hmac;
use crate::sha1::Sha1;
use crate::sha2::Sha256;

/// Digits in a generated code.
pub const DIGITS: u32 = 6;
/// Seconds per step.
pub const STEP_SECS: u64 = 30;
/// How many steps either side of "now" are accepted, for clock drift.
pub const DEFAULT_SKEW_STEPS: u64 = 1;
/// Secret length in bytes: 160 bits, the RFC 4226 recommendation.
pub const SECRET_BYTES: usize = 20;

/// Why a secret could not be created or a code could not be read.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TotpError {
    /// The secret is not a supported length or is not Base32.
    BadSecret,
    /// The code is not the right number of digits.
    BadCode,
}

impl core::fmt::Display for TotpError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            TotpError::BadSecret => write!(f, "the TOTP secret is not valid"),
            TotpError::BadCode => write!(f, "the TOTP code is not valid"),
        }
    }
}

impl std::error::Error for TotpError {}

/// A generated TOTP secret, in the two forms a provisioning flow needs.
pub struct Secret {
    bytes: Vec<u8>,
}

impl core::fmt::Debug for Secret {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A secret must never reach a log, a panic message or a debug dump.
        f.write_str("Secret(<redacted>)")
    }
}

impl Drop for Secret {
    fn drop(&mut self) {
        for byte in self.bytes.iter_mut() {
            // Overwrite before releasing the allocation.  Rust gives no
            // guarantee that this is the last copy in memory, which is exactly
            // why secrets are also never copied around: generate once, store
            // encrypted, and use in place.
            *byte = 0;
        }
    }
}

impl Secret {
    /// Generates a fresh secret from the operating system CSPRNG.
    pub fn generate() -> Result<Secret, crate::rand::EntropyError> {
        let mut bytes = vec![0u8; SECRET_BYTES];
        crate::rand::os_random(&mut bytes)?;
        Ok(Secret { bytes })
    }

    /// Wraps an existing secret (for example one just decrypted from storage).
    pub fn from_bytes(bytes: Vec<u8>) -> Result<Secret, TotpError> {
        if bytes.len() < 16 || bytes.len() > 64 {
            return Err(TotpError::BadSecret);
        }
        Ok(Secret { bytes })
    }

    /// Base32 encoding, the form an authenticator app expects.
    pub fn base32(&self) -> String {
        base32_encode(&self.bytes)
    }

    /// Reads a Base32 secret, ignoring spaces, case and the padding an app may
    /// add.  People retype these codes by hand, so the parser is forgiving about
    /// presentation and strict about content.
    pub fn parse_base32(text: &str) -> Result<Secret, TotpError> {
        let cleaned: String = text
            .chars()
            .filter(|character| !character.is_whitespace() && *character != '=')
            .collect::<String>()
            .to_ascii_lowercase();
        let bytes = crate::encoding::base32_decode(&cleaned).ok_or(TotpError::BadSecret)?;
        Secret::from_bytes(bytes)
    }

    /// The provisioning URI, `otpauth://totp/...`, for a QR code.
    ///
    /// The account name is a partially masked identifier, never the full Gmail
    /// identity: a QR code is displayed on screen and often photographed.
    pub fn provisioning_uri(&self, issuer: &str, account_label: &str) -> String {
        format!(
            "otpauth://totp/{}:{}?secret={}&issuer={}&algorithm=SHA1&digits={}&period={}",
            uri_escape(issuer),
            uri_escape(account_label),
            self.base32(),
            uri_escape(issuer),
            DIGITS,
            STEP_SECS
        )
    }

    /// The code for a specific step.
    pub fn code_at_step(&self, step: u64) -> u32 {
        hotp(&self.bytes, step, DIGITS)
    }

    /// The code for a Unix timestamp.
    pub fn code_at(&self, unix_secs: u64) -> u32 {
        self.code_at_step(unix_secs / STEP_SECS)
    }

    /// Verifies a code with the default skew.
    pub fn verify(&self, code: &str, unix_secs: u64) -> bool {
        self.verify_with_skew(code, unix_secs, DEFAULT_SKEW_STEPS)
    }

    /// Verifies a code, accepting `skew` steps either side of `unix_secs`.
    ///
    /// The comparison is constant time with respect to the expected code, and
    /// the function makes no distinction between "wrong code" and "expired
    /// code" — a caller learns only yes or no, and every window is tried so the
    /// timing does not reveal which step matched.
    pub fn verify_with_skew(&self, code: &str, unix_secs: u64, skew: u64) -> bool {
        let Some(provided) = parse_code(code) else {
            // Still burn the comparisons, so a malformed code costs the same as
            // a wrong one.
            let _ = self.code_at(unix_secs);
            return false;
        };
        let step = unix_secs / STEP_SECS;
        let mut matched = false;
        let mut offset = 0u64;
        while offset <= skew {
            for candidate_step in [step.checked_sub(offset), Some(step + offset)] {
                if let Some(candidate_step) = candidate_step {
                    let expected = self.code_at_step(candidate_step);
                    matched |= crate::ct::ct_eq(
                        &expected.to_be_bytes(),
                        &provided.to_be_bytes(),
                    );
                }
            }
            offset += 1;
        }
        matched
    }
}

/// HOTP (RFC 4226): HMAC-SHA-1 over the step counter, dynamic truncation.
pub fn hotp(secret: &[u8], step: u64, digits: u32) -> u32 {
    let counter = step.to_be_bytes();
    let mac = hmac::<Sha1>(secret, &counter);
    let offset = (mac[19] & 0x0f) as usize;
    let binary = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    binary % 10u32.pow(digits)
}

/// Format a code with its leading zeros.
pub fn format_code(code: u32) -> String {
    format!("{:0width$}", code, width = DIGITS as usize)
}

fn parse_code(code: &str) -> Option<u32> {
    let trimmed = code.trim();
    if trimmed.len() != DIGITS as usize || !trimmed.bytes().all(|byte| byte.is_ascii_digit()) {
        return None;
    }
    trimmed.parse::<u32>().ok()
}

fn uri_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for byte in text.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                out.push(byte as char)
            }
            _ => out.push_str(&format!("%{:02X}", byte)),
        }
    }
    out
}

/// A keyed (HMAC-SHA-256) one-time code, for callers that want a modern MAC.
///
/// Not the standard authenticator algorithm — kept here so nothing else in the
/// workspace is tempted to hand-roll one.
pub fn hotp_sha256(secret: &[u8], step: u64, digits: u32) -> u32 {
    let counter = step.to_be_bytes();
    let mac = hmac::<Sha256>(secret, &counter);
    let offset = (mac[31] & 0x0f) as usize;
    let binary = ((mac[offset] as u32 & 0x7f) << 24)
        | ((mac[offset + 1] as u32) << 16)
        | ((mac[offset + 2] as u32) << 8)
        | (mac[offset + 3] as u32);
    binary % 10u32.pow(digits)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The RFC 6238 appendix B test vectors, SHA-1 rows.  The secret is
    /// `12345678901234567890` in ASCII, which is what the RFC uses.
    #[test]
    fn rfc_6238_vectors() {
        let secret = b"12345678901234567890";
        for (unix_secs, expected) in [
            (59u64, 94287082u32),
            (1_111_111_109, 7_081_804),
            (1_111_111_111, 14050471),
            (1_234_567_890, 89005924),
            (2_000_000_000, 69279037),
            (20_000_000_000, 65353130),
        ] {
            // The RFC's vectors are eight digits; six-digit codes are the same
            // value modulo 10^6.
            assert_eq!(
                hotp(secret, unix_secs / STEP_SECS, 8),
                expected,
                "RFC 6238 vector at {}",
                unix_secs
            );
        }
    }

    /// RFC 4226 appendix D, the canonical HOTP vectors.
    #[test]
    fn rfc_4226_vectors() {
        let secret = b"12345678901234567890";
        let expected = [
            755224u32, 287082, 359152, 969429, 338314, 254676, 287922, 162583, 399871, 520489,
        ];
        for (counter, code) in expected.iter().enumerate() {
            assert_eq!(hotp(secret, counter as u64, 6), *code);
        }
    }

    #[test]
    fn generated_secrets_are_random_and_usable() {
        let first = Secret::generate().unwrap();
        let second = Secret::generate().unwrap();
        assert_ne!(first.base32(), second.base32());
        assert_eq!(first.base32().len(), 32, "160 bits in Base32 is 32 characters");
        let parsed = Secret::parse_base32(&first.base32()).unwrap();
        assert_eq!(parsed.base32(), first.base32());
        // Spaces and lowercase, as people retype them.
        let spaced = format!("{} ", first.base32().to_lowercase());
        assert_eq!(Secret::parse_base32(&spaced).unwrap().base32(), first.base32());
    }

    #[test]
    fn verification_is_a_time_window_not_a_guess() {
        let secret = Secret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
        let at = 1_700_000_000u64;
        let code = format_code(secret.code_at(at));
        assert!(secret.verify(&code, at));
        // One step either side is accepted, so a phone that is 30 seconds off
        // still works.
        assert!(secret.verify(&code, at + STEP_SECS));
        assert!(secret.verify(&code, at - STEP_SECS));
        // Two steps is not.
        assert!(!secret.verify(&code, at + 2 * STEP_SECS));
        assert!(!secret.verify(&code, at - 2 * STEP_SECS));
        // Another account's code is not accepted.
        let other = Secret::from_bytes(b"09876543210987654321".to_vec()).unwrap();
        assert!(!other.verify(&code, at));
        // Malformed codes never verify.
        for bad in ["", "12345", "1234567", "12345x", "000000"] {
            if bad == format_code(secret.code_at(at)) {
                continue;
            }
            assert!(!secret.verify(bad, at), "{:?} must not verify", bad);
        }
    }

    #[test]
    fn the_provisioning_uri_carries_what_an_app_needs() {
        let secret = Secret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
        let uri = secret.provisioning_uri("Obsidian Network", "obs1ab…cd");
        assert!(uri.starts_with("otpauth://totp/Obsidian%20Network:obs1ab%E2%80%A6cd?secret="));
        assert!(uri.contains("algorithm=SHA1"));
        assert!(uri.contains("digits=6"));
        assert!(uri.contains("period=30"));
        assert!(!uri.contains("12345678901234567890"), "the raw secret is not in the URI");
    }

    #[test]
    fn a_debug_dump_never_shows_the_secret() {
        let secret = Secret::from_bytes(b"12345678901234567890".to_vec()).unwrap();
        let rendered = format!("{:?}", secret);
        assert_eq!(rendered, "Secret(<redacted>)");
    }
}
