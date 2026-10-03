//! Account recovery, and why it is not wallet recovery.
//!
//! There are two ways to lose an Obsidian account, and they need two different
//! mechanisms.  Confusing them is how custodial wallets happen, so this module
//! keeps them apart in code as well as in the documentation:
//!
//! | | Wallet recovery | Account recovery |
//! |---|---|---|
//! | **Restores** | the keys | access to the account record |
//! | **Secret** | the 24-word phrase | a single-use recovery code |
//! | **Held by** | the user, offline | the user, plus a hash on the registration service |
//! | **Can move value?** | yes — it *is* the wallet | **no** |
//! | **Needs a server?** | no | yes |
//!
//! ## Account recovery codes
//!
//! At registration the service issues one high-entropy code (160 bits, in a
//! human-transcribable format).  It is displayed once, stored only as an
//! Argon2id hash, is single-use, and is *not* the wallet key: it authorises
//! administrative acts on the account record — re-enrolling MFA, resetting a
//! password, unblocking a locked account — and nothing that touches chain state.
//! The chain never sees it, so a stolen code cannot move a single grain.
//!
//! ## Key rotation
//!
//! If the *phrase* leaks, administrative recovery is not enough: the attacker has
//! the wallet key.  The remedy is the on-chain recovery key, derived at role 2,
//! which authorises a wallet-key rotation.  Rotation is a signed transaction, so
//! it is subject to every consensus rule, and it is the only path that changes
//! which key owns an account.
//!
//! ## The service's own limits
//!
//! The registration service can be tricked into *issuing* a rotation
//! authorisation by whoever holds the recovery code, but it cannot perform the
//! rotation itself: only the recovery key can sign it.  That is the boundary that
//! keeps account recovery non-custodial.

use obs_crypto::argon2::{argon2id, Argon2Params};
use obs_crypto::ct::{ct_eq, Zeroize, Zeroizing};

use crate::WalletError;

/// Entropy behind an account recovery code: 160 bits.
pub const RECOVERY_CODE_ENTROPY_BITS: usize = 160;
/// Alphabet used for the code's body: Crockford Base32, which has no `I`, `L`,
/// `O` or `U`, so a code read off paper cannot be mistyped into another code.
pub const ALPHABET: &[u8; 32] = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
/// Groups of four characters, separated by dashes.
pub const GROUP: usize = 4;
/// Groups per code: 8 × 4 characters = 32 characters = 160 bits.
pub const GROUPS: usize = 8;

/// A freshly generated account recovery code.  Shown once; never stored in this
/// form.
pub struct RecoveryCode {
    body: String,
}

impl core::fmt::Debug for RecoveryCode {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // A recovery code is a credential: it must not reach a log or a panic
        // message, whatever its entropy suggests.
        f.write_str("RecoveryCode(<redacted>)")
    }
}

impl Drop for RecoveryCode {
    fn drop(&mut self) {
        // Overwrite the heap buffer before it is released.
        let mut bytes = std::mem::take(&mut self.body).into_bytes();
        bytes.zeroize();
    }
}

impl RecoveryCode {
    /// Generates a code from the operating system CSPRNG.
    pub fn generate() -> Result<RecoveryCode, WalletError> {
        let bits = RECOVERY_CODE_ENTROPY_BITS;
        let characters = GROUPS * GROUP;
        let mut raw = vec![0u8; (bits + 7) / 8];
        obs_crypto::rand::os_random(&mut raw)?;
        let mut body = String::with_capacity(characters + GROUPS);
        let mut accumulator: u32 = 0;
        let mut available = 0u32;
        let mut index = 0usize;
        for _ in 0..characters {
            while available < 5 {
                accumulator = (accumulator << 8) | raw[index % raw.len()] as u32;
                index += 1;
                available += 8;
            }
            available -= 5;
            let value = ((accumulator >> available) & 0x1f) as usize;
            body.push(ALPHABET[value] as char);
        }
        raw.zeroize();
        // Group the body for transcription: XXXX-XXXX-...
        let mut grouped = String::with_capacity(body.len() + GROUPS);
        for (position, character) in body.chars().enumerate() {
            if position > 0 && position % GROUP == 0 {
                grouped.push('-');
            }
            grouped.push(character);
        }
        Ok(RecoveryCode { body: grouped })
    }

    /// The code, in the form a human writes down.
    pub fn as_str(&self) -> &str {
        &self.body
    }

    /// The code in a form a comparison can use: uppercase, no dashes, with the
    /// look-alike characters folded (`I`/`L` → `1`, `O` → `0`).
    pub fn normalize(text: &str) -> String {
        text.chars()
            .filter(|character| character.is_ascii_alphanumeric())
            .map(|character| match character.to_ascii_uppercase() {
                'I' | 'L' => '1',
                'O' => '0',
                'U' => 'V',
                other => other,
            })
            .collect()
    }

    /// The hash the registration service stores.  Never the code itself.
    pub fn hash(&self) -> Result<RecoveryHash, WalletError> {
        RecoveryHash::of(&self.body)
    }

    /// Length of the code's normalised body, for validation messages.
    pub fn body_len() -> usize {
        GROUPS * GROUP
    }
}

/// A stored hash of an account recovery code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryHash {
    salt: Vec<u8>,
    tag: Vec<u8>,
}

impl RecoveryHash {
    /// Hashes a recovery code with the protocol's high-entropy-code parameters.
    ///
    /// The code already has 160 bits of entropy, so the KDF is not the main
    /// defence; it is there so that a database dump cannot be verified offline
    /// without cost.
    pub fn of(code: &str) -> Result<RecoveryHash, WalletError> {
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt)?;
        let normalized = RecoveryCode::normalize(code);
        if normalized.len() != RecoveryCode::body_len() {
            return Err(WalletError::BadSeed(
                "an account recovery code is 32 characters".to_string(),
            ));
        }
        let mut tag = Zeroizing(
            argon2id(&Argon2Params::HIGH_ENTROPY_CODE, normalized.as_bytes(), &salt)
                .map_err(|detail| WalletError::BadSeed(detail.to_string()))?,
        );
        let hash = RecoveryHash {
            salt: salt.to_vec(),
            tag: tag.to_vec(),
        };
        tag.zeroize();
        Ok(hash)
    }

    /// Verifies a presented code in constant time.
    pub fn verify(&self, presented: &str) -> bool {
        let normalized = RecoveryCode::normalize(presented);
        if normalized.len() != RecoveryCode::body_len() {
            // Still spend the KDF so that a malformed code is not cheaper to
            // test than a real one.
            let _ = argon2id(
                &Argon2Params::HIGH_ENTROPY_CODE,
                b"invalid-recovery-code-placeholder",
                &self.salt,
            );
            return false;
        }
        match argon2id(&Argon2Params::HIGH_ENTROPY_CODE, normalized.as_bytes(), &self.salt) {
            Ok(candidate) => ct_eq(&candidate, &self.tag),
            Err(_) => false,
        }
    }

    /// The salt, for storage in a database column.
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    /// The hash, for storage in a database column.
    pub fn tag(&self) -> &[u8] {
        &self.tag
    }

    /// Rebuilds a hash from stored columns.
    pub fn from_parts(salt: &[u8], tag: &[u8]) -> RecoveryHash {
        RecoveryHash {
            salt: salt.to_vec(),
            tag: tag.to_vec(),
        }
    }
}

/// What account recovery may and may not do.  This enum exists so that a
/// service cannot quietly grow a "recover the funds" branch: the permitted acts
/// are a closed set, and every one of them is an administrative act on the
/// account record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecoveryAct {
    /// Let the owner enrol a new MFA device.
    ReenrolMfa,
    /// Let the owner set a new password.
    ResetPassword,
    /// Clear a lock caused by failed attempts.
    UnlockAccount,
    /// Issue a wallet-key rotation authorisation, which the *recovery key* must
    /// then sign on chain.  The service cannot complete this act alone.
    AuthoriseKeyRotation,
}

impl RecoveryAct {
    /// Whether this act can, on its own, move value or change ownership.
    ///
    /// Always `false` for every act: the whole set is administrative.  Callers
    /// that need to move value need the wallet key, which no server has.
    pub fn moves_value(self) -> bool {
        match self {
            RecoveryAct::ReenrolMfa
            | RecoveryAct::ResetPassword
            | RecoveryAct::UnlockAccount
            | RecoveryAct::AuthoriseKeyRotation => false,
        }
    }

    /// Human-readable name, for audit logs.
    pub fn name(self) -> &'static str {
        match self {
            RecoveryAct::ReenrolMfa => "reenrol_mfa",
            RecoveryAct::ResetPassword => "reset_password",
            RecoveryAct::UnlockAccount => "unlock_account",
            RecoveryAct::AuthoriseKeyRotation => "authorise_key_rotation",
        }
    }

    /// Every act, for documentation and tests.
    pub fn all() -> [RecoveryAct; 4] {
        [
            RecoveryAct::ReenrolMfa,
            RecoveryAct::ResetPassword,
            RecoveryAct::UnlockAccount,
            RecoveryAct::AuthoriseKeyRotation,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_code_is_grouped_and_has_the_advertised_entropy() {
        let code = RecoveryCode::generate().unwrap();
        let body: Vec<&str> = code.as_str().split('-').collect();
        assert_eq!(body.len(), GROUPS);
        for group in &body {
            assert_eq!(group.len(), GROUP);
            for character in group.bytes() {
                assert!(ALPHABET.contains(&character), "{} is not in the alphabet", character as char);
            }
        }
        assert_eq!(RecoveryCode::body_len(), 32);
        // Two codes never collide in practice; with 160 bits, not even close.
        let other = RecoveryCode::generate().unwrap();
        assert_ne!(code.as_str(), other.as_str());
    }

    #[test]
    fn transcription_mistakes_still_verify() {
        let code = RecoveryCode::generate().unwrap();
        let hash = code.hash().unwrap();
        assert!(hash.verify(code.as_str()));
        // Lowercase, no dashes, stray spaces: the same code.
        assert!(hash.verify(&code.as_str().to_lowercase().replace('-', "")));
        assert!(hash.verify(&format!("  {}  ", code.as_str().replace('-', " "))));
        // A wrong code does not.
        let other = RecoveryCode::generate().unwrap();
        assert!(!hash.verify(other.as_str()));
        assert!(!hash.verify(""));
        assert!(!hash.verify("SHORT"));
    }

    #[test]
    fn look_alike_characters_are_folded_rather_than_rejected() {
        // Someone reading a code off paper may write O for 0 and l for 1.
        assert_eq!(RecoveryCode::normalize("OOOO"), "0000");
        assert_eq!(RecoveryCode::normalize("llll"), "1111");
        assert_eq!(RecoveryCode::normalize("iiii"), "1111");
        assert_eq!(RecoveryCode::normalize("abcd-efgh"), "ABCDEFGH");
    }

    #[test]
    fn the_stored_form_is_a_hash_and_verifies_only_the_right_code() {
        let code = RecoveryCode::generate().unwrap();
        let hash = code.hash().unwrap();
        assert_eq!(hash.salt().len(), 16);
        assert_eq!(hash.tag().len(), 32);
        assert_ne!(hash.tag(), code.as_str().as_bytes());
        let rebuilt = RecoveryHash::from_parts(hash.salt(), hash.tag());
        assert!(rebuilt.verify(code.as_str()));
        assert_eq!(
            recovered(&hash, code.as_str()),
            true,
            "the hash is reproducible from its columns"
        );
    }

    fn recovered(hash: &RecoveryHash, code: &str) -> bool {
        RecoveryHash::from_parts(hash.salt(), hash.tag()).verify(code)
    }

    #[test]
    fn a_debug_dump_never_shows_the_code() {
        let code = RecoveryCode::generate().unwrap();
        assert_eq!(format!("{:?}", code), "RecoveryCode(<redacted>)");
        assert!(!format!("{:?}", code).contains(code.as_str()));
    }

    #[test]
    fn no_recovery_act_can_move_value() {
        for act in RecoveryAct::all() {
            assert!(!act.moves_value(), "{:?} must never move value", act);
        }
    }
}
