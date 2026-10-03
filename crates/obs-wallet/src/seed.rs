//! Seed and key derivation.
//!
//! The wallet recovery phrase is a BIP-39 phrase over 256 bits of CSPRNG
//! entropy: 24 words, checksummed, in the standard English wordlist.  Anyone who
//! has the words has the wallet — that is what makes recovery work without a
//! server, and it is why the phrase is generated on the device, shown once, and
//! never stored by this crate.
//!
//! Derivation is SLIP-0010 hardened for Ed25519, on this chain's purpose and
//! three roles.  Hardened derivation means a leaked child key never reveals a
//! sibling or the parent, so the validator node key, the recovery key and the
//! wallet key are isolated from one another.
//!
//! Kept in its own module so the *only* code that touches a phrase or a seed is
//! small enough to read in one sitting.

use obs_crypto::ct::Zeroizing;
use obs_crypto::ed25519::Keypair;
use obs_crypto::mnemonic;
use obs_primitives::network::Network;

use crate::{WalletError, PURPOSE};

/// Entropy for a wallet recovery phrase: 256 bits.
pub const ENTROPY_BYTES: usize = 32;

/// Generates a fresh 24-word phrase from the operating system CSPRNG.
pub fn generate_phrase() -> Result<String, WalletError> {
    mnemonic::generate_mnemonic().map_err(|error| WalletError::Entropy(error.to_string()))
}

/// Validates a phrase and checks its checksum, without deriving anything.
///
/// Used by the UI's "confirm your phrase" step, which must not turn a typo into a
/// new wallet.
pub fn validate_phrase(phrase: &str) -> Result<(), WalletError> {
    let normalized = normalize_phrase(phrase);
    mnemonic::mnemonic_to_entropy(&normalized)
        .map_err(|error| WalletError::BadPhrase(error.to_string()))?;
    Ok(())
}

/// Derives the 512-bit BIP-39 seed from a phrase and an optional passphrase.
pub fn seed_from_phrase(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, WalletError> {
    let normalized = normalize_phrase(phrase);
    mnemonic::mnemonic_to_seed(&normalized, passphrase)
        .map_err(|error| WalletError::BadPhrase(error.to_string()))
}

/// Derives one of a wallet's keys: role 0 wallet, 1 node identity, 2 recovery.
pub fn derive_key(seed: &[u8], account: u32, role: u32) -> Result<Keypair, WalletError> {
    if account > 0x7fff_ffff {
        return Err(WalletError::BadSeed(
            "account index must be below 2^31 (hardened derivation)".to_string(),
        ));
    }
    let master = mnemonic::ExtendedKey::from_seed(seed);
    let path = format!("m/{}'/{}'/{}'", PURPOSE, account, role);
    let child = master
        .derive_path(&path)
        .map_err(|detail| WalletError::BadSeed(detail))?;
    let mut secret = Zeroizing(*child.private_key);
    let keypair = Keypair::from_seed(&secret);
    // Wipe the copy this function made before returning: the keypair holds its
    // own copy, and the derivation intermediate has no reason to survive.
    obs_crypto::ct::Zeroize::zeroize(&mut *secret);
    Ok(keypair)
}

/// The derivation path for a wallet key, as documentation and support tooling
/// need it.
pub fn key_path(network: Network, account: u32, role: u32) -> String {
    let _ = network;
    format!("m/{}'/{}'/{}'", PURPOSE, account, role)
}

/// Collapses whitespace and lower-cases, the way every wallet must before
/// checking a phrase a human typed or pasted.
pub fn normalize_phrase(phrase: &str) -> String {
    phrase
        .split_whitespace()
        .map(|word| word.to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::MAINNET;

    #[test]
    fn a_generated_phrase_is_twenty_four_words_and_round_trips() {
        let phrase = generate_phrase().unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert!(validate_phrase(&phrase).is_ok());
        // Normalisation means a sloppy paste still recovers the same wallet.
        let messy = format!("  {}  ", phrase.to_uppercase().replace(' ', "   "));
        assert!(validate_phrase(&messy).is_ok());
        let clean = seed_from_phrase(&phrase, "").unwrap();
        let normalized = seed_from_phrase(&messy, "").unwrap();
        assert_eq!(*clean, *normalized);
    }

    #[test]
    fn derivation_is_deterministic_and_role_separated() {
        let phrase = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
        let seed = seed_from_phrase(phrase, "").unwrap();
        let wallet = derive_key(&*seed, 0, 0).unwrap();
        let wallet_again = derive_key(&*seed, 0, 0).unwrap();
        assert_eq!(wallet.public_key(), wallet_again.public_key());

        let node = derive_key(&*seed, 0, 1).unwrap();
        let recovery = derive_key(&*seed, 0, 2).unwrap();
        let other_account = derive_key(&*seed, 1, 0).unwrap();
        for (left, right) in [
            (wallet.public_key(), node.public_key()),
            (wallet.public_key(), recovery.public_key()),
            (wallet.public_key(), other_account.public_key()),
        ] {
            assert_ne!(left, right);
        }
        assert_eq!(key_path(MAINNET, 0, 0), "m/8504'/0'/0'");
    }

    #[test]
    fn a_word_that_is_not_in_the_wordlist_is_refused() {
        let phrase = generate_phrase().unwrap();
        let mut words: Vec<String> = phrase.split_whitespace().map(|word| word.to_string()).collect();
        words[3] = "notaword".to_string();
        let broken = words.join(" ");
        assert!(validate_phrase(&broken).is_err());
        // A swapped pair breaks the checksum, which is the point of the checksum.
        let mut words: Vec<String> = phrase.split_whitespace().map(|w| w.to_string()).collect();
        words.swap(0, 1);
        assert!(validate_phrase(&words.join(" ")).is_err());
    }

    #[test]
    fn an_out_of_range_account_is_refused() {
        let phrase = generate_phrase().unwrap();
        let seed = seed_from_phrase(&phrase, "").unwrap();
        assert!(derive_key(&*seed, 0x8000_0000, 0).is_err());
        assert!(derive_key(&*seed, 0x7fff_ffff, 0).is_ok());
    }
}
