//! BIP-39 recovery phrases and SLIP-0010 hierarchical key derivation.
//!
//! Obsidian wallets use **24 words = 256 bits of entropy** (the protocol
//! minimum is 256 bits of cryptographically secure entropy for wallet
//! generation).
//!
//! Passphrases are restricted to printable ASCII because Unicode NFKD
//! normalisation is not implemented here; ASCII is already NFKD-stable, so the
//! derivation stays fully deterministic and interoperable.

use crate::ct::{ct_eq, Zeroize, Zeroizing};
use crate::hmac::{hmac_sha512, pbkdf2_hmac_sha512};
use crate::sha2::sha256;

/// The vendored BIP-39 English word list.
pub const WORDLIST_RAW: &str = include_str!("data/bip39_english.txt");

/// Number of words in a BIP-39 word list.
pub const WORDLIST_SIZE: usize = 2048;

/// Errors produced when handling recovery phrases.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MnemonicError {
    /// The word count is not one of 12/15/18/21/24.
    InvalidWordCount(usize),
    /// A word is not in the word list.
    UnknownWord(String),
    /// The embedded checksum does not match the entropy.
    InvalidChecksum,
    /// The entropy length is not supported.
    InvalidEntropyLength(usize),
    /// The passphrase contains non-ASCII characters.
    NonAsciiPassphrase,
}

impl core::fmt::Display for MnemonicError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MnemonicError::InvalidWordCount(n) => write!(f, "invalid word count: {}", n),
            MnemonicError::UnknownWord(w) => write!(f, "unknown word: {}", w),
            MnemonicError::InvalidChecksum => write!(f, "invalid recovery phrase checksum"),
            MnemonicError::InvalidEntropyLength(n) => write!(f, "invalid entropy length: {}", n),
            MnemonicError::NonAsciiPassphrase => write!(f, "passphrase must be ASCII"),
        }
    }
}

impl std::error::Error for MnemonicError {}

/// Returns the BIP-39 English word list.
pub fn wordlist() -> Vec<&'static str> {
    WORDLIST_RAW.lines().collect()
}

/// Returns the index of a word in the word list, or `None`.
pub fn word_index(word: &str) -> Option<u16> {
    wordlist().iter().position(|w| *w == word).map(|i| i as u16)
}

/// Encodes entropy (16/24/32 bytes) as a recovery phrase.
pub fn entropy_to_mnemonic(entropy: &[u8]) -> Result<String, MnemonicError> {
    if !matches!(entropy.len(), 16 | 20 | 24 | 28 | 32) {
        return Err(MnemonicError::InvalidEntropyLength(entropy.len()));
    }
    let checksum_bits = entropy.len() / 4;
    let hash = sha256(entropy);
    let mut bits: Vec<bool> = Vec::with_capacity(entropy.len() * 8 + checksum_bits);
    for byte in entropy {
        for i in (0..8).rev() {
            bits.push((byte >> i) & 1 == 1);
        }
    }
    for i in 0..checksum_bits {
        let byte = i / 8;
        let bit = 7 - (i % 8);
        bits.push((hash[byte] >> bit) & 1 == 1);
    }
    let words = wordlist();
    let mut phrase = Vec::with_capacity(bits.len() / 11);
    for chunk in bits.chunks(11) {
        let mut index = 0usize;
        for bit in chunk {
            index = (index << 1) | usize::from(*bit);
        }
        phrase.push(words[index]);
    }
    Ok(phrase.join(" "))
}

/// Decodes a recovery phrase back to its entropy.
pub fn mnemonic_to_entropy(phrase: &str) -> Result<Vec<u8>, MnemonicError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if !matches!(words.len(), 12 | 15 | 18 | 21 | 24) {
        return Err(MnemonicError::InvalidWordCount(words.len()));
    }
    let total_bits = words.len() * 11;
    let checksum_bits = total_bits / 33;
    let entropy_bits = total_bits - checksum_bits;
    let mut bits: Vec<bool> = Vec::with_capacity(total_bits);
    for word in &words {
        let index = word_index(word).ok_or_else(|| MnemonicError::UnknownWord((*word).to_string()))?;
        for i in (0..11).rev() {
            bits.push((index >> i) & 1 == 1);
        }
    }
    let mut entropy = vec![0u8; entropy_bits / 8];
    for (i, byte) in entropy.iter_mut().enumerate() {
        for j in 0..8 {
            if bits[i * 8 + j] {
                *byte |= 1 << (7 - j);
            }
        }
    }
    let hash = sha256(&entropy);
    for i in 0..checksum_bits {
        let expected = (hash[i / 8] >> (7 - (i % 8))) & 1 == 1;
        if bits[entropy_bits + i] != expected {
            return Err(MnemonicError::InvalidChecksum);
        }
    }
    Ok(entropy)
}

/// Derives the 64-byte BIP-39 seed from a recovery phrase.
pub fn mnemonic_to_seed(phrase: &str, passphrase: &str) -> Result<Zeroizing<[u8; 64]>, MnemonicError> {
    if !passphrase.is_ascii() {
        return Err(MnemonicError::NonAsciiPassphrase);
    }
    // Validate the phrase first so that a typo cannot silently produce a
    // different wallet.
    mnemonic_to_entropy(phrase)?;
    let normalized = phrase.split_whitespace().collect::<Vec<_>>().join(" ");
    let salt = format!("mnemonic{}", passphrase);
    let mut seed = [0u8; 64];
    let derived = pbkdf2_hmac_sha512(normalized.as_bytes(), salt.as_bytes(), 2048, 64);
    seed.copy_from_slice(&derived);
    Ok(Zeroizing(seed))
}

/// Generates a new 24-word recovery phrase (256 bits) from OS entropy.
pub fn generate_mnemonic() -> Result<String, crate::rand::EntropyError> {
    let mut entropy = [0u8; 32];
    crate::rand::os_random(&mut entropy).map_err(|_| crate::rand::EntropyError::Unavailable)?;
    let phrase = entropy_to_mnemonic(&entropy).map_err(|_| crate::rand::EntropyError::Unavailable)?;
    entropy.zeroize();
    Ok(phrase)
}

/// SLIP-0010 extended private key for ed25519.
pub struct ExtendedKey {
    /// The 32-byte private key / chain code pair used for hardened derivation.
    pub private_key: Zeroizing<[u8; 32]>,
    /// The 32-byte chain code.
    pub chain_code: Zeroizing<[u8; 32]>,
    /// Derivation depth.
    pub depth: u8,
}

impl ExtendedKey {
    /// Derives the master key from a BIP-39 seed (SLIP-0010 ed25519).
    pub fn from_seed(seed: &[u8]) -> ExtendedKey {
        let i = hmac_sha512(b"ed25519 seed", seed);
        let mut key = [0u8; 32];
        let mut chain = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        ExtendedKey {
            private_key: Zeroizing(key),
            chain_code: Zeroizing(chain),
            depth: 0,
        }
    }

    /// Derives a hardened child key.  ed25519 only supports hardened derivation.
    pub fn derive_hardened(&self, index: u32) -> ExtendedKey {
        let mut data = Vec::with_capacity(37);
        data.push(0x00);
        data.extend_from_slice(&*self.private_key);
        data.extend_from_slice(&(index | 0x8000_0000).to_be_bytes());
        let i = hmac_sha512(&*self.chain_code, &data);
        let mut key = [0u8; 32];
        let mut chain = [0u8; 32];
        key.copy_from_slice(&i[..32]);
        chain.copy_from_slice(&i[32..]);
        ExtendedKey {
            private_key: Zeroizing(key),
            chain_code: Zeroizing(chain),
            depth: self.depth.saturating_add(1),
        }
    }

    /// Derives a hardened path such as `m/44'/8504'/0'/0'/0'`.
    pub fn derive_path(&self, path: &str) -> Result<ExtendedKey, String> {
        let mut current = ExtendedKey {
            private_key: Zeroizing(*self.private_key),
            chain_code: Zeroizing(*self.chain_code),
            depth: self.depth,
        };
        let trimmed = path.trim();
        let parts: Vec<&str> = trimmed.split('/').collect();
        if parts.is_empty() || (parts[0] != "m" && parts[0] != "M") {
            return Err("derivation path must start with 'm'".into());
        }
        for part in &parts[1..] {
            if part.is_empty() {
                return Err("empty path segment".into());
            }
            let (num_str, hardened) = if let Some(stripped) = part.strip_suffix('\'') {
                (stripped, true)
            } else if let Some(stripped) = part.strip_suffix('h') {
                (stripped, true)
            } else {
                (*part, false)
            };
            if !hardened {
                return Err("ed25519 derivation only supports hardened indices".into());
            }
            let index: u32 = num_str
                .parse()
                .map_err(|_| format!("invalid path segment: {}", part))?;
            if index >= 0x8000_0000 {
                return Err("path index out of range".into());
            }
            current = current.derive_hardened(index);
        }
        Ok(current)
    }
}

/// Checks that the vendored word list is the canonical BIP-39 English list.
pub fn wordlist_checksum_is_canonical() -> bool {
    let digest = sha256(WORDLIST_RAW.as_bytes());
    let expected = [
        0x2f, 0x5e, 0xed, 0x53, 0xa4, 0x72, 0x7b, 0x4b, 0xf8, 0x88, 0x0d, 0x8f, 0x3f, 0x19,
        0x9e, 0xfc, 0x90, 0xe5, 0x85, 0x03, 0x64, 0x6d, 0x9f, 0xf8, 0xef, 0xf3, 0xa2, 0xed,
        0x3b, 0x24, 0xdb, 0xda,
    ];
    ct_eq(&digest, &expected)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wordlist_is_canonical() {
        assert_eq!(wordlist().len(), WORDLIST_SIZE);
        assert_eq!(wordlist()[0], "abandon");
        assert_eq!(wordlist()[2047], "zoo");
        assert!(wordlist_checksum_is_canonical());
    }

    #[test]
    fn bip39_reference_vector_1() {
        // BIP-39 test vector: entropy 0x00..00 (16 bytes)
        let entropy = [0u8; 16];
        let phrase = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            phrase,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
        );
        assert_eq!(mnemonic_to_entropy(&phrase).unwrap(), entropy.to_vec());
        let seed = mnemonic_to_seed(&phrase, "TREZOR").unwrap();
        let expected = crate::encoding::hex_decode(
            "c55257c360c07c72029aebc1b53c05ed0362ada38ead3e3e9efa3708e53495531f09a6987599d18264c1e1c92f2cf141630c7a3c4ab7c81b2f001698e7463b04",
        )
        .unwrap();
        assert_eq!(&seed[..], &expected[..]);
    }

    #[test]
    fn bip39_reference_vector_2() {
        // Entropy 0x7f7f..7f (16 bytes)
        let entropy = [0x7fu8; 16];
        let phrase = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(
            phrase,
            "legal winner thank year wave sausage worth useful legal winner thank yellow"
        );
    }

    #[test]
    fn bip39_256_bit_entropy_produces_24_words() {
        let entropy: Vec<u8> = (0..32u8).collect();
        let phrase = entropy_to_mnemonic(&entropy).unwrap();
        assert_eq!(phrase.split_whitespace().count(), 24);
        assert_eq!(mnemonic_to_entropy(&phrase).unwrap(), entropy);
    }

    #[test]
    fn invalid_phrases_are_rejected() {
        assert!(matches!(
            mnemonic_to_entropy("abandon abandon"),
            Err(MnemonicError::InvalidWordCount(2))
        ));
        assert!(matches!(
            mnemonic_to_entropy(
                "notaword abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
            ),
            Err(MnemonicError::UnknownWord(_))
        ));
        // correct words, wrong checksum
        assert!(matches!(
            mnemonic_to_entropy(
                "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon"
            ),
            Err(MnemonicError::InvalidChecksum)
        ));
        assert!(mnemonic_to_seed(
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "pässword"
        )
        .is_err());
    }

    #[test]
    fn slip10_derivation_is_deterministic_and_path_sensitive() {
        let seed = b"obsidian slip10 test seed value";
        let master = ExtendedKey::from_seed(seed);
        let child = master.derive_path("m/44'/8504'/0'/0'/0'").unwrap();
        let child_again = ExtendedKey::from_seed(seed)
            .derive_path("m/44'/8504'/0'/0'/0'")
            .unwrap();
        assert_eq!(&child.private_key[..], &child_again.private_key[..]);
        let other = master.derive_path("m/44'/8504'/0'/0'/1'").unwrap();
        assert_ne!(&child.private_key[..], &other.private_key[..]);
        assert!(master.derive_path("m/44/8504").is_err());
        assert!(master.derive_path("44'/8504'").is_err());
    }
}
