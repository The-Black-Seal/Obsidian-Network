//! Wallet addresses.
//!
//! An address is a checksummed, network-scoped encoding of a 20-byte key hash:
//!
//! ```text
//! payload   = SHA256("OBSIDIAN/KEYHASH/v1" || chain_id_le32 || version || pubkey)[0..20]
//! checksum  = SHA256("OBSIDIAN/ADDRESS/v1" || chain_id_le32 || version || payload)[0..4]
//! body      = base32_lowercase(version || payload || checksum)      // 25 bytes -> 40 chars
//! address   = address_prefix || "1" || body                          // e.g. obs1...
//! ```
//!
//! * `version` is `1` for single-key Ed25519 accounts.
//! * The checksum covers the chain id, so an address from another network can
//!   never be mistaken for a mainnet address.
//! * Decoding is strict: wrong prefix, wrong length, non-canonical Base32 or a
//!   bad checksum are all rejected.

use crate::hash::Hash32;
use crate::network::Network;
use obs_crypto::encoding::{base32_decode, base32_encode};
use obs_crypto::sha2::sha256_tagged;

/// Address version byte for single-key Ed25519 accounts.
pub const ADDRESS_VERSION_ED25519_V1: u8 = 1;

/// Length of the address payload in bytes.
pub const ADDRESS_PAYLOAD_LEN: usize = 20;

/// Length of the checksum in bytes.
pub const ADDRESS_CHECKSUM_LEN: usize = 4;

/// Total length of the Base32 body.
pub const ADDRESS_BODY_LEN: usize = (1 + ADDRESS_PAYLOAD_LEN + ADDRESS_CHECKSUM_LEN) * 8 / 5;

/// Number of characters shown at the start of a masked address.
pub const MASK_PREFIX_CHARS: usize = 8;
/// Number of characters shown at the end of a masked address.
pub const MASK_SUFFIX_CHARS: usize = 4;

/// Errors produced when decoding addresses.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddressError {
    /// The string is empty or too short.
    TooShort,
    /// The prefix is missing or belongs to another network.
    BadPrefix,
    /// The separator `1` is missing.
    BadSeparator,
    /// The Base32 body is invalid.
    BadEncoding,
    /// The body has the wrong length.
    BadLength,
    /// The version byte is not supported.
    UnsupportedVersion(u8),
    /// The checksum does not match.
    BadChecksum,
}

impl core::fmt::Display for AddressError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AddressError::TooShort => write!(f, "address is too short"),
            AddressError::BadPrefix => write!(f, "address prefix does not match the network"),
            AddressError::BadSeparator => write!(f, "address separator '1' missing"),
            AddressError::BadEncoding => write!(f, "address is not valid Base32"),
            AddressError::BadLength => write!(f, "address body has the wrong length"),
            AddressError::UnsupportedVersion(v) => write!(f, "unsupported address version {}", v),
            AddressError::BadChecksum => write!(f, "address checksum mismatch"),
        }
    }
}

impl std::error::Error for AddressError {}

/// A validated wallet address belonging to a specific network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Address {
    network: Network,
    version: u8,
    payload: [u8; ADDRESS_PAYLOAD_LEN],
}

impl Address {
    /// Derives the address for a 32-byte Ed25519 public key.
    pub fn from_public_key(network: Network, public_key: &[u8; 32]) -> Address {
        let digest = sha256_tagged(
            "OBSIDIAN/KEYHASH/v1",
            &[
                &network.chain_id.to_le_bytes()[..],
                &[ADDRESS_VERSION_ED25519_V1],
                public_key,
            ]
            .concat(),
        );
        let mut payload = [0u8; ADDRESS_PAYLOAD_LEN];
        payload.copy_from_slice(&digest[..ADDRESS_PAYLOAD_LEN]);
        Address {
            network,
            version: ADDRESS_VERSION_ED25519_V1,
            payload,
        }
    }

    /// Builds an address from raw parts (used by the decoder and tests).
    pub fn from_parts(
        network: Network,
        version: u8,
        payload: [u8; ADDRESS_PAYLOAD_LEN],
    ) -> Address {
        Address {
            network,
            version,
            payload,
        }
    }

    /// The network this address belongs to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The raw 20-byte payload.
    pub fn payload(&self) -> &[u8; ADDRESS_PAYLOAD_LEN] {
        &self.payload
    }

    /// The address version byte.
    pub fn version(&self) -> u8 {
        self.version
    }

    fn checksum(&self) -> [u8; ADDRESS_CHECKSUM_LEN] {
        let digest = sha256_tagged(
            "OBSIDIAN/ADDRESS/v1",
            &[
                &self.network.chain_id.to_le_bytes()[..],
                &[self.version],
                &self.payload[..],
            ]
            .concat(),
        );
        let mut out = [0u8; ADDRESS_CHECKSUM_LEN];
        out.copy_from_slice(&digest[..ADDRESS_CHECKSUM_LEN]);
        out
    }

    /// Encodes the canonical textual address.
    pub fn to_string_canonical(&self) -> String {
        let mut body = Vec::with_capacity(1 + ADDRESS_PAYLOAD_LEN + ADDRESS_CHECKSUM_LEN);
        body.push(self.version);
        body.extend_from_slice(&self.payload);
        body.extend_from_slice(&self.checksum());
        format!(
            "{}1{}",
            self.network.address_prefix,
            base32_encode(&body)
        )
    }

    /// Parses and fully validates an address for the given network.
    pub fn parse(network: Network, s: &str) -> Result<Address, AddressError> {
        let s = s.trim();
        if s.len() < network.address_prefix.len() + 1 + ADDRESS_BODY_LEN {
            return Err(AddressError::TooShort);
        }
        let rest = s
            .strip_prefix(network.address_prefix)
            .ok_or(AddressError::BadPrefix)?;
        let body_str = rest.strip_prefix('1').ok_or(AddressError::BadSeparator)?;
        if body_str.len() != ADDRESS_BODY_LEN {
            return Err(AddressError::BadLength);
        }
        let body = base32_decode(body_str).ok_or(AddressError::BadEncoding)?;
        if body.len() != 1 + ADDRESS_PAYLOAD_LEN + ADDRESS_CHECKSUM_LEN {
            return Err(AddressError::BadLength);
        }
        let version = body[0];
        if version != ADDRESS_VERSION_ED25519_V1 {
            return Err(AddressError::UnsupportedVersion(version));
        }
        let mut payload = [0u8; ADDRESS_PAYLOAD_LEN];
        payload.copy_from_slice(&body[1..1 + ADDRESS_PAYLOAD_LEN]);
        let address = Address {
            network,
            version,
            payload,
        };
        let expected = address.checksum();
        if expected.as_slice() != &body[1 + ADDRESS_PAYLOAD_LEN..] {
            return Err(AddressError::BadChecksum);
        }
        Ok(address)
    }

    /// Detects the network the address belongs to by trying every known prefix.
    pub fn detect_network(s: &str) -> Option<(Network, Address)> {
        for network in crate::network::ALL_NETWORKS {
            if let Ok(addr) = Address::parse(network, s) {
                return Some((network, addr));
            }
        }
        None
    }
}

impl PartialOrd for Address {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Address {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        (self.network.chain_id, self.version, self.payload)
            .cmp(&(other.network.chain_id, other.version, other.payload))
    }
}

impl core::hash::Hash for Address {
    fn hash<H: core::hash::Hasher>(&self, state: &mut H) {
        self.network.chain_id.hash(state);
        self.version.hash(state);
        self.payload.hash(state);
    }
}

impl core::fmt::Display for Address {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.to_string_canonical())
    }
}

/// Reduces an address to its public, masked representation:
/// `obs1q9x7...4k8m`.
///
/// **Privacy rule.** Every public surface (Explorer, Explorer API, block and
/// transaction listings, search results, logs) must use this function rather
/// than the full address.  Full addresses are only available to the wallet
/// owner through authenticated wallet endpoints.
pub fn mask_address(address: &str) -> String {
    if address.len() <= MASK_PREFIX_CHARS + MASK_SUFFIX_CHARS {
        return "…".to_string();
    }
    let prefix = &address[..MASK_PREFIX_CHARS];
    let suffix = &address[address.len() - MASK_SUFFIX_CHARS..];
    format!("{}...{}", prefix, suffix)
}

/// Masks an already-parsed address.
pub fn mask(address: &Address) -> String {
    mask_address(&address.to_string_canonical())
}

/// Hashes a secret value for public commitment purposes (never reversible).
pub fn public_commitment(value: &[u8]) -> Hash32 {
    Hash32::tagged("OBSIDIAN/PUBLIC-COMMITMENT/v1", &[value])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::network::{DEVNET, MAINNET, TESTNET};

    fn sample_key(seed: u8) -> [u8; 32] {
        let mut k = [0u8; 32];
        for (i, b) in k.iter_mut().enumerate() {
            *b = seed.wrapping_add(i as u8);
        }
        k
    }

    #[test]
    fn encoding_is_deterministic_and_prefixed() {
        let addr = Address::from_public_key(MAINNET, &sample_key(1));
        let s = addr.to_string_canonical();
        assert!(s.starts_with("obs1"), "got {}", s);
        assert_eq!(s.len(), 4 + ADDRESS_BODY_LEN);
        assert_eq!(Address::parse(MAINNET, &s).unwrap(), addr);
    }

    #[test]
    fn networks_are_isolated() {
        let key = sample_key(7);
        let main = Address::from_public_key(MAINNET, &key);
        let test = Address::from_public_key(TESTNET, &key);
        let dev = Address::from_public_key(DEVNET, &key);
        assert_ne!(main.to_string_canonical(), test.to_string_canonical());
        assert!(main.to_string_canonical().starts_with("obs1"));
        assert!(test.to_string_canonical().starts_with("tobs1"));
        assert!(dev.to_string_canonical().starts_with("dobs1"));
        // A testnet address is not a mainnet address.
        assert!(Address::parse(MAINNET, &test.to_string_canonical()).is_err());
        // Cross-network detection still works.
        let (net, parsed) = Address::detect_network(&test.to_string_canonical()).unwrap();
        assert_eq!(net, TESTNET);
        assert_eq!(parsed, test);
    }

    #[test]
    fn corruption_is_rejected() {
        let addr = Address::from_public_key(MAINNET, &sample_key(3)).to_string_canonical();
        // Flip one character in the body.
        let mut chars: Vec<char> = addr.chars().collect();
        let last = chars.len() - 1;
        chars[last] = if chars[last] == 'a' { 'b' } else { 'a' };
        let corrupted: String = chars.into_iter().collect();
        assert!(matches!(
            Address::parse(MAINNET, &corrupted),
            Err(AddressError::BadChecksum)
        ));
        assert!(Address::parse(MAINNET, "obs1").is_err());
        assert!(Address::parse(MAINNET, "obs1AAAA").is_err());
        // Uppercase Base32 is not canonical.
        let upper = addr.to_uppercase();
        assert!(Address::parse(MAINNET, &upper).is_err());
    }

    #[test]
    fn masking_matches_the_documented_format() {
        let addr = Address::from_public_key(MAINNET, &sample_key(9)).to_string_canonical();
        let masked = mask_address(&addr);
        assert!(masked.starts_with(&addr[..8]));
        assert!(masked.ends_with(&addr[addr.len() - 4..]));
        assert!(masked.contains("..."));
        assert_eq!(masked.len(), 8 + 3 + 4);
        // Masking never leaks the middle of the address.
        let middle = &addr[8..addr.len() - 4];
        assert!(!masked.contains(&middle[..middle.len().min(8)]));
    }

    #[test]
    fn different_keys_produce_different_addresses() {
        let a = Address::from_public_key(MAINNET, &sample_key(1));
        let b = Address::from_public_key(MAINNET, &sample_key(2));
        assert_ne!(a, b);
    }
}
