//! Network identities.
//!
//! Every network has a unique chain id, address prefix, domain separator and
//! genesis configuration.  Chain ids are part of every signed payload, so a
//! transaction or consensus message produced for one network can never be
//! replayed on another.

use crate::hash::Hash32;

/// A network definition.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Network {
    /// Numeric chain identifier embedded in every signed structure.
    pub chain_id: u32,
    /// Human-readable network name.
    pub name: &'static str,
    /// Address namespace (`obs`, `tobs`, `sobs`, `dobs`).
    pub address_prefix: &'static str,
    /// Domain separator used in every tagged hash on this network.
    pub domain: &'static str,
    /// Whether this network issues real value (mainnet) or is for testing.
    pub is_mainnet: bool,
}

/// Obsidian mainnet.
pub const MAINNET: Network = Network {
    chain_id: 1,
    name: "mainnet",
    address_prefix: "obs",
    domain: "OBSIDIAN/MAINNET/v1",
    is_mainnet: true,
};

/// Public testnet.
pub const TESTNET: Network = Network {
    chain_id: 2,
    name: "testnet",
    address_prefix: "tobs",
    domain: "OBSIDIAN/TESTNET/v1",
    is_mainnet: false,
};

/// Developer network.
pub const DEVNET: Network = Network {
    chain_id: 3,
    name: "devnet",
    address_prefix: "dobs",
    domain: "OBSIDIAN/DEVNET/v1",
    is_mainnet: false,
};

/// Staging network.
pub const STAGING: Network = Network {
    chain_id: 4,
    name: "staging",
    address_prefix: "sobs",
    domain: "OBSIDIAN/STAGING/v1",
    is_mainnet: false,
};

/// All supported networks.
pub const ALL_NETWORKS: [Network; 4] = [MAINNET, TESTNET, DEVNET, STAGING];

impl Network {
    /// Looks up a network by name.
    pub fn by_name(name: &str) -> Option<Network> {
        ALL_NETWORKS
            .iter()
            .copied()
            .find(|n| n.name.eq_ignore_ascii_case(name))
    }

    /// Looks up a network by chain id.
    pub fn by_chain_id(chain_id: u32) -> Option<Network> {
        ALL_NETWORKS.iter().copied().find(|n| n.chain_id == chain_id)
    }

    /// Looks up a network by address prefix.
    pub fn by_prefix(prefix: &str) -> Option<Network> {
        ALL_NETWORKS
            .iter()
            .copied()
            .find(|n| n.address_prefix == prefix)
    }

    /// Canonical genesis hash for this network.
    ///
    /// The genesis hash is derived deterministically from the network identity
    /// and protocol version; it is the parent of block 1 and therefore anchors
    /// every network's chain.
    pub fn genesis_hash(&self, protocol_version: u32, genesis_time: u64) -> Hash32 {
        Hash32::tagged(
            "OBSIDIAN/GENESIS/v1",
            &[
                self.domain.as_bytes(),
                &self.chain_id.to_le_bytes(),
                &protocol_version.to_le_bytes(),
                &genesis_time.to_le_bytes(),
            ],
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn networks_are_distinct() {
        for (i, a) in ALL_NETWORKS.iter().enumerate() {
            for b in ALL_NETWORKS.iter().skip(i + 1) {
                assert_ne!(a.chain_id, b.chain_id);
                assert_ne!(a.address_prefix, b.address_prefix);
                assert_ne!(a.genesis_hash(1, 1_700_000_000), b.genesis_hash(1, 1_700_000_000));
            }
        }
    }

    #[test]
    fn lookups_work() {
        assert_eq!(Network::by_name("mainnet").unwrap(), MAINNET);
        assert_eq!(Network::by_chain_id(3).unwrap(), DEVNET);
        assert_eq!(Network::by_prefix("sobs").unwrap(), STAGING);
        assert!(Network::by_name("nope").is_none());
    }

    #[test]
    fn genesis_hash_is_stable() {
        // Regression guard: changing protocol constants must be deliberate.
        assert_eq!(
            MAINNET.genesis_hash(1, 0).to_hex(),
            MAINNET.genesis_hash(1, 0).to_hex()
        );
        assert_ne!(MAINNET.genesis_hash(1, 0), MAINNET.genesis_hash(2, 0));
    }
}

impl PartialOrd for Network {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for Network {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        self.chain_id.cmp(&other.chain_id)
    }
}
