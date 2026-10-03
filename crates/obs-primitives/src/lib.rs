//! # obs-primitives
//!
//! Foundational value types shared by every Obsidian Network component:
//! integer money, hashes and Merkle commitments, network identities,
//! checksummed wallet addresses (and the public masking rule), the canonical
//! binary codec and a strict JSON implementation.
//!
//! Everything here is deterministic: given the same inputs, the same bytes and
//! the same strings are produced on every platform and in every build.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod address;
pub mod codec;
pub mod hash;
pub mod identity;
pub mod json;
pub mod money;
pub mod network;
pub mod time;

pub use address::{mask, mask_address, Address, AddressError};
pub use codec::{decode_exact, Decode, Decoder, Encode};
pub use hash::{merkle_root, Hash32};
pub use identity::{canonical_gmail, is_gmail, GmailError};
pub use json::Json;
pub use money::{Amount, GRAINS_PER_OBS, MAX_SUPPLY};
pub use network::{Network, ALL_NETWORKS, DEVNET, MAINNET, STAGING, TESTNET};

/// Protocol version implemented by this release.
///
/// It is part of the genesis hash and of every signed consensus structure, so
/// incompatible protocol changes require a new version and a new network.
pub const PROTOCOL_VERSION: u32 = 1;

/// Software version reported by nodes and in release metadata.
pub const SOFTWARE_VERSION: &str = env!("CARGO_PKG_VERSION");

/// Unit name of the native coin.
pub const COIN_NAME: &str = "Obsidian Seal Coin";

/// Ticker of the native coin.
pub const COIN_TICKER: &str = "OBS";
