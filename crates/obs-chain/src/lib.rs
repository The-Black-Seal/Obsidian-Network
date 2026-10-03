//! Consensus data structures for the Obsidian Network.
//!
//! This crate defines the canonical, deterministic representation of every
//! consensus object — accounts, claims, transactions, blocks, attestations and
//! validator records — and the validation rules that operate on them.  It has
//! **no** dependency on networking, storage or user interface code: a block
//! that validates here validates identically on every node, in every language,
//! on every platform.
//!
//! Design rules enforced in this crate:
//!
//! * Money is an integer number of grains (`1 OBS = 10^12 grains`); no
//!   floating-point value ever reaches a balance, fee, reward or supply
//!   calculation.
//! * Every signed structure covers the chain id, so a transaction valid on one
//!   network is invalid on every other network.
//! * Every identifier is a hash of the canonical encoding, never a wallet
//!   address and never a nonce.
//! * Serialization is the canonical binary codec from `obs-primitives`; there
//!   is exactly one encoding of any object, so hashes and signatures are
//!   reproducible.
//! * All ordering is explicit (transactions and attestations are sorted by
//!   their identifiers before a block root is computed), so two honest nodes
//!   with the same mempool always build the same block.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]

pub mod block;
pub mod chain;
pub mod mining;
pub mod params;
pub mod pot;
pub mod state;
pub mod tx;
pub mod validate;

pub use block::{Attestation, Block, BlockHeader};
pub use chain::{
    Account, Claim, InviteAuthorization, InviteRecord, TxId, TxKind, ValidatorRecord,
    gmail_commitment, invite_commitment,
};
pub use pot::{
    fork_choice_better, median_time_past, next_difficulty_bp, proposer_for_slot, slots_between,
    weight_of_block, PoTWeight,
};
pub use state::{
    Applied, BlockEffects, ChainState, GenesisConfig, LedgerEntry, StateError,
};
pub use tx::Transaction;
pub use validate::{check_claim_protocol_time, check_mtp_rule, check_parent_rule, check_timestamp_rules};
