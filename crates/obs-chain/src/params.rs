//! Obsidian Network protocol parameters (protocol version 1).
//!
//! **These values are consensus-critical.**  They are compiled into the node,
//! committed to by the genesis hash and published in every block header, so a
//! frontend, API client, database operator or node operator cannot change them.
//! Changing any of them requires a new protocol version and therefore a new
//! network.
//!
//! Every monetary value is an integer number of grains (`1 OBS = 10^12`).

pub use obs_primitives::money::{GENESIS_ALLOCATION, VALIDATOR_BOND};
use obs_primitives::money::Amount;

/// Protocol version.
pub const PROTOCOL_VERSION: u32 = 1;

// ---------------------------------------------------------------------------
// Time and slots
// ---------------------------------------------------------------------------

/// Duration of one PoT slot in protocol seconds.
///
/// Blocks are produced at most once per slot and each slot has exactly one
/// deterministically scheduled proposer.
pub const SLOT_DURATION_SECS: u64 = 30;

/// Target block interval (identical to the slot duration by construction).
pub const TARGET_BLOCK_INTERVAL_SECS: u64 = SLOT_DURATION_SECS;

/// Number of slots in a PoT difficulty epoch.
pub const EPOCH_SLOTS: u64 = 128;

/// Number of recent blocks used for the difficulty measurement window.
pub const DIFFICULTY_WINDOW_BLOCKS: usize = 32;

/// Initial PoT difficulty in basis points (10_000 bp = exactly on target).
pub const DIFFICULTY_INITIAL_BP: u32 = 10_000;

/// Lower bound for PoT difficulty (nodes producing blocks faster than target).
pub const DIFFICULTY_MIN_BP: u32 = 6_666;

/// Upper bound for PoT difficulty (nodes producing blocks slower than target).
pub const DIFFICULTY_MAX_BP: u32 = 15_000;

/// Exponential moving average weight denominator for difficulty updates
/// (`new = (7 * old + raw) / 8`).
pub const DIFFICULTY_EMA_DEN: u32 = 8;

/// Rule 1: a block timestamp must be strictly greater than the median time past
/// of the previous `MTP_WINDOW` blocks.
pub const MTP_WINDOW: usize = 11;

/// Rule 2: a block timestamp may be at most this far ahead of its parent.
pub const MAX_BLOCK_DRIFT_SECS: u64 = 60;

/// Rule 2: a block timestamp must be at least this far ahead of its parent.
pub const MIN_BLOCK_SPACING_SECS: u64 = 1;

/// Non-consensus sanity bound: a node refuses to *gossip* a block whose
/// timestamp is more than this far ahead of its own wall clock.  This never
/// affects consensus — a block that violates [`MAX_BLOCK_DRIFT_SECS`] relative
/// to its parent is invalid regardless of any local clock.
pub const LOCAL_FUTURE_SANITY_SECS: u64 = 120;

/// Maximum number of slots a single block may advance beyond its parent
/// (used for the time-weight contribution).
pub const MAX_SLOT_GAP: u64 = 8;

// ---------------------------------------------------------------------------
// PoT weight
// ---------------------------------------------------------------------------

/// Weight atoms contributed per elapsed slot, before the difficulty scaling.
pub const SLOT_WEIGHT_ATOMS: u128 = 1_000;

/// Maximum weight atoms contributed by a fully attested block, before the
/// difficulty scaling.  One fully attested block therefore weighs as much as
/// 1,000 slots of pure elapsed time.
pub const BLOCK_WEIGHT_ATOMS: u128 = 1_000_000;

/// Participation floor in basis points: even a block that carries no
/// attestations still contributes this fraction of [`BLOCK_WEIGHT_ATOMS`].
pub const PARTICIPATION_FLOOR_BP: u32 = 2_500;

/// Basis-point denominator.
pub const BP_DENOMINATOR: u32 = 10_000;

/// Reported healthy maximum lag, in slots, between the chain head and the
/// highest finalised block.  Used by node health reporting and the Explorer to
/// flag a chain that is not finalising; it never affects consensus.
pub const FINALITY_DEPTH_SLOTS: u64 = 128;

/// Finality quorum numerator: two thirds of the active validator set.
///
/// Expressed as an exact fraction rather than basis points, because 2/3 cannot
/// be represented in basis points: `ceil(2n/3)` is computed with integers, so
/// three validators need two attestations, four need three, and one needs one.
pub const FINALITY_QUORUM_NUMERATOR: u64 = 2;

/// Finality quorum denominator.
pub const FINALITY_QUORUM_DENOMINATOR: u64 = 3;

/// Measurement window (in slots) for the reported Time-Rate.
pub const TIME_RATE_WINDOW_SLOTS: u64 = 2_880; // 24 hours

// ---------------------------------------------------------------------------
// Bootstrap
// ---------------------------------------------------------------------------

/// Slots after the genesis block during which the bootstrap proposer rule is
/// active.
pub const BOOTSTRAP_SLOTS: u64 = 2_880; // 24 hours

/// Number of active validators required before proposer selection switches from
/// the bootstrap rule to deterministic scheduling over the validator set.
///
/// With one or more active validators past the bootstrap window, the proposer
/// of every slot is selected deterministically from the validator set.  With
/// **no** active validator, the network falls back to the bootstrap rule rather
/// than halting: a validator-less chain has no authority to capture, and
/// keeping it live lets the community re-register validators.  This is a
/// liveness fallback, never a consensus bypass — no rule, reward, fee or supply
/// parameter changes because of it.
pub const MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL: usize = 1;

// ---------------------------------------------------------------------------
// Mining
// ---------------------------------------------------------------------------

/// Minimum interval between two mining claims, in protocol seconds (4 hours).
pub const CLAIM_INTERVAL_SECS: u64 = 4 * 3_600;

/// Maximum number of valid claims per protocol day (86,400 protocol seconds).
pub const MAX_CLAIMS_PER_DAY: u64 = 6;

/// Length of a protocol day used for the claim cap.
pub const PROTOCOL_DAY_SECS: u64 = 24 * 3_600;

/// Base mining reward per claim, in grains.
///
/// The protocol defines the initial mining rate as `0.001 OBS per 24 hours`
/// (1_000_000_000 grains) distributed over six 4-hour claims, i.e. exactly
/// `1/6000 OBS` per claim = `166_666_666.67` grains.  The protocol fixes the
/// base claim reward at the truncated integer `166_666_666` grains
/// (`0.000166666666 OBS`).  Truncation is applied once, when the protocol
/// defines the constant — never per calculation — so every node computes the
/// same integer for every claim.
pub const BASE_CLAIM_GRAINS: u128 = 166_666_666;

/// Per-claim floor: `0.0002 OBS per 24 hours / 6 = 0.000033333... OBS`.
///
/// `0.0002 * 10^12 / 6 = 33_333_333.33`, truncated to `33_333_333` grains.
/// The mining rate never falls below this value, so mining keeps working for
/// every active-miner count.
pub const MIN_CLAIM_GRAINS: u128 = 33_333_333;

/// Number of active miners that triggers one halving step.
pub const HALVING_ACTIVE_MINERS: u64 = 100_000;

/// Halving ratio numerator (each step multiplies the rate by 995/1000).
pub const HALVING_NUMERATOR: u128 = 995;

/// Halving ratio denominator.
pub const HALVING_DENOMINATOR: u128 = 1_000;

/// Maximum number of halving steps applied.
///
/// The floor is reached after ~320 steps (`0.995^320 ≈ 0.2`), so this bound is
/// never binding in practice; it exists so that the calculation is provably
/// bounded for any active-miner count.
pub const MAX_HALVING_STEPS: u32 = 512;

/// Window during which a miner counts as active (30 days).
pub const ACTIVE_MINER_WINDOW_SECS: u64 = 30 * 24 * 3_600;

// ---------------------------------------------------------------------------
// Genesis and treasury
// ---------------------------------------------------------------------------

/// Height of the block that must contain the genesis claim.
pub const GENESIS_BLOCK_HEIGHT: u64 = 1;

/// Timestamp of the genesis block (2026-01-01T00:00:00Z).
///
/// Every network starts from this protocol time; the first real block must be
/// later than it (rule 1).
pub const GENESIS_TIMESTAMP: u64 = 1_767_225_600;

// ---------------------------------------------------------------------------
// Transactions and fees
// ---------------------------------------------------------------------------

/// Gas fee numerator: 0.02% of the transferred amount.
pub const GAS_FEE_NUMERATOR: u128 = 2;

/// Gas fee denominator (2/10_000 = 0.02%).
pub const GAS_FEE_DENOMINATOR: u128 = 10_000;

/// Maximum gas fee: 0.01 OBS.
pub const MAX_GAS_FEE: Amount = Amount(10_000_000_000);

/// Minimum gas fee charged for any transfer with a non-zero amount (1 grain).
pub const MIN_GAS_FEE: Amount = Amount(1);

/// Share of transaction gas fees routed to the validator reward pool.
pub const VALIDATOR_FEE_SHARE_NUMERATOR: u128 = 40;

/// Denominator for the gas split (40/100 to validators, the remainder to the
/// mining pool).
pub const FEE_SHARE_DENOMINATOR: u128 = 100;

// ---------------------------------------------------------------------------
// Validators
// ---------------------------------------------------------------------------

/// Bond return cooldown after deregistration: 48 hours.
pub const UNBONDING_PERIOD_SECS: u64 = 48 * 3_600;

/// Minimum attestation uptime in basis points for a validator to receive a
/// share of the validator reward pool in an epoch (50%).
pub const MIN_UPTIME_BP: u32 = 5_000;

/// Score weights (must sum to 100).
pub const SCORE_WEIGHT_UPTIME: u32 = 40;
/// Participation component weight.
pub const SCORE_WEIGHT_PARTICIPATION: u32 = 30;
/// Operational efficiency component weight.
pub const SCORE_WEIGHT_EFFICIENCY: u32 = 20;
/// Reliability component weight.
pub const SCORE_WEIGHT_RELIABILITY: u32 = 10;

/// Blocks per validator-reward epoch (24 hours at 30-second slots).
pub const VALIDATOR_REWARD_EPOCH_SLOTS: u64 = 2_880;

/// Maximum length of a validator node endpoint string.
pub const MAX_NODE_ENDPOINT_LEN: usize = 128;

// ---------------------------------------------------------------------------
// Limits
// ---------------------------------------------------------------------------

/// Maximum number of transactions per block.
pub const MAX_TXS_PER_BLOCK: usize = 4_096;

/// Maximum number of attestations per block.
pub const MAX_ATTESTATIONS_PER_BLOCK: usize = 1_024;

/// Maximum number of invitations a single account may issue.
pub const MAX_INVITES_PER_ACCOUNT: u32 = 5;

/// Number of recent blocks retained in consensus state for the median-time-past,
/// difficulty, attestation and fork-choice windows.
pub const STATE_HISTORY_BLOCKS: u64 = 1_024;

/// Maximum number of validators in the set (defensive bound for iteration).
pub const MAX_VALIDATORS: usize = 100_000;

/// Maximum number of peer addresses in a P2P message.
pub const MAX_PEER_ADDRESSES: usize = 256;

/// Domain separation tags used across the protocol.
pub mod tags {
    /// Transaction identity.
    pub const TX: &str = "OBSIDIAN/TX/v1";
    /// Transaction signature payload.
    pub const TX_SIGN: &str = "OBSIDIAN/TX-SIGN/v1";
    /// Block hash.
    pub const BLOCK: &str = "OBSIDIAN/BLOCK/v1";
    /// Block proposer signature payload.
    pub const BLOCK_SIGN: &str = "OBSIDIAN/BLOCK-SIGN/v1";
    /// State root commitment.
    pub const STATE: &str = "OBSIDIAN/STATE/v1";
    /// Attestation signature payload.
    pub const ATTESTATION_SIGN: &str = "OBSIDIAN/ATTESTATION-SIGN/v1";
    /// Proposer scheduling seed.
    pub const PROPOSER_SEED: &str = "OBSIDIAN/PROPOSER-SEED/v1";
    /// Proposer selection function.
    pub const PROPOSER_PICK: &str = "OBSIDIAN/PROPOSER-PICK/v1";
    /// Proposal nonce derivation.
    pub const PROPOSAL_NONCE: &str = "OBSIDIAN/PROPOSAL-NONCE/v1";
    /// Validator registration payload.
    pub const VALIDATOR_REGISTER: &str = "OBSIDIAN/VALIDATOR-REGISTER/v1";
    /// Peer handshake.
    pub const PEER_HANDSHAKE: &str = "OBSIDIAN/PEER-HANDSHAKE/v1";
    /// Node heartbeat evidence.
    pub const HEARTBEAT: &str = "OBSIDIAN/HEARTBEAT/v1";
    /// Invitation commitment (never the code itself).
    pub const INVITE: &str = "OBSIDIAN/INVITE/v1";
    /// Registration authority signature over an invite authorisation.
    pub const INVITE_SIGN: &str = "OBSIDIAN/INVITE-SIGN/v1";
    /// Canonical Gmail identity commitment.
    pub const GMAIL: &str = "OBSIDIAN/GMAIL/v1";
}

/// Returns the exact gas fee for a transfer amount, in grains.
///
/// `fee = clamp(ceil(amount * 2 / 10_000), 1 grain, 0.01 OBS)`, and `0` for a
/// zero-amount transfer.  The ceiling makes the fee strictly positive for every
/// non-zero transfer, which removes zero-fee spam as a possibility, and the cap
/// implements the protocol maximum of 0.01 OBS.
pub fn gas_fee_for(amount: Amount) -> Amount {
    if amount.is_zero() {
        return Amount::ZERO;
    }
    let numerator = amount.grains() * GAS_FEE_NUMERATOR;
    let fee = numerator / GAS_FEE_DENOMINATOR + u128::from(numerator % GAS_FEE_DENOMINATOR != 0);
    let capped = if fee > MAX_GAS_FEE.grains() {
        MAX_GAS_FEE.grains()
    } else {
        fee
    };
    Amount(capped.max(MIN_GAS_FEE.grains()))
}

/// Splits a gas fee into the validator share and the mining-pool share.
///
/// `validator = floor(fee * 40 / 100)`; the mining pool receives the entire
/// remainder, so `validator + mining_pool == fee` exactly for every fee.
pub fn split_gas_fee(fee: Amount) -> (Amount, Amount) {
    let validator = fee.grains() * VALIDATOR_FEE_SHARE_NUMERATOR / FEE_SHARE_DENOMINATOR;
    (Amount(validator), Amount(fee.grains() - validator))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fee_examples_match_the_specification() {
        // 0.02% of 1 OBS = 0.0002 OBS
        assert_eq!(gas_fee_for(Amount::parse("1").unwrap()).to_decimal_string(), "0.0002");
        // 0.02% of 100 OBS = 0.02 OBS, above the cap of 0.01 OBS
        assert_eq!(gas_fee_for(Amount::parse("100").unwrap()), MAX_GAS_FEE);
        // The cap binds from 50 OBS upwards.
        assert_eq!(gas_fee_for(Amount::parse("50").unwrap()), MAX_GAS_FEE);
        // Tiny transfers still pay at least one grain.
        assert_eq!(gas_fee_for(Amount::parse("0.000000000001").unwrap()).grains(), 1);
        assert_eq!(gas_fee_for(Amount::ZERO), Amount::ZERO);
    }

    #[test]
    fn gas_split_is_exact() {
        for fee_grains in [1u128, 2, 3, 7, 99, 100, 101, 9_999, 10_000_000_000] {
            let fee = Amount(fee_grains);
            let (validator, pool) = split_gas_fee(fee);
            assert_eq!(validator.grains() + pool.grains(), fee.grains());
            assert_eq!(
                validator.grains(),
                fee_grains * 40 / 100,
                "validator share must be the floor of 40%"
            );
        }
        // 40% of 0.01 OBS = 0.004 OBS, 60% = 0.006 OBS
        let (v, p) = split_gas_fee(MAX_GAS_FEE);
        assert_eq!(v.to_decimal_string(), "0.004");
        assert_eq!(p.to_decimal_string(), "0.006");
    }

    #[test]
    fn parameters_are_self_consistent() {
        assert_eq!(SLOT_DURATION_SECS, TARGET_BLOCK_INTERVAL_SECS);
        assert!(DIFFICULTY_MIN_BP < DIFFICULTY_INITIAL_BP);
        assert!(DIFFICULTY_INITIAL_BP < DIFFICULTY_MAX_BP);
        assert!(MIN_CLAIM_GRAINS < BASE_CLAIM_GRAINS);
        assert_eq!(
            SCORE_WEIGHT_UPTIME + SCORE_WEIGHT_PARTICIPATION + SCORE_WEIGHT_EFFICIENCY
                + SCORE_WEIGHT_RELIABILITY,
            100
        );
        assert_eq!(MAX_CLAIMS_PER_DAY * CLAIM_INTERVAL_SECS, PROTOCOL_DAY_SECS);
    }
}
