//! Proof of Time: weight, difficulty, time rules, proposer scheduling and fork
//! choice.
//!
//! **PoT is not Proof of Work.**  There is no puzzle, no nonce search, no hash
//! target and no hash-rate competition anywhere in this module.  Validators do
//! not race to find hashes; they are *scheduled* deterministically by protocol
//! time and are rewarded in proportion to the weight they verifiably
//! contributed.
//!
//! * **PoT weight** is a deterministic integer derived from elapsed protocol
//!   time (slot gap) plus the fraction of the validator set that attested the
//!   block, scaled by the bounded PoT difficulty.  Time itself is the scarce
//!   resource being measured.
//! * **PoT difficulty** is a slow-moving, bounded multiplier on the base slot
//!   weight.  It compensates for long-run deviations between the observed block
//!   cadence and the 30-second target.  It is *not* a threshold: no block is
//!   ever rejected because a hash is above or below a value.  Bounds are
//!   `6_666 <= difficulty_bp <= 15_000` (0.6666× to 1.5× the base weight).
//! * **Time-Rate** (never "hash rate") is the number of weight atoms the chain
//!   accumulated per protocol second over a measurement window.
//! * **Fork choice** is: greatest accumulated PoT weight, then the objective
//!   tie-breakers documented in [`fork_choice_better`].

use obs_primitives::hash::Hash32;

use crate::params::{
    BP_DENOMINATOR, DIFFICULTY_EMA_DEN, DIFFICULTY_INITIAL_BP, DIFFICULTY_MAX_BP,
    DIFFICULTY_MIN_BP, BLOCK_WEIGHT_ATOMS, MAX_SLOT_GAP, MTP_WINDOW, PARTICIPATION_FLOOR_BP,
    SLOT_WEIGHT_ATOMS, tags,
};

/// Accumulated PoT weight, in integer atoms.
///
/// Weight is the measure of protocol time a chain has verifiably accumulated.
/// One atom is one thousandth of one fully-participating slot-second; the units
/// are arbitrary but fixed by the protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct PoTWeight {
    /// Total atoms.
    pub atoms: u128,
}

impl PoTWeight {
    /// Zero weight (the genesis chain).
    pub const ZERO: PoTWeight = PoTWeight { atoms: 0 };

    /// Builds a weight from raw atoms.
    pub fn from_atoms(atoms: u128) -> PoTWeight {
        PoTWeight { atoms }
    }

    /// Adds weight, saturating instead of overflowing: an overflow is
    /// impossible in practice (it would take ~10^25 blocks) and saturation
    /// keeps the operation total and deterministic.
    pub fn checked_add(self, other: PoTWeight) -> PoTWeight {
        PoTWeight {
            atoms: self.atoms.saturating_add(other.atoms),
        }
    }

    /// Subtracts weight, saturating at zero.
    pub fn saturating_sub(self, other: PoTWeight) -> PoTWeight {
        PoTWeight {
            atoms: self.atoms.saturating_sub(other.atoms),
        }
    }

    /// Time-Rate in atoms per protocol second, truncated.
    pub fn time_rate_per_sec(self, elapsed_secs: u64) -> u128 {
        if elapsed_secs == 0 {
            return 0;
        }
        self.atoms / elapsed_secs as u128
    }
}

/// Number of whole slots between two protocol timestamps.
///
/// Truncating integer division: exact protocol time, no rounding assumptions.
pub fn slots_between(from_secs: u64, to_secs: u64) -> u64 {
    to_secs.saturating_sub(from_secs) / crate::params::SLOT_DURATION_SECS
}

/// Median time past: the median timestamp of a window of previous blocks.
///
/// Rule 1 of the protocol's three timestamp rules uses this value; the window
/// is the last [`MTP_WINDOW`] blocks *before* the block being validated.  For
/// an even number of samples the lower of the two middle values is used, which
/// keeps the result an exact integer and independent of sorting stability.
pub fn median_time_past(timestamps: &[u64]) -> Option<u64> {
    if timestamps.is_empty() {
        return None;
    }
    let mut window: Vec<u64> = timestamps
        .iter()
        .rev()
        .take(MTP_WINDOW)
        .copied()
        .collect();
    window.sort_unstable();
    Some(window[(window.len() - 1) / 2])
}

/// Weight contributed by a single block.
///
/// ```text
/// time_atoms        = min(slot_gap, MAX_SLOT_GAP) * SLOT_WEIGHT_ATOMS
/// participation_bp  = clamp(attesting_validators * 10_000 / active_validators,
///                           PARTICIPATION_FLOOR_BP, 10_000)
/// participation_atoms = BLOCK_WEIGHT_ATOMS * participation_bp / 10_000
/// base              = time_atoms + participation_atoms
/// weight            = base * difficulty_bp / 10_000
/// ```
///
/// * **Time dominates.**  `SLOT_WEIGHT_ATOMS` per slot means a block always
///   carries at least one slot of weight, and each additional elapsed slot (up
///   to `MAX_SLOT_GAP`) adds the same amount again.  Weight is thus, first and
///   last, a count of protocol time.
/// * **Participation is verified evidence.**  The attested fraction of the
///   active validator set can add at most `BLOCK_WEIGHT_ATOMS`, i.e. 1,000
///   slots' worth in one block, and never less than the
///   `PARTICIPATION_FLOOR_BP` floor, so liveness never stops accruing weight.
///   Attestations are signatures checked by the state machine; no validator can
///   inflate them without the corresponding private key.
/// * **PoT difficulty scales the result within hard bounds.**  Because
///   `difficulty_bp` is clamped to `6_666..=15_000`, this factor is always
///   between 0.6666 and 1.5 — it corrects drift in the *measured* cadence
///   towards the 30-second target and cannot be pushed further by any
///   proposer, since the value itself is recomputed and checked by every node.
pub fn weight_of_block(
    slot_gap: u64,
    attesting_validators: usize,
    active_validators: usize,
    difficulty_bp: u32,
) -> u128 {
    let gap = slot_gap.clamp(1, MAX_SLOT_GAP) as u128;
    let time_atoms = gap * SLOT_WEIGHT_ATOMS;

    let participation_bp = if active_validators == 0 {
        BP_DENOMINATOR as u64
    } else {
        let bp = (attesting_validators as u128) * BP_DENOMINATOR as u128
            / active_validators as u128;
        bp.min(BP_DENOMINATOR as u128) as u64
    }
    .max(PARTICIPATION_FLOOR_BP as u64);

    let participation_atoms =
        BLOCK_WEIGHT_ATOMS * participation_bp as u128 / BP_DENOMINATOR as u128;
    let base = time_atoms + participation_atoms;
    base * difficulty_bp as u128 / BP_DENOMINATOR as u128
}

/// Raw PoT difficulty for a measurement window, in basis points.
///
/// `raw = DIFFICULTY_INITIAL_BP * expected_span / observed_span`, clamped to
/// `[DIFFICULTY_MIN_BP, DIFFICULTY_MAX_BP]`.
///
/// If blocks arrive *slower* than the slot target (`observed > expected`) the
/// multiplier falls: the network needs fewer difficulty-adjusted units per
/// second of protocol time.  If they arrive faster, the multiplier rises.
/// `observed_span == 0` returns the maximum, which is the conservative choice
/// (it can never make the chain easier to advance).
pub fn raw_difficulty_bp(expected_span_secs: u64, observed_span_secs: u64) -> u32 {
    if observed_span_secs == 0 {
        return DIFFICULTY_MAX_BP;
    }
    let raw = (DIFFICULTY_INITIAL_BP as u128) * (expected_span_secs as u128)
        / (observed_span_secs as u128);
    raw.clamp(DIFFICULTY_MIN_BP as u128, DIFFICULTY_MAX_BP as u128) as u32
}

/// Exponential moving average update used at every difficulty epoch.
///
/// `next = (7 * previous + raw) / 8`, integer arithmetic, truncating.  The
/// result is always clamped into the protocol bounds, so a single anomalous
/// window can move difficulty by at most 1/8 of the distance to the bound.
pub fn next_difficulty_bp(previous_bp: u32, raw_bp: u32) -> u32 {
    let numerator = (DIFFICULTY_EMA_DEN as u128 - 1) * previous_bp as u128 + raw_bp as u128;
    let next = numerator / DIFFICULTY_EMA_DEN as u128;
    next.clamp(DIFFICULTY_MIN_BP as u128, DIFFICULTY_MAX_BP as u128) as u32
}

/// Deterministic seed for proposer selection in a slot.
///
/// The seed commits to the chain id, the parent block hash and the slot number,
/// so nobody — including the previous proposer — can bias selection without
/// changing the parent.
pub fn proposer_seed(chain_id: u32, parent: &Hash32, slot: u64) -> Hash32 {
    Hash32::tagged(
        tags::PROPOSER_SEED,
        &[&chain_id.to_le_bytes(), &parent.0, &slot.to_le_bytes()],
    )
}

/// Deterministically selects the proposer index for a slot.
///
/// `index = LE_u64(seed[..8]) mod validator_count`, where the seed is derived
/// from the previous block hash.  Every node computes the same index from the
/// same parent, with no communication and no race: this is scheduling, not
/// competition.  The modulo bias is at most `count / 2^64`, which for the
/// protocol cap of 100,000 validators is below `6 * 10^-15` and therefore
/// irrelevant; the function is nonetheless total and deterministic for every
/// input.
pub fn proposer_for_slot(
    chain_id: u32,
    parent: &Hash32,
    slot: u64,
    validator_count: usize,
) -> Option<usize> {
    if validator_count == 0 {
        return None;
    }
    let seed = proposer_seed(chain_id, parent, slot);
    let mut bytes = [0u8; 8];
    bytes.copy_from_slice(&seed.0[..8]);
    Some((u64::from_le_bytes(bytes) % validator_count as u64) as usize)
}

/// Fork-choice comparison.
///
/// Returns `true` when candidate `a` should be preferred over `b`.  The rules
/// are applied in order and are total, so all honest nodes agree:
///
/// 1. **Higher accumulated PoT weight wins.**  Weight measures protocol time
///    plus verified validator participation, never raw block count.
/// 2. **Lower block height wins** when weights are exactly equal.  A shorter
///    chain that accumulated the same weight did so with older (less
///    re-organisable) history.
/// 3. **Lexicographically smaller head hash wins** when weights and heights are
///    equal.  This is an objective, unpredictable-at-build-time tie-breaker:
///    it cannot be influenced by a proposer without grinding the hash, which
///    the protocol does not reward and which the deterministic proposer
///    schedule makes pointless.
pub fn fork_choice_better(
    a_weight: PoTWeight,
    a_height: u64,
    a_head: &Hash32,
    b_weight: PoTWeight,
    b_height: u64,
    b_head: &Hash32,
) -> bool {
    if a_weight != b_weight {
        return a_weight.atoms > b_weight.atoms;
    }
    if a_height != b_height {
        return a_height < b_height;
    }
    a_head.0 < b_head.0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mtp_uses_the_median_of_the_last_window() {
        // 11 timestamps: median is the 6th smallest.
        let stamps: Vec<u64> = (1..=11).collect();
        assert_eq!(median_time_past(&stamps), Some(6));

        // A window longer than 11 entries uses the most recent 11.
        let mut longer = vec![0u64; 20];
        for (i, s) in longer.iter_mut().enumerate() {
            *s = i as u64;
        }
        assert_eq!(median_time_past(&longer), Some(14));

        // Even counts take the lower middle value.
        assert_eq!(median_time_past(&[10, 20, 30, 40]), Some(20));
        assert_eq!(median_time_past(&[]), None);
    }

    #[test]
    fn weight_is_time_based_and_bounded() {
        const D: u32 = DIFFICULTY_INITIAL_BP; // neutral difficulty
        // A one-validator chain: full participation, one slot gap.
        let w = weight_of_block(1, 1, 1, D);
        assert_eq!(w, SLOT_WEIGHT_ATOMS + BLOCK_WEIGHT_ATOMS);
        // Long gaps gain more time weight, but are capped.
        assert!(weight_of_block(4, 1, 1, D) > w);
        assert_eq!(
            weight_of_block(1_000, 1, 1, D),
            weight_of_block(MAX_SLOT_GAP, 1, 1, D)
        );
        // No attestations: the floor still credits time.
        assert_eq!(
            weight_of_block(1, 0, 10, D),
            SLOT_WEIGHT_ATOMS + BLOCK_WEIGHT_ATOMS * PARTICIPATION_FLOOR_BP as u128 / 10_000
        );
        // Weight never exceeds the full-participation bound.
        assert!(weight_of_block(8, 10, 10, D) <= 8 * SLOT_WEIGHT_ATOMS + BLOCK_WEIGHT_ATOMS);
        // More attesters never decreases weight.
        for n in 0..10 {
            assert!(
                weight_of_block(2, n + 1, 10, D) >= weight_of_block(2, n, 10, D)
            );
        }
    }

    #[test]
    fn difficulty_scales_weight_strictly_within_its_bounds() {
        let base = DIFFICULTY_INITIAL_BP;
        let neutral = weight_of_block(2, 1, 1, base);
        let easiest = weight_of_block(2, 1, 1, DIFFICULTY_MIN_BP);
        let hardest = weight_of_block(2, 1, 1, DIFFICULTY_MAX_BP);
        assert!(easiest < neutral);
        assert!(neutral < hardest);
        assert_eq!(easiest, neutral * DIFFICULTY_MIN_BP as u128 / 10_000);
        assert_eq!(hardest, neutral * DIFFICULTY_MAX_BP as u128 / 10_000);
        // The factor is bounded to [0.6666, 1.5]: no proposer can inflate
        // weight by more than 50% through difficulty, and no combination of
        // parameters can deflate it below two thirds.
        assert!(hardest * 2 <= neutral * 3);
        // Integer division truncates, so the scaled value can only differ from
        // the exact ratio by less than one unit of the scale (10,000).
        assert!(easiest * 10_000 + 9_999 >= neutral * DIFFICULTY_MIN_BP as u128);
        assert!(hardest * 10_000 <= neutral * DIFFICULTY_MAX_BP as u128);
    }

    #[test]
    fn difficulty_is_bounded_and_slow_moving() {
        assert_eq!(raw_difficulty_bp(30, 30), DIFFICULTY_INITIAL_BP);
        assert_eq!(raw_difficulty_bp(30, 0), DIFFICULTY_MAX_BP);
        // Slow blocks (large observed span) lower difficulty.
        assert!(raw_difficulty_bp(60, 120) < DIFFICULTY_INITIAL_BP);
        // Fast blocks raise it, up to the cap.
        assert!(raw_difficulty_bp(60, 30) > DIFFICULTY_INITIAL_BP);
        assert_eq!(raw_difficulty_bp(60, 1), DIFFICULTY_MAX_BP);

        // EMA moves by at most 1/8 of the distance and stays in bounds.
        let up = next_difficulty_bp(10_000, DIFFICULTY_MAX_BP);
        assert_eq!(up, (7 * 10_000 + DIFFICULTY_MAX_BP) / 8);
        assert!(up <= DIFFICULTY_MAX_BP);
        for _ in 0..1_000 {
            let d = next_difficulty_bp(0, 0);
            assert!((DIFFICULTY_MIN_BP..=DIFFICULTY_MAX_BP).contains(&d));
        }
        // Repeated max-raw updates converge to the cap without exceeding it.
        let mut d = DIFFICULTY_INITIAL_BP;
        for _ in 0..100 {
            d = next_difficulty_bp(d, DIFFICULTY_MAX_BP);
            assert!(d <= DIFFICULTY_MAX_BP);
        }
        assert!(d > DIFFICULTY_INITIAL_BP);
    }

    #[test]
    fn proposer_selection_is_deterministic_and_well_distributed() {
        let parent = Hash32::from_bytes([9u8; 32]);
        let first = proposer_for_slot(1, &parent, 100, 7).unwrap();
        for _ in 0..10 {
            assert_eq!(proposer_for_slot(1, &parent, 100, 7).unwrap(), first);
        }
        assert!(proposer_for_slot(1, &parent, 100, 0).is_none());
        // Different slots select different proposers over a window.
        let mut seen = std::collections::BTreeSet::new();
        for slot in 0..200u64 {
            seen.insert(proposer_for_slot(1, &parent, slot, 5).unwrap());
        }
        assert_eq!(seen.len(), 5);
        // Changing the parent changes selection.
        let other = Hash32::from_bytes([10u8; 32]);
        let changed = (0..200u64)
            .filter(|s| {
                proposer_for_slot(1, &parent, *s, 5) != proposer_for_slot(1, &other, *s, 5)
            })
            .count();
        assert!(changed > 50, "selection must depend on the parent hash");
    }

    #[test]
    fn fork_choice_prefers_weight_then_height_then_hash() {
        let head_a = Hash32::from_bytes([1u8; 32]);
        let head_b = Hash32::from_bytes([2u8; 32]);
        // 1: heavier wins.
        assert!(fork_choice_better(
            PoTWeight::from_atoms(200),
            5,
            &head_a,
            PoTWeight::from_atoms(100),
            5,
            &head_b
        ));
        assert!(!fork_choice_better(
            PoTWeight::from_atoms(100),
            5,
            &head_a,
            PoTWeight::from_atoms(200),
            5,
            &head_b
        ));
        // 2: equal weight, lower height wins.
        assert!(fork_choice_better(
            PoTWeight::from_atoms(100),
            4,
            &head_a,
            PoTWeight::from_atoms(100),
            5,
            &head_b
        ));
        // 3: equal weight and height, smaller hash wins, and the order is total.
        assert!(fork_choice_better(
            PoTWeight::from_atoms(100),
            5,
            &head_a,
            PoTWeight::from_atoms(100),
            5,
            &head_b
        ));
        assert!(!fork_choice_better(
            PoTWeight::from_atoms(100),
            5,
            &head_b,
            PoTWeight::from_atoms(100),
            5,
            &head_a
        ));
        assert!(!fork_choice_better(
            PoTWeight::from_atoms(100),
            5,
            &head_a,
            PoTWeight::from_atoms(100),
            5,
            &head_a
        ));
    }

    #[test]
    fn time_rate_is_truncating_and_safe() {
        let w = PoTWeight::from_atoms(1_000_000);
        assert_eq!(w.time_rate_per_sec(10), 100_000);
        assert_eq!(w.time_rate_per_sec(3), 333_333);
        assert_eq!(w.time_rate_per_sec(0), 0);
        assert_eq!(slots_between(0, 29), 0);
        assert_eq!(slots_between(0, 30), 1);
        assert_eq!(slots_between(0, 61), 2);
    }
}
