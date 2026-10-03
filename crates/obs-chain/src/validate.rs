//! The three timestamp validation rules.
//!
//! Obsidian validates protocol time with exactly three rules.  Every rule is a
//! pure integer comparison against values that are already in chain state, so
//! validation is deterministic across nodes and does not depend on any node's
//! wall clock.
//!
//! 1. **Median-time-past (historical boundary).**  A block's timestamp must be
//!    strictly greater than the median of the previous `MTP_WINDOW` block
//!    timestamps:
//!    `ts(n+1) > median(ts(n-10) .. ts(n))`.
//! 2. **Future-time tolerance (parent-relative).**  A block's timestamp must be
//!    strictly greater than its parent's and at most `MAX_BLOCK_DRIFT_SECS`
//!    ahead of it:
//!    `parent_ts + 1 <= ts(n+1) <= parent_ts + 60`.
//! 3. **Protocol-time claim validation.**  A mining claim may only be accepted
//!    when the blockchain's protocol time — the timestamp of the block that
//!    includes it — satisfies the claim's interval and daily rules.  A browser
//!    timer, a server clock or a client "now" value has no effect on
//!    eligibility; see [`crate::state`] for the claim rules.
//!
//! **Note on wall clocks.**  A node additionally refuses to *gossip* a block
//! whose timestamp is far in its own local future
//! (`LOCAL_FUTURE_SANITY_SECS`).  That is a relaying policy, not a consensus
//! rule: it can never make an otherwise-valid block invalid, and it can never
//! make an invalid block valid.

use crate::params::{MAX_BLOCK_DRIFT_SECS, MIN_BLOCK_SPACING_SECS};
use crate::state::StateError;

/// Rule 1: median-time-past.
pub fn check_mtp_rule(timestamp: u64, median_time_past: u64) -> Result<(), StateError> {
    if timestamp <= median_time_past {
        return Err(StateError::new(
            "timestamp_mtp",
            format!(
                "block timestamp {} is not after median time past {}",
                timestamp, median_time_past
            ),
        ));
    }
    Ok(())
}

/// Rule 2: parent-relative spacing and drift.
pub fn check_parent_rule(parent_timestamp: u64, timestamp: u64) -> Result<(), StateError> {
    if timestamp < parent_timestamp.saturating_add(MIN_BLOCK_SPACING_SECS) {
        return Err(StateError::new(
            "timestamp_parent_min",
            format!(
                "block timestamp {} is not at least {} second after the parent timestamp {}",
                timestamp, MIN_BLOCK_SPACING_SECS, parent_timestamp
            ),
        ));
    }
    if timestamp > parent_timestamp.saturating_add(MAX_BLOCK_DRIFT_SECS) {
        return Err(StateError::new(
            "timestamp_parent_drift",
            format!(
                "block timestamp {} is more than {} seconds after the parent timestamp {}",
                timestamp, MAX_BLOCK_DRIFT_SECS, parent_timestamp
            ),
        ));
    }
    Ok(())
}

/// Applies rules 1 and 2 together.  Rule 3 lives with the claim rules in the
/// state machine, because it depends on claim state rather than only on time.
pub fn check_timestamp_rules(
    parent_timestamp: u64,
    median_time_past: u64,
    timestamp: u64,
) -> Result<(), StateError> {
    check_mtp_rule(timestamp, median_time_past)?;
    check_parent_rule(parent_timestamp, timestamp)?;
    Ok(())
}

/// Rule 3: a claim's declared protocol time must be the block's protocol time.
///
/// This binds the claim to consensus time: a miner cannot claim "earlier" or
/// "later" than the block that carries the claim, and because a block's
/// timestamp is itself constrained by rules 1 and 2, the effective precision is
/// protocol time, not client time.
pub fn check_claim_protocol_time(
    claim_timestamp: u64,
    block_timestamp: u64,
) -> Result<(), StateError> {
    if claim_timestamp != block_timestamp {
        return Err(StateError::new(
            "timestamp_protocol_claim",
            format!(
                "claim declares protocol time {} but the block's protocol time is {}",
                claim_timestamp, block_timestamp
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rule_one_rejects_timestamps_at_or_before_mtp() {
        assert!(check_mtp_rule(101, 100).is_ok());
        assert!(check_mtp_rule(100, 100).is_err());
        assert!(check_mtp_rule(99, 100).is_err());
        assert_eq!(
            check_mtp_rule(100, 100).unwrap_err().rule,
            "timestamp_mtp"
        );
    }

    #[test]
    fn rule_two_bounds_spacing_and_drift() {
        // Exactly one second after the parent is valid.
        assert!(check_parent_rule(1_000, 1_001).is_ok());
        // Equal timestamps are rejected: time must move forward.
        assert!(check_parent_rule(1_000, 1_000).is_err());
        // One second before the parent is rejected.
        assert!(check_parent_rule(1_000, 999).is_err());
        // Exactly the drift limit is accepted, one second more is not.
        assert!(check_parent_rule(1_000, 1_060).is_ok());
        assert!(check_parent_rule(1_000, 1_061).is_err());
        assert_eq!(
            check_parent_rule(1_000, 1_061).unwrap_err().rule,
            "timestamp_parent_drift"
        );
        assert_eq!(
            check_parent_rule(1_000, 1_000).unwrap_err().rule,
            "timestamp_parent_min"
        );
    }

    #[test]
    fn combined_rules_are_applied_in_order() {
        // Parent at 1000, MTP 995: 1001 is valid, 995 is not.
        assert!(check_timestamp_rules(1_000, 995, 1_001).is_ok());
        assert!(check_timestamp_rules(1_000, 995, 995).is_err());
        // Saturating arithmetic: extreme values are rejected or accepted by
        // rule, never by panic.
        assert!(check_timestamp_rules(0, 0, u64::MAX).is_err());
        assert!(check_timestamp_rules(u64::MAX, 0, u64::MAX).is_ok());
        assert!(check_timestamp_rules(u64::MAX - 1, 0, u64::MAX - 1).is_err());
    }

    #[test]
    fn rule_three_pins_the_claim_to_block_time() {
        assert!(check_claim_protocol_time(1_700_000_000, 1_700_000_000).is_ok());
        assert!(check_claim_protocol_time(1_699_999_999, 1_700_000_000).is_err());
        assert_eq!(
            check_claim_protocol_time(1, 2).unwrap_err().rule,
            "timestamp_protocol_claim"
        );
    }
}
