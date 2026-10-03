//! Mining economics.
//!
//! Mining on Obsidian is **not** hash-rate competition.  A miner claims once
//! per protocol-defined interval (4 hours), at most six times per protocol day,
//! and the reward is a deterministic function of *how many miners are active*
//! and *elapsed protocol time* — never of computing power, luck or hardware.
//!
//! * base rate: `BASE_CLAIM_GRAINS` per claim (0.001 OBS/day in six claims),
//! * halving: the rate is multiplied by `995/1000` once per 100,000 active
//!   miners, where "active" means "claimed within the last 30 days",
//! * floor: the rate never falls below `MIN_CLAIM_GRAINS` per claim
//!   (0.0002 OBS/day), which keeps mining viable at any scale.
//!
//! Every value is an integer number of grains.  The schedule is a pure
//! function of chain state, so two nodes with the same state always agree, and
//! no miner can influence another miner's rate except by claiming (which is the
//! intended signal of real activity).

use obs_primitives::money::Amount;

use crate::params::{
    ACTIVE_MINER_WINDOW_SECS, BASE_CLAIM_GRAINS, HALVING_ACTIVE_MINERS, HALVING_DENOMINATOR,
    HALVING_NUMERATOR, MAX_HALVING_STEPS, MIN_CLAIM_GRAINS,
};

/// Number of halving steps that apply for a given number of active miners.
///
/// `steps = floor(active_miners / 100_000)`, capped at [`MAX_HALVING_STEPS`].
pub fn halving_steps(active_miners: u64) -> u32 {
    let steps = active_miners / HALVING_ACTIVE_MINERS;
    steps.min(MAX_HALVING_STEPS as u64) as u32
}

/// The mining reward for one claim, in grains.
///
/// `reward = max(BASE * (995/1000)^steps, MIN_CLAIM_GRAINS)` where each step is
/// an integer multiplication followed by an integer floor division, applied in
/// order.  The result is monotonically non-increasing in `active_miners` and
/// never leaves `[MIN_CLAIM_GRAINS, BASE_CLAIM_GRAINS]`.
pub fn reward_for_claim(active_miners: u64) -> Amount {
    let mut reward = BASE_CLAIM_GRAINS;
    for _ in 0..halving_steps(active_miners) {
        reward = reward * HALVING_NUMERATOR / HALVING_DENOMINATOR;
        if reward <= MIN_CLAIM_GRAINS {
            // The floor is reached: further steps cannot lower the rate.
            // (Iterating to the cap would be a no-op anyway, so stopping here
            // changes no result — only the amount of work done.)
            return Amount(MIN_CLAIM_GRAINS);
        }
    }
    Amount(reward.max(MIN_CLAIM_GRAINS))
}

/// Counts active miners from the sequence of "last claim" timestamps.
///
/// A miner is active when its most recent accepted claim happened within
/// [`ACTIVE_MINER_WINDOW_SECS`] before `at`.  The count is a pure function of
/// chain state and protocol time, so the reward for a claim in block `h` is
/// identical on every node that has block `h`.
pub fn active_miner_count<'a, I>(last_claim_times: I, at: u64) -> u64
where
    I: IntoIterator<Item = &'a u64>,
{
    let window_start = at.saturating_sub(ACTIVE_MINER_WINDOW_SECS);
    last_claim_times
        .into_iter()
        .filter(|last| **last >= window_start && **last <= at)
        .count() as u64
}

/// Total issuance contributed by mining up to and including `claims` claims at
/// a constant active-miner count.  Used by documentation and tests to reason
/// about the supply schedule; the chain itself always sums actual rewards.
pub fn cumulative_mining_issuance(claims: u64, active_miners: u64) -> Amount {
    let per_claim = reward_for_claim(active_miners);
    Amount(per_claim.grains().saturating_mul(claims as u128))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params::MAX_CLAIMS_PER_DAY;

    #[test]
    fn base_rate_matches_the_protocol_definition() {
        // 0.001 OBS per day over six claims.
        let per_claim = reward_for_claim(0);
        assert_eq!(per_claim.grains(), 166_666_666);
        assert_eq!(per_claim.to_decimal_string(), "0.000166666666");
        let per_day = per_claim.grains() * 6;
        assert_eq!(per_day, 999_999_996);
        // The full-protocol day value is within one grain-per-six of the target.
        assert_eq!(MAX_CLAIMS_PER_DAY, 6);
        assert!(per_day > 999_999_990);
    }

    #[test]
    fn halving_is_one_step_per_hundred_thousand_miners() {
        assert_eq!(halving_steps(0), 0);
        assert_eq!(halving_steps(99_999), 0);
        assert_eq!(halving_steps(100_000), 1);
        assert_eq!(halving_steps(199_999), 1);
        assert_eq!(halving_steps(200_000), 2);
        assert_eq!(halving_steps(1_000_000), 10);

        // Regression values for the first steps: each step floors its own
        // result, which is what makes the schedule exactly reproducible.
        assert_eq!(reward_for_claim(0).grains(), 166_666_666);
        assert_eq!(reward_for_claim(100_000).grains(), 165_833_332);
        assert_eq!(reward_for_claim(200_000).grains(), 165_004_165);
        assert_eq!(reward_for_claim(300_000).grains(), 164_179_144);
        assert_eq!(reward_for_claim(400_000).grains(), 163_358_248);
        assert_eq!(reward_for_claim(1_000_000).grains(), 158_518_350);
    }

    #[test]
    fn reward_is_monotonic_and_never_leaves_its_bounds() {
        let mut previous = u128::MAX;
        for miners in (0..40_000_000u64).step_by(250_000) {
            let reward = reward_for_claim(miners).grains();
            assert!(reward <= previous, "reward must never increase");
            assert!(reward >= MIN_CLAIM_GRAINS, "reward must never drop below the floor");
            assert!(reward <= BASE_CLAIM_GRAINS, "reward must never exceed the base rate");
            previous = reward;
        }
    }

    #[test]
    fn the_floor_binds_at_32_2_million_active_miners() {
        // 0.995^322 ~= 0.2: the floor (20% of the base rate) is reached at
        // 32,200,000 active miners, i.e. 322 halving steps.
        assert!(reward_for_claim(32_100_000).grains() > MIN_CLAIM_GRAINS);
        assert_eq!(reward_for_claim(32_200_000).grains(), MIN_CLAIM_GRAINS);
        assert_eq!(reward_for_claim(u64::MAX).grains(), MIN_CLAIM_GRAINS);
        // And it stays there: mining never becomes impossible.
        assert_eq!(reward_for_claim(u64::MAX - 1).grains(), MIN_CLAIM_GRAINS);
    }

    #[test]
    fn active_miner_count_uses_protocol_time_windows() {
        let day = 86_400u64;
        let now = 1_800_000_000u64;
        let times = vec![
            now,             // active (claimed just now)
            now - day,       // active
            now - 29 * day,  // active (inside the 30-day window)
            now - 30 * day,  // active: the window is inclusive at its start
            now - 31 * day,  // inactive (outside the 30-day window)
            0,               // never claimed
            now + day,       // impossible (future claim) -> excluded
        ];
        assert_eq!(active_miner_count(times.iter(), now), 4);
        assert_eq!(active_miner_count([].iter(), now), 0);
    }

    #[test]
    fn cumulative_issuance_stays_far_below_the_cap() {
        // One year of full-rate mining by a single miner is a rounding error
        // against the 21,000,000 OBS cap; this documents that mining issuance
        // is intentionally slow.
        let year = 365u64;
        let issuance = cumulative_mining_issuance(year * 6, 0);
        let cap = obs_primitives::money::MAX_SUPPLY;
        assert!(issuance.grains() * 1_000 < cap.grains());
        assert_eq!(issuance.grains(), (year * 6) as u128 * 166_666_666);
    }
}
