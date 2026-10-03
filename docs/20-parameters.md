# 20 — Parameters

Every consensus constant, from `crates/obs-chain/src/params.rs` (protocol version
1) and `crates/obs-primitives/src/money.rs`. They are compiled in, committed to by
the genesis hash and published in every block header. A frontend, API client,
database operator or node operator cannot change one; changing any of them
requires a new protocol version and therefore a new network.

## Money

| Constant | Value | Note |
|----------|-------|------|
| `GRAINS_PER_OBS` | `10^12` | `1 OBS` is a trillion grains |
| `MAX_SUPPLY` | `21,000,000 OBS` | hard cap, enforced in the state machine |
| `GENESIS_ALLOCATION` | `100,000 OBS` | once, in block 1, to the treasury (the founder's account) |
| `VALIDATOR_BOND` | `50 OBS` | held, not spent; returned after unbonding |
| `MIN_GAS_FEE` | `1 grain` | any transfer with a non-zero amount |
| `MAX_GAS_FEE` | `0.01 OBS` | `10,000,000,000` grains |
| `GAS_FEE_NUMERATOR / DENOMINATOR` | `2 / 10,000` | 0.02 % of the amount, rounded up |
| `VALIDATOR_FEE_SHARE_NUMERATOR` | `40 / 100` | the remainder (60 %) funds the mining pool |

## Time and slots

| Constant | Value |
|----------|-------|
| `PROTOCOL_VERSION` | 1 |
| `SLOT_DURATION_SECS` | 30 |
| `TARGET_BLOCK_INTERVAL_SECS` | 30 |
| `EPOCH_SLOTS` | 128 |
| `DIFFICULTY_WINDOW_BLOCKS` | 32 |
| `MTP_WINDOW` | 11 |
| `MIN_BLOCK_SPACING_SECS` | 1 |
| `MAX_BLOCK_DRIFT_SECS` | 60 |
| `LOCAL_FUTURE_SANITY_SECS` | 120 (gossip only, not consensus) |
| `MAX_SLOT_GAP` | 8 |
| `GENESIS_TIMESTAMP` | `1,767,225,600` (2026-01-01T00:00:00Z) |
| `GENESIS_BLOCK_HEIGHT` | 1 |
| `BOOTSTRAP_SLOTS` | 2,880 (24 h) |
| `MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL` | 1 |
| `STATE_HISTORY_BLOCKS` | 1,024 |
| `FINALITY_DEPTH_SLOTS` | 128 |
| `FINALITY_QUORUM` | 2/3, `ceil(2n/3)` in integers |
| `TIME_RATE_WINDOW_SLOTS` | 2,880 (24 h) |

## Weight and difficulty

| Constant | Value |
|----------|-------|
| `SLOT_WEIGHT_ATOMS` | 1,000 per elapsed slot |
| `BLOCK_WEIGHT_ATOMS` | 1,000,000 for full participation |
| `PARTICIPATION_FLOOR_BP` | 2,500 (25 % of `BLOCK_WEIGHT_ATOMS`) |
| `BP_DENOMINATOR` | 10,000 |
| `DIFFICULTY_INITIAL_BP` | 10,000 (exactly on target) |
| `DIFFICULTY_MIN_BP` | 6,666 |
| `DIFFICULTY_MAX_BP` | 15,000 |
| `DIFFICULTY_EMA_DEN` | 8 (`next = (7·previous + raw) / 8`) |

## Mining

| Constant | Value |
|----------|-------|
| `CLAIM_INTERVAL_SECS` | 14,400 (4 hours) |
| `MAX_CLAIMS_PER_DAY` | 6 |
| `PROTOCOL_DAY_SECS` | 86,400 |
| `BASE_CLAIM_GRAINS` | 166,666,666 (`0.000166666666 OBS`) |
| `MIN_CLAIM_GRAINS` | 33,333,333 (`0.000033333333 OBS`) |
| `HALVING_ACTIVE_MINERS` | 100,000 |
| `HALVING_NUMERATOR / DENOMINATOR` | 995 / 1000 (−0.5 % per step) |
| `MAX_HALVING_STEPS` | 512 |
| `ACTIVE_MINER_WINDOW_SECS` | 2,592,000 (30 days) |

## Validators

| Constant | Value |
|----------|-------|
| `UNBONDING_PERIOD_SECS` | 172,800 (48 hours) |
| `MIN_UPTIME_BP` | 5,000 (50 %) |
| `SCORE_WEIGHT_UPTIME / PARTICIPATION / EFFICIENCY / RELIABILITY` | 40 / 30 / 20 / 10 |
| `VALIDATOR_REWARD_EPOCH_SLOTS` | 2,880 (24 h) |
| `MAX_VALIDATORS` | 100,000 |
| `MAX_NODE_ENDPOINT_LEN` | 128 |

## Limits

| Constant | Value |
|----------|-------|
| `MAX_TXS_PER_BLOCK` | 4,096 |
| `MAX_ATTESTATIONS_PER_BLOCK` | 1,024 |
| `MAX_PEER_ADDRESSES` | 256 |
| `MAX_INVITES_PER_ACCOUNT` | 5 |

## Registration service

| Constant | Value |
|----------|-------|
| `MIN_PASSWORD_BYTES / MAX_PASSWORD_BYTES` | 12 / 256 |
| `MAX_FAILED_ATTEMPTS` | 8 |
| `LOCKOUT_SECS` | 900 |
| `SESSION_SECS` | 43,200 (12 hours) |
| `ENROLMENT_SECS` | 1,800 (30 minutes) |
| `INVITE_SECS` | 604,800 (7 days) |
| `SESSION_TOKEN_BYTES` | 32 |
| `AUTHORIZATION_SECS` | 86,400 (24 hours) |
| TOTP `STEP_SECS` / `DEFAULT_SKEW_STEPS` | 30 / 1 |

## Portal

| Constant | Value |
|----------|-------|
| Rate limits | clamped to `[10, 6000]` requests/minute per key |
| Scopes | `read:blocks`, `read:transactions`, `read:validators` |
| Key secret | shown once, stored as a tagged hash |
