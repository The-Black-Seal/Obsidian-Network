# 07 — Mining

Mining on Obsidian is claiming a fixed protocol reward. It is not a race, not a
puzzle, and not improvable by hardware.

## The rules

| Rule | Value | Constant |
|------|-------|----------|
| Minimum interval between claims | 4 hours (`14,400` protocol seconds) | `CLAIM_INTERVAL_SECS` |
| Maximum claims per protocol day | 6 | `MAX_CLAIMS_PER_DAY` |
| Protocol day | 86,400 protocol seconds | `PROTOCOL_DAY_SECS` |
| Base reward per claim | `0.000166666666` OBS (`166,666,666` grains) | `BASE_CLAIM_GRAINS` |
| Initial daily rate | `0.001` OBS per 24 hours | — |
| Halving step | −0.5 % (×995/1000) per 100,000 active miners | `HALVING_NUMERATOR`, `HALVING_ACTIVE_MINERS` |
| Floor per claim | `0.000033333333` OBS (`33,333,333` grains) | `MIN_CLAIM_GRAINS` |
| Floor daily rate | `0.0002` OBS per 24 hours | — |
| Active miner window | 30 days | `ACTIVE_MINER_WINDOW_SECS` |

## The reward formula

```
steps   = min(active_miners / 100,000, MAX_HALVING_STEPS = 512)
rate(g) = max(BASE_CLAIM_GRAINS × 995^steps / 1000^steps, MIN_CLAIM_GRAINS)
```

Worked values (per claim, in grains):

| Active miners | Steps | Computed | Paid |
|---|---|---|---|
| 1 | 0 | 166,666,666 | 166,666,666 (`0.000166666666` OBS) |
| 99,999 | 0 | 166,666,666 | 166,666,666 |
| 100,000 | 1 | 165,833,332 | 165,833,332 (`0.000165833332` OBS) |
| 200,000 | 2 | 165,004,165 | 165,004,165 |
| ≥ 10,000,000 | ≥ 100 | floor reached | 33,333,333 (`0.000033333333` OBS) |

Two decisions worth stating:

* **Truncation happens once**, when the protocol defines the constant
  (`1/6000 OBS` = `166,666,666.67` grains → `166,666,666`), never per
  calculation. Every node therefore computes the same integer for every claim.
* **The floor is a protocol constant**, not an emergent behaviour: mining keeps
  working at any active-miner count, and the total issuance is bounded by the
  21,000,000 OBS supply cap.

An **active miner** is an account that has made at least one valid claim in the
last 30 days of protocol time. The count is derived from the chain, not
reported by anyone.

## What a claim is

A signed statement that a registered account's interval has passed. The wallet:

1. reads the chain's count of the account's claims and its protocol time,
2. stamps the claim with that protocol time,
3. signs it,
4. hands the signed bytes to a node.

The chain then checks, in the state machine:

* the account exists and is registered,
* `block.protocol_time ≥ last_claim_at + 14,400`,
* `claims_today < 6` for the claim's protocol day,
* `claim.timestamp == block.timestamp` (rule 3 of
  [04](04-time-and-timestamps.md)),
* the nonce and the signature.

Any failure is a refusal. There is no partial or best-effort acceptance, and no
API, index or interface can overrule the state machine.

## The genesis claim

The **first valid claim on a network is the genesis claim**: it is carried by the
first block and allocates `100,000 OBS` exactly once. See
[08 — Genesis and treasury](08-genesis-and-treasury.md).

## The mining pool

Gas fees route 60 % of every fee to the mining pool, which is what funds mining
rewards once issuance has been spent. The pool is protocol state, not a wallet:
no key can spend it, and a claim draws from it only through the state machine.
