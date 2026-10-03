# 10 — Gas and fees

## The rule

```
GAS_FEE_NUMERATOR   = 2
GAS_FEE_DENOMINATOR = 10,000        # 0.02 % of the transferred amount
MAX_GAS_FEE         = 0.01 OBS      # 10,000,000,000 grains
MIN_GAS_FEE         = 1 grain       # charged on any transfer with a non-zero amount

fee = clamp(ceil(amount × 2 / 10,000), 1 grain, 0.01 OBS)     # integers only
```

Worked examples, in grains:

| Transfer | 0.02 % (rounded up) | Charged |
|---|---|---|
| 1 OBS (`10^12`) | 200,000,000 | 200,000,000 (`0.0002 OBS`) |
| 100 OBS | 20,000,000,000 | 10,000,000,000 (`0.01 OBS`, capped) |
| 50 OBS | 10,000,000,000 | 10,000,000,000 (`0.01 OBS`, cap) |
| 0.5 OBS (`5×10^11`) | 100,000,000 | 100,000,000 |
| 1 grain | 1 (rounded up) | 1 |

The rounding is **up**, always, and it is applied by comparing integers: the
implementation computes `(amount × 2 + 9,999) / 10,000` with `u128` arithmetic.
No float ever participates, so two nodes can never disagree about a fee by one
grain.

A mining **claim is not a transfer** and carries no fee.

## Where the fee goes

```
split_gas_fee(fee):
    to_validator_pool = fee × 40 / 100
    to_mining_pool    = fee − to_validator_pool      # the remainder, exactly
```

* 40 % to the **validator reward pool**.
* 60 % to the **mining pool**.
* The split is computed by subtraction for the second part, so the two shares
  always sum to the fee exactly — no grain is created or lost to rounding.

Both are consensus state (see [08](08-genesis-and-treasury.md)). Neither has a
key or an administrative path, and the split is enforced inside the state
machine: a block whose fee accounting does not balance is invalid.

## Why a capped fee

* The cap (`0.01 OBS`) means the largest possible transfer costs one hundredth of
  a coin, so fees can never become a governance lever or a market.
* The floor (one grain) keeps a transfer from being free in a way that would let
  an attacker fill blocks with zero-cost messages; a grain is the smallest unit
  the protocol has.
* Because the fee is a pure function of the amount, a wallet can compute the
  exact fee before signing, and a person can see it. The interface shows the
  module's own value rather than formatting a guess: the "fee" number in the
  wallet view is the one the Rust module put in the transaction.

## Non-transfer operations

| Operation | Fee |
|-----------|-----|
| Claim (mining) | none |
| Register | none (the invitation is the cost) |
| Register validator | none (the 50 OBS bond is held, not spent) |
| Deregister validator | none |
| Attest | none |

Fees exist to price transfers, which are the only operation that moves value
between accounts.

## Amounts that cannot exist

A transfer's amount comes from the sender's bytes, so it can be any `u128`.
Two rules close that surface, and neither changes the economics:

* A transfer above the maximum supply is refused with `tx_amount_above_supply`.
  No account can hold that much, so the transfer is unpayable on every chain
  this protocol can build; refusing it by name is the balance rule stated early,
  before any arithmetic touches the amount.
* The fee for a very large amount is the cap. `gas_fee_for` saturates at
  `MAX_GAS_FEE` when doubling the amount would overflow a `u128` — the cap binds
  from 50 OBS, so saturation is the exact answer, not an approximation.

Both are covered in [Testing](19-testing.md) and in the state-machine suite.
