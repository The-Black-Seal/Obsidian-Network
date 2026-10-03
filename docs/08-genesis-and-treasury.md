# 08 — Genesis and treasury

## The genesis claim

The first valid claim on a network is the **genesis claim**, and it allocates
`GENESIS_ALLOCATION = 100,000 OBS` to the claiming account.

* **Once.** The state machine records `genesis_claimed = true` on that account and
  refuses a second genesis allocation for the life of the chain. The flag is part
  of the state root, so it is part of what every node verifies.
* **In the first block.** `GENESIS_BLOCK_HEIGHT = 1`. A genesis claim that tries
  to arrive at any other height is not a genesis claim.
* **Treasury.** The genesis account **is** the treasury wallet. There is no
  second treasury address, no protocol-owned key and no hidden allocation: the
  founder's account holds the genesis allocation exactly as any account holds a
  balance, and the treasury is that account.
* **In the chain.** The allocation is an entry in blockchain state — the same
  ledger as every other balance — and moves only by signed transaction.

Bootstrap sequence on an empty network:

1. The founding account registers with the network's single genesis invitation.
   On an empty chain the first block may carry a proposer's own `Register`.
2. The founder's first claim is the genesis claim.
3. The first block contains the registration and that claim, and is stamped with
   the claim's declared protocol time.
4. The state after the block holds `100,000 OBS + one claim reward` issued, and
   the indexer reads it from the node like any other block.

## The invitation that starts a network

The **mainnet genesis invitation** is a single code, single use, held by the
network's founding authority and **never published**. It does not appear in
documentation, in this repository, in the interface, in logs, in API responses,
or in test fixtures — and the acceptance run checks that it is absent from
everything that ships, including the acceptance run itself. If it is lost, the
correct response is a new genesis, never a reprint.

Testnet, devnet and staging each get their own disposable invitations, minted by
an authority key for that network, so a leaked development code is worthless
elsewhere.

## Supply

* Hard maximum: `21,000,000 OBS` (`MAX_SUPPLY`), enforced in the state machine.
  An issuance that would cross it is refused; no administrative path can exceed
  it.
* Issued supply is published in every block header, so every node and every
  index can verify it against the cap and against its own history.
* Money is integer grains (`1 OBS = 10^12`), and every arithmetic operation on
  it is checked: `Amount` has `checked_add` and `checked_sub` and no unchecked
  operators.

## The pools

| Pool | Funded by | Spent by |
|------|-----------|----------|
| Mining pool | 60 % of every gas fee | Mining claims, through the state machine |
| Validator reward pool | 40 % of every gas fee | Validator epoch rewards, through the state machine |

Both are consensus state. Neither has a key, an API, or an administrative
withdrawal path. A pool that runs dry simply pays what it has; the protocol never
mints to cover it.
