# 15 — Security

## What this system claims

Obsidian is built as a **high-assurance, defence-in-depth** system: several
independent mechanisms stand between a mistake and a loss, every one of them
fail-closed, and the security-critical logic is written once, in Rust, and shared
by the node, the command-line client and the browser wallet.

It does **not** claim to be unhackable, and no document, API response or screen
in this project says so. Cryptographic systems fail through implementation bugs,
key management, and the humans running them; the honest goal is to make each of
those failures hard, visible and survivable.

## Assets and the threats to them

| Asset | Threat | Control |
|-------|--------|---------|
| A wallet's private keys | Theft by a compromised front end or service | Keys are generated and used only inside the Rust core; they never cross to JavaScript, are never sent, never logged, never stored in the clear |
| An account's funds | A forged or replayed transaction | Ed25519 signature over a preimage bound to the chain id and the exact next nonce |
| Supply | Issuance beyond the cap, or a second genesis allocation | Enforced in the state machine, part of the state root, verified by every node |
| Consensus | A proposer writing favourable parameters | Difficulty, weight and state root are recomputed by every node; the proposer schedule is deterministic and public |
| Privacy | Learning an account's balance from public APIs | No public balance route; a balance requires a signature over a fresh nonce; the response scrubber refuses any body that would leak a balance; the index never holds one |
| Identities | One person holding many accounts | Canonical Gmail identity, atomic reservation, one account per canonical identity |
| Invitations | Reuse, leakage, cross-network replay | Single-use, spent atomically, bound to the identity and chain, and the mainnet genesis code is never published |
| Availability | A chain that stops producing blocks | Slots and scheduling are deterministic; finality is tracked and reported; the bootstrap fallback keeps an empty network provable |

## Guarantees that are structural, not procedural

* **The interface cannot mint.** It holds no key that the person did not create,
  and the only writes it can perform are a signed transaction and a signed proof
  of ownership. Everything else is a read.
* **There is no administrative backdoor.** There is no route, flag or code path
  that creates value, changes a balance, approves a claim, changes a fee, a
  reward, a supply or a timing rule, or bypasses consensus. The acceptance run
  searches for such routes and finds none.
* **No hidden emergency bypass.** The bootstrap rule is the only fallback, it
  applies only when there is no validator set, and it changes no parameter. It is
  documented in [03](03-proof-of-time.md).
* **No internal exchange, no price feed in consensus.** Any external USD figure
  is presentation-only: it is fetched by a page, never stored in state, and can
  never affect a reward, a fee or a balance.
* **Fail closed.** Unknown kinds, malformed encodings, bad roots, bad signatures,
  wrong chain ids, oversized payloads, unknown routes and unparseable responses
  are all refusals. There is no permissive mode and no "best effort".

## Key management

| Secret | Where it lives | Protection |
|--------|----------------|------------|
| Wallet phrase | Nowhere but the person's own copy and the sealed keystore | Generated on device; shown once; never transmitted |
| Keystore | The person's device | Argon2id (64 MiB, 3 passes) + ChaCha20-Poly1305; header bound as additional data |
| Node identity key | The validator host | A separate key from the wallet key; losing it does not lose the account |
| Authority key (invitation minting) | A `0600` file | The service refuses to start without it; it can mint invitations and nothing else |
| Service key (sealing TOTP secrets) | A `0600` file | Same discipline |
| API key secret | Shown once, stored as a tagged hash | Read-only scope, rate-limited, rotatable, revocable |

## What is deliberately absent

* No API endpoint that accepts a private key, a seed phrase or a password.
* No server-side wallet, no custodial balance, no "withdraw on behalf of".
* No email verification step, and therefore no email account as an authentication
  factor.
* No admin console, no impersonation, no balance override.
* No floating point in any monetary or consensus computation.

## Operational security

* Networks are isolated by chain id, genesis, database directory and secrets;
  cross-network replay is refused at the signature level.
* Logs deliberately omit invitation codes, secrets and key material. The
  operator CLI never prints an invitation code.
* Files that hold secrets are created `0600`.
* `git` history contains no genesis invitation and no private key; the acceptance
  run greps for both.

## Reporting

A vulnerability should be reported privately to the maintainers before any public
disclosure, with the affected version, the network, and a reproduction. Do not
test against mainnet with funds you are not prepared to lose; use devnet.
