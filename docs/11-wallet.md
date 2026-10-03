# 11 — Wallet

## What it is

A wallet is 256 bits of entropy from the device's own CSPRNG, encoded as a
**24-word** recovery phrase. From it the wallet derives three **separate**
Ed25519 keys:

| Key | Used for | Address namespace |
|-----|----------|-------------------|
| `wallet_key` | The account: spending, claiming, registering, the bond | `obs1…` / `tobs1…` / `sobs1…` / `dobs1…` |
| `node_key` | Validator node identity — attestations and proposals | same namespace, a different address |
| `recovery_key` | Account recovery, separate from the wallet | same namespace |

The separation is deliberate: a leaked node identity is not a leaked wallet, and
recovering an account whose MFA device was lost is not the same operation as
restoring a wallet from its phrase.

## Non-custodial guarantees, and how they are kept

* **The phrase is generated where it is used.** It is produced inside the Rust
  wallet core — the same code the command-line client runs — compiled to
  WebAssembly and loaded by the page.
* **The phrase crosses the boundary exactly twice.** Out, once, when a wallet is
  created (a phrase its owner never saw is a wallet its owner can never recover);
  in, when a wallet is restored from one. It is never written to storage by any
  service, never sent to a node, and never logged.
* **Nothing else crosses.** Transactions, signatures and the public view leave
  the module. Private keys stay behind an opaque handle: the interface calls
  `sign_transfer(handle, …)` and receives a signature, not a key.
* **Randomness is the host's CSPRNG.** The module imports exactly one host
  function, `obs_wasm_random`, which is `crypto.getRandomValues` in a browser.
* **The keystore is sealed.** `keystore_seal` produces Argon2id (64 MiB, 3
  passes) + ChaCha20-Poly1305 text. The header is bound as additional data, so
  altering the network or label breaks decryption rather than silently producing
  a different wallet.
* **Nothing is transmitted except a signed transaction.** The page's only writes
  are `POST /node/api/v1/transactions` (already signed) and
  `POST /node/api/v1/account/proof` (a signature over a fresh nonce, proving the
  account holder's own identity to read that account's own state).

## Recovery: two different things

| | Wallet recovery | Account recovery |
|---|---|---|
| Lost | The device / the browser storage | The MFA device |
| What you have | The 24-word phrase, or the sealed keystore | The account recovery code |
| What it restores | The keys and every address derived from them | Access to the account, with its keys unchanged |
| Where it happens | In the wallet, locally | In the registration service, verified, then MFA is re-enrolled |

The wallet view states this in the interface, because conflating the two is how
people lose money: an account recovery code cannot restore a wallet whose phrase
is lost, and a phrase cannot re-enrol an authenticator.

## The keystore, and the locked state

A sealed keystore cannot be opened without its password — that is the point of
it — so a page that has just loaded cannot read even the wallet's address from
it. The address is not a secret: it is the account's public name. The interface
therefore keeps the public view (address, node and recovery addresses, public
keys, network) beside the sealed text, and shows a **locked** wallet after a
reload:

* the address and public keys are shown, so a person can recognise which wallet
  they are holding;
* the keys are not, because they are inside the sealed text;
* unlocking asks the Rust module to open the keystore and then **checks that the
  wallet that came out is the one this browser recorded**. A keystore that opens
  to a different address is reported as a mismatch and locked again, rather than
  shown as if it were the right wallet.

Nothing in that record is secret and nothing in it can spend.

## What a wallet cannot do

A freshly created wallet holds keys but has no account: registration requires an
invitation, and the chain creates the account in a block. Until that block is
mined, the node answers `account_not_found` and the interface says so — it never
shows a balance of zero as if it had read one.

A wallet cannot mint, cannot change a protocol parameter, cannot approve
anything, and cannot make the chain accept a transaction the consensus rules
refuse. It can only sign statements its owner is entitled to make.
