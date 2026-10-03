# 12 — Registration and recovery

## The six steps

```
Gmail ──▶ Password ──▶ Invitation code ──▶ Mining Account Recovery Code ──▶ MFA (TOTP) ──▶ Wallet ──▶ Activated
  1          2               3                          4                        5              6
```

| Step | Route | What happens |
|------|-------|--------------|
| 1 | `POST /v1/register/begin` | The Gmail address is canonicalised and reserved. **No email verification code is sent or required** |
| 2 | `POST /v1/register/password` | `MIN_PASSWORD_BYTES = 12`, `MAX_PASSWORD_BYTES = 256`, hashed with Argon2id |
| 3 | `POST /v1/register/invite` | An invitation is validated and spent atomically, single use |
| 4 | `POST /v1/register/recovery-code` | The **account** recovery code is issued, shown once |
| 5 | `POST /v1/register/mfa`, `/mfa/confirm` | A TOTP secret is enrolled; the first valid code confirms it |
| 6 | `POST /v1/register/wallet` | Three public keys are accepted; an activation is produced |
| — | `POST /v1/auth/sign-in` | Gmail + password + TOTP code; session token for 12 hours |

**There is no email verification-code step anywhere.** Registration is: Gmail,
password, invitation, recovery code, MFA, wallet. Step 1 records a commitment to
the Gmail address; it never mails anything.

## Gmail canonicalisation, and one account per identity

```
canonical(gmail):
    lower-case
    strip dots from the local part
    strip a +tag from the local part
    map googlemail.com → gmail.com
    require an @ and a dot in the domain
```

`founder+2@GoogleMail.com`, `f.ounder@gmail.com` and `founder@gmail.com` are **the
same identity**. The registration service reserves the canonical form
**atomically** — the check and the write happen under one lock — so two
simultaneous registrations for the same canonical identity cannot both succeed.
A second attempt is refused; a race is refused with the same error as a
duplicate.

The chain stores only a **commitment** (`gmail_commitment`) to the canonical
address, never the address itself. The invitation authorization carries the
commitment too, so an invitation is bound to the identity that will spend it.

## Invitations

| Rule | Value |
|------|-------|
| Maximum per account | `MAX_INVITES_PER_ACCOUNT = 5` |
| Use | Single use, spent atomically |
| Lifetime | `INVITE_SECS = 7 days` from issue |
| Genesis invite (mainnet) | One, single use, never published |
| Development invites | Separate codes per network, minted by that network's authority key |

The invitation is validated **server-side** and spent as part of the registration
transaction, so a code cannot be used twice even under concurrent attempts.
Minting an invitation requires the network's authority key, which lives in a
`0600` file and stops the service if it is missing.

## MFA

* TOTP, `STEP_SECS = 30`, `DEFAULT_SKEW_STEPS = 1` (one step either side).
* Codes are six digits, always formatted with leading zeros — a real code of
  `012345` is `012345`, not `12345` — and the verifier accepts exactly six digits.
* The secret is sealed with the service key; the service can verify a code
  without ever holding it in the clear.
* `MAX_FAILED_ATTEMPTS = 8` failures within a window trigger a
  `LOCKOUT_SECS = 900` lockout.
* Sessions last `SESSION_SECS = 12 hours` and are held in the tab; enrolment
  tokens live `ENROLMENT_SECS = 30 minutes`.

## Recovery

Account recovery is for a lost MFA device, not a lost wallet.

1. `POST /v1/recovery/verify` — the account recovery code plus Gmail and
   password.
2. `POST /v1/recovery/mfa` — a new TOTP secret is enrolled and confirmed.

The account's keys do not change: recovery restores *access* to an account whose
keys are unaffected. There is no path that lets a recovery code move funds, and
no path by which a service operator can recover a wallet.

## What the service never sees

* a private key, a seed phrase, or a keystore password;
* an account password in the clear (only an Argon2id hash);
* a TOTP secret in the clear (sealed with the service key);
* a Gmail address in chain state (only a commitment);
* an invitation code in any log or API response.

## The authorisation is dated in the chain's time

The last step of registration mints an **invitation authorisation**: the
authority's signature binding one invitation code to one Gmail identity. The
wallet puts it in the registration transaction, and the chain accepts that
transaction only when

```text
authorisation.issued_at  <=  block time  <=  authorisation.expires_at
```

`block time` is **protocol time**. So `issued_at` must be protocol time too, and
that is what the service stamps: the timestamp of the node's head block, read
from the node it follows, never the machine's wall clock. The window is still
24 hours — measured in protocol time, like every other chain deadline.

The distinction is not pedantic. Protocol time advances at most
`MAX_BLOCK_DRIFT_SECS` (60) per block, so a chain that is behind the wall clock —
a brand-new network at its epoch, or one that has been quiet — cannot include a
transaction stamped with a wall clock that is minutes ahead. On a running chain
that costs a delay. On a network's **first** block it would be permanent: block 1
is the only block that can carry the founder's registration, because during the
bootstrap window a proposer must already be a registered account, an active
validator, or an account that the block itself registers. Dated in chain time,
the founder's registration goes in whenever the founder gets to it.

A deployment that cannot establish the chain's time — the node is unreachable —
**refuses** the step with `503 chain_time_unknown` rather than minting an
authorisation it cannot date correctly. Failing closed is the whole point: an
unusable authorisation looks like success and behaves like a dead end.

The same rule applies to the operator tools: `obs-cli devnet register` stamps its
authorisation with the chain's head time, and `obs-cli register` — which goes
through this service — inherits the service's stamp.
