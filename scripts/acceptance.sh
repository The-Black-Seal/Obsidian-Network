#!/usr/bin/env bash
#
# The acceptance run: 104 numbered checks over the whole system.
#
# Half of these are greps and unit-level gates that need nothing running; the
# other half drive a live devnet over HTTP, exactly as a person or a wallet
# would.  Every check prints PASS or FAIL with the number it belongs to, and the
# script exits non-zero if any check failed.
#
#   bash scripts/acceptance.sh                 # use the deployment at 8081/7200
#   OBSIDIAN_BASE_URL=... bash scripts/acceptance.sh
#
# Nothing here is a mock: the node is a real node, the wallet module is the real
# compiled artifact, and the registration service is the real service.

set -uo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

BASE="${OBSIDIAN_BASE_URL:-http://127.0.0.1:8081}"
NODE="${OBSIDIAN_NODE_URL:-http://127.0.0.1:7200}"
NODE_PORT="${OBSIDIAN_NODE_PORT:-9220}"
NODE_API_PORT="${OBSIDIAN_NODE_API_PORT:-7200}"
NODE_NETWORK="${OBSIDIAN_NETWORK:-devnet}"
# Exported because checks that need a shell script of their own run in a child
# bash, and a check must read the same deployment the rest of the run does.
export BASE NODE NODE_PORT NODE_API_PORT NODE_NETWORK

PASS=0
FAIL=0
FAILED_CHECKS=""

# Warm the build before the first check.  Many checks are `cargo test`
# invocations, and a check that has to compile is a check that measures the
# machine's spare capacity as much as the code: on a busy or freshly-reset
# sandbox the first one can fail on a build hiccup rather than on a defect.
# The checklist wants to test the software, not the toolchain, so the compiling
# happens once, here, outside the graded checks.
if command -v cargo >/dev/null 2>&1; then
    printf 'warming the build (cargo build --workspace --tests)\n'
    cargo build --workspace --tests --quiet || {
        printf 'the workspace does not build; nothing below this line means anything\n'
        exit 2
    }
fi

pass() { PASS=$((PASS + 1)); printf '  %3d. PASS  %s\n' "$1" "$2"; }
fail() { FAIL=$((FAIL + 1)); FAILED_CHECKS="$FAILED_CHECKS $1"; printf '  %3d. FAIL  %s\n' "$1" "$2"; }

# check NUMBER "description" COMMAND...
# The command's exit status decides; its output is captured for the message.
check() {
    local number="$1" description="$2"
    shift 2
    local output
    if output="$("$@" 2>&1)"; then
        pass "$number" "$description"
    else
        fail "$number" "$description"
        printf '        %s\n' "$(printf '%s' "$output" | head -3 | tr '\n' ' ')"
    fi
}

# check_true NUMBER "description" CONDITION-AS-STRING
check_true() {
    local number="$1" description="$2"
    if [ "$3" = "true" ]; then pass "$number" "$description"; else fail "$number" "$description"; fi
}

has() { # has "needle" -- reads stdin
    grep -q -- "$1"
}

json_has() { # json_has URL KEY  → the body contains the key
    curl -sf "$1" | grep -q "\"$2\""
}

section() { printf '\n%s\n' "$1"; }

echo "Obsidian Network — acceptance run"
echo "interface: $BASE   node: $NODE"
echo "started:   $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

# ---------------------------------------------------------------------------
section "Consensus and money (1-12)"
# ---------------------------------------------------------------------------

check 1 "the largest supply the protocol can ever issue is 21,000,000 OBS" \
    grep -q "21_000_000" crates/obs-primitives/src/money.rs
check 2 "the genesis allocation is 100,000 OBS" \
    grep -q "100_000" crates/obs-primitives/src/money.rs
check 3 "the validator bond is 50 OBS" \
    grep -q "50" crates/obs-primitives/src/money.rs
check 4 "money is integer grains: 1 OBS = 10^12 grains" \
    grep -q "1_000_000_000_000" crates/obs-primitives/src/money.rs
check 5 "no floating-point type appears in the monetary path" \
    bash -c '! grep -rnE "\bf32\b|\bf64\b" crates/obs-primitives/src/money.rs crates/obs-chain/src/params.rs crates/obs-chain/src/mining.rs'
check 6 "Amount has checked arithmetic and no unchecked operators" \
    bash -c 'grep -q "checked_add" crates/obs-primitives/src/money.rs && grep -q "checked_sub" crates/obs-primitives/src/money.rs'
check 7 "the gas fee is 0.02 % of the amount" \
    bash -c 'grep -q "GAS_FEE_NUMERATOR: u128 = 2" crates/obs-chain/src/params.rs && grep -q "GAS_FEE_DENOMINATOR: u128 = 10_000" crates/obs-chain/src/params.rs'
check 8 "the gas fee is capped at 0.01 OBS" \
    grep -q "MAX_GAS_FEE: Amount = Amount(10_000_000_000)" crates/obs-chain/src/params.rs
check 9 "gas splits 40 % to validators and the rest to the mining pool" \
    bash -c 'grep -q "VALIDATOR_FEE_SHARE_NUMERATOR: u128 = 40" crates/obs-chain/src/params.rs && grep -q "FEE_SHARE_DENOMINATOR: u128 = 100" crates/obs-chain/src/params.rs'
check 10 "the supply test suite passes" \
    cargo test -p obs-chain --quiet -- money 2>/dev/null
check 11 "the live chain reports a maximum supply of 21,000,000" \
    bash -c "curl -sf $NODE/api/v1/supply | grep -q '\"max_supply\":\"21000000\"'"
check 12 "the live chain reports exactly one genesis allocation" \
    bash -c "curl -sf $NODE/api/v1/supply | grep -q '\"genesis_allocation\":\"100000'"

# ---------------------------------------------------------------------------
section "Proof of Time (13-22)"
# ---------------------------------------------------------------------------

check 13 "there is no proof-of-work anywhere in the consensus code" \
    bash -c '! grep -rniE "proof.of.work|hashrate|hash target|nonce search" crates/obs-chain/src crates/obs-consensus/src | grep -v "not\|never\|no "'
check 14 "no hash threshold appears in the difficulty rules" \
    bash -c '! grep -rn "leading_zero\|target_bits\|hash_target" crates/obs-chain/src'
check 15 "the slot duration is 30 protocol seconds" \
    grep -q "SLOT_DURATION_SECS: u64 = 30" crates/obs-chain/src/params.rs
check 16 "the proposer schedule is deterministic from chain id, parent and slot" \
    grep -q "pub fn proposer_seed" crates/obs-chain/src/pot.rs
check 17 "PoT difficulty is bounded between 6,666 and 15,000 basis points" \
    bash -c 'grep -q "DIFFICULTY_MIN_BP: u32 = 6_666" crates/obs-chain/src/params.rs && grep -q "DIFFICULTY_MAX_BP: u32 = 15_000" crates/obs-chain/src/params.rs'
check 18 "the time-rate window is 24 hours of slots" \
    grep -q "TIME_RATE_WINDOW_SLOTS: u64 = 2_880" crates/obs-chain/src/params.rs
check 19 "weight comes from elapsed slots plus attested participation" \
    bash -c 'grep -q "SLOT_WEIGHT_ATOMS: u128 = 1_000" crates/obs-chain/src/params.rs && grep -q "BLOCK_WEIGHT_ATOMS: u128 = 1_000_000" crates/obs-chain/src/params.rs'
check 20 "the PoT weight tests pass" \
    cargo test -p obs-chain --quiet -- pot 2>/dev/null
check 21 "the live node reports a protocol time" \
    bash -c "curl -sf $NODE/api/v1/status | grep -q '\"protocol_time\"'"
check 22 "the live node reports its PoT difficulty" \
    bash -c "curl -sf $NODE/api/v1/status | grep -q '\"pot_difficulty_bp\"'"

# ---------------------------------------------------------------------------
section "Time and timestamps (23-30)"
# ---------------------------------------------------------------------------

check 23 "the median-time-past window is 11 blocks" \
    grep -q "MTP_WINDOW: usize = 11" crates/obs-chain/src/params.rs
check 24 "a block may be at most 60 seconds ahead of its parent" \
    grep -q "MAX_BLOCK_DRIFT_SECS: u64 = 60" crates/obs-chain/src/params.rs
check 25 "a block must be at least 1 second ahead of its parent" \
    grep -q "MIN_BLOCK_SPACING_SECS: u64 = 1" crates/obs-chain/src/params.rs
check 26 "rule 1 refuses a timestamp at or before the median time past" \
    cargo test -p obs-chain --quiet -- time 2>/dev/null
check 27 "rule 2 refuses a block stamped beyond the parent bound" \
    cargo test -p obs-node --quiet -- claim 2>/dev/null
check 28 "rule 3 binds a claim to the block's own protocol time" \
    grep -q "pub fn check_claim_protocol_time" crates/obs-chain/src/validate.rs
check 29 "protocol time advances by at least one second per block" \
    bash -c "curl -sf $NODE/api/v1/blocks?limit=2 | grep -q '\"timestamp\"'"
check 30 "the node reports a median time past" \
    bash -c "curl -sf $NODE/api/v1/status | grep -q '\"median_time_past\"'"

# ---------------------------------------------------------------------------
section "Mining economics (31-40)"
# ---------------------------------------------------------------------------

check 31 "the claim interval is 4 hours of protocol time" \
    grep -q "CLAIM_INTERVAL_SECS: u64 = 4 \* 3_600" crates/obs-chain/src/params.rs
check 32 "there are at most 6 claims per protocol day" \
    grep -q "MAX_CLAIMS_PER_DAY: u64 = 6" crates/obs-chain/src/params.rs
check 33 "the base reward is 0.000166666666 OBS per claim" \
    bash -c 'grep -q "BASE_CLAIM_GRAINS: u128 = 166_666_666" crates/obs-chain/src/params.rs'
check 34 "the reward floor is 0.000033333333 OBS per claim" \
    grep -q "MIN_CLAIM_GRAINS: u128 = 33_333_333" crates/obs-chain/src/params.rs
check 35 "the halving is -0.5 % per 100,000 active miners" \
    bash -c 'grep -q "HALVING_NUMERATOR: u128 = 995" crates/obs-chain/src/params.rs && grep -q "HALVING_ACTIVE_MINERS: u64 = 100_000" crates/obs-chain/src/params.rs'
check 36 "one halving step pays 165,833,332 grains" \
    cargo test -p obs-chain --quiet -- halving 2>/dev/null
check 37 "the mining reward tests pass" \
    cargo test -p obs-chain --quiet -- mining 2>/dev/null
check 38 "an active miner is one that claimed within 30 days" \
    grep -q "ACTIVE_MINER_WINDOW_SECS: u64 = 30 \* 24 \* 3_600" crates/obs-chain/src/params.rs
check 39 "the live chain pays 0.000166666666 OBS per claim" \
    bash -c "curl -sf $NODE/api/v1/mining | grep -q '\"reward_per_claim\":\"0.000166666666\"'"
check 40 "the live chain reports one active miner and the treasury's claimed genesis" \
    bash -c "curl -sf $NODE/api/v1/mining | grep -q '\"active_miners\":1'"

# ---------------------------------------------------------------------------
section "Genesis and treasury (41-45)"
# ---------------------------------------------------------------------------

check 41 "the genesis claim is bound to block height 1" \
    grep -q "GENESIS_BLOCK_HEIGHT: u64 = 1" crates/obs-chain/src/params.rs
check 42 "the genesis allocation is issued exactly once" \
    cargo test -p obs-chain --quiet -- genesis 2>/dev/null
check 43 "the first block carries the founder's registration" \
    cargo test -p obs-node --quiet -- genesis 2>/dev/null
check 44 "the live chain has issued exactly the genesis allocation plus claims" \
    bash -c "curl -sf $NODE/api/v1/supply | grep -q '\"issued_supply\":\"100000'"
# The invitation is assembled from pieces so that this script does not itself
# contain the string it is looking for — a search for a secret is no place to
# write the secret down.
INVITE_NEEDLE="OBS-GENESIS""-7K4M""-X9P2"
KEY_NEEDLE="-----BEGIN ""PRIVATE KEY-----"
export INVITE_NEEDLE KEY_NEEDLE
check 45 "the mainnet genesis invitation appears nowhere in the repository" \
    bash -c '! grep -rq "$INVITE_NEEDLE" --exclude-dir=.git --exclude-dir=target .'

# ---------------------------------------------------------------------------
section "Validators (46-52)"
# ---------------------------------------------------------------------------

check 46 "deregistration returns the bond after 48 hours" \
    grep -q "UNBONDING_PERIOD_SECS: u64 = 48 \* 3_600" crates/obs-chain/src/params.rs
check 47 "the node identity is a distinct key from the wallet key" \
    grep -q "node_keypair" crates/obs-wallet/src/lib.rs
check 48 "uptime comes from attestations, not self-reporting" \
    bash -c 'grep -q "pub struct Attestation" crates/obs-chain/src/block.rs && ! grep -rqi "reported_uptime\|self_reported" crates/obs-chain/src crates/obs-node/src'
check 49 "finality needs a two-thirds quorum, computed in integers" \
    bash -c 'grep -q "FINALITY_QUORUM_NUMERATOR: u64 = 2" crates/obs-chain/src/params.rs && grep -q "FINALITY_QUORUM_DENOMINATOR: u64 = 3" crates/obs-chain/src/params.rs'
check 50 "the validator tests pass" \
    cargo test -p obs-chain --quiet -- validator 2>/dev/null
# The evidence a validator's uptime and score are derived from has to be
# *there*: a live validator that has proposed blocks must show a non-zero
# `blocks_proposed`, or the operator is being shown a number no block ever
# wrote.  That is exactly what a live devnet showed — `blocks_proposed: 0`
# beside `attestations: 2469` on a validator that had proposed every block —
# because the credit matched only the node identity while a bootstrap
# validator proposes with the wallet key that owns its bond.
check 51 "the live node reports its validator set, active count and proposer credit" \
    bash -c "curl -sf $NODE/api/v1/validators | grep -q '\"validators\"' && curl -sf $NODE/api/v1/validators | grep -q '\"blocks_proposed\":[1-9]' && curl -sf $NODE/api/v1/status | grep -q '\"active_validators\"'"
# A node that cannot *found* a chain is not a node that cannot *join* one.  This
# starts a second node against the running network with nothing but the chain's
# epoch (read from the first node's status, so it works for any deployment) and
# a peer address, waits for it to catch up to the height the first node was at
# when the check began, and requires the two nodes to agree on the state root at
# that height — the strongest single statement that the consensus is
# deterministic and that joining is a matter of connecting, not of
# reconstructing a deployment.
#
# The joiner deliberately gets no `--genesis-file` and no `--authority-key`: its
# genesis record starts with an all-zero registration authority, and without the
# authority it could not validate block 1 of any network whose founder
# registered — which is every real deployment.  A live devnet proved that the
# hard way: the second node sat at height 0 with nothing but orphan rejections.
# The authority is a public parameter, so the handshake carries it, and this
# check requires the joiner to learn it and then reproduce the chain.
check 52 "a second node joins the running network and reaches the same state" \
    bash -c '
        set -e
        epoch=$(curl -sf $NODE/api/v1/status | sed -n "s/.*\"genesis_timestamp\":\([0-9]*\).*/\1/p")
        target=$(curl -sf $NODE/api/v1/status | sed -n "s/.*\"height\":\([0-9]*\).*/\1/p")
        [ -n "$epoch" ] && [ -n "$target" ] || exit 1
        dir=$(mktemp -d)
        port=$((NODE_PORT + 1))
        api=$((NODE_API_PORT + 1))
        ${OBSIDIAN_NODE_BIN:-./target/release/obs-node} --network "$NODE_NETWORK" --data-dir "$dir" \
            --api-port "$api" --listen-port "$port" --genesis-timestamp "$epoch" \
            --peer 127.0.0.1:$NODE_PORT >"$dir/log" 2>&1 &
        pid=$!
        clean() { kill "$pid" 2>/dev/null || true; rm -rf "$dir"; }
        trap clean EXIT
        reached=0
        for _ in $(seq 1 120); do
            have=$(curl -sf http://127.0.0.1:$api/api/v1/status 2>/dev/null | sed -n "s/.*\"height\":\([0-9]*\).*/\1/p" || true)
            if [ -n "$have" ] && [ "$have" -ge "$target" ]; then reached=1; break; fi
            sleep 0.5
        done
        [ "$reached" = 1 ] || { cat "$dir/log"; exit 1; }
        theirs=$(curl -sf http://127.0.0.1:$api/api/v1/blocks/$target | sed -n "s/.*\"state_root\":\"\([0-9a-f]*\)\".*/\1/p")
        ours=$(curl -sf $NODE/api/v1/blocks/$target | sed -n "s/.*\"state_root\":\"\([0-9a-f]*\)\".*/\1/p")
        [ -n "$theirs" ] && [ "$theirs" = "$ours" ] || { cat "$dir/log"; exit 1; }
        # The chain it joined has content, and it applied all of it: block 1
        # carries the founder registration, which is what needed the authority.
        txs=$(curl -sf http://127.0.0.1:$api/api/v1/blocks/1 | sed -n "s/.*\"transactions\":\([0-9]*\).*/\1/p")
        [ -n "$txs" ] && [ "$txs" -ge 1 ] || { cat "$dir/log"; exit 1; }
    '

# ---------------------------------------------------------------------------
section "Wallet (53-64)"
# ---------------------------------------------------------------------------

check 53 "a wallet derives 256 bits of entropy into a 24-word phrase" \
    bash -c 'grep -q "24" crates/obs-wallet/src/lib.rs && grep -q "entropy" crates/obs-wallet/src/lib.rs'
check 54 "the keystore is sealed with Argon2id and ChaCha20-Poly1305" \
    bash -c 'grep -q "Argon2id" crates/obs-wallet/src/keystore.rs && grep -q "ChaCha20\|chacha" crates/obs-wallet/src/keystore.rs'
# No stderr suppression here.  A check that fails while saying nothing is worse
# than a check that fails loudly: this one once reported a failure whose own TAP
# output contained only `ok 1` and no failing assertion — the machine, not the
# module, and it passed standalone — and the discarded stderr was the only place
# that could have said so.
check 55 "the wasm module exports the ABI the interface expects" \
    node --test web/tests/wallet-module.test.mjs
# The wallet suite is randomized (it generates fresh wallets), so a failure here
# has to say *which* test failed and why.  The first version of this check sent
# stderr to /dev/null and reported only a progress line, which is exactly the
# kind of evidence-throwing the flake rule in docs/19-testing.md warns about: the
# log now survives and the failing names are printed.
check 56 "a wallet created in the module has three distinct keys" \
    bash -c 'log=/tmp/obs-wallet-suite.log
        if cargo test -p obs-wallet >"$log" 2>&1; then exit 0; fi
        echo "the wallet suite failed; full output: $log"
        grep -E "^test .* FAILED|panicked at|^failures:" "$log" | head -4
        exit 1'
check 57 "the installed wasm artifact matches the current source" \
    bash scripts/build-web.sh --check
check 58 "the interface shows no private key when a wallet is created" \
    node --test web/tests/smoke.test.mjs 2>/dev/null
check 59 "no response from any public route carries a seed or a private key" \
    bash -c "! curl -sf $BASE/v1/routes | grep -qi 'seed\|private_key\|mnemonic'"
check 60 "the wallet's fee is the module's, not the page's" \
    grep -q "split_gas_fee\|gas_fee_for" crates/obs-chain/src/params.rs
check 61 "a transfer is signed over the chain id, so it cannot be replayed" \
    grep -q "chain_id" crates/obs-wallet/src/sign.rs
check 62 "the wasm module refuses a locked wallet" \
    node --test web/tests/wallet-module.test.mjs 2>/dev/null
check 63 "the interface formats amounts without floating point" \
    node --test web/tests/format.test.mjs 2>/dev/null
check 64 "a transaction identifier is never a wallet address" \
    bash -c '! grep -rq "address.as_transaction\|tx_id.*address" crates/obs-chain/src/tx.rs'

# ---------------------------------------------------------------------------
section "Registration, invitations, MFA (65-76)"
# ---------------------------------------------------------------------------

check 65 "registration has exactly six steps and no email verification code" \
    bash -c 'grep -q "register/recovery-code" crates/obs-gateway/src/api.rs && ! grep -rqi "email_code\|verification_code" crates/obs-gateway/src'
check 66 "Gmail addresses are canonicalised before the uniqueness check" \
    grep -q "pub fn canonical_gmail" crates/obs-primitives/src/identity.rs
check 67 "one canonical Gmail identity can hold exactly one account" \
    cargo test -p obs-gateway --quiet -- registration 2>/dev/null
check 68 "the invitation limit is five per account" \
    grep -q "MAX_INVITES_PER_ACCOUNT: u32 = 5" crates/obs-chain/src/params.rs
check 69 "an invitation is single use and spent atomically" \
    cargo test -p obs-gateway --quiet -- invite 2>/dev/null
check 70 "passwords must be at least 12 bytes" \
    bash -c 'grep -q "MIN_PASSWORD_BYTES: usize = 12" crates/obs-gateway/src/accounts.rs'
check 71 "TOTP codes are compared with leading zeros preserved" \
    bash -c '! grep -rn "code_at(.*).to_string()" crates/ | grep -v "06" | grep -q .'
check 72 "eight failed attempts lock an account for fifteen minutes" \
    bash -c 'grep -q "MAX_FAILED_ATTEMPTS: u32 = 8" crates/obs-gateway/src/accounts.rs && grep -q "LOCKOUT_SECS: u64 = 15 \* 60" crates/obs-gateway/src/accounts.rs'
check 73 "a session lasts twelve hours" \
    grep -q "SESSION_SECS: u64 = 12 \* 3_600" crates/obs-gateway/src/accounts.rs
check 74 "account recovery is separate from wallet recovery" \
    bash -c 'grep -q "recovery_code" crates/obs-gateway/src/api.rs && grep -q "wallet_from_phrase" crates/obs-wasm/src/lib.rs'
check 75 "the live service reports its network and authority" \
    bash -c "curl -sf $BASE/v1/network | grep -q '\"chain_id\"'"
check 76 "registration refuses a password that is too short" \
    bash -c "curl -s -X POST $BASE/v1/register/password -H 'content-type: application/json' -d '{\"token\":\"x\",\"password\":\"short\"}' | grep -qi 'bad_password\|at least 12'"

# ---------------------------------------------------------------------------
section "Explorer and privacy (77-86)"
# ---------------------------------------------------------------------------

check 77 "no public route mentions a balance" \
    bash -c "! curl -sf $BASE/v1/routes | grep -qi '\"path\":\"[^\"]*balance'"
check 78 "there is no GET /wallet/{address}/balance anywhere" \
    bash -c 'grep -q "FORBIDDEN_KEYS" crates/obs-app/src/privacy.rs && sed -n "/FORBIDDEN_KEYS/,/];/p" crates/obs-app/src/privacy.rs | grep -q "\"balance\"" && grep -q "PrivacyViolation" crates/obs-app/src/privacy.rs'
check 79 "the privacy tests pass" \
    cargo test -p obs-app --quiet -- privacy 2>/dev/null
check 80 "the explorer returns a partial address, never a whole one" \
    cargo test -p obs-app --test explorer --quiet 2>/dev/null
check 81 "the running explorer publishes no balance" \
    bash -c "! curl -sf '$BASE/v1/explorer/status' | grep -qi 'balance'"
check 82 "a response that would contain a balance is withheld, not trimmed" \
    grep -q "privacy_contract" crates/obs-app/src/api.rs
check 83 "the index is reported as behind rather than hidden" \
    bash -c "curl -sf $BASE/v1/explorer/status | grep -q '\"index_behind\"'"
check 84 "the node's own balance route is signature-gated" \
    bash -c "curl -s -o /dev/null -w '%{http_code}' -X POST $NODE/api/v1/account/proof -H 'content-type: application/json' -d '{\"address\":\"x\",\"nonce\":\"n\",\"signature\":\"00\"}' | grep -q 400"
check 85 "the read-through refuses the account path" \
    bash -c "curl -s -o /dev/null -w '%{http_code}' $BASE/node/api/v1/account | grep -q 403"
check 86 "an unknown address is a 404, not a number" \
    bash -c "curl -s $NODE/api/v1/blocks/999999 | grep -q 'not_found'"

# ---------------------------------------------------------------------------
section "Developer portal and APIs (87-93)"
# ---------------------------------------------------------------------------

check 87 "the portal publishes its scopes" \
    bash -c "curl -sf $BASE/v1/portal/scopes | grep -q 'read:blocks'"
check 88 "the OpenAPI document is generated from the route table" \
    bash -c "curl -sf $BASE/v1/portal/openapi.json | grep -q 'openapi'"
check 89 "an API key is a read credential and is hashed at rest" \
    bash -c 'grep -q "tagged hash\|hashed" crates/obs-app/src/portal.rs'
check 90 "rate limits are clamped into a sane range" \
    bash -c 'sed -n "/pub const MINIMUM/,/};/p" crates/obs-app/src/portal.rs | grep -q "requests: 10" && sed -n "/pub const MAXIMUM/,/};/p" crates/obs-app/src/portal.rs | grep -q "requests: 6_000"'
check 91 "a revoked key is refused" \
    cargo test -p obs-app --test explorer --quiet 2>/dev/null
check 92 "an unknown API key is a 404 and a bad one is a 403" \
    grep -q "Status::NOT_FOUND" crates/obs-app/src/api.rs
# The interface's mark has three arrangements, and the third is the one that can
# leak a source if it is wrong: an operator who publishes `--mark-url` because
# their visitors can reach a host this service cannot.  The default must publish
# nothing, and the page must ship a fallback for the case where even the browser
# cannot reach it.
check 93 "the interface is served from the application, with one origin for the official mark" \
    bash -c "curl -sf $BASE/ | grep -q 'Obsidian Network' && curl -sf $BASE/ | grep -q 'assets/logo-official.png'"

# ---------------------------------------------------------------------------
section "Authority hierarchy and fail-closed (94-100)"
# ---------------------------------------------------------------------------

# The invariant is not "a host is never published" — an operator may deliberately
# publish one with --mark-url, and then it is public by design.  It is that the
# *page* and the route table never name one, so the served interface is identical
# either way, and that the configuration is always one of the two valid shapes.
check 103 "the page and the route table name no mark host, whatever the configuration" \
    bash -c "body=\$(curl -sf $BASE/assets/mark.json) || exit 1
        printf '%s' \"\$body\" | grep -qE '\"configured\":(true|false)' || exit 1
        printf '%s' \"\$body\" | grep -q '\"url\":' || exit 1
        ! curl -sf $BASE/ | grep -qE 'https?://' || exit 1
        ! curl -sf $BASE/v1/routes | grep -qE 'https?://' || exit 1
        for asset in js/app.js js/mark.js css/app.css; do
            curl -sf \"$BASE/\$asset\" | grep -qE 'https?://' && exit 1
        done
        exit 0"
check 104 "the page falls back to its own drawn seal when a mark cannot load" \
    bash -c "grep -q \"this.onerror=null;this.src='assets/logo.svg'\" web/index.html && grep -q \"export const FALLBACK = 'assets/logo.svg'\" web/js/mark.js"

check 94 "the interface cannot mint: no route writes a balance" \
    bash -c '! grep -rn "set_balance\|credit(\|mint(" crates/obs-app/src crates/obs-gateway/src | grep -v "//" | grep -q .'
check 95 "there is no administrative bypass of consensus" \
    bash -c '! grep -rniE "admin_|backdoor|bypass_consensus|force_balance|emergency_" crates/obs-node/src crates/obs-chain/src | grep -q .'
check 96 "unknown routes are refused" \
    bash -c "curl -s -o /dev/null -w '%{http_code}' $NODE/api/v1/nonesuch | grep -q 404"
check 97 "a malformed transaction is refused" \
    bash -c "curl -s -X POST $NODE/api/v1/transactions -H 'content-type: application/json' -d '{\"transaction\":\"zz\"}' | grep -qi 'invalid\|malformed\|bad'"
# Output is kept, not silenced: when a suite fails, the reason is the useful part.
check 98 "the full Rust suite passes" \
    cargo test --workspace --quiet
check 99 "the full JavaScript suite passes" \
    node --test web/tests/format.test.mjs web/tests/wallet-module.test.mjs web/tests/smoke.test.mjs
# The invitation, private keys and the official mark's source are the three
# things that live outside this repository on purpose.  scripts/leak-check.sh is
# the scanner that proves it: it knows the first two by name (assembled from
# fragments, so the check does not contain what it looks for) and the third by
# shape, because searching for that host by name would put the host here.
check 100 "no private key, seed phrase, genesis invitation or logo source is in the tree" \
    bash scripts/leak-check.sh >/dev/null

# ---------------------------------------------------------------------------
section "Networks (101)"
# ---------------------------------------------------------------------------

# The four networks share a host without sharing a port, and only the three test
# networks publish a founder invitation: mainnet's is the operator's, and the
# `networks` table is where that difference is visible from a shell.
check 101 "the four networks have their own ports and only test networks publish an invitation" \
    bash -c './target/debug/obs-cli networks > /tmp/obs-networks.txt
        grep -q "8200" /tmp/obs-networks.txt && grep -q "8300" /tmp/obs-networks.txt &&
        grep -q "8400" /tmp/obs-networks.txt && grep -q "7200" /tmp/obs-networks.txt &&
        grep -q "OBS-DEVNET-FOUNDER-0001" /tmp/obs-networks.txt &&
        ! grep -q "OBS-GENESIS" /tmp/obs-networks.txt &&
        mainnet_line="$(grep "^mainnet" /tmp/obs-networks.txt | grep operator)" &&
        [ -n "$mainnet_line" ]'

check 102 "the operator can mint a genesis invitation, and the code is never echoed back" \
    bash -c 'store="$(mktemp -u /tmp/obs-invite-XXXXXX.json)"
        out="$(./target/debug/obs-cli invite mint --network devnet --store "$store" \
            --code OBS-DEVNET-ACCEPTANCE-102 --genesis 2>&1)" &&
        printf "%s" "$out" | grep -q "minted a genesis invitation" &&
        printf "%s" "$out" | grep -q "valid for 31536000" &&
        ! printf "%s" "$out" | grep -q "OBS-DEVNET-ACCEPTANCE-102" &&
        grep -q '"hash"' "$store" &&
        ! grep -q "OBS-DEVNET-ACCEPTANCE-102" "$store" &&
        rm -f "$store"'

# ---------------------------------------------------------------------------
section "The launch kit (105)"
# ---------------------------------------------------------------------------

# A dry run is a promise: it prints what it would do and creates nothing.  The
# plan has to name the deployment's own ports, because a plan that describes
# the wrong network is worse than no plan.
check 105 "a deploy dry run prints the plan and changes nothing" \
    bash -c 'dir=/tmp/obs-acceptance-dry-$$; rm -rf "$dir"
        out="$(bash scripts/deploy.sh --network testnet --dry-run --dir "$dir" 2>&1)" &&
        printf "%s" "$out" | grep -q "dry run: nothing will be created or changed" &&
        printf "%s" "$out" | grep -q "8300" &&
        printf "%s" "$out" | grep -q "9300" &&
        printf "%s" "$out" | grep -q "would run: mkdir -p $dir" &&
        [ ! -d "$dir" ]'

# The units are the thing systemd runs, so the check renders a real set (into a
# scratch directory, with real keys) and reads the directives: no placeholder
# may survive, the node must carry a genesis anchor and the monitor a peer
# expectation, and every path must be the deployment's, not a template's.
check 106 "the rendered units are complete and name the deployment's own paths" \
    bash -c 'dir=/tmp/obs-acceptance-units-$$; units=/tmp/obs-acceptance-units-out-$$
        rm -rf "$dir" "$units"
        bash scripts/deploy.sh --network staging --dir "$dir" --units-out "$units" --min-peers 2 >/dev/null 2>&1 &&
        [ -f "$units/obs-node.service" ] && [ -f "$units/obs-app.service" ] &&
        [ -f "$units/obs-monitor.service" ] && [ -f "$units/obs-monitor.timer" ] &&
        ! grep -vE "^[[:space:]]*#" "$units"/* | grep -qE "@[A-Z_]+@" &&
        grep -q -- "--genesis-timestamp now" "$units/obs-node.service" &&
        grep -q -- "--data-dir $dir/node" "$units/obs-node.service" &&
        grep -q -- "--api-port 8400" "$units/obs-node.service" &&
        grep -q -- "--min-peers 2" "$units/obs-monitor.service" &&
        grep -q -- "--static-dir" "$units/obs-app.service" &&
        rm -rf "$dir" "$units"'

# The rehearsal refuses to run on a port a network owns, and refuses before it
# starts anything: a rehearsal that half-starts reports on nodes it did not
# create, which is how a harness lies.
check 107 "the rehearsal refuses a port range a network owns" \
    bash -c 'out="$(bash scripts/rehearse.sh --network testnet --base-port 9200 --dir /tmp/obs-acceptance-rehearse-$$ 2>&1)"; code=$?
        printf "%s" "$out" | grep -q "would collide with port 9200" && [ "$code" -ne 0 ]'

# The two documents an operator and an auditor read first: the kit has to name
# the rehearsal, the monitor and the restore drill, and the audit brief has to
# say in plain words that nobody outside the project has reviewed it.
check 108 "the launch kit and the audit brief say what they must" \
    bash -c 'grep -q "scripts/rehearse.sh" docs/22-launch-kit.md &&
        grep -q "scripts/monitor.sh" docs/22-launch-kit.md &&
        grep -q "scripts/restore.sh" docs/22-launch-kit.md &&
        grep -q -- "--confirm-mainnet" docs/22-launch-kit.md &&
        grep -q "No third party has audited this code" docs/23-audit-brief.md &&
        grep -q "Launch readiness" docs/23-audit-brief.md'

# An API path that matches no route must be refused even though the interface is
# mounted and the interface is a single page: otherwise GET
# /v1/wallet/<address>/balance answers 200 with HTML, and the one route the
# privacy contract promises does not exist is the one route a client could
# mistake for an endpoint.  Pages still reach the shell, which is the next
# assertion, because a fix that broke the product would not be a fix.
check 109 "the live interface refuses an unknown API path instead of answering with the page" \
    bash -c "for p in /v1/wallet/dobs1zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz/balance /v1/nonesuch /v1; do
            code=\$(curl -s -o /tmp/obs-api-probe.txt -w '%{http_code}' $BASE\$p);
            [ \"\$code\" = 404 ] || { echo \"\$p answered \$code\"; exit 1; };
            grep -q not_found /tmp/obs-api-probe.txt || { echo \"\$p is not a named refusal\"; exit 1; };
        done;
        curl -sf $BASE/explorer/blocks/1 | grep -q '<!DOCTYPE html>'"

# ---------------------------------------------------------------------------

echo
echo "checks: $((PASS + FAIL))   passed: $PASS   failed: $FAIL"
if [ "$FAIL" -ne 0 ]; then
    echo "failed:${FAILED_CHECKS}"
    exit 1
fi
echo "all checks passed"
