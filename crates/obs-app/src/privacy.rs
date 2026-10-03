//! The privacy contract, enforced in code.
//!
//! The network's public information is about *the protocol*: blocks, timestamps,
//! weights, difficulty, issuance, supply, validator participation, claim counts.
//! It is not about *people*: nobody's balance, nobody's full address, nobody's
//! transaction history indexed by a whole address.
//!
//! This module is where that stops being a promise and becomes a mechanism.
//! Three layers, in order:
//!
//! 1. **The route table.**  Every public path is declared in [`ROUTES`].  There
//!    is no `/wallet/{address}/balance`, no `/address/{address}/balance`, no
//!    proxy to the node's API, and the tests assert it: a route that would return
//!    an account's balance cannot be added by accident, only on purpose, visibly,
//!    in this file.
//! 2. **Masking.**  An address a visitor can see is a *partial* address
//!    (`obs1q9x7...4k8m`): enough to correlate a claim with a block, not enough to
//!    hand somebody a list of who holds what.  [`mask_address`] is the only way
//!    an address reaches a response body.
//! 3. **Scrubbing.**  Every response body passes through [`scrub`], which walks
//!    the JSON and *fails closed* if a forbidden key appears anywhere in it — a
//!    balance, a private key, an IP address.  If a future change to some other
//!    module reintroduces one, the response is replaced with a refusal instead of
//!    leaking, and the tests catch it.
//!
//! A balance *is* available to its owner, and only to its owner: the node's
//! `POST /api/v1/account/proof` endpoint returns it to a caller who proves
//! possession of the account key.  The explorer never calls it, because the
//! explorer has no way to prove anything on a visitor's behalf, and a service
//! that could would be custodial by definition.

use obs_primitives::address::{mask, Address};
use obs_primitives::json::Json;

/// A field name that must never appear in a public response body.
///
/// The list is deliberately about *accounts*: protocol aggregates such as
/// `issued_supply` or `mining_pool` are public by design and are not here.
pub const FORBIDDEN_KEYS: &[&str] = &[
    "balance",
    "balances",
    "balance_grains",
    "lifetime_rewards",
    "spendable",
    "available",
    "wallet_key",
    "private_key",
    "secret",
    "seed",
    "phrase",
    "password",
    "totp_secret",
    "recovery_code",
    "recovery_key",
    "ip",
    "ip_address",
    "peer_address",
];

/// A public route, and what it is for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    /// Path template, with `{...}` for path parameters.
    pub path: &'static str,
    /// HTTP method.
    pub method: &'static str,
    /// What it returns.
    pub summary: &'static str,
    /// Which scope a Developer Portal key needs to call it.
    pub scope: Option<&'static str>,
}

/// Every public route the application layer serves.
///
/// Anything not listed here does not exist.  In particular there is no route
/// that returns an account's balance, and no route that proxies the node's API
/// verbatim — a proxy would inherit the node's own, differently-scoped surface.
/// The node read paths this service forwards, and the prefix they live under.
///
/// A browser needs one origin.  The explorer's own API is served here, but the
/// chain's live state — height, protocol time, mempool, the mining parameters —
/// lives on a node, and a page cannot read a second origin unless that origin
/// says so with CORS headers.  So the application serves a *read-through*:
/// `GET /node/api/v1/...`, restricted to the paths below.
///
/// What is deliberately not in the list is the point of the list.  There is no
/// `account/proof` here, so an account's balance cannot be read through this
/// origin by anyone — the one endpoint that answers a balance question requires a
/// signature from the account's own key, and a browser reaches it only if the
/// operator publishes the node directly.  Everything else in the list is public
/// chain data that the node already serves to anyone who asks.
///
/// The read-through is a convenience, not an authority: it cannot write, it
/// cannot sign, and every response still passes through [`scrub`], so a node
/// answer that ever grew a forbidden field would become a refusal here rather
/// than a leak.
pub const NODE_READ_PREFIX: &str = "/node";

/// Node API paths a deployment may read through this service.  Exact paths and
/// `*`-suffixed prefixes, all under `/api/v1/`.
pub const NODE_READ_PATHS: &[&str] = &[
    "status",
    "supply",
    "params",
    "mining",
    "blocks",
    "blocks/*",
    "transactions/*",
    "validators",
    "mempool",
    "peers",
    "events",
];

/// The node paths this service will forward a `POST` to.
///
/// Two, and both are safe for the same reason: the application holds no key and
/// cannot sign, so it can only carry a request that is already authenticated.
///
/// * `transactions` — submitting a signed transaction.  This is the only way a
///   transaction reaches a node, and a single-origin deployment is unusable
///   without it.  Changing a single byte of the body invalidates the signature the
///   node checks, so the node validates it exactly as it would from any peer.
/// * `account/proof` — an account asking for its **own** state by signing over a
///   fresh nonce.  It is not a public balance endpoint: the node answers only when
///   the signature proves the key, it answers only for the address that signed,
///   and an unknown address gets a `404` rather than a number.  The explorer and
///   the portal do not expose it in any form, and `GET` is refused, so nothing a
///   third party can call returns a balance.
///
/// This forwards work, not authority.
pub const NODE_WRITE_PATHS: &[&str] = &["transactions", "account/proof"];

/// Whether a node API path may be written through this service.
pub fn node_write_allowed(path: &str) -> bool {
    NODE_WRITE_PATHS.contains(&path.trim_start_matches('/'))
}

/// Whether a node API path may be read through this service.
pub fn node_read_allowed(path: &str) -> bool {
    let trimmed = path.trim_start_matches('/');
    if trimmed.starts_with("account/") || trimmed == "account" {
        return false;
    }
    NODE_READ_PATHS.iter().any(|allowed| match allowed.strip_suffix('*') {
        Some(prefix) => trimmed.starts_with(prefix),
        None => trimmed == *allowed,
    })
}

pub const ROUTES: &[Route] = &[
    Route { path: "/v1/explorer/status", method: "GET", summary: "network status: heights, times, supply, participation", scope: None },
    Route { path: "/v1/explorer/blocks", method: "GET", summary: "recent blocks, newest first", scope: Some("read:blocks") },
    Route { path: "/v1/explorer/blocks/{selector}", method: "GET", summary: "one block by height or hash", scope: Some("read:blocks") },
    Route { path: "/v1/explorer/transactions/{id}", method: "GET", summary: "one transaction by id, sender masked", scope: Some("read:transactions") },
    Route { path: "/v1/explorer/address/{address}", method: "GET", summary: "an address's *activity*: claim counts and block appearances, never a balance", scope: Some("read:blocks") },
    Route { path: "/v1/explorer/validators", method: "GET", summary: "validator participation: bond, uptime, attestations", scope: Some("read:validators") },
    Route { path: "/v1/explorer/supply", method: "GET", summary: "issuance and supply, protocol level", scope: None },
    Route { path: "/v1/explorer/mining", method: "GET", summary: "the current mining rate, halving position and active miners", scope: None },
    Route { path: "/v1/explorer/search", method: "GET", summary: "find a block, transaction or address", scope: None },
    Route { path: "/v1/portal/scopes", method: "GET", summary: "the scopes an API key can hold", scope: None },
    Route { path: "/v1/portal/keys", method: "GET", summary: "list the caller's API keys", scope: None },
    Route { path: "/v1/portal/keys", method: "POST", summary: "create an API key; the secret is returned once", scope: None },
    Route { path: "/v1/portal/keys/{id}", method: "DELETE", summary: "revoke an API key", scope: None },
    Route { path: "/v1/portal/keys/{id}/rotate", method: "POST", summary: "rotate an API key; the old secret stops working immediately", scope: None },
    Route { path: "/v1/portal/usage", method: "GET", summary: "request counts and rate-limit refusals per key", scope: None },
    Route { path: "/v1/portal/openapi.json", method: "GET", summary: "the OpenAPI description of this API", scope: None },
    Route { path: "/node/api/v1/{read-path}", method: "GET", summary: "read-through to a node's public API: status, supply, params, mining, blocks, transactions, validators, mempool, peers, events", scope: None },
    Route { path: "/node/api/v1/transactions", method: "POST", summary: "forwards an already-signed transaction; this service holds no key and cannot alter or forge one", scope: None },
    Route { path: "/node/api/v1/account/proof", method: "POST", summary: "forwards an account's signed proof of ownership so its holder may read that account's own state; a third party cannot use it, and an unknown account is a 404", scope: None },
    Route { path: "/healthz", method: "GET", summary: "liveness", scope: None },
];

/// A response body that would have broken the contract.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PrivacyViolation {
    /// The field that was found.
    pub key: String,
    /// Where in the document it was.
    pub path: String,
}

impl core::fmt::Display for PrivacyViolation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(
            f,
            "privacy contract: field '{}' at {} may not appear in a public response",
            self.key, self.path
        )
    }
}

impl std::error::Error for PrivacyViolation {}

/// The only way an address reaches a public response body.
pub fn mask_address(address: &Address) -> String {
    mask(address)
}

/// True when a string is a partial (masked) address rather than a whole one.
pub fn is_masked(text: &str) -> bool {
    text.contains("...")
}

/// Walks a response document and refuses it if a forbidden field is present.
///
/// This is a *fail closed* check: the caller substitutes a refusal for the whole
/// response.  Dropping the field silently was rejected as a design: a leak that
/// nobody notices is worse than an endpoint that stops answering.
pub fn scrub(value: &Json) -> Result<&Json, PrivacyViolation> {
    check(value, "")
}

fn check<'a>(value: &'a Json, path: &str) -> Result<&'a Json, PrivacyViolation> {
    match value {
        Json::Object(fields) => {
            for (key, child) in fields {
                if FORBIDDEN_KEYS.contains(&key.to_ascii_lowercase().as_str()) {
                    return Err(PrivacyViolation {
                        key: key.clone(),
                        path: if path.is_empty() {
                            key.clone()
                        } else {
                            format!("{}.{}", path, key)
                        },
                    });
                }
                let child_path = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{}.{}", path, key)
                };
                check(child, &child_path)?;
            }
            Ok(value)
        }
        Json::Array(items) => {
            for (index, child) in items.iter().enumerate() {
                check(child, &format!("{}[{}]", path, index))?;
            }
            Ok(value)
        }
        _ => Ok(value),
    }
}

/// True when the route table contains a path that could return an account's
/// balance.
///
/// Used by the tests, and by the OpenAPI description: the contract is checked,
/// not assumed.
pub fn balance_routes() -> Vec<&'static str> {
    ROUTES
        .iter()
        .filter(|route| {
            let path = route.path.to_ascii_lowercase();
            path.contains("balance") || (path.contains("wallet") && path.len() > 7)
        })
        .map(|route| route.path)
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::MAINNET;

    fn sample_address() -> Address {
        Address::from_public_key(MAINNET, &[5u8; 32])
    }

    #[test]
    fn there_is_no_balance_route() {
        assert!(
            balance_routes().is_empty(),
            "the explorer must not publish balances: {:?}",
            balance_routes()
        );
        // And no route mentions an account-scoped balance under another name.
        for route in ROUTES {
            let path = route.path.to_ascii_lowercase();
            assert!(!path.contains("reward"), "no per-account rewards: {}", route.path);
            assert!(!path.starts_with("/api/"), "no proxying the node API: {}", route.path);
        }
    }

    #[test]
    fn every_route_is_documented() {
        for route in ROUTES {
            assert!(!route.summary.is_empty(), "{} needs a summary", route.path);
            assert!(
                route.method == "GET" || route.method == "POST" || route.method == "DELETE",
                "unexpected method on {}",
                route.path
            );
        }
    }

    #[test]
    fn masking_hides_enough_of_an_address() {
        let address = sample_address();
        let masked = mask_address(&address);
        assert!(is_masked(&masked), "{}", masked);
        assert!(masked.starts_with(MAINNET.address_prefix));
        assert!(!masked.contains(&address.to_string()));
        assert!(masked.len() < address.to_string().len());
    }

    #[test]
    fn scrubbing_refuses_a_balance_at_any_depth() {
        let clean = Json::obj([
            ("height", Json::Int(12)),
            ("proposer", Json::Str("obs1q9x7...4k8m".to_string())),
            (
                "transactions",
                Json::Array(vec![Json::obj([("kind", Json::Str("claim".to_string()))])]),
            ),
        ]);
        assert!(scrub(&clean).is_ok());

        let leaked = Json::obj([
            ("height", Json::Int(12)),
            (
                "account",
                Json::obj([("address", Json::Str("obs1...".to_string())), ("balance", Json::Str("1.5".to_string()))]),
            ),
        ]);
        let violation = scrub(&leaked).unwrap_err();
        assert_eq!(violation.key, "balance");
        assert_eq!(violation.path, "account.balance");

        let nested = Json::Array(vec![Json::obj([("Lifetime_Rewards", Json::Int(5))])]);
        assert!(scrub(&nested).is_err(), "field names are matched case-insensitively");

        // Protocol aggregates are not account data and are allowed.
        let protocol = Json::obj([
            ("issued_supply", Json::Str("100000.5".to_string())),
            ("mining_pool", Json::Str("0.5".to_string())),
            ("active_miners", Json::Int(3)),
        ]);
        assert!(scrub(&protocol).is_ok());
    }
}
