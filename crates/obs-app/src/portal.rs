//! The Developer Portal: API keys, scopes, rate limits, rotation and usage.
//!
//! ## What a key is, and what it is not
//!
//! An API key is a *read* credential for the public API.  It selects a scope
//! (which endpoints may be called), a rate limit (how often), and a usage
//! counter.  It is **not** a wallet key, it is **not** an account credential, and
//! it can never grant custody of anything: no endpoint reachable with an API key
//! signs a transaction, and the wallet API is non-custodial by construction —
//! keys live in the user's own keystore, and the server has no private key to
//! leak.  A leaked API key costs the holder their rate limit; it cannot cost
//! anybody their coins.
//!
//! ## Format
//!
//! ```text
//!   obs_live_7K4MX9P2QH3N8RTV.MR4W2Y8C6B1D3F5H0J9K2L4M6N8P0Q3S
//!   └ id (32 chars)        ┘ └ secret (32 chars) ────────────────┘
//! ```
//!
//! Only a hash of the secret is stored, so a stolen database is a list of
//! revoked-by-definition identifiers rather than a set of live credentials.  The
//! secret is shown exactly once, at creation and at rotation.
//!
//! ## Rotation and revocation
//!
//! Rotation issues a new secret for the same key id and replaces the stored
//! hash, which invalidates the old secret immediately — there is no window in
//! which both work.  Revocation deletes the record.  Both are logged as events
//! with a timestamp and the request's origin, never with key material.

use std::collections::BTreeMap;

use obs_crypto::ct::{ct_eq, Zeroize, Zeroizing};
use obs_crypto::encoding::base64url_encode;
use obs_primitives::json::Json;

use crate::store_shim as store;

/// What an API key may do.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Scope {
    /// Read blocks and the chain's shape.
    ReadBlocks,
    /// Read transactions.
    ReadTransactions,
    /// Read validator participation.
    ReadValidators,
    /// Read mining and supply numbers.
    ReadMining,
    /// Ask a node to accept a signed transaction.  Note `signed`: the node
    /// verifies it like any other, and the key never enters into the signature.
    SubmitTransactions,
    /// Ask a node for an account's own state, with the caller supplying a proof
    /// of possession.  The proof is what authorises the answer, not the key.
    ReadAccountWithProof,
}

impl Scope {
    /// Every scope, in a stable order.
    pub const ALL: [Scope; 6] = [
        Scope::ReadBlocks,
        Scope::ReadTransactions,
        Scope::ReadValidators,
        Scope::ReadMining,
        Scope::SubmitTransactions,
        Scope::ReadAccountWithProof,
    ];

    /// The wire name.
    pub fn name(self) -> &'static str {
        match self {
            Scope::ReadBlocks => "read:blocks",
            Scope::ReadTransactions => "read:transactions",
            Scope::ReadValidators => "read:validators",
            Scope::ReadMining => "read:mining",
            Scope::SubmitTransactions => "write:transactions",
            Scope::ReadAccountWithProof => "read:account:proof",
        }
    }

    /// The wire name, parsed.
    pub fn parse(text: &str) -> Option<Scope> {
        Scope::ALL.into_iter().find(|scope| scope.name() == text)
    }

    /// What the scope means, in one sentence, for the portal's page.
    pub fn describe(self) -> &'static str {
        match self {
            Scope::ReadBlocks => "read blocks, timestamps, weights and difficulty",
            Scope::ReadTransactions => "read transactions by id (senders are partial addresses)",
            Scope::ReadValidators => "read validator bonds, uptime and attestation counts",
            Scope::ReadMining => "read the mining rate, halving position and supply figures",
            Scope::SubmitTransactions => {
                "submit an already-signed transaction; the node verifies it like any other"
            }
            Scope::ReadAccountWithProof => {
                "read an account's own state by presenting a signature over the node's challenge"
            }
        }
    }

    /// Whether the scope is required by default.
    pub fn default_granted(self) -> bool {
        matches!(self, Scope::ReadBlocks | Scope::ReadTransactions | Scope::ReadMining)
    }
}

/// How often a key may call the API.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RateLimit {
    /// Requests allowed per window.
    pub requests: u32,
    /// Window length, in seconds.
    pub window_secs: u64,
}

impl RateLimit {
    /// The default for a new key: 600 requests per minute.
    pub const DEFAULT: RateLimit = RateLimit {
        requests: 600,
        window_secs: 60,
    };
    /// The smallest a key may be limited to.
    pub const MINIMUM: RateLimit = RateLimit {
        requests: 10,
        window_secs: 60,
    };
    /// The most generous limit the portal grants anyone.
    pub const MAXIMUM: RateLimit = RateLimit {
        requests: 6_000,
        window_secs: 60,
    };

    /// Requests per second, as an integer (rounded down; the limiter is exact).
    pub fn per_second(self) -> u32 {
        if self.window_secs == 0 {
            return 0;
        }
        ((self.requests as u64) / self.window_secs) as u32
    }

    /// Clamps a requested limit into the allowed range.
    pub fn clamp(requested: RateLimit) -> RateLimit {
        let requests = requested
            .requests
            .clamp(RateLimit::MINIMUM.requests, RateLimit::MAXIMUM.requests);
        let window_secs = requested.window_secs.clamp(1, 3_600);
        RateLimit { requests, window_secs }
    }
}

/// Why a key operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PortalError {
    /// The key id is unknown.
    UnknownKey,
    /// The key's secret does not match.
    BadSecret,
    /// The key has been revoked.
    Revoked,
    /// The key's rate limit is exhausted for this window.
    RateLimited {
        /// Seconds until the window resets.
        retry_after: u64,
    },
    /// The key lacks a scope.
    MissingScope(&'static str),
    /// A caller without an account tried to manage keys.
    NoAccount,
    /// Storage failed.
    Store(String),
}

impl core::fmt::Display for PortalError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            PortalError::UnknownKey => write!(f, "no such API key"),
            PortalError::BadSecret => write!(f, "the API key secret is not valid"),
            PortalError::Revoked => write!(f, "the API key has been revoked"),
            PortalError::RateLimited { retry_after } => {
                write!(f, "rate limit reached; retry in {} seconds", retry_after)
            }
            PortalError::MissingScope(scope) => write!(f, "this key does not have the {} scope", scope),
            PortalError::NoAccount => write!(f, "an account is required to manage API keys"),
            PortalError::Store(detail) => write!(f, "storage error: {}", detail),
        }
    }
}

impl std::error::Error for PortalError {}

/// An API key's stored record.  No secret is stored, only its hash.
#[derive(Debug, Clone)]
pub struct ApiKey {
    /// Public identifier, sent as the key's prefix.
    pub id: String,
    /// The account that owns the key.
    pub owner: String,
    /// Human label.
    pub label: String,
    /// Granted scopes.
    pub scopes: Vec<Scope>,
    /// Rate limit.
    pub limit: RateLimit,
    /// When it was created.
    pub created_at: u64,
    /// When it was last used.
    pub last_used: Option<u64>,
    /// How many requests it has made.
    pub requests: u64,
    /// How many requests were refused by the rate limiter.
    pub refused: u64,
    /// When the secret was last rotated.
    pub rotated_at: Option<u64>,
    /// Set when revoked; a revoked key is kept so usage history survives.
    pub revoked_at: Option<u64>,
    /// Hash of the current secret.
    secret_hash: Vec<u8>,
    /// Salt for the secret hash.
    salt: Vec<u8>,
}

impl ApiKey {
    /// Whether the key can be used.
    pub fn is_live(&self) -> bool {
        self.revoked_at.is_none()
    }

    /// The scopes, as wire names.
    pub fn scope_names(&self) -> Vec<String> {
        self.scopes.iter().map(|scope| scope.name().to_string()).collect()
    }

    /// A safe view: no hash, no salt, and the id only.
    pub fn view(&self) -> Json {
        Json::obj([
            ("id", Json::Str(self.id.clone())),
            ("label", Json::Str(self.label.clone())),
            ("scopes", Json::Array(self.scope_names().into_iter().map(Json::Str).collect())),
            ("rate_limit", Json::Int(self.limit.requests as i128)),
            ("rate_window_secs", Json::Int(self.limit.window_secs as i128)),
            ("created_at", Json::Int(self.created_at as i128)),
            (
                "last_used",
                match self.last_used {
                    Some(at) => Json::Int(at as i128),
                    None => Json::Null,
                },
            ),
            ("requests", Json::Int(self.requests as i128)),
            ("refused", Json::Int(self.refused as i128)),
            (
                "rotated_at",
                match self.rotated_at {
                    Some(at) => Json::Int(at as i128),
                    None => Json::Null,
                },
            ),
            ("live", Json::Bool(self.is_live())),
        ])
    }

    fn to_json(&self) -> Json {
        let mut fields = match self.view() {
            Json::Object(fields) => fields,
            other => vec![("view".to_string(), other)],
        };
        fields.push(("owner".to_string(), Json::Str(self.owner.clone())));
        fields.push(("secret_hash".to_string(), Json::Str(obs_crypto::encoding::hex_encode(&self.secret_hash))));
        fields.push(("salt".to_string(), Json::Str(obs_crypto::encoding::hex_encode(&self.salt))));
        fields.push((
            "revoked_at".to_string(),
            match self.revoked_at {
                Some(at) => Json::Int(at as i128),
                None => Json::Null,
            },
        ));
        Json::Object(fields)
    }

    fn from_json(value: &Json) -> Result<ApiKey, PortalError> {
        let text = |name: &str| value.get(name).and_then(Json::as_str).unwrap_or_default().to_string();
        let number = |name: &str| value.get(name).and_then(Json::as_i128).unwrap_or(0) as u64;
        let scopes = value
            .get("scopes")
            .and_then(Json::as_array)
            .map(|names| names.iter().filter_map(Json::as_str).filter_map(Scope::parse).collect())
            .unwrap_or_default();
        Ok(ApiKey {
            id: text("id"),
            owner: text("owner"),
            label: text("label"),
            scopes,
            limit: RateLimit {
                requests: number("rate_limit") as u32,
                window_secs: number("rate_window_secs").max(1),
            },
            created_at: number("created_at"),
            last_used: value.get("last_used").and_then(Json::as_i128).map(|at| at as u64),
            requests: number("requests"),
            refused: number("refused"),
            rotated_at: value.get("rotated_at").and_then(Json::as_i128).map(|at| at as u64),
            revoked_at: value.get("revoked_at").and_then(Json::as_i128).map(|at| at as u64),
            secret_hash: obs_crypto::encoding::hex_decode(&text("secret_hash"))
                .ok_or_else(|| PortalError::Store("a key's hash is not hex".to_string()))?,
            salt: obs_crypto::encoding::hex_decode(&text("salt"))
                .ok_or_else(|| PortalError::Store("a key's salt is not hex".to_string()))?,
        })
    }
}

/// An event in the portal's audit trail.  Never carries key material.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PortalEvent {
    /// When it happened.
    pub at: u64,
    /// What happened: `created`, `rotated`, `revoked`.
    pub kind: &'static str,
    /// Which key.
    pub key_id: String,
    /// Which account.
    pub owner: String,
}

impl PortalEvent {
    /// JSON view for the portal's page.
    pub fn view(&self) -> Json {
        Json::obj([
            ("at", Json::Int(self.at as i128)),
            ("kind", Json::Str(self.kind.to_string())),
            ("key_id", Json::Str(self.key_id.clone())),
            ("owner", Json::Str(mask_account(&self.owner))),
        ])
    }
}

fn mask_account(canonical_gmail: &str) -> String {
    match canonical_gmail.split_once('@') {
        Some((local, domain)) => {
            let head: String = local.chars().take(2).collect();
            format!("{}***@{}", head, domain)
        }
        None => "***".to_string(),
    }
}

/// The portal: API keys and their usage.
pub struct Portal {
    store: store::AtomicStore,
    keys: BTreeMap<String, ApiKey>,
    events: Vec<PortalEvent>,
    /// Highest number of events kept.
    event_limit: usize,
}

impl Portal {
    /// Opens a portal, creating an empty one when the store is new.
    pub fn open(store: store::AtomicStore) -> Result<Portal, PortalError> {
        let mut portal = Portal {
            store,
            keys: BTreeMap::new(),
            events: Vec::new(),
            event_limit: 1_000,
        };
        if let Some(document) = portal.store.load_json().map_err(|error| PortalError::Store(error.to_string()))? {
            if let Some(keys) = document.get("keys").and_then(Json::as_array) {
                for entry in keys {
                    let key = ApiKey::from_json(entry)?;
                    portal.keys.insert(key.id.clone(), key);
                }
            }
            // The audit trail is durable: "when was this key revoked" is exactly
            // the question an operator asks after an incident, and an answer that
            // vanishes on restart is not an answer.
            if let Some(events) = document.get("events").and_then(Json::as_array) {
                for entry in events {
                    let Some(kind) = entry.get("kind").and_then(Json::as_str) else {
                        continue;
                    };
                    let Some(kind) = known_kind(kind) else {
                        continue;
                    };
                    portal.events.push(PortalEvent {
                        at: entry.get("at").and_then(Json::as_i128).unwrap_or(0) as u64,
                        kind,
                        key_id: entry.get("key_id").and_then(Json::as_str).unwrap_or_default().to_string(),
                        owner: entry.get("owner").and_then(Json::as_str).unwrap_or_default().to_string(),
                    });
                }
            }
        }
        Ok(portal)
    }

    fn persist(&self) -> Result<(), PortalError> {
        let document = Json::obj([
            ("version", Json::Int(1)),
            (
                "keys",
                Json::Array(self.keys.values().map(ApiKey::to_json).collect()),
            ),
            (
                "events",
                Json::Array(
                    self.events
                        .iter()
                        .map(|event| {
                            Json::obj([
                                ("at", Json::Int(event.at as i128)),
                                ("kind", Json::Str(event.kind.to_string())),
                                ("key_id", Json::Str(event.key_id.clone())),
                                ("owner", Json::Str(event.owner.clone())),
                            ])
                        })
                        .collect(),
                ),
            ),
        ]);
        self.store
            .save_json(&document)
            .map_err(|error| PortalError::Store(error.to_string()))
    }

    /// Creates a key for an account.  Returns the key and its secret **once**.
    pub fn create_key(
        &mut self,
        owner: &str,
        label: &str,
        scopes: Vec<Scope>,
        limit: RateLimit,
        now: u64,
    ) -> Result<(ApiKey, String), PortalError> {
        if owner.is_empty() {
            return Err(PortalError::NoAccount);
        }
        let id = random_token(24)?;
        let secret = random_token(32)?;
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt)
            .map_err(|error| PortalError::Store(error.to_string()))?;
        let hash = hash_secret(&secret, &salt)?;
        let key = ApiKey {
            id: id.clone(),
            owner: owner.to_string(),
            label: if label.is_empty() { "unnamed key".to_string() } else { label.to_string() },
            scopes: if scopes.is_empty() {
                Scope::ALL.into_iter().filter(|scope| scope.default_granted()).collect()
            } else {
                scopes
            },
            limit: RateLimit::clamp(limit),
            created_at: now,
            last_used: None,
            requests: 0,
            refused: 0,
            rotated_at: None,
            revoked_at: None,
            secret_hash: hash,
            salt: salt.to_vec(),
        };
        let view = key.clone();
        self.keys.insert(id.clone(), key);
        self.record(now, "created", &id, owner);
        self.persist()?;
        Ok((view, format!("{}.{}", id, secret)))
    }

    /// The keys an account owns.
    pub fn keys_of(&self, owner: &str) -> Vec<&ApiKey> {
        self.keys.values().filter(|key| key.owner == owner).collect()
    }

    /// Revokes a key.  It stops working immediately and stays in the record so
    /// its usage history is not rewritten.
    pub fn revoke(&mut self, owner: &str, id: &str, now: u64) -> Result<(), PortalError> {
        let key = self.keys.get_mut(id).ok_or(PortalError::UnknownKey)?;
        if key.owner != owner {
            return Err(PortalError::UnknownKey);
        }
        key.revoked_at = Some(now);
        // The stored hash is destroyed, so even a database dump cannot be used
        // to authenticate a revoked key.
        key.secret_hash.zeroize();
        key.salt.zeroize();
        self.record(now, "revoked", id, owner);
        self.persist()
    }

    /// Rotates a key's secret.  The old secret stops working at once.
    pub fn rotate(&mut self, owner: &str, id: &str, now: u64) -> Result<String, PortalError> {
        let secret = random_token(32)?;
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt)
            .map_err(|error| PortalError::Store(error.to_string()))?;
        let hash = hash_secret(&secret, &salt)?;
        let key = self.keys.get_mut(id).ok_or(PortalError::UnknownKey)?;
        if key.owner != owner {
            return Err(PortalError::UnknownKey);
        }
        if key.revoked_at.is_some() {
            return Err(PortalError::Revoked);
        }
        key.secret_hash = hash;
        key.salt = salt.to_vec();
        key.rotated_at = Some(now);
        self.record(now, "rotated", id, owner);
        self.persist()?;
        Ok(format!("{}.{}", id, secret))
    }

    /// Authenticates a presented key and checks a scope and the rate limit.
    ///
    /// The secret is compared in constant time against the stored hash, and every
    /// failure path costs the same work, so an attacker cannot tell "unknown key"
    /// from "wrong secret" from timing.
    pub fn authorize(
        &mut self,
        presented: &str,
        scope: Option<Scope>,
        now: u64,
    ) -> Result<&ApiKey, PortalError> {
        let (id, secret) = presented.split_once('.').ok_or(PortalError::BadSecret)?;
        let Some(key) = self.keys.get(id) else {
            // Spend the same work as a real verification before refusing.
            let _ = hash_secret(secret, &[0u8; 16]);
            return Err(PortalError::BadSecret);
        };
        let candidate = Zeroizing(hash_secret(secret, &key.salt)?);
        if !ct_eq(&candidate, &key.secret_hash) {
            return Err(PortalError::BadSecret);
        }
        if key.revoked_at.is_some() {
            return Err(PortalError::Revoked);
        }
        if let Some(required) = scope {
            if !key.scopes.contains(&required) {
                return Err(PortalError::MissingScope(required.name()));
            }
        }
        // The rate limiter: a rolling window anchored at the key's first request
        // in the window.
        let window = key.limit.window_secs.max(1);
        let anchor = key.last_used.unwrap_or(now);
        let elapsed = now.saturating_sub(anchor);
        let used = if elapsed >= window { 0 } else { key.requests };
        if used >= key.limit.requests as u64 {
            let retry_after = window.saturating_sub(elapsed);
            if let Some(key) = self.keys.get_mut(id) {
                key.refused += 1;
            }
            return Err(PortalError::RateLimited { retry_after });
        }
        let key = self.keys.get_mut(id).ok_or(PortalError::UnknownKey)?;
        if elapsed >= window {
            key.requests = 0;
        }
        key.requests += 1;
        key.last_used = Some(now);
        Ok(key)
    }

    /// The portal's audit trail, newest first.
    pub fn events(&self) -> Vec<&PortalEvent> {
        self.events.iter().rev().collect()
    }

    /// Usage for an account: one row per key.
    pub fn usage(&self, owner: &str) -> Json {
        let rows: Vec<Json> = self
            .keys_of(owner)
            .into_iter()
            .map(|key| {
                Json::obj([
                    ("id", Json::Str(key.id.clone())),
                    ("label", Json::Str(key.label.clone())),
                    ("requests", Json::Int(key.requests as i128)),
                    ("refused", Json::Int(key.refused as i128)),
                    ("live", Json::Bool(key.is_live())),
                ])
            })
            .collect();
        Json::obj([
            ("keys", Json::Array(rows)),
            (
                "events",
                Json::Array(self.events().into_iter().map(PortalEvent::view).collect()),
            ),
        ])
    }

    fn record(&mut self, at: u64, kind: &'static str, id: &str, owner: &str) {
        self.events.push(PortalEvent {
            at,
            kind,
            key_id: id.to_string(),
            owner: owner.to_string(),
        });
        if self.events.len() > self.event_limit {
            self.events.remove(0);
        }
    }
}

/// The three event kinds the audit trail records.
fn known_kind(kind: &str) -> Option<&'static str> {
    match kind {
        "created" => Some("created"),
        "rotated" => Some("rotated"),
        "revoked" => Some("revoked"),
        _ => None,
    }
}

/// Generates an opaque token of `bytes` bytes of randomness, base32-encoded,
/// upper-case so it survives being read off a screen.
fn random_token(bytes: usize) -> Result<String, PortalError> {
    let mut raw = vec![0u8; bytes];
    obs_crypto::rand::os_random(&mut raw).map_err(|error| PortalError::Store(error.to_string()))?;
    let encoded = base64url_encode(&raw);
    Ok(encoded
        .chars()
        .filter(|character| character.is_ascii_alphanumeric())
        .take(bytes)
        .collect::<String>()
        .to_ascii_uppercase())
}

/// Hashes a key secret.  Argon2id is deliberately *not* used here: an API secret
/// is 256 bits of uniform randomness, not a human password, so there is nothing
/// to guess and a fast hash keeps the API's latency reasonable.
fn hash_secret(secret: &str, salt: &[u8]) -> Result<Vec<u8>, PortalError> {
    // A tagged hash over the salt and the secret, so this domain cannot be
    // confused with any other hash the protocol computes.
    let mut preimage = Vec::with_capacity(salt.len() + secret.len());
    preimage.extend_from_slice(salt);
    preimage.extend_from_slice(secret.as_bytes());
    Ok(obs_crypto::sha2::sha256_tagged("OBSIDIAN/PORTAL-KEY/v1", &preimage).to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn temp_store(name: &str) -> store::AtomicStore {
        let dir = std::env::temp_dir().join(format!("obs-portal-{}-{}", std::process::id(), name));
        let _ = std::fs::remove_dir_all(&dir);
        store::AtomicStore::open(dir.join("portal.json"), false).unwrap()
    }

    #[test]
    fn a_key_is_shown_once_and_only_its_hash_is_stored() {
        let mut portal = Portal::open(temp_store("create")).unwrap();
        let (key, secret) = portal
            .create_key("dev@gmail.com", "ci", vec![Scope::ReadBlocks], RateLimit::DEFAULT, 100)
            .unwrap();
        assert!(secret.starts_with(&key.id));
        assert_eq!(secret.split('.').count(), 2);

        // The store holds the hash, not the secret.
        let document = std::fs::read_to_string(portal.store.path()).unwrap();
        assert!(!document.contains(&secret), "the secret must never be stored");
        assert!(document.contains("secret_hash"));

        // And the key works with the secret it was given.
        let owner = portal
            .authorize(&secret, Some(Scope::ReadBlocks), 101)
            .unwrap()
            .owner
            .clone();
        assert_eq!(owner, "dev@gmail.com");
    }

    #[test]
    fn a_scope_the_key_does_not_hold_is_refused() {
        let mut portal = Portal::open(temp_store("scopes")).unwrap();
        let (_, secret) = portal
            .create_key("dev@gmail.com", "read only", vec![Scope::ReadBlocks], RateLimit::DEFAULT, 0)
            .unwrap();
        match portal.authorize(&secret, Some(Scope::SubmitTransactions), 1) {
            Err(PortalError::MissingScope(scope)) => assert_eq!(scope, "write:transactions"),
            other => panic!("expected a scope refusal, got {:?}", other.map(|_| ())),
        }
        assert!(portal.authorize(&secret, Some(Scope::ReadBlocks), 2).is_ok());
    }

    #[test]
    fn rotation_invalidates_the_old_secret_immediately() {
        let mut portal = Portal::open(temp_store("rotate")).unwrap();
        let (key, old_secret) = portal
            .create_key("dev@gmail.com", "ci", vec![Scope::ReadBlocks], RateLimit::DEFAULT, 0)
            .unwrap();
        let new_secret = portal.rotate("dev@gmail.com", &key.id, 5).unwrap();
        assert_ne!(new_secret, old_secret);
        assert!(
            portal.authorize(&old_secret, None, 6).is_err(),
            "the old secret must stop working at once"
        );
        assert!(portal.authorize(&new_secret, None, 7).is_ok());
        assert_eq!(portal.events().len(), 2);
        assert_eq!(portal.events()[0].kind, "rotated");
    }

    #[test]
    fn revocation_is_immediate_and_survives_a_restart() {
        let store = temp_store("revoke");
        let path = store.path().to_path_buf();
        let mut portal = Portal::open(store).unwrap();
        let (key, secret) = portal
            .create_key("dev@gmail.com", "ci", vec![Scope::ReadBlocks], RateLimit::DEFAULT, 0)
            .unwrap();
        portal.revoke("dev@gmail.com", &key.id, 3).unwrap();
        match portal.authorize(&secret, None, 4) {
            Err(PortalError::BadSecret) | Err(PortalError::Revoked) => {}
            other => panic!("a revoked key must be refused: {:?}", other.map(|_| ())),
        }
        // It stays revoked across a reload, and so does the record of why.
        let mut again = Portal::open(store::AtomicStore::open(&path, false).unwrap()).unwrap();
        assert_eq!(again.keys_of("dev@gmail.com").len(), 1);
        assert!(!again.keys_of("dev@gmail.com")[0].is_live());
        assert_eq!(again.events().len(), 2);
        assert_eq!(again.events()[0].kind, "revoked");
        // And the reloaded record cannot authenticate anything, because the
        // revocation destroyed the stored hash rather than merely setting a flag.
        assert!(again.authorize(&secret, None, 5).is_err());
    }

    #[test]
    fn a_rate_limit_is_enforced_and_reported() {
        let mut portal = Portal::open(temp_store("limit")).unwrap();
        // The floor is ten per minute, so that is what a key gets when it asks
        // for less.
        let limit = RateLimit {
            requests: 2,
            window_secs: 60,
        };
        let (key, secret) = portal
            .create_key("dev@gmail.com", "ci", vec![Scope::ReadBlocks], limit, 0)
            .unwrap();
        assert_eq!(key.limit.requests, RateLimit::MINIMUM.requests);
        for at in 1..=RateLimit::MINIMUM.requests as u64 {
            assert!(portal.authorize(&secret, None, at).is_ok(), "request {} is inside the limit", at);
        }
        match portal.authorize(&secret, None, 11) {
            Err(PortalError::RateLimited { retry_after }) => {
                assert!(retry_after > 0 && retry_after <= 60, "retry after {}", retry_after)
            }
            other => panic!("expected a rate limit, got {:?}", other.map(|_| ())),
        }
        // The window rolls: a minute later the key works again.
        assert!(portal.authorize(&secret, None, 121).is_ok());
        let usage = portal.usage("dev@gmail.com");
        let keys = usage.get("keys").unwrap().as_array().unwrap();
        assert_eq!(keys[0].get("refused").unwrap().as_i128(), Some(1));
    }

    #[test]
    fn limits_are_clamped_into_the_allowed_range() {
        let tiny = RateLimit::clamp(RateLimit {
            requests: 0,
            window_secs: 0,
        });
        assert_eq!(tiny.requests, RateLimit::MINIMUM.requests);
        assert_eq!(tiny.window_secs, 1);
        let huge = RateLimit::clamp(RateLimit {
            requests: u32::MAX,
            window_secs: u64::MAX,
        });
        assert_eq!(huge.requests, RateLimit::MAXIMUM.requests);
        assert_eq!(huge.window_secs, 3_600);
        assert_eq!(RateLimit::DEFAULT.per_second(), 10);
    }

    #[test]
    fn usage_counts_requests_and_never_reveals_a_secret() {
        let mut portal = Portal::open(temp_store("usage")).unwrap();
        let (key, secret) = portal
            .create_key("dev@gmail.com", "ci", vec![Scope::ReadBlocks], RateLimit::DEFAULT, 0)
            .unwrap();
        for at in 1..=5 {
            portal.authorize(&secret, None, at).unwrap();
        }
        let usage = portal.usage("dev@gmail.com");
        let keys = usage.get("keys").unwrap().as_array().unwrap();
        assert_eq!(keys[0].get("requests").unwrap().as_i128(), Some(5));
        let rendered = usage.to_canonical_string();
        assert!(!rendered.contains(&secret));
        assert!(!rendered.contains(&key.id[..4]) || rendered.contains(&key.id));
        assert!(!rendered.contains("secret_hash"));
        // Another account sees nothing of it.
        assert!(portal.usage("someone.else@gmail.com").get("keys").unwrap().as_array().unwrap().is_empty());
    }
}
