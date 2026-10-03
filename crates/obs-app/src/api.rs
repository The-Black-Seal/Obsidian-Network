//! The application API: the Explorer and the Developer Portal over one HTTP
//! surface.
//!
//! Route layout, and the reasoning behind it:
//!
//! * `/v1/explorer/...` — public, read-only, rate-limited, and subject to the
//!   privacy contract in [`crate::privacy`].  Every response is scrubbed before
//!   it leaves; a violated response becomes a refusal instead of a leak.
//! * `/v1/portal/...` — the Developer Portal's key management.  These routes
//!   require an account session from the registration gateway, because a key
//!   belongs to an account.
//! * `/healthz` — liveness, no index needed.
//!
//! There is no route that proxies the node API, and there is no route that
//! returns an account's balance.  See [`crate::privacy::ROUTES`] for the whole
//! surface and the tests that hold it.

use std::sync::{Arc, Mutex};

use obs_gateway::accounts::Registry;
use obs_primitives::json::Json;
use obs_primitives::network::Network;
use obs_rpc::http::{Method, Request, Response, Status};
use obs_rpc::server::{Handler, Peer};

use crate::indexer::Indexer;
use crate::portal::{Portal, PortalError, RateLimit, Scope};
use crate::privacy::{scrub, ROUTES};

/// Configuration for the application service.
#[derive(Debug, Clone)]
pub struct AppConfig {
    /// The node whose API is indexed.
    pub node_url: String,
    /// Served network.
    pub network: Network,
    /// Largest page a listing endpoint will return.
    pub max_page: usize,
    /// Default page size.
    pub default_page: usize,
    /// Whether an API key is required for explorer reads.  A public explorer
    /// sets this to `false`; a portal for developers sets it to `true`.
    pub require_key: bool,
}

impl Default for AppConfig {
    fn default() -> Self {
        AppConfig {
            node_url: "http://127.0.0.1:7200".to_string(),
            network: obs_primitives::network::MAINNET,
            max_page: 100,
            default_page: 25,
            require_key: false,
        }
    }
}

/// The application service.
pub struct App {
    indexer: Arc<Mutex<Indexer>>,
    portal: Arc<Mutex<Portal>>,
    /// The registration gateway's registry, for account sessions.
    accounts: Option<Arc<Mutex<Registry>>>,
    config: AppConfig,
    clock: Box<dyn Fn() -> u64 + Send + Sync>,
}

impl App {
    /// Builds the service.
    pub fn new(config: AppConfig, indexer: Indexer, portal: Portal) -> App {
        App {
            indexer: Arc::new(Mutex::new(indexer)),
            portal: Arc::new(Mutex::new(portal)),
            accounts: None,
            config,
            clock: Box::new(|| {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or(0),
                )
                .unwrap_or(0)
            }),
        }
    }

    /// Shares the registration service's registry, so portal routes can check
    /// account sessions.
    pub fn with_accounts(mut self, registry: Arc<Mutex<Registry>>) -> App {
        self.accounts = Some(registry);
        self
    }

    /// Replaces the clock (test hook).
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> App {
        self.clock = clock;
        self
    }

    /// The indexer, for the operator's own tooling and for tests.
    pub fn indexer(&self) -> Arc<Mutex<Indexer>> {
        Arc::clone(&self.indexer)
    }

    /// The portal, for the operator's own tooling and for tests.
    pub fn portal(&self) -> Arc<Mutex<Portal>> {
        Arc::clone(&self.portal)
    }

    /// The configured service.
    pub fn config(&self) -> &AppConfig {
        &self.config
    }

    fn now(&self) -> u64 {
        (self.clock)()
    }

    fn index(&self) -> std::sync::MutexGuard<'_, Indexer> {
        self.indexer.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn keys(&self) -> std::sync::MutexGuard<'_, Portal> {
        self.portal.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Follows the node, updating the index.  Called by a background thread in
    /// production and directly by tests.
    pub fn sync(&self) -> Result<usize, crate::indexer::IndexError> {
        self.index().sync()
    }
}

fn ok(value: Json) -> Response {
    Response::json(Status::OK, &value).no_store().hardened()
}

fn error(status: Status, code: &str, message: &str) -> Response {
    Response::error(status, code, message).no_store().hardened()
}

/// Scrubs a response body and turns a violation into a refusal.
///
/// The message deliberately does not name the offending field: the field list is
/// a design document, and a public response should not teach an attacker which
/// internal names exist.
fn publish(value: Json) -> Response {
    match scrub(&value) {
        Ok(clean) => ok(clean.clone()),
        Err(_violation) => error(
            Status::INTERNAL,
            "privacy_contract",
            "the response was withheld: it did not satisfy the network's privacy contract",
        ),
    }
}

fn page_of(request: &Request, config: &AppConfig) -> (usize, usize) {
    let limit = request
        .param("limit")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(config.default_page)
        .min(config.max_page);
    let offset = request
        .param("offset")
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    (limit, offset)
}

fn block_json(block: &crate::indexer::IndexedBlock) -> Json {
    Json::obj([
        ("height", Json::Int(block.height as i128)),
        ("hash", Json::Str(block.hash.clone())),
        ("parent", Json::Str(block.parent.clone())),
        ("state_root", Json::Str(block.state_root.clone())),
        ("timestamp", Json::Int(block.timestamp as i128)),
        ("slot", Json::Int(block.slot as i128)),
        ("weight_atoms", Json::Int(block.weight_atoms as i128)),
        ("difficulty_bp", Json::Int(block.difficulty_bp as i128)),
        ("proposer", Json::Str(block.proposer.clone())),
        ("transactions", Json::Int(block.transaction_ids.len() as i128)),
        ("attestations", Json::Int(block.attestations as i128)),
        ("finalized", Json::Bool(block.finalized)),
    ])
}

fn transaction_json(transaction: &crate::indexer::IndexedTransaction) -> Json {
    Json::obj([
        ("id", Json::Str(transaction.id.clone())),
        ("kind", Json::Str(transaction.kind.clone())),
        ("height", Json::Int(transaction.height as i128)),
        ("fee", Json::Str(transaction.fee.clone())),
        ("sender", Json::Str(transaction.sender.clone())),
        ("size_bytes", Json::Int(transaction.size_bytes as i128)),
    ])
}

impl Handler for App {
    fn handle(&self, request: &Request, _peer: &Peer) -> Response {
        let now = self.now();
        let state_changing = matches!(request.method, Method::Post | Method::Put | Method::Delete);
        if state_changing && !request.same_origin(&[]) && !request.same_origin(&["obsidian.network".to_string()]) {
            // Portal writes are same-origin; explorer reads are not writes.
            if request.path.starts_with("/v1/portal") {
                return error(
                    Status::FORBIDDEN,
                    "cross_origin",
                    "state-changing requests must come from the service's own origin",
                );
            }
        }
        let segments: Vec<&str> = request
            .path
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        let response = match (request.method, segments.as_slice()) {
            (Method::Get, ["healthz"]) => publish(Json::obj([
                ("status", Json::Str("ok".to_string())),
                ("chain_id", Json::Int(self.config.network.chain_id as i128)),
                ("indexed_height", Json::Int(self.index().indexed_height as i128)),
            ])),
            (Method::Get, ["v1", "routes"]) => publish(Json::obj([(
                "routes",
                Json::Array(
                    ROUTES
                        .iter()
                        .map(|route| {
                            Json::obj([
                                ("path", Json::Str(route.path.to_string())),
                                ("method", Json::Str(route.method.to_string())),
                                ("summary", Json::Str(route.summary.to_string())),
                                (
                                    "scope",
                                    match route.scope {
                                        Some(scope) => Json::Str(scope.to_string()),
                                        None => Json::Null,
                                    },
                                ),
                            ])
                        })
                        .collect(),
                ),
            )])),
            (Method::Get, ["v1", "explorer", "status"]) => self.status(),
            (Method::Get, ["v1", "explorer", "blocks"]) => self.blocks(request),
            (Method::Get, ["v1", "explorer", "blocks", selector]) => self.block(selector),
            (Method::Get, ["v1", "explorer", "transactions", id]) => self.transaction(id),
            (Method::Get, ["v1", "explorer", "address", address]) => self.address_activity(address),
            (Method::Get, ["v1", "explorer", "validators"]) => self.validators(),
            (Method::Get, ["v1", "explorer", "supply"]) => self.supply(),
            (Method::Get, ["v1", "explorer", "mining"]) => self.mining(),
            (Method::Get, ["v1", "explorer", "search"]) => self.search(request),
            (Method::Get, ["v1", "portal", "scopes"]) => publish(Json::obj([(
                "scopes",
                Json::Array(
                    Scope::ALL
                        .into_iter()
                        .map(|scope| {
                            Json::obj([
                                ("name", Json::Str(scope.name().to_string())),
                                ("description", Json::Str(scope.describe().to_string())),
                                ("default", Json::Bool(scope.default_granted())),
                            ])
                        })
                        .collect(),
                ),
            )])),
            (Method::Get, ["v1", "portal", "keys"]) => self.portal_keys(request),
            (Method::Post, ["v1", "portal", "keys"]) => self.portal_create(request),
            (Method::Delete, ["v1", "portal", "keys", id]) => self.portal_revoke(request, id),
            (Method::Post, ["v1", "portal", "keys", id, "rotate"]) => self.portal_rotate(request, id),
            (Method::Get, ["v1", "portal", "usage"]) => self.portal_usage(request),
            (Method::Get, ["v1", "portal", "openapi.json"]) => publish(openapi(&self.config)),
            _ => error(Status::NOT_FOUND, "not_found", "no such endpoint"),
        };
        let _ = now;
        response
    }
}

impl App {
    /// The key presented with a request, when the service requires one.
    fn authorized(&self, request: &Request, scope: Scope) -> Result<(), Response> {
        let presented = request
            .header("x-api-key")
            .or_else(|| {
                request
                    .header("authorization")
                    .and_then(|value| value.strip_prefix("ApiKey "))
            })
            .map(|value| value.to_string());
        let Some(presented) = presented else {
            if self.config.require_key {
                return Err(error(Status::FORBIDDEN, "api_key_required", "an API key is required"));
            }
            return Ok(());
        };
        let now = self.now();
        match self.keys().authorize(&presented, Some(scope), now) {
            Ok(_) => Ok(()),
            Err(failure) => Err(portal_error(failure)),
        }
    }

    fn scoped(&self, request: &Request, scope: Scope, body: impl FnOnce() -> Json) -> Response {
        if let Err(response) = self.authorized(request, scope) {
            return response;
        }
        publish(body())
    }

    fn status(&self) -> Response {
        // Refresh from the node on every status call: the explorer's status page
        // is where a visitor sees whether the index is behind.
        let _ = self.index().sync();
        let indexer = self.index();
        let indexed_height = indexer.indexed_height;
        let reorgs = indexer.reorgs_seen;
        let failures = indexer.sync_failures;
        let last_error = indexer.last_error.clone();
        let blocks_indexed = indexer.block_count();
        let addresses = indexer.address_count();
        let validators = indexer.validators().len();
        let snapshot = indexer.status();
        drop(indexer);
        match snapshot {
            Ok(snapshot) => publish(Json::obj([
                ("network", Json::Str(snapshot.network)),
                ("chain_id", Json::Int(snapshot.chain_id as i128)),
                ("node_height", Json::Int(snapshot.node_height as i128)),
                ("indexed_height", Json::Int(indexed_height as i128)),
                (
                    "index_behind",
                    Json::Int(snapshot.node_height.saturating_sub(indexed_height) as i128),
                ),
                ("head", Json::Str(snapshot.head)),
                ("state_root", Json::Str(snapshot.state_root)),
                ("protocol_time", Json::Int(snapshot.protocol_time as i128)),
                ("median_time_past", Json::Int(snapshot.median_time_past as i128)),
                ("pot_difficulty_bp", Json::Int(snapshot.difficulty_bp as i128)),
                ("total_weight_atoms", Json::Int(snapshot.total_weight_atoms as i128)),
                ("issued_supply", Json::Str(snapshot.issued_supply)),
                ("max_supply", Json::Str(snapshot.max_supply)),
                ("active_validators", Json::Int(snapshot.active_validators as i128)),
                ("active_miners", Json::Int(snapshot.active_miners as i128)),
                ("pooled_transactions", Json::Int(snapshot.pooled_transactions as i128)),
                ("peers", Json::Int(snapshot.peers as i128)),
                ("blocks_indexed", Json::Int(blocks_indexed as i128)),
                ("addresses_seen", Json::Int(addresses as i128)),
                ("validators_known", Json::Int(validators as i128)),
                ("reorgs_seen", Json::Int(reorgs as i128)),
                ("sync_failures", Json::Int(failures as i128)),
                (
                    "last_sync_error",
                    match last_error {
                        Some(message) => Json::Str(message),
                        None => Json::Null,
                    },
                ),
                (
                    "note",
                    Json::Str(
                        "this is an index of a node's view; the chain is the authority".to_string(),
                    ),
                ),
            ])),
            Err(failure) => error(
                Status::UNAVAILABLE,
                "node_unavailable",
                &format!("the node could not be read: {}", failure),
            ),
        }
    }

    fn blocks(&self, request: &Request) -> Response {
        let (limit, offset) = page_of(request, &self.config);
        let _ = self.index().sync();
        self.scoped(request, Scope::ReadBlocks, || {
            let indexer = self.index();
            let blocks: Vec<Json> = indexer
                .blocks(limit, offset)
                .iter()
                .map(block_json)
                .collect();
            Json::obj([
                ("indexed_height", Json::Int(indexer.indexed_height as i128)),
                ("count", Json::Int(blocks.len() as i128)),
                ("limit", Json::Int(limit as i128)),
                ("offset", Json::Int(offset as i128)),
                ("blocks", Json::Array(blocks)),
            ])
        })
    }

    fn block(&self, selector: &str) -> Response {
        let _ = self.index().sync();
        let indexer = self.index();
        match indexer.block(selector) {
            Some(block) => publish(Json::obj([("block", block_json(&block))])),
            None => error(Status::NOT_FOUND, "block_not_found", "no such block"),
        }
    }

    fn transaction(&self, id: &str) -> Response {
        let _ = self.index().sync();
        let indexer = self.index();
        match indexer.transaction(id) {
            Some(transaction) => publish(Json::obj([("transaction", transaction_json(&transaction))])),
            None => error(Status::NOT_FOUND, "transaction_not_found", "no such transaction"),
        }
    }

    /// An address's activity.
    ///
    /// Note what is *not* in this response: no balance, no reward total, no list
    /// of what the address holds.  The record is keyed by the partial address and
    /// holds only appearances.
    fn address_activity(&self, address: &str) -> Response {
        let lookup = obs_primitives::address::Address::parse(self.config.network, address);
        let Ok(parsed) = lookup else {
            return error(
                Status::BAD_REQUEST,
                "bad_address",
                "an address must be a valid obs1 address for this network",
            );
        };
        let _ = self.index().sync();
        let indexer = self.index();
        let full = parsed.to_string();
        match indexer.activity(&full) {
            Some(activity) => publish(Json::obj([
                ("address", Json::Str(activity.partial)),
                ("claims", Json::Int(activity.claims as i128)),
                ("blocks_proposed", Json::Int(activity.blocks_proposed as i128)),
                ("first_seen", Json::Int(activity.first_seen as i128)),
                ("last_seen", Json::Int(activity.last_seen as i128)),
                (
                    "recent_heights",
                    Json::Array(
                        activity
                            .recent_heights
                            .iter()
                            .map(|height| Json::Int(*height as i128))
                            .collect(),
                    ),
                ),
                (
                    "note",
                    Json::Str(
                        "activity only: the network does not publish balances".to_string(),
                    ),
                ),
            ])),
            None => publish(Json::obj([
                ("address", Json::Str(crate::privacy::mask_address(&parsed))),
                ("claims", Json::Int(0)),
                ("blocks_proposed", Json::Int(0)),
                ("first_seen", Json::Int(0)),
                ("last_seen", Json::Int(0)),
                ("recent_heights", Json::Array(Vec::new())),
                (
                    "note",
                    Json::Str("this index has not seen this address yet; it may still be new".to_string()),
                ),
            ])),
        }
    }

    fn validators(&self) -> Response {
        let _ = self.index().sync();
        let indexer = self.index();
        publish(Json::obj([
            (
                "validators",
                Json::Array(
                    indexer
                        .validators()
                        .iter()
                        .map(|validator| {
                            Json::obj([
                                ("node_key", Json::Str(validator.node_key.clone())),
                                ("owner", Json::Str(validator.owner.clone())),
                                ("bond", Json::Str(validator.bond.clone())),
                                ("uptime_bp", Json::Int(validator.uptime_bp as i128)),
                                ("attestations", Json::Int(validator.attestations as i128)),
                                ("blocks_proposed", Json::Int(validator.blocks_proposed as i128)),
                                ("missed_slots", Json::Int(validator.missed_slots as i128)),
                                ("active", Json::Bool(validator.active)),
                            ])
                        })
                        .collect(),
                ),
            ),
            (
                "note",
                Json::Str("uptime is evidenced by attestations, never self-reported".to_string()),
            ),
        ]))
    }

    fn supply(&self) -> Response {
        let _ = self.index().sync();
        let indexer = self.index();
        match indexer.supply() {
            Ok(supply) => publish(Json::obj([
                ("max_supply", Json::Str(supply.max_supply)),
                ("issued_supply", Json::Str(supply.issued_supply)),
                ("genesis_allocation", Json::Str(supply.genesis_allocation)),
                ("genesis_issued", Json::Bool(supply.genesis_issued)),
                ("mining_pool", Json::Str(supply.mining_pool)),
                ("validator_pool", Json::Str(supply.validator_pool)),
                ("locked_validator_bonds", Json::Str(supply.locked_validator_bonds)),
                ("circulating", Json::Str(supply.circulating)),
                ("remaining", Json::Str(supply.remaining)),
                (
                    "note",
                    Json::Str(
                        "protocol aggregates; these are not per-account figures".to_string(),
                    ),
                ),
            ])),
            Err(failure) => error(Status::UNAVAILABLE, "node_unavailable", &failure.to_string()),
        }
    }

    fn mining(&self) -> Response {
        let _ = self.index().sync();
        let indexer = self.index();
        match indexer.mining() {
            Ok(mining) => publish(Json::obj([
                ("reward_per_claim", Json::Str(mining.reward_per_claim)),
                (
                    "reward_per_claim_grains",
                    Json::Int(mining.reward_per_claim_grains as i128),
                ),
                ("daily_rate", Json::Str(mining.daily_rate)),
                ("active_miners", Json::Int(mining.active_miners as i128)),
                ("claims_issued", Json::Int(mining.claims_issued as i128)),
                ("interval_secs", Json::Int(mining.interval_secs as i128)),
                ("max_claims_per_day", Json::Int(mining.max_claims_per_day as i128)),
                ("genesis_claim_issued", Json::Bool(mining.genesis_claim_issued)),
                (
                    "note",
                    Json::Str(
                        "eligibility is decided by protocol time; browser timers are only a display"
                            .to_string(),
                    ),
                ),
            ])),
            Err(failure) => error(Status::UNAVAILABLE, "node_unavailable", &failure.to_string()),
        }
    }

    /// Search: a height, a block hash, a transaction id, or an address.
    ///
    /// The shape of the answer is chosen by the query, and an address answer is
    /// an *activity* answer, never a balance.
    fn search(&self, request: &Request) -> Response {
        let Some(query) = request.param("q") else {
            return error(Status::BAD_REQUEST, "missing_query", "pass ?q=");
        };
        let query = query.trim();
        if query.is_empty() || query.len() > 128 {
            return error(Status::BAD_REQUEST, "bad_query", "the query must be 1 to 128 characters");
        }
        // An address for this network.
        if query.starts_with(self.config.network.address_prefix) {
            return self.address_activity(query);
        }
        // A height.
        if let Ok(height) = query.parse::<u64>() {
            let _ = self.index().sync();
            let indexer = self.index();
            return match indexer.block(&height.to_string()) {
                Some(block) => publish(Json::obj([
                    ("kind", Json::Str("block".to_string())),
                    ("block", block_json(&block)),
                ])),
                None => error(Status::NOT_FOUND, "block_not_found", "no such height in this index"),
            };
        }
        // A 64-character hex string is a hash: a block or a transaction.
        if query.len() == 64 && query.chars().all(|character| character.is_ascii_hexdigit()) {
            let _ = self.index().sync();
            let indexer = self.index();
            if let Some(block) = indexer.block(query) {
                return publish(Json::obj([
                    ("kind", Json::Str("block".to_string())),
                    ("block", block_json(&block)),
                ]));
            }
            if let Some(transaction) = indexer.transaction(query) {
                return publish(Json::obj([
                    ("kind", Json::Str("transaction".to_string())),
                    ("transaction", transaction_json(&transaction)),
                ]));
            }
            return error(Status::NOT_FOUND, "not_found", "no such block or transaction");
        }
        error(
            Status::BAD_REQUEST,
            "bad_query",
            "search accepts a height, a 32-byte hash, or an address",
        )
    }

    // -----------------------------------------------------------------------
    // Portal
    // -----------------------------------------------------------------------

    /// The account a portal request belongs to, from the gateway session.
    fn account_of(&self, request: &Request) -> Result<String, Response> {
        let Some(registry) = &self.accounts else {
            return Err(error(
                Status::NOT_IMPLEMENTED,
                "no_accounts",
                "this deployment does not share the registration service's accounts",
            ));
        };
        let Some(token) = request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
        else {
            return Err(error(Status::FORBIDDEN, "bad_session", "a bearer session token is required"));
        };
        let now = self.now();
        let registry = registry.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        match registry.session(token, now) {
            Ok(session) => Ok(session.canonical_gmail.clone()),
            Err(_) => Err(error(Status::FORBIDDEN, "bad_session", "the session is not valid")),
        }
    }

    fn portal_keys(&self, request: &Request) -> Response {
        let owner = match self.account_of(request) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let portal = self.keys();
        publish(Json::obj([
            (
                "keys",
                Json::Array(portal.keys_of(&owner).into_iter().map(|key| key.view()).collect()),
            ),
            (
                "scopes_available",
                Json::Array(
                    Scope::ALL
                        .into_iter()
                        .map(|scope| Json::Str(scope.name().to_string()))
                        .collect(),
                ),
            ),
        ]))
    }

    fn portal_create(&self, request: &Request) -> Response {
        let owner = match self.account_of(request) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let body = match request.json() {
            Ok(body) => body,
            Err(_) => Json::obj(Vec::<(String, Json)>::new()),
        };
        let label = body.get("label").and_then(Json::as_str).unwrap_or("").to_string();
        let scopes: Vec<Scope> = body
            .get("scopes")
            .and_then(Json::as_array)
            .map(|names| {
                names
                    .iter()
                    .filter_map(Json::as_str)
                    .filter_map(Scope::parse)
                    .collect()
            })
            .unwrap_or_default();
        let limit = body
            .get("rate_limit")
            .and_then(Json::as_i128)
            .map(|requests| RateLimit {
                requests: requests.clamp(0, u32::MAX as i128) as u32,
                window_secs: RateLimit::DEFAULT.window_secs,
            })
            .unwrap_or(RateLimit::DEFAULT);
        let now = self.now();
        let created = self.keys().create_key(&owner, &label, scopes, limit, now);
        match created {
            Ok((key, secret)) => publish(Json::obj([
                ("id", Json::Str(key.id.clone())),
                ("key", Json::Str(secret)),
                ("scopes", Json::Array(key.scope_names().into_iter().map(Json::Str).collect())),
                ("rate_limit", Json::Int(key.limit.requests as i128)),
                (
                    "notice",
                    Json::Str(
                        "shown once. Store it now: only a hash is kept, so it cannot be shown again."
                            .to_string(),
                    ),
                ),
            ])),
            Err(failure) => portal_error(failure),
        }
    }

    fn portal_revoke(&self, request: &Request, id: &str) -> Response {
        let owner = match self.account_of(request) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let now = self.now();
        match self.keys().revoke(&owner, id, now) {
            Ok(()) => publish(Json::obj([("revoked", Json::Bool(true)), ("id", Json::Str(id.to_string()))])),
            Err(failure) => portal_error(failure),
        }
    }

    fn portal_rotate(&self, request: &Request, id: &str) -> Response {
        let owner = match self.account_of(request) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let now = self.now();
        match self.keys().rotate(&owner, id, now) {
            Ok(secret) => publish(Json::obj([
                ("id", Json::Str(id.to_string())),
                ("key", Json::Str(secret)),
                (
                    "notice",
                    Json::Str("the previous secret stopped working at this moment".to_string()),
                ),
            ])),
            Err(failure) => portal_error(failure),
        }
    }

    fn portal_usage(&self, request: &Request) -> Response {
        let owner = match self.account_of(request) {
            Ok(owner) => owner,
            Err(response) => return response,
        };
        let portal = self.keys();
        publish(portal.usage(&owner))
    }
}

fn portal_error(failure: PortalError) -> Response {
    match failure {
        PortalError::UnknownKey => error(Status::NOT_FOUND, "unknown_key", "no such API key"),
        PortalError::BadSecret => error(Status::FORBIDDEN, "bad_key", "the API key is not valid"),
        PortalError::Revoked => error(Status::FORBIDDEN, "revoked_key", "the API key has been revoked"),
        PortalError::RateLimited { retry_after } => Response::error(
            Status::TOO_MANY_REQUESTS,
            "rate_limited",
            "the API key's rate limit is reached",
        )
        .header("Retry-After", retry_after.to_string())
        .no_store()
        .hardened(),
        PortalError::MissingScope(scope) => error(
            Status::FORBIDDEN,
            "missing_scope",
            &format!("this key does not have the {} scope", scope),
        ),
        PortalError::NoAccount => error(Status::FORBIDDEN, "no_account", "an account is required"),
        PortalError::Store(detail) => error(Status::INTERNAL, "storage_error", &detail),
    }
}

/// The OpenAPI description of the public API.
///
/// It is generated from [`ROUTES`], so the documentation cannot drift from the
/// route table: a route that exists is described, and a route that is described
/// exists.
pub fn openapi(config: &AppConfig) -> Json {
    // Several methods share a path (`/v1/portal/keys` is both a listing and a
    // creation), and OpenAPI expresses that as one path object with one entry per
    // method — so paths are merged rather than repeated.  Repeating a path would
    // also produce a document with a duplicate object key, which this workspace's
    // canonical JSON rejects outright, and which some clients would silently
    // resolve to one of the two.
    let mut paths: Vec<(String, Json)> = Vec::new();
    for route in ROUTES {
        let method = route.method.to_ascii_lowercase();
        let operation = Json::obj([
            ("summary", Json::Str(route.summary.to_string())),
            (
                "security",
                match route.scope {
                    Some(scope) => Json::Array(vec![Json::obj([(
                        "apiKey",
                        Json::Array(vec![Json::Str(scope.to_string())]),
                    )])]),
                    None => Json::Array(Vec::new()),
                },
            ),
            (
                "responses",
                Json::obj([(
                    "200",
                    Json::obj([("description", Json::Str("success".to_string()))]),
                )]),
            ),
        ]);
        match paths.iter_mut().find(|(path, _)| *path == route.path) {
            Some((_, Json::Object(fields))) => fields.push((method, operation)),
            Some((_, other)) => {
                // Unreachable: every path is inserted as an object above.
                *other = Json::obj([(method, operation)]);
            }
            None => paths.push((route.path.to_string(), Json::obj([(method, operation)]))),
        }
    }

    Json::obj([
        ("openapi", Json::Str("3.0.3".to_string())),
        (
            "info",
            Json::obj([
                ("title", Json::Str("Obsidian Network API".to_string())),
                ("version", Json::Str(obs_rpc::API_VERSION.to_string())),
                (
                    "description",
                    Json::Str(
                        "The Obsidian Network's public read API and developer portal. The chain is \
                         the authority; this API is an index of what a node reports. Balances are \
                         never published: an account's own state is available only to a caller who \
                         proves possession of that account's key. An API key is a read credential \
                         and can never grant custody of value."
                            .to_string(),
                    ),
                ),
            ]),
        ),
        (
            "servers",
            Json::Array(vec![Json::obj([
                ("url", Json::Str("http://127.0.0.1:8081".to_string())),
                ("description", Json::Str(config.network.name.to_string())),
            ])]),
        ),
        (
            "components",
            Json::obj([(
                "securitySchemes",
                Json::obj([(
                    "apiKey",
                    Json::obj([
                        ("type", Json::Str("apiKey".to_string())),
                        ("in", Json::Str("header".to_string())),
                        ("name", Json::Str("X-API-Key".to_string())),
                        (
                            "description",
                            Json::Str(
                                "A read credential. It selects scopes and a rate limit; it never \
                                 grants custody of value."
                                    .to_string(),
                            ),
                        ),
                    ]),
                )]),
            )]),
        ),
        ("paths", Json::Object(paths)),
        ("x-obsidian-chain-id", Json::Int(config.network.chain_id as i128)),
        (
            "x-obsidian-privacy",
            Json::Str(
                "No endpoint returns an account balance or a whole address. Activity is published \
                 by partial address only."
                    .to_string(),
            ),
        ),
    ])
}
