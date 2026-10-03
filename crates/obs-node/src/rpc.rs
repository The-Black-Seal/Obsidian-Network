//! The node's HTTP API.
//!
//! Every response here is a *view* of the chain.  The API holds no state of its
//! own, mints nothing, and moves no value: it reads the node's chain store and
//! pool, and it forwards signed transactions to the pool for validation.  If
//! this module were deleted the node would still work — that is the point.
//!
//! ## What the API will not do
//!
//! * **No balances by address.**  There is no `GET /wallet/{address}/balance`
//!   and there will not be one.  The Explorer and this API show *chain* facts
//!   (blocks, supply, validators, mining parameters) and partial addresses.  An
//!   account's balance is visible only to a caller that proves it holds the
//!   account's key (`POST /api/v1/account/proof`).
//! * **No key material.**  Nothing here accepts a private key, a seed phrase or
//!   a password.
//! * **No judgement.**  A transaction submitted here is validated by the pool
//!   and the chain, exactly like a transaction from a peer.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use obs_primitives::address::mask;
use obs_primitives::hash::Hash32;
use obs_primitives::json::Json;
use obs_rpc::http::{Method, Request, Response, Status};
use obs_rpc::server::{Handler, Peer};

use crate::Node;

/// How many blocks a single listing request may return.
pub const MAX_BLOCK_PAGE: usize = 200;
/// Largest transaction a submission may carry.
pub const MAX_SUBMITTED_TX_BYTES: usize = 64 * 1024;

/// The node's API handler.
pub struct NodeApi {
    node: Arc<Mutex<Node>>,
    started: u64,
    requests: AtomicU64,
    /// Chain id this API answers for, so a request can never be answered by the
    /// wrong chain's node by accident.
    chain_id: u32,
}

impl NodeApi {
    /// Wraps a node in an API handler.
    pub fn new(node: Node) -> NodeApi {
        let chain_id = node.config().network.chain_id;
        NodeApi {
            node: Arc::new(Mutex::new(node)),
            started: unix_now(),
            requests: AtomicU64::new(0),
            chain_id,
        }
    }

    /// The shared node handle, for tests and for the operator CLI.
    pub fn node(&self) -> Arc<Mutex<Node>> {
        Arc::clone(&self.node)
    }

    /// Number of requests served.
    pub fn requests(&self) -> u64 {
        self.requests.load(Ordering::Relaxed)
    }

    /// The network this API answers for.
    fn chain_id_network(&self) -> obs_primitives::network::Network {
        obs_primitives::network::Network::by_chain_id(self.chain_id)
            .unwrap_or(obs_primitives::network::MAINNET)
    }

    fn with_node<T>(&self, f: impl FnOnce(&mut Node) -> T) -> Result<T, Response> {
        let mut node = self
            .node
            .lock()
            .map_err(|_| Response::error(Status::INTERNAL, "node_unavailable", "the node is not available"))?;
        Ok(f(&mut node))
    }

    fn route(&self, request: &Request, _peer: &Peer) -> Response {
        self.requests.fetch_add(1, Ordering::Relaxed);
        let segments: Vec<&str> = request
            .path
            .trim_start_matches('/')
            .split('/')
            .filter(|segment| !segment.is_empty())
            .collect();
        if segments.len() < 2 || segments[0] != "api" {
            return Response::error(Status::NOT_FOUND, "not_found", "the request is not understood");
        }
        let version = segments[1];
        if version != obs_rpc::API_VERSION {
            return Response::error(
                Status::NOT_FOUND,
                "unknown_api_version",
                "this node serves v1",
            );
        }
        let tail = &segments[2..];
        let response = match request.method {
            Method::Get | Method::Head => self.get(request, tail),
            Method::Post => self.post(request, tail),
            _ => Response::error(
                Status::METHOD_NOT_ALLOWED,
                "method_not_allowed",
                "this endpoint is read-only",
            ),
        };
        response.no_store().hardened()
    }

    fn get(&self, request: &Request, tail: &[&str]) -> Response {
        match tail {
            [] | ["status"] => self.status(),
            ["supply"] => self.supply(),
            ["params"] => self.params(),
            ["mining"] | ["mining", "params"] => self.mining(),
            ["blocks"] => self.blocks(request),
            ["blocks", selector] => self.block(selector),
            ["transactions", id] => self.transaction(id),
            ["validators"] => self.validators(),
            ["mempool"] => self.mempool(),
            ["peers"] => self.peers(),
            ["events"] => self.events(),
            _ => Response::error(Status::NOT_FOUND, "not_found", "no such endpoint"),
        }
    }

    fn post(&self, request: &Request, tail: &[&str]) -> Response {
        match tail {
            ["transactions"] => self.submit_transaction(request),
            ["account", "proof"] => self.account_proof(request),
            _ => Response::error(
                Status::NOT_FOUND,
                "not_found",
                "no such endpoint, or it is not writable",
            ),
        }
    }

    // -----------------------------------------------------------------------
    // Chain views
    // -----------------------------------------------------------------------

    fn status(&self) -> Response {
        self.with_node(|node| {
            let network = node.config().network;
            let head = node.head_state();
            let mining = node.mining_info();
            let now = node.protocol_time();
            let expected_difficulty = head.expected_difficulty_bp(head.height + 1).unwrap_or(0);
            ok_json(json_obj([
                ("network", Json::Str(network.name.to_string())),
                ("chain_id", Json::Int(network.chain_id as i128)),
                ("protocol_version", Json::Int(obs_chain::params::PROTOCOL_VERSION as i128)),
                // The chain's epoch is part of its identity — two devnets started
                // a minute apart are two different chains — so a node publishes
                // the one it is actually running.  It is public information (it
                // is the genesis anchor's own input); the registration
                // authority behind the anchor is not.
                (
                    "genesis_timestamp",
                    Json::Int(node.genesis_timestamp() as i128),
                ),
                ("height", Json::Int(node.height() as i128)),
                ("head", Json::Str(node.head().to_hex())),
                ("state_root", Json::Str(head.state_root().to_hex())),
                ("finalized_height", Json::Int(head.finalized_height as i128)),
                ("total_weight_atoms", Json::Int(clamp_u128(head.total_weight.atoms))),
                ("pot_difficulty_bp", Json::Int(expected_difficulty as i128)),
                ("median_time_past", Json::Int(head.median_time_past() as i128)),
                ("last_block_time", Json::Int(head.last_timestamp as i128)),
                ("protocol_time", Json::Int(now as i128)),
                ("issued_supply", Json::Str(head.issued_supply.to_decimal_string())),
                ("max_supply", Json::Str(obs_primitives::money::MAX_SUPPLY.to_decimal_string())),
                ("active_validators", Json::Int(head.active_validators().len() as i128)),
                ("active_miners", Json::Int(mining.active_miners as i128)),
                ("peers", Json::Int(node.peer_status().len() as i128)),
                ("pooled_transactions", Json::Int(node.mempool_stats().transactions as i128)),
                ("timestamp_unix", Json::Int(now as i128)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn supply(&self) -> Response {
        self.with_node(|node| {
            let head = node.head_state();
            ok_json(json_obj([
                ("max_supply", Json::Str(obs_primitives::money::MAX_SUPPLY.to_decimal_string())),
                ("issued_supply", Json::Str(head.issued_supply.to_decimal_string())),
                ("genesis_allocation", Json::Str(obs_primitives::money::GENESIS_ALLOCATION.to_decimal_string())),
                ("genesis_issued", Json::Bool(head.genesis_issued)),
                ("mining_pool", Json::Str(head.mining_pool.to_decimal_string())),
                ("validator_pool", Json::Str(head.validator_pool.to_decimal_string())),
                ("locked_validator_bonds", Json::Str(head.locked_bonds().to_decimal_string())),
                ("circulating", Json::Str(
                    head.issued_supply
                        .checked_sub(head.mining_pool)
                        .and_then(|value| value.checked_sub(head.validator_pool))
                        .unwrap_or(obs_primitives::money::Amount::ZERO)
                        .to_decimal_string(),
                )),
                ("remaining", Json::Str(
                    obs_primitives::money::MAX_SUPPLY
                        .checked_sub(head.issued_supply)
                        .unwrap_or(obs_primitives::money::Amount::ZERO)
                        .to_decimal_string(),
                )),
                ("unit", Json::Str("grains".to_string())),
                ("smallest_unit", Json::Str("1 grain = 0.000000000001 OBS".to_string())),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn params(&self) -> Response {
        self.with_node(|node| {
            let network = node.config().network;
            let parameters = crate::ProtocolParameters::current(network);
            ok_json(json_obj([
                ("protocol_version", Json::Int(parameters.version as i128)),
                ("chain_id", Json::Int(parameters.chain_id as i128)),
                ("address_prefix", Json::Str(network.address_prefix.to_string())),
                ("slot_duration_secs", Json::Int(parameters.slot_duration_secs as i128)),
                ("mtp_window", Json::Int(parameters.mtp_window as i128)),
                ("max_block_drift_secs", Json::Int(parameters.max_block_drift_secs as i128)),
                ("claim_interval_secs", Json::Int(parameters.claim_interval_secs as i128)),
                ("max_claims_per_day", Json::Int(parameters.max_claims_per_day as i128)),
                ("validator_bond", Json::Str(parameters.validator_bond.to_decimal_string())),
                ("unbonding_secs", Json::Int(parameters.unbonding_secs as i128)),
                ("max_gas_fee", Json::Str(parameters.max_gas_fee.to_decimal_string())),
                ("validator_fee_share_percent", Json::Int(parameters.validator_fee_share_percent as i128)),
                ("mining_fee_share_percent", Json::Int(parameters.mining_fee_share_percent as i128)),
                ("max_supply", Json::Str(parameters.max_supply.to_decimal_string())),
                ("max_invites_per_account", Json::Int(parameters.max_invites_per_account as i128)),
                ("authority", Json::Str("consensus decides; this API only reports".to_string())),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn mining(&self) -> Response {
        self.with_node(|node| {
            let info = node.mining_info();
            ok_json(json_obj([
                ("reward_per_claim", Json::Str(info.reward_per_claim.to_decimal_string())),
                ("reward_per_claim_grains", Json::Int(info.reward_per_claim.grains() as i128)),
                ("daily_rate", Json::Str(
                    info.reward_per_claim
                        .checked_mul(info.max_claims_per_day as u128)
                        .unwrap_or(obs_primitives::money::Amount::ZERO)
                        .to_decimal_string(),
                )),
                ("active_miners", Json::Int(info.active_miners as i128)),
                ("claims_issued", Json::Int(info.claims_issued as i128)),
                ("interval_secs", Json::Int(info.interval_secs as i128)),
                ("max_claims_per_day", Json::Int(info.max_claims_per_day as i128)),
                ("genesis_claim_issued", Json::Bool(info.genesis_claim_issued)),
                ("eligibility", Json::Str(
                    "protocol time only: a claim is valid when the block's protocol time is at least the interval after the account's last claim and inside the daily window".to_string(),
                )),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn blocks(&self, request: &Request) -> Response {
        let limit = request
            .param("limit")
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(20)
            .min(MAX_BLOCK_PAGE);
        self.with_node(|node| {
            let height = node.height();
            let mut blocks = Vec::new();
            let mut cursor = height;
            while blocks.len() < limit && cursor >= 1 {
                if let Some(block) = node.block_at(cursor) {
                    blocks.push(block_summary(node, block));
                }
                cursor -= 1;
            }
            ok_json(json_obj([
                ("height", Json::Int(height as i128)),
                ("count", Json::Int(blocks.len() as i128)),
                ("blocks", Json::Array(blocks)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn block(&self, selector: &str) -> Response {
        self.with_node(|node| {
            let block = if let Ok(height) = selector.parse::<u64>() {
                node.block_at(height).cloned()
            } else {
                match parse_hash(selector) {
                    Some(hash) => node.block_by_hash(&hash).cloned(),
                    None => {
                        return Response::error(
                            Status::BAD_REQUEST,
                            "bad_selector",
                            "a block is selected by height or by hash",
                        )
                    }
                }
            };
            match block {
                Some(block) => ok_json(json_obj([
                    ("height", Json::Int(block.header.height as i128)),
                    ("hash", Json::Str(block.hash().to_hex())),
                    ("parent", Json::Str(block.header.parent.to_hex())),
                    ("state_root", Json::Str(block.header.state_root.to_hex())),
                    ("tx_root", Json::Str(block.header.tx_root.to_hex())),
                    ("timestamp", Json::Int(block.header.timestamp as i128)),
                    ("slot", Json::Int(block.header.slot as i128)),
                    ("difficulty_bp", Json::Int(block.header.difficulty_bp as i128)),
                    ("weight_atoms", Json::Int(clamp_u128(block.header.weight_atoms))),
                    ("proposer", Json::Str(mask_proposer(node, &block.header.proposer))),
                    ("transactions", Json::Int(block.transactions.len() as i128)),
                    ("attestations", Json::Int(block.attestations.len() as i128)),
                    (
                        "transaction_ids",
                        Json::Array(
                            block
                                .transactions
                                .iter()
                                .map(|tx| Json::Str(tx.id().0.to_hex()))
                                .collect(),
                        ),
                    ),
                    ("finalized", Json::Bool(node.head_state().is_finalized(block.header.height))),
                ])),
                None => Response::error(Status::NOT_FOUND, "block_not_found", "no such block"),
            }
        })
        .unwrap_or_else(|error| error)
    }

    fn transaction(&self, id: &str) -> Response {
        let Some(hash) = parse_hash(id) else {
            return Response::error(Status::BAD_REQUEST, "bad_transaction_id", "a transaction id is a 32 byte hash");
        };
        self.with_node(|node| match node.find_transaction(&hash) {
            Some((tx, Some(height))) => ok_json(json_obj([
                ("id", Json::Str(hash.to_hex())),
                ("status", Json::Str("confirmed".to_string())),
                ("height", Json::Int(height as i128)),
                ("kind", Json::Str(tx.kind_name().to_string())),
                ("fee", Json::Str(obs_mempool::transaction_fee(&tx).to_decimal_string())),
                ("size_bytes", Json::Int(tx.to_bytes().len() as i128)),
                ("sender", Json::Str(mask(&tx.sender().unwrap_or_else(|| {
                    obs_primitives::address::Address::from_parts(node.config().network, 1, [0u8; 20])
                })))),
            ])),
            Some((tx, None)) => ok_json(json_obj([
                ("id", Json::Str(hash.to_hex())),
                ("status", Json::Str("pooled".to_string())),
                ("height", Json::Null),
                ("kind", Json::Str(tx.kind_name().to_string())),
                ("fee", Json::Str(obs_mempool::transaction_fee(&tx).to_decimal_string())),
                ("size_bytes", Json::Int(tx.to_bytes().len() as i128)),
                ("sender", Json::Str(mask(&tx.sender().unwrap_or_else(|| {
                    obs_primitives::address::Address::from_parts(node.config().network, 1, [0u8; 20])
                })))),
            ])),
            None => Response::error(Status::NOT_FOUND, "transaction_not_found", "no such transaction"),
        })
        .unwrap_or_else(|error| error)
    }

    fn validators(&self) -> Response {
        self.with_node(|node| {
            let state = node.head_state();
            let at = node.protocol_time();
            let mut validators = Vec::new();
            let mut active = 0;
            for node_key in state.active_validators() {
                if let Some(record) = state.validator(&node_key) {
                    active += 1;
                    validators.push(Json::obj([
                        ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&node_key))),
                        ("owner", Json::Str(mask(&record.owner))),
                        ("bond", Json::Str(record.bond.to_decimal_string())),
                        ("uptime_bp", Json::Int(state.uptime_bp(&node_key, at) as i128)),
                        ("score", Json::Int(state.validator_score(&node_key, at).unwrap_or(0) as i128)),
                        ("attestations", Json::Int(record.attestation_count as i128)),
                        ("blocks_proposed", Json::Int(record.blocks_proposed as i128)),
                        ("missed_slots", Json::Int(record.missed_slots as i128)),
                        ("registered_at", Json::Int(record.registered_at as i128)),
                        ("active", Json::Bool(record.active)),
                    ]));
                }
            }
            ok_json(json_obj([
                ("active", Json::Int(active as i128)),
                ("quorum", Json::Int(quorum_for(active) as i128)),
                ("validators", Json::Array(validators)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn mempool(&self) -> Response {
        self.with_node(|node| {
            let stats = node.mempool_stats();
            let pooled = node
                .pooled_transactions()
                .iter()
                .take(50)
                .map(|tx| {
                    Json::obj([
                        ("id", Json::Str(tx.id().0.to_hex())),
                        ("kind", Json::Str(tx.kind_name().to_string())),
                        ("fee", Json::Str(obs_mempool::transaction_fee(tx).to_decimal_string())),
                        ("size_bytes", Json::Int(tx.to_bytes().len() as i128)),
                    ])
                })
                .collect();
            ok_json(json_obj([
                ("transactions", Json::Int(stats.transactions as i128)),
                ("accounts", Json::Int(stats.accounts as i128)),
                ("bytes", Json::Int(stats.bytes as i128)),
                ("total_fees", Json::Str(stats.total_fees.to_decimal_string())),
                ("capacity", Json::Int(stats.max_transactions as i128)),
                ("dropped", Json::Int(stats.dropped as i128)),
                ("replaced", Json::Int(stats.replaced as i128)),
                ("sample", Json::Array(pooled)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn peers(&self) -> Response {
        self.with_node(|node| {
            let peers = node
                .peer_status()
                .into_iter()
                .map(|peer| {
                    Json::obj([
                        ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&peer.node_key))),
                        ("address", Json::Str(peer.addr.to_string())),
                        ("inbound", Json::Bool(peer.inbound)),
                        ("height", Json::Int(peer.height as i128)),
                        ("head", Json::Str(peer.head.to_hex())),
                        ("connected_secs", Json::Int(peer.connected_secs as i128)),
                        ("idle_secs", Json::Int(peer.idle_secs as i128)),
                        ("messages_in", Json::Int(peer.messages_in as i128)),
                        ("messages_out", Json::Int(peer.messages_out as i128)),
                        ("bytes_in", Json::Int(peer.bytes_in.min(i64::MAX as u64) as i128)),
                        ("bytes_out", Json::Int(peer.bytes_out.min(i64::MAX as u64) as i128)),
                        ("last_message", Json::Str(peer.last_message.unwrap_or_default())),
                    ])
                })
                .collect();
            ok_json(json_obj([
                ("count", Json::Int(node.peer_status().len() as i128)),
                ("peers", Json::Array(peers)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    fn events(&self) -> Response {
        self.with_node(|node| {
            let events = node
                .recent_events(50)
                .iter()
                .map(|event| {
                    let (kind, detail) = describe_event(event);
                    Json::obj([("kind", Json::Str(kind)), ("detail", Json::Str(detail))])
                })
                .collect();
            ok_json(json_obj([
                ("uptime_secs", Json::Int(unix_now().saturating_sub(self.started) as i128)),
                ("requests", Json::Int(self.requests() as i128)),
                ("events", Json::Array(events)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }

    // -----------------------------------------------------------------------
    // Writes
    // -----------------------------------------------------------------------

    fn submit_transaction(&self, request: &Request) -> Response {
        if request.body.len() > MAX_SUBMITTED_TX_BYTES {
            return Response::error(Status::PAYLOAD_TOO_LARGE, "transaction_too_large", "the transaction exceeds the pool limit");
        }
        let json = match request.json() {
            Ok(json) => json,
            Err(_) => {
                return Response::error(Status::BAD_REQUEST, "bad_json", "the body must be JSON")
            }
        };
        let Some(hex) = json.get("transaction").and_then(Json::as_str) else {
            return Response::error(
                Status::BAD_REQUEST,
                "missing_transaction",
                "send {\"transaction\": \"<hex>\"}",
            );
        };
        let Some(bytes) = obs_crypto::encoding::hex_decode(hex) else {
            return Response::error(Status::BAD_REQUEST, "bad_hex", "the transaction must be hex");
        };
        let tx = match obs_chain::Transaction::from_bytes(&bytes) {
            Ok(tx) => tx,
            Err(_) => {
                return Response::error(
                    Status::BAD_REQUEST,
                    "malformed_transaction",
                    "the transaction could not be decoded",
                )
            }
        };
        if tx.chain_id != self.chain_id {
            return Response::error(
                Status::UNPROCESSABLE_ENTITY,
                "wrong_chain",
                "the transaction belongs to another network",
            );
        }
        let id = tx.id();
        self.with_node(|node| {
            let state = node.head_state().clone();
            let at = node.protocol_time();
            match node.mempool.insert(&state, tx.clone(), at) {
                Ok(_) => ok_json(json_obj([
                    ("accepted", Json::Bool(true)),
                    ("id", Json::Str(id.0.to_hex())),
                    ("status", Json::Str("pooled".to_string())),
                ])),
                Err(error) => {
                    let (code, rule) = pool_error_code(&error);
                    Response::error(Status::UNPROCESSABLE_ENTITY, code, &rule)
                }
            }
        })
        .unwrap_or_else(|error| error)
    }

    /// Proves ownership of an account and returns the details only its owner
    /// may see.
    ///
    /// The caller signs a domain-separated challenge with the account's wallet
    /// key.  No key material is sent; the node verifies a signature and then
    /// answers about the account the caller has just proved it controls.
    fn account_proof(&self, request: &Request) -> Response {
        let json = match request.json() {
            Ok(json) => json,
            Err(_) => return Response::error(Status::BAD_REQUEST, "bad_json", "the body must be JSON"),
        };
        let (Some(address_text), Some(nonce), Some(signature_hex)) = (
            json.get("address").and_then(Json::as_str),
            json.get("nonce").and_then(Json::as_str),
            json.get("signature").and_then(Json::as_str),
        ) else {
            return Response::error(
                Status::BAD_REQUEST,
                "missing_fields",
                "send {\"address\", \"nonce\", \"signature\"}",
            );
        };
        if nonce.len() > 64 {
            return Response::error(Status::BAD_REQUEST, "bad_nonce", "the nonce is too long");
        }
        let network = self.chain_id_network();
        let Ok(address) = obs_primitives::address::Address::parse(network, address_text) else {
            return Response::error(Status::BAD_REQUEST, "bad_address", "the address is not valid");
        };
        let Some(signature) = obs_crypto::encoding::hex_decode(signature_hex) else {
            return Response::error(Status::BAD_REQUEST, "bad_signature", "the signature must be hex");
        };
        if signature.len() != 64 {
            return Response::error(Status::BAD_REQUEST, "bad_signature", "signatures are 64 bytes");
        }
        let mut signature_bytes = [0u8; 64];
        signature_bytes.copy_from_slice(&signature);

        self.with_node(|node| {
            let state = node.head_state();
            let Some(account) = state.account(&address) else {
                return Response::error(Status::NOT_FOUND, "account_not_found", "no such account");
            };
            let preimage = account_proof_preimage(self.chain_id, &address, nonce);
            if !obs_crypto::ed25519::verify(&account.wallet_key, &preimage, &signature_bytes) {
                return Response::error(
                    Status::FORBIDDEN,
                    "bad_proof",
                    "the signature does not prove ownership of this account",
                );
            }
            let at = node.protocol_time();
            let interval_ready = account.last_claim_at + obs_chain::params::CLAIM_INTERVAL_SECS;
            let mining = node.mining_info();
            let claimable = state
                .account(&address)
                .map(|account| {
                    at >= interval_ready && account.claims_today < obs_chain::params::MAX_CLAIMS_PER_DAY
                })
                .unwrap_or(false);
            ok_json(json_obj([
                ("address", Json::Str(address.to_string())),
                ("balance", Json::Str(account.balance.to_decimal_string())),
                ("balance_grains", Json::Int(account.balance.grains() as i128)),
                ("lifetime_rewards", Json::Str(account.lifetime_rewards.to_decimal_string())),
                ("last_nonce", Json::Int(account.last_nonce as i128)),
                ("next_nonce", Json::Int(state.expected_nonce(&address) as i128)),
                ("registered_at", Json::Int(account.registered_at as i128)),
                ("claims_today", Json::Int(account.claims_today as i128)),
                ("last_claim_at", Json::Int(account.last_claim_at as i128)),
                ("last_claim_sequence", Json::Int(account.last_claim_sequence as i128)),
                ("next_claim_at", Json::Int(interval_ready as i128)),
                ("claimable_now", Json::Bool(claimable)),
                ("next_claim_reward", Json::Str(mining.reward_per_claim.to_decimal_string())),
                ("invites_issued", Json::Int(account.invites_issued as i128)),
                ("invites_remaining", Json::Int(
                    obs_chain::params::MAX_INVITES_PER_ACCOUNT.saturating_sub(account.invites_issued) as i128,
                )),
                ("genesis_claimed", Json::Bool(account.genesis_claimed)),
            ]))
        })
        .unwrap_or_else(|error| error)
    }
}

impl Handler for NodeApi {
    fn handle(&self, request: &Request, peer: &Peer) -> Response {
        self.route(request, peer)
    }
}

/// The bytes an account owner signs to prove ownership of an address.
///
/// Domain separated so a signature made for this endpoint can never be replayed
/// as a transaction or on another network.
pub fn account_proof_preimage(chain_id: u32, address: &obs_primitives::address::Address, nonce: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(64 + nonce.len());
    out.extend_from_slice(b"OBSIDIAN/API/ACCOUNT-PROOF/v1");
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&obs_primitives::codec::Encode::encoded(address));
    out.extend_from_slice(nonce.as_bytes());
    out
}

fn pool_error_code(error: &obs_mempool::MempoolError) -> (&'static str, String) {
    match error {
        obs_mempool::MempoolError::Invalid(state) => ("invalid_transaction", state.to_string()),
        obs_mempool::MempoolError::TooLarge { .. } => ("transaction_too_large", error.to_string()),
        obs_mempool::MempoolError::Duplicate(_) => ("duplicate_transaction", error.to_string()),
        obs_mempool::MempoolError::NonceGap { .. } => ("nonce_gap", error.to_string()),
        obs_mempool::MempoolError::NonceConflict { .. } => ("nonce_conflict", error.to_string()),
        obs_mempool::MempoolError::AccountFull { .. } => ("account_full", error.to_string()),
        obs_mempool::MempoolError::PoolFull { .. } => ("pool_full", error.to_string()),
    }
}

fn block_summary(node: &Node, block: &obs_chain::Block) -> Json {
    let finalized = node.head_state().is_finalized(block.header.height);
    Json::obj([
        ("height", Json::Int(block.header.height as i128)),
        ("hash", Json::Str(block.hash().to_hex())),
        ("timestamp", Json::Int(block.header.timestamp as i128)),
        ("transactions", Json::Int(block.transactions.len() as i128)),
        ("attestations", Json::Int(block.attestations.len() as i128)),
        ("weight_atoms", Json::Int(clamp_u128(block.header.weight_atoms))),
        ("difficulty_bp", Json::Int(block.header.difficulty_bp as i128)),
        ("proposer", Json::Str(mask_proposer(node, &block.header.proposer))),
        ("finalized", Json::Bool(finalized)),
    ])
}

/// The protocol masks addresses everywhere they are shown to a third party.
///
/// The prefix is the *chain's* own namespace, so a mainnet block can never be
/// mistaken for a testnet one even in a masked listing.
fn mask_proposer(node: &Node, key: &[u8; 32]) -> String {
    let address = obs_primitives::address::Address::from_public_key(node.config().network, key);
    mask(&address)
}

fn describe_event(event: &crate::NodeEvent) -> (String, String) {
    match event {
        crate::NodeEvent::Head {
            hash,
            height,
            reorg,
            transactions,
            ours,
        } => (
            "head".to_string(),
            format!(
                "height {} hash {} reorg {} transactions {} ours {}",
                height,
                hash.to_hex(),
                reorg,
                transactions,
                ours
            ),
        ),
        crate::NodeEvent::BlockRejected { hash, rule } => (
            "block_rejected".to_string(),
            format!("hash {} rule {}", hash.to_hex(), rule),
        ),
        crate::NodeEvent::TransactionAccepted { id } => {
            ("transaction_accepted".to_string(), format!("id {}", id.to_hex()))
        }
        crate::NodeEvent::TransactionRejected { id, reason } => (
            "transaction_rejected".to_string(),
            format!("id {} reason {}", id.to_hex(), reason),
        ),
        crate::NodeEvent::PeerConnected { node_key } => (
            "peer_connected".to_string(),
            obs_crypto::encoding::hex_encode(node_key),
        ),
        crate::NodeEvent::GenesisEpochGap {
            genesis_timestamp,
            clock,
        } => (
            "genesis_epoch_gap".to_string(),
            format!(
                "the chain's genesis epoch is {} but this node's clock is {}; it can sync but cannot found the chain",
                genesis_timestamp, clock
            ),
        ),
        crate::NodeEvent::GenesisLearned { authority, from } => (
            "genesis_learned".to_string(),
            format!(
                "registration authority {} learned from peer {}",
                Hash32(*authority).to_hex(),
                obs_crypto::encoding::hex_encode(from)
            ),
        ),
        crate::NodeEvent::GenesisMismatch {
            peer_authority,
            ours,
        } => (
            "genesis_mismatch".to_string(),
            format!(
                "peer reports registration authority {} but this chain uses {}",
                Hash32(*peer_authority).to_hex(),
                Hash32(*ours).to_hex()
            ),
        ),
        crate::NodeEvent::PeerRejected { reason } => (
            "connection_rejected".to_string(),
            reason.clone(),
        ),
        crate::NodeEvent::AttestationQueued { node_key, height } => (
            "attestation_queued".to_string(),
            format!("{} height {}", obs_crypto::encoding::hex_encode(node_key), height),
        ),
        crate::NodeEvent::PeerDisconnected { node_key, reason } => (
            "peer_disconnected".to_string(),
            format!("{} {}", obs_crypto::encoding::hex_encode(node_key), reason),
        ),
        crate::NodeEvent::Mined {
            hash,
            height,
            transactions,
            claimed,
        } => (
            "mined".to_string(),
            format!(
                "height {} hash {} transactions {} claimed {}",
                height,
                hash.to_hex(),
                transactions,
                claimed
            ),
        ),
        crate::NodeEvent::GenesisIssued { account, amount } => (
            "genesis_issued".to_string(),
            format!("account {} amount {}", mask(account), amount.to_decimal_string()),
        ),
    }
}

fn quorum_for(active: u64) -> u64 {
    let numerator = obs_chain::params::FINALITY_QUORUM_NUMERATOR;
    let denominator = obs_chain::params::FINALITY_QUORUM_DENOMINATOR;
    (active * numerator + denominator - 1) / denominator
}

fn parse_hash(text: &str) -> Option<Hash32> {
    let bytes = obs_crypto::encoding::hex_decode(text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut hash = [0u8; 32];
    hash.copy_from_slice(&bytes);
    Some(Hash32::from_bytes(hash))
}

fn clamp_u128(value: u128) -> i128 {
    value.min(i128::MAX as u128) as i128
}

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn json_obj<const N: usize>(pairs: [(&str, Json); N]) -> Json {
    Json::obj(pairs.map(|(key, value)| (key.to_string(), value)))
}

/// A hardened, uncacheable success response.
fn ok_json(value: Json) -> Response {
    Response::json(Status::OK, &value).no_store().hardened()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_preimages_are_domain_separated_and_bound_to_the_chain() {
        let address = obs_primitives::address::Address::from_parts(
            obs_primitives::network::MAINNET,
            1,
            [7u8; 20],
        );
        let mainnet = account_proof_preimage(1, &address, "nonce-a");
        let testnet = account_proof_preimage(2, &address, "nonce-a");
        let nonce_b = account_proof_preimage(1, &address, "nonce-b");
        assert_ne!(mainnet, testnet);
        assert_ne!(mainnet, nonce_b);
        assert!(mainnet.starts_with(b"OBSIDIAN/API/ACCOUNT-PROOF/v1"));
    }

    #[test]
    fn selectors_and_codes_behave() {
        let hash = Hash32::from_bytes([9u8; 32]);
        assert_eq!(parse_hash(&hash.to_hex()), Some(hash));
        assert_eq!(parse_hash("zz"), None);
        assert_eq!(parse_hash(&"aa".repeat(31)), None);
        assert_eq!(quorum_for(1), 1);
        assert_eq!(quorum_for(3), 2);
        assert_eq!(quorum_for(4), 3);
        assert_eq!(clamp_u128(u128::MAX), i128::MAX);
    }
}
