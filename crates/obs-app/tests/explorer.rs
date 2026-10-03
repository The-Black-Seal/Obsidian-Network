//! The application layer, end to end: a real node, a real indexer, a real
//! Explorer API and a real Developer Portal key.
//!
//! What this test is really checking is the *authority* and *privacy* claims:
//!
//! * the explorer's figures come from a node and follow it — mine a block and the
//!   index catches up, because the index reads the chain rather than inventing
//!   anything;
//! * no response body anywhere contains a balance, and every address in one is a
//!   partial address;
//! * an account's own state is available only through the node's proof endpoint,
//!   which the explorer does not call and cannot call for a visitor;
//! * an API key is a read credential: it is shown once, hashed at rest, scoped,
//!   rate-limited, rotatable and revocable, and it grants nothing custodial.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obs_app::api::App;
use obs_app::api::AppConfig;
use obs_app::indexer::Indexer;
use obs_app::portal::{Portal, RateLimit, Scope};
use obs_app::privacy::ROUTES;
use obs_crypto::ed25519::Keypair;
use obs_gateway::accounts::Registry;
use obs_gateway::store::AtomicStore;
use obs_node::rpc::NodeApi;
use obs_node::{Node, NodeConfig};
use obs_primitives::json::Json;
use obs_primitives::network::{Network, DEVNET};
use obs_rpc::client::{json_body, Client};
use obs_rpc::http::Response as ClientResponse;
use obs_rpc::http::Method;
use obs_rpc::server::{Server, ServerConfig};
use obs_wallet::Wallet;

const NETWORK: Network = DEVNET;
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unix_now() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs()
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "obs-app-{}-{}-{}",
        name,
        std::process::id(),
        unique
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// Everything the test drives, on real sockets.
struct Harness {
    api: Arc<NodeApi>,
    app_port: u16,
    registry: Arc<Mutex<Registry>>,
    wallet: Wallet,
    dir: PathBuf,
    shutdown: Arc<AtomicBool>,
}

impl Harness {
    fn launch(require_key: bool) -> Harness {
        let dir = temp_dir("explorer");
        let authority_seed = [17u8; 32];
        let authority_key = Keypair::from_seed(&authority_seed).public_key();

        // --- the node ------------------------------------------------------
        let wallet = Wallet::from_phrase(NETWORK, PHRASE, "", 0).unwrap();
        let mut config = NodeConfig::new(
            NETWORK,
            dir.join("node"),
            authority_key,
            Keypair::from_seed(&[19u8; 32]),
        );
        config.genesis.timestamp = unix_now() - 30;
        config.listen_port = free_port();
        config.fsync = false;
        config.block_interval = Duration::from_millis(1);
        let mut node = Node::open(config.with_mining(wallet.wallet_keypair().clone())).unwrap();

        // Found the chain.  On an empty network the protocol lets a block be
        // proposed by an account *it registers itself*, so the first block
        // carries the founder's registration — and, on an empty chain, the
        // founder's first claim, which is also the genesis claim.  Every later
        // block is an ordinary one.
        let keys = wallet.public_keys();
        let now = unix_now();
        let authorization = obs_chain::InviteAuthorization::issue(
            NETWORK.chain_id,
            &Keypair::from_seed(&authority_seed),
            obs_chain::invite_commitment(NETWORK.chain_id, "OBS-APP-FOUNDER-1"),
            obs_chain::gmail_commitment(
                NETWORK.chain_id,
                &obs_primitives::identity::canonical_gmail("founder@gmail.com").unwrap(),
            ),
            now,
            now + 3_600,
            None,
        );
        let registration = obs_chain::Transaction::sign(
            NETWORK,
            1,
            obs_chain::TxKind::Register {
                account: wallet.address(),
                wallet_key: keys.wallet_key,
                gmail_commitment: authorization.gmail_commitment,
                invite: authorization,
            },
            wallet.wallet_keypair(),
        );
        node.submit_transaction(registration)
            .expect("the founder's registration is accepted");
        {
            let target = node.head_state().last_timestamp + 60;
            node.set_clock_offset(target as i64 - unix_now() as i64);
            assert!(node.mine_once().is_some(), "the founding block applies");
        }
        let api = Arc::new(NodeApi::new(node));

        // The node's own API, over HTTP.
        let node_port = free_port();
        let node_shutdown = Arc::new(AtomicBool::new(false));
        Server::bind(("127.0.0.1", node_port), ServerConfig::default())
            .unwrap()
            .spawn(Arc::clone(&api) as Arc<dyn obs_rpc::server::Handler>, Arc::clone(&node_shutdown));

        // --- the registration service (for account sessions) ----------------
        let registry = Arc::new(Mutex::new(
            Registry::open(
                AtomicStore::open(dir.join("accounts.json"), false).unwrap(),
                NETWORK,
                [23u8; 32],
            )
            .unwrap(),
        ));

        // --- the application service ---------------------------------------
        let config = AppConfig {
            node_url: format!("http://127.0.0.1:{}", node_port),
            network: NETWORK,
            require_key,
            ..AppConfig::default()
        };
        let portal = Portal::open(AtomicStore::open(dir.join("portal.json"), false).unwrap()).unwrap();
        let app = App::new(config, Indexer::new(format!("http://127.0.0.1:{}", node_port), NETWORK), portal)
            .with_accounts(Arc::clone(&registry));
        let app_port = free_port();
        let shutdown = Arc::new(AtomicBool::new(false));
        Server::bind(("127.0.0.1", app_port), ServerConfig::default())
            .unwrap()
            .spawn(Arc::new(app), Arc::clone(&shutdown));

        Harness {
            api,
            app_port,
            registry,
            wallet,
            dir,
            shutdown,
        }
    }

    fn client(&self) -> Client {
        Client::with_timeout(Duration::from_secs(10))
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.app_port, path)
    }

    /// Mines one block (protocol time advances one drift step).
    fn mine(&self) {
        let handle = self.api.node();
        let mut node = handle.lock().unwrap();
        let target = node.head_state().last_timestamp + 60;
        node.set_clock_offset(target as i64 - unix_now() as i64);
        assert!(
            node.mine_once().is_some(),
            "a block must apply (head {}, clock {}): {:?}",
            node.head_state().last_timestamp,
            node.protocol_time(),
            node.recent_events(4)
        );
    }

    /// Creates an account in the registration service and returns a session
    /// token for it.  The enrolment is done through the library so this test
    /// stays about the application layer.
    fn session_token(&self, gmail: &str) -> String {
        use obs_crypto::totp::Secret;
        let invite = format!(
            "OBS-APP-{}-{}",
            &gmail[..4].to_ascii_uppercase(),
            COUNTER.fetch_add(1, Ordering::Relaxed)
        );
        let now = unix_now();
        let keys = self.wallet.public_keys();
        let mut registry = self.registry.lock().unwrap();
        registry
            .mint_network_invite(&invite, now, now + 3_600, false)
            .unwrap();
        let (token, _) = registry.begin(gmail, now).unwrap();
        registry.set_password(&token, "correct horse battery staple", now).unwrap();
        registry.redeem_invite(&token, &invite, now).unwrap();
        let step = registry.issue_recovery_code(&token, now).unwrap();
        let _recovery = step;
        let step = registry.enrol_mfa(&token, now).unwrap();
        let uri = match step {
            obs_gateway::accounts::Step::Show { value, .. } => value,
            other => panic!("expected the provisioning URI, got {:?}", other),
        };
        let secret = Secret::parse_base32(
            uri.split("secret=")
                .nth(1)
                .and_then(|rest| rest.split('&').next())
                .unwrap(),
        )
        .unwrap();
        let code = secret.code_at(now).to_string();
        registry.confirm_mfa(&token, &code, now).unwrap();
        registry
            .attach_wallet(&token, keys.wallet_key, keys.node_key, keys.recovery_key, now)
            .unwrap();
        // Sign in with a code from the same instant we present, so landing on a
        // thirty-second boundary cannot make this a flake.
        let at = unix_now();
        let mut session = None;
        for offset in [0u64, 30, 0] {
            let code = secret.code_at(at.saturating_add(offset)).to_string();
            if let Ok((token, _)) = registry.sign_in(gmail, "correct horse battery staple", &code, at) {
                session = Some(token);
                break;
            }
        }
        session.expect("the password and the authenticator together sign in")
    }

    fn get(&self, path: &str) -> Json {
        let response = self
            .client()
            .get(&self.url(path))
            .expect("the service answers");
        assert_eq!(response.status.code(), 200, "GET {} failed", path);
        json_body(&response).expect("the body is JSON")
    }

    fn get_raw(&self, path: &str) -> (u16, String) {
        let response = self
            .client()
            .get(&self.url(path))
            .expect("the service answers");
        (
            response.status.code(),
            String::from_utf8_lossy(&response.body).to_string(),
        )
    }

    fn with_key(&self, method: Method, path: &str, key: &str, body: Option<&Json>) -> (u16, String) {
        let client = self.client().with_header("X-API-Key", key);
        let response: ClientResponse = client
            .send(method, &self.url(path), body, None)
            .expect("the service answers");
        (
            response.status.code(),
            String::from_utf8_lossy(&response.body).to_string(),
        )
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn the_index_follows_the_chain_and_never_invents_anything() {
    let harness = Harness::launch(false);
    harness.mine();

    let status = harness.get("/v1/explorer/status");
    assert_eq!(status.get("chain_id").unwrap().as_i128(), Some(NETWORK.chain_id as i128));
    let node_height = status.get("node_height").unwrap().as_i128().unwrap() as u64;
    let indexed = status.get("indexed_height").unwrap().as_i128().unwrap() as u64;
    assert!(node_height >= 1, "the node has produced a block");
    assert_eq!(
        indexed, node_height,
        "the index caught up with the node it follows"
    );

    // The supply figures are the node's own, not the index's arithmetic.
    let supply = harness.get("/v1/explorer/supply");
    let node_supply = {
        let handle = harness.api.node();
        let node = handle.lock().unwrap();
        node.head_state().issued_supply.to_decimal_string()
    };
    assert_eq!(supply.get("issued_supply").unwrap().as_str(), Some(node_supply.as_str()));
    assert_eq!(supply.get("max_supply").unwrap().as_str(), Some("21000000"));
    assert_eq!(supply.get("genesis_issued").unwrap().as_bool(), Some(true));

    // The mining view explains the rate and where the halving stands.
    let mining = harness.get("/v1/explorer/mining");
    assert_eq!(mining.get("interval_secs").unwrap().as_i128(), Some(4 * 3_600));
    assert_eq!(mining.get("max_claims_per_day").unwrap().as_i128(), Some(6));

    // Blocks are listed newest first, with the proposer masked.
    let blocks = harness.get("/v1/explorer/blocks?limit=5");
    let listed = blocks.get("blocks").unwrap().as_array().unwrap();
    assert!(!listed.is_empty(), "at least one block is indexed");
    let first = &listed[0];
    assert_eq!(first.get("height").unwrap().as_i128(), Some(node_height as i128));
    let proposer = first.get("proposer").unwrap().as_str().unwrap();
    assert!(proposer.contains("..."), "the proposer is a partial address: {}", proposer);
    assert!(first.get("weight_atoms").unwrap().as_i128().unwrap() > 0);

    // And one block can be fetched by height.
    let single = harness.get(&format!("/v1/explorer/blocks/{}", node_height));
    assert_eq!(
        single
            .get("block")
            .unwrap()
            .get("hash")
            .unwrap()
            .as_str()
            .unwrap(),
        first.get("hash").unwrap().as_str().unwrap()
    );

    // Mining again moves both the node and the index.
    harness.mine();
    let after = harness.get("/v1/explorer/status");
    assert!(
        after.get("node_height").unwrap().as_i128().unwrap() > node_height as i128,
        "the chain moved"
    );
    assert_eq!(
        after.get("indexed_height").unwrap().as_i128().unwrap() as u64,
        after.get("node_height").unwrap().as_i128().unwrap() as u64,
    );
}

#[test]
fn no_response_publishes_a_balance_or_a_whole_address() {
    let harness = Harness::launch(false);
    harness.mine();
    let address = harness.wallet.address().to_string();

    let paths = [
        "/healthz".to_string(),
        "/v1/routes".to_string(),
        "/v1/explorer/status".to_string(),
        "/v1/explorer/blocks".to_string(),
        "/v1/explorer/blocks/1".to_string(),
        "/v1/explorer/validators".to_string(),
        "/v1/explorer/supply".to_string(),
        "/v1/explorer/mining".to_string(),
        format!("/v1/explorer/address/{}", address),
        format!("/v1/explorer/search?q={}", address),
        "/v1/portal/scopes".to_string(),
        "/v1/portal/openapi.json".to_string(),
    ];

    for path in &paths {
        let (code, body) = harness.get_raw(path);
        assert_eq!(code, 200, "GET {} should succeed, body: {}", path, body);
        for forbidden in ["\"balance", "\"spendable", "\"private_key", "\"seed\"", "\"secret\""] {
            assert!(
                !body.contains(forbidden),
                "{} published {}: {}",
                path,
                forbidden,
                body
            );
        }
        assert!(
            !body.contains(&address),
            "{} published a whole address: {}",
            path,
            body
        );
    }

    // The address view is activity only, and it names the address partially.
    let activity = harness.get(&format!("/v1/explorer/address/{}", address));
    assert!(activity.get("claims").is_some());
    assert!(activity.get("address").unwrap().as_str().unwrap().contains("..."));
    assert!(activity.get("balance").is_none());
    assert!(
        activity.get("blocks_proposed").unwrap().as_i128().unwrap() >= 1,
        "the founder proposed the block that registered it"
    );

    // The OpenAPI document describes every route in the table and no others.
    let openapi = harness.get("/v1/portal/openapi.json");
    let paths_doc = openapi.get("paths").unwrap();
    for route in ROUTES {
        let path = paths_doc
            .get(route.path)
            .unwrap_or_else(|| panic!("{} is missing from the OpenAPI document", route.path));
        assert!(
            path.get(&route.method.to_ascii_lowercase()).is_some(),
            "{} {} is missing from the OpenAPI document",
            route.method,
            route.path
        );
    }
    // A path that carries two methods is one entry with two operations.
    let keys = paths_doc.get("/v1/portal/keys").unwrap();
    assert!(keys.get("get").is_some() && keys.get("post").is_some());
}

#[test]
fn an_api_key_is_a_read_credential_that_can_be_scoped_rotated_and_revoked() {
    let harness = Harness::launch(false);
    harness.mine();
    let token = harness.session_token("developer@gmail.com");

    // Without a session nobody can manage keys.
    let (code, _) = harness.get_raw("/v1/portal/keys");
    assert_eq!(code, 403, "key management needs an account session");

    let client = harness.client();
    let body = Json::obj([
        ("label", Json::Str("ci".to_string())),
        ("scopes", Json::Array(vec![Json::Str("read:blocks".to_string())])),
        ("rate_limit", Json::Int(1_000)),
    ]);
    let created = client
        .send(Method::Post, &harness.url("/v1/portal/keys"), Some(&body), Some(&token))
        .map(|response| {
            assert_eq!(response.status.code(), 200);
            json_body(&response).unwrap()
        })
        .expect("the key is created");
    let key = created.get("key").unwrap().as_str().unwrap().to_string();
    let id = created.get("id").unwrap().as_str().unwrap().to_string();
    assert_eq!(key.split('.').count(), 2, "id.secret: {}", key);

    // It works on the scope it holds, and is refused on the one it does not.
    let (code, _) = harness.with_key(Method::Get, "/v1/explorer/blocks", &key, None);
    assert_eq!(code, 200, "the key reads blocks");
    let (code, _) = harness.with_key(Method::Post, "/v1/portal/keys", &key, Some(&body));
    assert_eq!(code, 403, "a read key cannot mint keys, and needs a session anyway");

    // A wrong secret under a real id is refused.
    let (code, _) = harness.with_key(
        Method::Get,
        "/v1/explorer/blocks",
        &format!("{}.NOTTHESECRET", id),
        None,
    );
    assert_eq!(code, 403);

    // Rotation invalidates the old secret at once.
    let rotated = client
        .send(
            Method::Post,
            &harness.url(&format!("/v1/portal/keys/{}/rotate", id)),
            Some(&Json::obj(Vec::<(String, Json)>::new())),
            Some(&token),
        )
        .map(|response| {
            assert_eq!(response.status.code(), 200);
            json_body(&response).unwrap()
        })
        .expect("the key rotates");
    let new_key = rotated.get("key").unwrap().as_str().unwrap().to_string();
    assert_ne!(new_key, key);
    assert_eq!(harness.with_key(Method::Get, "/v1/explorer/blocks", &key, None).0, 403);
    assert_eq!(harness.with_key(Method::Get, "/v1/explorer/blocks", &new_key, None).0, 200);

    // Revocation is immediate.
    let revoked = client
        .send(
            Method::Delete,
            &harness.url(&format!("/v1/portal/keys/{}", id)),
            None,
            Some(&token),
        )
        .map(|response| response.status.code())
        .expect("the key is revoked");
    assert_eq!(revoked, 200);
    assert_eq!(harness.with_key(Method::Get, "/v1/explorer/blocks", &new_key, None).0, 403);

    // The usage view counts what happened and never shows key material.
    let usage = client
        .send(Method::Get, &harness.url("/v1/portal/usage"), None, Some(&token))
        .map(|response| json_body(&response).unwrap())
        .expect("usage is readable");
    let rendered = usage.to_canonical_string();
    assert!(!rendered.contains(&new_key));
    assert!(!rendered.contains("secret_hash"));
    let events = usage.get("events").unwrap().as_array().unwrap();
    let kinds: Vec<&str> = events.iter().filter_map(|event| event.get("kind").and_then(Json::as_str)).collect();
    assert!(kinds.contains(&"created"));
    assert!(kinds.contains(&"rotated"));
    assert!(kinds.contains(&"revoked"));

    // The portal's own store holds only the hash of the current secret.
    let store = std::fs::read_to_string(harness.dir.join("portal.json")).unwrap();
    assert!(!store.contains(&new_key));
    assert!(store.contains("secret_hash"));
}

#[test]
fn a_deployment_that_requires_keys_refuses_anonymous_readers() {
    let harness = Harness::launch(true);
    harness.mine();
    let (code, _) = harness.get_raw("/v1/explorer/blocks");
    assert_eq!(code, 403, "this deployment requires a key");

    let token = harness.session_token("keyed@gmail.com");
    let client = harness.client();
    let created = client
        .send(
            Method::Post,
            &harness.url("/v1/portal/keys"),
            Some(&Json::obj([("label", Json::Str("app".to_string()))])),
            Some(&token),
        )
        .map(|response| json_body(&response).unwrap())
        .expect("a key is created");
    let key = created.get("key").unwrap().as_str().unwrap().to_string();
    // A key created without an explicit scope list gets the three read scopes.
    let scopes = created.get("scopes").unwrap().as_array().unwrap();
    assert_eq!(scopes.len(), 3);
    let (code, _) = harness.with_key(Method::Get, "/v1/explorer/blocks", &key, None);
    assert_eq!(code, 200);

    // Health, scopes and the OpenAPI document stay public: a developer must be
    // able to discover the API before they have a key.
    assert_eq!(harness.get_raw("/healthz").0, 200);
    assert_eq!(harness.get_raw("/v1/portal/scopes").0, 200);
    assert_eq!(harness.get_raw("/v1/portal/openapi.json").0, 200);
}

#[test]
fn search_finds_blocks_and_addresses_and_refuses_nonsense() {
    let harness = Harness::launch(false);
    harness.mine();
    let address = harness.wallet.address().to_string();

    let by_height = harness.get("/v1/explorer/search?q=1");
    assert_eq!(by_height.get("kind").unwrap().as_str(), Some("block"));

    let by_address = harness.get(&format!("/v1/explorer/search?q={}", address));
    assert!(by_address.get("address").is_some());
    assert!(by_address.get("claims").is_some());

    let block_hash = harness
        .get("/v1/explorer/blocks/1")
        .get("block")
        .unwrap()
        .get("hash")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();
    let by_hash = harness.get(&format!("/v1/explorer/search?q={}", block_hash));
    assert_eq!(by_hash.get("kind").unwrap().as_str(), Some("block"));

    let (code, _) = harness.get_raw("/v1/explorer/search?q=");
    assert_eq!(code, 400);
    let (code, _) = harness.get_raw("/v1/explorer/search");
    assert_eq!(code, 400);
    let (code, _) = harness.get_raw(&format!("/v1/explorer/search?q={}", "z".repeat(200)));
    assert_eq!(code, 400);
    // A hash-shaped query that is not in the index is a 404, not an invention.
    let (code, _) = harness.get_raw(&format!("/v1/explorer/search?q={}", "ab".repeat(32)));
    assert_eq!(code, 404);
}

#[test]
fn scope_and_rate_limit_types_agree_with_the_route_table() {
    // Every scope named in the route table must exist, and every scope an API
    // key can hold must be one of them.
    let declared: Vec<&str> = ROUTES.iter().filter_map(|route| route.scope).collect();
    for scope in &declared {
        assert!(
            Scope::parse(scope).is_some(),
            "the route table names an unknown scope: {}",
            scope
        );
    }
    for scope in Scope::ALL {
        assert!(!scope.describe().is_empty());
        assert_eq!(Scope::parse(scope.name()), Some(scope));
    }
    assert_eq!(Scope::ALL.len(), 6);
    assert_eq!(RateLimit::DEFAULT.per_second(), 10);
}
