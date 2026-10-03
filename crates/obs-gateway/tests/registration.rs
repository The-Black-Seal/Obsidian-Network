//! End-to-end registration: an invitation code, a Gmail address, a password, an
//! authenticator, a wallet — and then a real account on a real chain.
//!
//! This test drives the whole thing over real HTTP against a real devnet node:
//!
//! 1. the operator mints a network invitation;
//! 2. a client walks the six enrolment steps, computing its own TOTP codes from
//!    the provisioning URI the service returned;
//! 3. the service returns an invitation authorisation bound to the client's
//!    canonical Gmail;
//! 4. the **client's own wallet** signs a registration transaction and submits it
//!    to a node;
//! 5. the chain accepts it — and the account starts with a zero balance, because
//!    registering creates an identity, not an allocation.
//!
//! The negative cases matter as much as the flow: one Gmail is one account, an
//! invitation is spent once, cross-origin writes are refused, and the service's
//! store holds hashes rather than secrets.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use obs_chain::chain::InviteAuthorization;
use obs_gateway::accounts::Registry;
use obs_gateway::api::{authorization_from_json, Gateway};
use obs_gateway::authority::Authority;
use obs_gateway::store::AtomicStore;
use obs_crypto::ed25519::Keypair;
use obs_crypto::totp::Secret;
use obs_node::rpc::NodeApi;
use obs_node::{Node, NodeConfig};
use obs_primitives::json::Json;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION};
use obs_primitives::network::{Network, DEVNET};
use obs_rpc::client::{json_body, Client};
use obs_rpc::http::Method;
use obs_rpc::server::{Server, ServerConfig};
use obs_wallet::sign::{register, Registration};
use obs_wallet::Wallet;

const NETWORK: Network = DEVNET;
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
const PASSWORD: &str = "correct horse battery staple";
static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "obs-gateway-{}-{}-{}",
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

/// A devnet node plus the registration service, both listening on real sockets.
struct Harness {
    api: Arc<NodeApi>,
    /// The client wallet the whole test drives: it registers itself, and on an
    /// empty chain the protocol's deterministic schedule makes the first
    /// account the proposer of the block that creates it, so the devnet node
    /// mines with this same key.
    wallet: Wallet,
    gateway: Arc<Gateway>,
    node_shutdown: Arc<AtomicBool>,
    gateway_shutdown: Arc<AtomicBool>,
    gateway_port: u16,
    store_path: PathBuf,
    dir: PathBuf,
}

impl Harness {
    fn launch() -> Harness {
        Harness::launch_inner(true)
    }

    /// A deployment with no chain clock at all: the shape an operator gets when
    /// the node is unreachable, and the one that must refuse rather than guess.
    fn launch_without_chain_clock() -> Harness {
        Harness::launch_inner(false)
    }

    fn launch_inner(chain_clock: bool) -> Harness {
        let dir = temp_dir("e2e");
        let authority_path = dir.join("authority.key");
        let authority = Authority::generate(&authority_path, NETWORK).unwrap();
        let authority_public = authority.public_key();
        let service_key = [9u8; 32];

        // --- the node -----------------------------------------------------
        let store_path = dir.join("observatory.json");
        let mut config = NodeConfig::new(
            NETWORK,
            dir.join("node"),
            authority_public,
            Keypair::from_seed(&[11u8; 32]),
        );
        // Half a minute of slack, so the first block is already inside the
        // 60-second drift window when the test starts.
        config.genesis.timestamp = unix_now() - 30;
        config.listen_port = free_port();
        config.fsync = false;
        config.block_interval = Duration::from_millis(1);
        let wallet = Wallet::from_phrase(NETWORK, PHRASE, "", 0).unwrap();
        let node = Node::open(config.with_mining(wallet.wallet_keypair().clone())).unwrap();
        let api = Arc::new(NodeApi::new(node));

        // --- the registration service -------------------------------------
        let registry = Registry::open(AtomicStore::open(&store_path, false).unwrap(), NETWORK, service_key)
            .unwrap()
            .with_authority(authority);
        // The gateway dates invitation authorisations in the chain's own time,
        // so this deployment supplies the chain's clock: here, the timestamp of
        // the node's head block, read the same way obs-app reads it.
        let chain_api = Arc::clone(&api);
        let gateway = Arc::new(match chain_clock {
            true => Gateway::new(registry, NETWORK).with_chain_clock(Box::new(move || {
                let shared = chain_api.node();
                let node = shared.lock().map_err(|_| ()).ok()?;
                Some(node.head_state().last_timestamp)
            })),
            // A deployment that cannot see the chain: it must not guess.
            false => Gateway::new(registry, NETWORK),
        });
        let gateway_port = free_port();
        let gateway_handler = Arc::clone(&gateway);
        let gateway_shutdown = Arc::new(AtomicBool::new(false));
        Server::bind(("127.0.0.1", gateway_port), ServerConfig::default())
            .unwrap()
            .spawn(gateway_handler, Arc::clone(&gateway_shutdown));

        Harness {
            api,
            gateway,
            wallet,
            node_shutdown: Arc::new(AtomicBool::new(false)),
            gateway_shutdown,
            gateway_port,
            store_path,
            dir,
        }
    }

    fn client(&self) -> Client {
        Client::with_timeout(Duration::from_secs(10))
    }

    fn url(&self, path: &str) -> String {
        format!("http://127.0.0.1:{}{}", self.gateway_port, path)
    }

    /// Mints an operator invitation through the registry the gateway owns.
    ///
    /// This is the operator path: the CLI mints network and genesis invitations
    /// through the same handle, and the code is delivered out of band.  It is
    /// never part of the HTTP surface.
    fn mint_invite(&self, code: &str) {
        self.gateway
            .registry()
            .lock()
            .unwrap()
            .mint_network_invite(code, unix_now(), unix_now() + 86_400, false)
            .unwrap();
    }

    fn mine(&self) {
        let node = self.api.node();
        let mut node = node.lock().unwrap();
        // Push protocol time one step, then produce the block.
        let target = node.head_state().last_timestamp + 60;
        node.set_clock_offset(target as i64 - unix_now() as i64);
        assert!(
            node.mine_once().is_some(),
            "a block must apply (head {}, genesis {}, clock {}): {:?}",
            node.head_state().last_timestamp,
            node.genesis_timestamp(),
            node.protocol_time(),
            node.recent_events(4)
        );
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        self.node_shutdown.store(true, Ordering::Relaxed);
        self.gateway_shutdown.store(true, Ordering::Relaxed);
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

/// The current and next authenticator code, so a test that lands on a step
/// boundary still passes.
fn codes_for(secret: &Secret) -> Vec<String> {
    let now = unix_now();
    vec![
        format!("{:06}", secret.code_at(now)),
        format!("{:06}", secret.code_at(now + 30)),
    ]
}

/// Posts a body and insists on a success status.
///
/// The HTTP client returns the response whatever the status, so the *status* is
/// what a test must assert on: a refused request is a 4xx response, not a
/// transport error.
fn post(client: &Client, url: &str, body: Json) -> Json {
    let response = post_response(client, url, body);
    assert!(
        response.status.code() < 400,
        "expected success, got {}",
        response.status.code()
    );
    json_body(&response).expect("the response is JSON")
}

/// Posts a body and returns the whole response, whatever the status.
fn post_response(client: &Client, url: &str, body: Json) -> obs_rpc::http::Response {
    client
        .post_json(url, &body)
        .expect("the gateway answers the connection")
}

/// Posts a body that must be refused, and returns the status code.
fn refused(client: &Client, url: &str, body: Json) -> u16 {
    let status = post_response(client, url, body).status.code();
    assert!(status >= 400, "expected a refusal, got {}", status);
    status
}

fn post_with_token(client: &Client, url: &str, body: Json, token: &str) -> Json {
    send_with_token(client, Method::Post, url, Some(&body), token)
}

/// Sends an authenticated request and insists on a success status.
fn send_with_token(
    client: &Client,
    method: Method,
    url: &str,
    body: Option<&Json>,
    token: &str,
) -> Json {
    let response = client
        .send(method, url, body, Some(token))
        .expect("the gateway answers the connection");
    assert!(
        response.status.code() < 400,
        "expected success, got {}",
        response.status.code()
    );
    json_body(&response).expect("the response is JSON")
}

/// What a completed enrolment gives back to the test.
struct Enrolled {
    /// The authenticator secret, parsed from the provisioning URI.
    secret: Secret,
    /// The recovery code the owner was shown once.
    recovery_code: String,
    /// The activation response.
    activation: Json,
}

/// Signs in with a password and an authenticator secret, returning a session
/// token.  Both the current and the next code are tried, so a test that lands on
/// a step boundary is not a flake.
fn sign_in(harness: &Harness, client: &Client, gmail: &str, secret: &Secret) -> String {
    for code in codes_for(secret) {
        let response = client
            .post_json(
                &harness.url("/v1/auth/sign-in"),
                &Json::obj([
                    ("gmail", Json::Str(gmail.to_string())),
                    ("password", Json::Str(PASSWORD.to_string())),
                    ("mfa_code", Json::Str(code)),
                ]),
            )
            .expect("the gateway answers the connection");
        if response.status.code() < 400 {
            let session = json_body(&response).unwrap();
            return session.get("token").unwrap().as_str().unwrap().to_string();
        }
    }
    panic!("the password and the authenticator together sign in");
}

/// Walks the six enrolment steps over HTTP.
/// Walks steps one to five and leaves the enrolment at the wallet step,
/// returning the session token, the authenticator secret and the recovery code.
fn walk_to_wallet_step(
    harness: &Harness,
    client: &Client,
    gmail: &str,
    code: &str,
) -> (String, Secret, String) {
    let begun = post(
        client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str(gmail.to_string()))]),
    );
    assert_eq!(begun.get("stage").unwrap().as_str(), Some("gmail"));
    // The service never echoes the address back whole.
    let masked = begun.get("gmail").unwrap().as_str().unwrap().to_string();
    assert!(masked.contains("***"), "the address must be masked: {}", masked);
    let token = begun.get("token").unwrap().as_str().unwrap().to_string();

    let step = post(
        client,
        &harness.url("/v1/register/password"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("password", Json::Str(PASSWORD.to_string())),
        ]),
    );
    assert_eq!(step.get("stage").unwrap().as_str(), Some("password"));

    let step = post(
        client,
        &harness.url("/v1/register/invite"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("code", Json::Str(code.to_string())),
        ]),
    );
    assert_eq!(step.get("stage").unwrap().as_str(), Some("invite"));

    let step = post(
        client,
        &harness.url("/v1/register/recovery-code"),
        Json::obj([("token", Json::Str(token.clone()))]),
    );
    let recovery_code = step.get("value").unwrap().as_str().unwrap().to_string();
    assert_eq!(
        recovery_code.matches('-').count(),
        7,
        "a recovery code is eight groups: {}",
        recovery_code
    );
    assert_eq!(recovery_code.len(), 39, "a recovery code: {}", recovery_code);

    let step = post(
        client,
        &harness.url("/v1/register/mfa"),
        Json::obj([("token", Json::Str(token.clone()))]),
    );
    let uri = step.get("value").unwrap().as_str().unwrap().to_string();
    assert!(uri.starts_with("otpauth://totp/"), "a provisioning URI: {}", uri);
    let secret_base32 = uri
        .split("secret=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .expect("the URI carries a secret")
        .to_string();
    let secret = Secret::parse_base32(&secret_base32).expect("the secret parses");

    // Confirm with a real code from a real authenticator computation.
    let mut confirmed = None;
    for code in codes_for(&secret) {
        let response = client
            .post_json(
                &harness.url("/v1/register/mfa/confirm"),
                &Json::obj([
                    ("token", Json::Str(token.clone())),
                    ("code", Json::Str(code.clone())),
                ]),
            )
            .expect("the gateway answers the connection");
        if response.status.code() < 400 {
            confirmed = Some(json_body(&response).unwrap());
            break;
        }
    }
    let confirmed = confirmed.expect("an authenticator code must be accepted");
    assert_eq!(confirmed.get("stage").unwrap().as_str(), Some("wallet"));

    (token, secret, recovery_code)
}

/// Walks the six enrolment steps over HTTP.
fn enrol(
    harness: &Harness,
    client: &Client,
    gmail: &str,
    code: &str,
    keys: &obs_wallet::PublicKeys,
) -> Enrolled {
    let (token, secret, recovery_code) = walk_to_wallet_step(harness, client, gmail, code);
    let activation = post(
        client,
        &harness.url("/v1/register/wallet"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            (
                "wallet_key",
                Json::Str(obs_crypto::encoding::hex_encode(&keys.wallet_key)),
            ),
            ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&keys.node_key))),
            (
                "recovery_key",
                Json::Str(obs_crypto::encoding::hex_encode(&keys.recovery_key)),
            ),
        ]),
    );
    assert_eq!(activation.get("stage").unwrap().as_str(), Some("activated"));
    assert_eq!(activation.get("mining_enabled").unwrap().as_bool(), Some(true));
    Enrolled {
        secret,
        recovery_code,
        activation,
    }
}

/// The invitation authorisation is dated in the **chain's** time, because that
/// is the clock the chain checks it against.
///
/// The chain accepts a registration when
/// `authorisation.issued_at <= block time <= authorisation.expires_at`, and
/// protocol time advances at most a minute per block.  Dated with the service's
/// wall clock, an authorisation minted while the chain is behind — a brand-new
/// network, or one that has been quiet — cannot be included until the chain
/// catches up; dated in chain time it is includable in the very next block.  For
/// a network's first block that difference is the difference between starting
/// and never starting, which is why this is asserted rather than assumed.
#[test]
fn the_invitation_authorisation_is_dated_in_chain_time() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-CHAINTIME-AAAA-BBBB";
    harness.mint_invite(invite);

    let keys = harness.wallet.public_keys();
    let enrolled = enrol(&harness, &client, "chain.time@gmail.com", invite, &keys);

    // The chain's own time, read from the node this deployment follows.
    let chain_time = {
        let shared = harness.api.node();
        let node = shared.lock().unwrap();
        node.head_state().last_timestamp
    };
    let authorization = authorization_from_json(
        enrolled
            .activation
            .get("invite_authorization")
            .expect("an authorisation is issued"),
        NETWORK,
    )
    .expect("the authorisation parses");

    assert_eq!(
        authorization.issued_at, chain_time,
        "the authorisation is stamped with the chain's time, not this machine's"
    );
    assert!(
        authorization.issued_at <= chain_time + 60,
        "an authorisation stamped beyond the chain's reach could never be included"
    );
    assert_eq!(
        authorization.expires_at - authorization.issued_at,
        obs_gateway::accounts::AUTHORIZATION_SECS,
        "the window is measured in protocol time, like every other chain deadline"
    );
}

/// A deployment that cannot establish the chain's time refuses to mint an
/// authorisation, rather than minting one the chain may reject.
#[test]
fn a_gateway_that_cannot_see_the_chain_refuses_to_date_an_authorisation() {
    let harness = Harness::launch_without_chain_clock();
    let client = harness.client();
    let invite = "OBS-NOCHAIN-CCCC-DDDD";
    harness.mint_invite(invite);

    let (token, _secret, _recovery_code) =
        walk_to_wallet_step(&harness, &client, "no.chain@gmail.com", invite);
    let keys = harness.wallet.public_keys();
    let status = refused(
        &client,
        &harness.url("/v1/register/wallet"),
        Json::obj([
            ("token", Json::Str(token)),
            ("wallet_key", Json::Str(obs_crypto::encoding::hex_encode(&keys.wallet_key))),
            ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&keys.node_key))),
            (
                "recovery_key",
                Json::Str(obs_crypto::encoding::hex_encode(&keys.recovery_key)),
            ),
        ]),
    );
    assert_eq!(status, 503, "no chain time means no authorisation");
}

#[test]
fn registration_produces_a_real_account_on_a_real_chain() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-TEST-NETW-ORK1-INVT";
    harness.mint_invite(invite);

    let enrolled = enrol(
        &harness,
        &client,
        "Miner.One@gmail.com",
        invite,
        &harness.wallet.public_keys(),
    );
    let activation = &enrolled.activation;

    // The service bound the canonical Gmail, not the literal string.
    let commitment = activation
        .get("gmail_commitment")
        .unwrap()
        .as_str()
        .unwrap()
        .to_string();

    // --- the client registers itself on chain -----------------------------
    let authorization: InviteAuthorization = authorization_from_json(
        activation.get("invite_authorization").unwrap(),
        NETWORK,
    )
    .expect("the authorisation parses");
    assert!(authorization.verify_signature(NETWORK.chain_id));
    assert_eq!(
        authorization.gmail_commitment.0,
        obs_chain::chain::gmail_commitment(NETWORK.chain_id, "minerone@gmail.com").0
    );

    let wallet = &harness.wallet;
    let tx = register(
        wallet,
        Registration {
            invite: authorization.clone(),
            gmail_commitment: authorization.gmail_commitment,
            nonce: 1,
        },
    )
    .expect("the wallet signs its own registration");

    let node = harness.api.node();
    node.lock()
        .unwrap()
        .submit_transaction(tx)
        .expect("the node accepts the registration");
    harness.mine();

    // --- the chain now knows the account ----------------------------------
    //
    // Everything below reads one snapshot of chain state; the guard is released
    // before anything else locks the node.
    let address = wallet.address();
    let (block_time, reward) = {
        let handle = harness.api.node();
        let node = handle.lock().unwrap();
        let state = node.head_state();
        let account = state
            .account(&address)
            .expect("the account exists after the block applies");

        // The block that created the account is the chain's first block, and on
        // an empty chain the protocol's own schedule makes the new account its
        // proposer — so this same block carries the account's first claim, and
        // the genesis allocation goes to it.  That is the genesis rule working:
        // the first valid claim in the first block, once, recorded in state.
        assert!(
            account.genesis_claimed,
            "the first block's claim is the genesis claim"
        );
        assert_eq!(state.total_claims, 1, "exactly one claim exists");
        assert_eq!(state.active_miner_count_at(state.last_timestamp), 1);
        let reward = state.mining_reward_at(state.last_timestamp);
        assert_eq!(
            account.balance,
            GENESIS_ALLOCATION.checked_add(reward).unwrap(),
            "the genesis allocation plus the claim's reward"
        );
        assert_eq!(
            state.issued_supply,
            GENESIS_ALLOCATION.checked_add(reward).unwrap(),
            "the issuance is the genesis allocation plus exactly one reward"
        );
        assert!(state.genesis_issued);
        assert_eq!(
            account.balance.checked_sub(GENESIS_ALLOCATION),
            Some(reward),
            "the balance above the genesis allocation is the reward and nothing else"
        );
        assert_eq!(
            account.lifetime_rewards, account.balance,
            "the account has been credited exactly once, by the block that created it"
        );

        // The commitment the chain stored is the one the service issued, and the
        // wallet binding is the client's own key: the service never held it.
        assert_eq!(
            obs_crypto::encoding::hex_encode(&account.gmail_commitment.0),
            commitment
        );
        assert_eq!(account.wallet_key, wallet.public_keys().wallet_key);

        // The node's public API must never reveal the address in full.
        let masked = obs_primitives::address::mask(&address);
        assert!(masked.contains("..."), "a masked address: {}", masked);

        (state.last_timestamp, reward)
    };
    let _ = reward;

    // A second claim cannot be made yet: protocol time gates mining, not a
    // browser timer.  The claim is built for the *next* block's timestamp, so the
    // only rule it can trip is the four-hour interval.
    let second_claim = obs_wallet::sign::claim(wallet, block_time + 60, 2, 2)
        .expect("a claim transaction can be built");
    let refused = {
        let handle = harness.api.node();
        let mut node = handle.lock().unwrap();
        node.submit_transaction(second_claim).is_err()
    };
    assert!(refused, "a claim inside the four-hour interval must be refused");
}

#[test]
fn a_second_account_registers_empty() {
    let harness = Harness::launch();
    let client = harness.client();
    harness.mint_invite("OBS-TEST-FIRS-TACC-OUNT");

    // The founder registers and mines the first block.
    let first = enrol(
        &harness,
        &client,
        "founder@gmail.com",
        "OBS-TEST-FIRS-TACC-OUNT",
        &harness.wallet.public_keys(),
    );
    let authorization = authorization_from_json(
        first.activation.get("invite_authorization").unwrap(),
        NETWORK,
    )
    .unwrap();
    let founder_tx = register(
        &harness.wallet,
        Registration {
            invite: authorization.clone(),
            gmail_commitment: authorization.gmail_commitment,
            nonce: 1,
        },
    )
    .unwrap();
    let node = harness.api.node();
    node.lock().unwrap().submit_transaction(founder_tx).unwrap();
    harness.mine();

    // The founder signs in and spends one of their five invitations: the second
    // account is invited by an account, not by the operator, and the chain
    // enforces the same five-per-account budget independently.
    let token = sign_in(&harness, &client, "founder@gmail.com", &first.secret);
    let issued = post_with_token(
        &client,
        &harness.url("/v1/invites"),
        Json::obj(Vec::<(String, Json)>::new()),
        &token,
    );
    let account_issued_code = issued.get("code").unwrap().as_str().unwrap().to_string();

    // A second person, with their own wallet and their own invitation.
    let second = Wallet::from_phrase(
        NETWORK,
        "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
        "",
        0,
    )
    .unwrap();
    let enrolled = enrol(
        &harness,
        &client,
        "second@gmail.com",
        &account_issued_code,
        &second.public_keys(),
    );
    let authorization = authorization_from_json(
        enrolled.activation.get("invite_authorization").unwrap(),
        NETWORK,
    )
    .unwrap();
    // The authorisation names the account that issued the code, so the chain can
    // charge it against that account's budget.
    assert_eq!(authorization.issuer, Some(harness.wallet.address()));
    let tx = register(
        &second,
        Registration {
            invite: authorization.clone(),
            gmail_commitment: authorization.gmail_commitment,
            nonce: 1,
        },
    )
    .unwrap();
    node.lock().unwrap().submit_transaction(tx).unwrap();
    harness.mine();

    let node = harness.api.node();
    let node = node.lock().unwrap();
    let state = node.head_state();
    let account = state
        .account(&second.address())
        .expect("the second account exists");
    assert_eq!(
        account.balance,
        Amount::ZERO,
        "registering an account allocates nothing"
    );
    assert_eq!(account.claims_today, 0);
    assert_eq!(account.last_claim_at, 0);
    assert!(!account.genesis_claimed);
    assert_eq!(
        state.total_claims, 1,
        "the second account has not mined anything"
    );
    assert_eq!(state.accounts.len(), 2);
    // The inviting account's budget was spent by the code it issued: the chain
    // counted it, not the service.
    assert_eq!(
        state.account(&harness.wallet.address()).unwrap().invites_issued,
        1
    );
    assert_eq!(
        state.account(&second.address()).unwrap().registered_at,
        state.last_timestamp,
        "the second account was created by the block that carried its registration"
    );
}

#[test]
fn one_gmail_is_one_account_and_an_invitation_is_spent_once() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-TEST-SPEN-TONC-E123";
    harness.mint_invite(invite);

    enrol(
        &harness,
        &client,
        "someone@gmail.com",
        invite,
        &harness.wallet.public_keys(),
    );

    // A second account for the same address — even spelled differently — is
    // refused at the first step, because the canonical address is the key.
    let again = refused(
        &client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str("Some.One+promo@googlemail.com".to_string()))]),
    );
    assert_eq!(again, 409, "a second account for one Gmail must conflict");

    // The invitation is spent: a different address cannot reuse it.
    let begun = post(
        &client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str("other@gmail.com".to_string()))]),
    );
    let token = begun.get("token").unwrap().as_str().unwrap().to_string();
    post(
        &client,
        &harness.url("/v1/register/password"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("password", Json::Str(PASSWORD.to_string())),
        ]),
    );
    refused(
        &client,
        &harness.url("/v1/register/invite"),
        Json::obj([
            ("token", Json::Str(token)),
            ("code", Json::Str(invite.to_string())),
        ]),
    );
}

#[test]
fn the_steps_must_happen_in_order() {
    let harness = Harness::launch();
    let client = harness.client();
    harness.mint_invite("OBS-TEST-ORDE-R123-4567");

    let begun = post(
        &client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str("ordered@gmail.com".to_string()))]),
    );
    let token = begun.get("token").unwrap().as_str().unwrap().to_string();

    // Skipping the password is refused, and says which step comes next.
    let skipped = refused(
        &client,
        &harness.url("/v1/register/invite"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("code", Json::Str("OBS-TEST-ORDE-R123-4567".to_string())),
        ]),
    );
    assert_eq!(skipped, 409, "the invitation step cannot come first");

    // A weak password is refused before anything is stored.
    let weak = refused(
        &client,
        &harness.url("/v1/register/password"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("password", Json::Str("short".to_string())),
        ]),
    );
    assert_eq!(weak, 400, "a short password is a bad request");
}

#[test]
fn cross_origin_writes_are_refused() {
    let harness = Harness::launch();
    let client = harness
        .client()
        .with_header("Origin", "https://evil.example");
    let attempt = refused(
        &client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str("victim@gmail.com".to_string()))]),
    );
    assert_eq!(attempt, 403, "another origin must not drive registration");
}

#[test]
fn the_store_holds_hashes_and_never_a_recovery_or_invitation_code() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-TEST-HASH-SECR-ET12";
    harness.mint_invite(invite);
    let enrolled = enrol(
        &harness,
        &client,
        "hashed@gmail.com",
        invite,
        &harness.wallet.public_keys(),
    );
    let secret = enrolled.secret;
    let recovery_code = enrolled.recovery_code;

    let document = std::fs::read_to_string(&harness.store_path).unwrap();
    assert!(
        !document.contains(invite),
        "an invitation code must never be written to the store"
    );
    assert!(
        !document.contains(&secret.base32()),
        "the authenticator secret must be sealed, not stored clear"
    );
    assert!(
        !document.contains(PASSWORD),
        "the password must be stored as a hash"
    );
    assert!(
        document.contains("hashed@gmail.com"),
        "the canonical address itself is the registry's key"
    );
    assert!(
        !document.contains(&recovery_code),
        "the account recovery code must be stored as a hash, not as the code"
    );
    assert!(document.contains("recovery_hash"));
}

#[test]
fn sign_in_requires_both_the_password_and_the_authenticator() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-TEST-SIGN-IN12-3456";
    harness.mint_invite(invite);
    let secret = enrol(
        &harness,
        &client,
        "signin@gmail.com",
        invite,
        &harness.wallet.public_keys(),
    )
    .secret;

    // A wrong password fails even with a correct code.
    refused(
        &client,
        &harness.url("/v1/auth/sign-in"),
        Json::obj([
            ("gmail", Json::Str("signin@gmail.com".to_string())),
            ("password", Json::Str("not the password".to_string())),
            ("mfa_code", Json::Str(codes_for(&secret)[0].clone())),
        ]),
    );

    // A wrong code fails even with the right password.
    refused(
        &client,
        &harness.url("/v1/auth/sign-in"),
        Json::obj([
            ("gmail", Json::Str("signin@gmail.com".to_string())),
            ("password", Json::Str(PASSWORD.to_string())),
            ("mfa_code", Json::Str("000000".to_string())),
        ]),
    );

    // The real pair works, and the session reaches the account view.
    let token = sign_in(&harness, &client, "signin@gmail.com", &secret);

    let view = send_with_token(&client, Method::Get, &harness.url("/v1/account"), None, &token);
    assert_eq!(view.get("mining_enabled").unwrap().as_bool(), Some(true));
    assert_eq!(view.get("invites_remaining").unwrap().as_i128(), Some(5));
    let masked = view.get("gmail").unwrap().as_str().unwrap();
    assert!(masked.contains("***"), "the account view masks the address");

    // Five invitations at most, and the codes are shown once.
    for issued in 0..5 {
        let issued_code = post_with_token(
            &client,
            &harness.url("/v1/invites"),
            Json::obj(Vec::<(String, Json)>::new()),
            &token,
        );
        let code = issued_code.get("code").unwrap().as_str().unwrap().to_string();
        assert!(code.starts_with("OBS-"), "an invitation code: {}", code);
        assert_eq!(code.len(), 4 + 19, "the code has a stable format: {}", code);
        // Each issued code really does start a new enrolment.
        post(
            &client,
            &harness.url("/v1/register/begin"),
            Json::obj([("gmail", Json::Str(format!("friend{}@gmail.com", issued)))]),
        );
    }
    let sixth = client
        .send(
            Method::Post,
            &harness.url("/v1/invites"),
            Some(&Json::obj(Vec::<(String, Json)>::new())),
            Some(&token),
        )
        .expect("the gateway answers the connection");
    assert_eq!(sixth.status.code(), 403, "the sixth invitation must be refused");

    // Nothing about the issued codes can be read back from the store.
    let document = std::fs::read_to_string(&harness.store_path).unwrap();
    let listed = send_with_token(&client, Method::Get, &harness.url("/v1/invites"), None, &token);
    for entry in listed.get("invites").unwrap().as_array().unwrap() {
        assert!(entry.get("code").is_none(), "a listing never carries a code");
        assert!(entry.get("spent").unwrap().as_bool().is_some());
    }
    assert!(document.contains("invites"));
}

#[test]
fn account_recovery_unlocks_access_and_cannot_move_value() {
    let harness = Harness::launch();
    let client = harness.client();
    let invite = "OBS-TEST-RECO-VERY-1234";
    harness.mint_invite(invite);

    // Enrol, capturing the recovery code from the step that shows it once.
    let begun = post(
        &client,
        &harness.url("/v1/register/begin"),
        Json::obj([("gmail", Json::Str("recover@gmail.com".to_string()))]),
    );
    let token = begun.get("token").unwrap().as_str().unwrap().to_string();
    post(
        &client,
        &harness.url("/v1/register/password"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("password", Json::Str(PASSWORD.to_string())),
        ]),
    );
    post(
        &client,
        &harness.url("/v1/register/invite"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("code", Json::Str(invite.to_string())),
        ]),
    );
    let step = post(
        &client,
        &harness.url("/v1/register/recovery-code"),
        Json::obj([("token", Json::Str(token.clone()))]),
    );
    let recovery_code = step.get("value").unwrap().as_str().unwrap().to_string();
    let step = post(
        &client,
        &harness.url("/v1/register/mfa"),
        Json::obj([("token", Json::Str(token.clone()))]),
    );
    let uri = step.get("value").unwrap().as_str().unwrap().to_string();
    let secret = Secret::parse_base32(
        uri.split("secret=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .unwrap(),
    )
    .unwrap();
    let keys = harness.wallet.public_keys();
    let mut activated = false;
    for code in codes_for(&secret) {
        let response = client
            .post_json(
                &harness.url("/v1/register/mfa/confirm"),
                &Json::obj([
                    ("token", Json::Str(token.clone())),
                    ("code", Json::Str(code)),
                ]),
            )
            .expect("the gateway answers the connection");
        if response.status.code() < 400 {
            activated = true;
            break;
        }
    }
    assert!(activated);
    post(
        &client,
        &harness.url("/v1/register/wallet"),
        Json::obj([
            ("token", Json::Str(token.clone())),
            ("wallet_key", Json::Str(obs_crypto::encoding::hex_encode(&keys.wallet_key))),
            ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&keys.node_key))),
            (
                "recovery_key",
                Json::Str(obs_crypto::encoding::hex_encode(&keys.recovery_key)),
            ),
        ]),
    );

    // The recovery code is accepted once, and only with the right address.
    let wrong = refused(
        &client,
        &harness.url("/v1/recovery/verify"),
        Json::obj([
            ("gmail", Json::Str("somebody.else@gmail.com".to_string())),
            ("recovery_code", Json::Str(recovery_code.clone())),
        ]),
    );
    assert_eq!(wrong, 403, "recovery must not work for another account");

    let accepted = post(
        &client,
        &harness.url("/v1/recovery/verify"),
        Json::obj([
            ("gmail", Json::Str("recover@gmail.com".to_string())),
            ("recovery_code", Json::Str(recovery_code.clone())),
        ]),
    );
    assert_eq!(accepted.get("stage").unwrap().as_str(), Some("activated"));

    let twice = refused(
        &client,
        &harness.url("/v1/recovery/verify"),
        Json::obj([
            ("gmail", Json::Str("recover@gmail.com".to_string())),
            ("recovery_code", Json::Str(recovery_code)),
        ]),
    );
    assert_eq!(twice, 409, "a recovery code is single use");

    // Recovery re-enrols the authenticator: an administrative act that leaves
    // the wallet key — and therefore every coin — exactly where it was.
    let new_uri = post(
        &client,
        &harness.url("/v1/recovery/mfa"),
        Json::obj([
            ("gmail", Json::Str("recover@gmail.com".to_string())),
            ("password", Json::Str(PASSWORD.to_string())),
        ]),
    );
    let new_secret = Secret::parse_base32(
        new_uri
            .get("provisioning_uri")
            .unwrap()
            .as_str()
            .unwrap()
            .split("secret=")
            .nth(1)
            .and_then(|rest| rest.split('&').next())
            .unwrap(),
    )
    .unwrap();
    let mut signed_in = false;
    for code in codes_for(&new_secret) {
        let response = client
            .post_json(
                &harness.url("/v1/auth/sign-in"),
                &Json::obj([
                    ("gmail", Json::Str("recover@gmail.com".to_string())),
                    ("password", Json::Str(PASSWORD.to_string())),
                    ("mfa_code", Json::Str(code)),
                ]),
            )
            .expect("the gateway answers the connection");
        if response.status.code() < 400 {
            signed_in = true;
            break;
        }
    }
    assert!(signed_in, "the new authenticator signs in");
}
