//! Integration tests for the full node: block production, the transaction
//! lifecycle, two nodes over real sockets, and the node's HTTP API.
//!
//! These are deliberately end-to-end.  They run real TCP peers, real Ed25519
//! signatures and a real chain store on disk, because the point of this layer is
//! that the pieces work *together*: a block the node builds still has to be
//! accepted by the state machine, a transaction the API accepts still has to be
//! mined, and a block from a peer still has to prove itself.
//!
//! ## Why the tests move a clock
//!
//! Obsidian's protocol time is a chain quantity: a block's timestamp must be
//! greater than its parent's and at most 60 seconds ahead of it.  Protocol time
//! therefore advances *through blocks*, not through a clock, and a test that
//! wants four hours of protocol time mines four hours of 60-second blocks.  The
//! harness's [`advance`] does exactly that, from a devnet genesis pinned at the
//! moment the test starts — which is how a real devnet deployment starts, and
//! why a network's genesis epoch is its launch moment.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use obs_chain::params::{CLAIM_INTERVAL_SECS, MAX_CLAIMS_PER_DAY};
use obs_chain::state::GenesisConfig;
use obs_chain::{Claim, InviteAuthorization, Transaction, TxKind};
use obs_crypto::ed25519::Keypair;
use obs_node::rpc::NodeApi;
use obs_node::{Node, NodeConfig, NodeEvent};
use obs_primitives::address::{mask, Address};
use obs_primitives::identity::canonical_gmail;
use obs_primitives::json::Json;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION};
use obs_primitives::network::{Network, DEVNET};
use obs_rpc::client::{json_body, Client};
use obs_rpc::server::{Handler, Server, ServerConfig};

const NETWORK: Network = DEVNET;
/// Seed for the network's registration authority, which in production is the
/// registration server and never a node.
const AUTHORITY_SEED: [u8; 32] = [7u8; 32];

static COUNTER: AtomicU64 = AtomicU64::new(0);

fn unix_now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

fn authority() -> Keypair {
    Keypair::from_seed(&AUTHORITY_SEED)
}

fn address_of(key: &Keypair) -> Address {
    Address::from_public_key(NETWORK, &key.public_key())
}

fn temp_dir(name: &str) -> PathBuf {
    let unique = COUNTER.fetch_add(1, Ordering::Relaxed);
    let dir = std::env::temp_dir().join(format!(
        "obs-node-{}-{}-{}",
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

// ---------------------------------------------------------------------------
// The devnet under test
// ---------------------------------------------------------------------------

/// The genesis a devnet deployment runs with.
///
/// Every node of one devnet is configured with the same value.  Two nodes with
/// different genesis epochs are two different chains, and their handshake
/// refuses each other because the genesis hash differs — which is the point of
/// committing to the genesis.
#[derive(Clone)]
struct Devnet {
    genesis: GenesisConfig,
}

impl Devnet {
    fn launch() -> Devnet {
        // Half a minute of slack, so the first block is already inside the
        // 60-second drift window when a test starts.
        Devnet {
            genesis: GenesisConfig {
                network: NETWORK,
                registration_authority: authority().public_key(),
                timestamp: unix_now() - 30,
            },
        }
    }

    fn config(&self, name: &str, seed: u8) -> NodeConfig {
        let mut config = NodeConfig::new(
            NETWORK,
            temp_dir(name),
            authority().public_key(),
            Keypair::from_seed(&[seed; 32]),
        );
        config.genesis = self.genesis.clone();
        config.listen_port = free_port();
        config.fsync = false;
        config.block_interval = Duration::from_millis(1);
        config
    }

    fn node(&self, name: &str, seed: u8, mining_key: Option<&Keypair>) -> Node {
        let config = self.config(name, seed);
        let config = match mining_key {
            Some(key) => config.with_mining(key.clone()),
            None => config,
        };
        Node::open(config).expect("the node opens")
    }
}

/// Points the node's own clock just past its chain, so the next block it is
/// asked for is inside the protocol's one-second-to-one-minute window.
///
/// A sped-up devnet does in a test what protocol time does on a real network:
/// the clock is only ever used to *ask* for a block, never to judge one.
fn set_clock_to(node: &mut Node, timestamp: u64) {
    node.set_clock_offset(timestamp as i64 - unix_now() as i64);
}

/// Points the node's clock at the next block and returns that timestamp.
///
/// Everything a test builds for the next block — an invitation window, a claim,
/// a transfer — is expressed in protocol time, so the clock has to be pointed
/// *before* the transaction is built, not after.
fn next_block_time(node: &mut Node) -> u64 {
    let timestamp = node.head_state().last_timestamp + 1;
    set_clock_to(node, timestamp);
    timestamp
}

/// Asks the node for a block, first pointing its clock at the chain.
fn mine(node: &mut Node) -> bool {
    next_block_time(node);
    node.mine_once().is_some()
}

/// Takes one full protocol step: the next block at the 60-second drift maximum.
fn mine_step(node: &mut Node) -> bool {
    set_clock_to(node, node.head_state().last_timestamp + 60);
    node.mine_once().is_some()
}

/// Advances protocol time by at least `secs`, producing the blocks that carry it
/// there (at most 60 seconds of protocol time per block), and leaves the node's
/// clock one second ahead of the chain.
fn advance(node: &mut Node, secs: u64) {
    let target = node.head_state().last_timestamp + secs;
    while node.head_state().last_timestamp < target {
        let height = node.height();
        assert!(mine_step(node), "a block must apply while protocol time advances");
        assert!(node.height() > height, "the chain must move");
    }
    set_clock_to(node, node.head_state().last_timestamp + 1);
}

// ---------------------------------------------------------------------------
// Registration and claims
// ---------------------------------------------------------------------------

/// Builds the registration transaction for `key`, signed by `key` itself.
///
/// This is what the registration server hands a new account once the Gmail
/// identity has been canonicalised and verified: an invitation authorisation
/// bound to that identity, plus the account's own signature.  The chain checks
/// both, so the registration server cannot create an account on somebody else's
/// key, and a client cannot register a second account for the same Gmail.
fn register_tx(key: &Keypair, email: &str, code: &str, at: u64) -> Transaction {
    let canonical = canonical_gmail(email).expect("test email is canonicalisable");
    let commitment = obs_chain::invite_commitment(NETWORK.chain_id, code);
    let gmail = obs_chain::gmail_commitment(NETWORK.chain_id, &canonical);
    let invite = InviteAuthorization::issue(
        NETWORK.chain_id,
        &authority(),
        commitment,
        gmail,
        at,
        at + 86_400,
        None,
    );
    Transaction::sign(
        NETWORK,
        1,
        TxKind::Register {
            account: address_of(key),
            wallet_key: key.public_key(),
            gmail_commitment: gmail,
            invite,
        },
        key,
    )
}

/// A claim transaction, used by tests that want to hand the chain a claim the
/// node would never build.
fn claim_tx(key: &Keypair, sequence: u64, nonce: u64, at: u64) -> Transaction {
    Transaction::sign(
        NETWORK,
        nonce,
        TxKind::Claim(Claim {
            account: address_of(key),
            claimed_at: at,
            sequence,
        }),
        key,
    )
}

/// Registers an account on `node` and mines it into the chain.
fn register_account(node: &mut Node, key: &Keypair, name: &str) {
    next_block_time(node);
    let email = format!("{}@gmail.com", name.replace('-', ""));
    let code = format!("INVITE-{}", name.to_uppercase().replace('-', ""));
    let tx = register_tx(key, &email, &code, node.protocol_time());
    node.submit_transaction(tx).expect("the registration is poolable");
    if node.mine_once().is_none() {
        panic!(
            "the registration block is produced (height {}): {:?}",
            node.height(),
            node.recent_events(8)
        );
    }
}

// ---------------------------------------------------------------------------
// Chain
// ---------------------------------------------------------------------------

#[test]
fn a_new_node_starts_at_the_genesis_block() {
    let devnet = Devnet::launch();
    let node = devnet.node("fresh", 1, None);
    assert_eq!(node.height(), 0);
    assert_eq!(node.head(), node.store().genesis_hash());
    assert!(node.head_state().accounts.is_empty());
    assert_eq!(node.head_state().issued_supply, Amount::ZERO);
    assert!(!node.head_state().genesis_issued);
    assert!(node.head_state().treasury.is_none());
    assert_eq!(node.config().network.chain_id, NETWORK.chain_id);
    assert!(node.genesis_epoch_gap().is_none(), "a fresh devnet can be founded");
}

#[test]
fn a_node_cannot_found_a_chain_whose_genesis_epoch_has_passed() {
    // Protocol time moves at most 60 seconds per block, so a chain whose genesis
    // is an hour old cannot be founded: block 1 would have to be an hour after
    // its parent.  The node says so instead of quietly mining nothing.
    let mut devnet = Devnet::launch();
    devnet.genesis.timestamp = unix_now() - 3_600;
    let node = devnet.node("late", 2, None);
    match node.genesis_epoch_gap() {
        Some(NodeEvent::GenesisEpochGap {
            genesis_timestamp,
            clock,
        }) => {
            assert_eq!(genesis_timestamp, unix_now() - 3_600);
            assert!(clock > genesis_timestamp + 60);
        }
        other => panic!("expected a genesis-epoch diagnostic, got {:?}", other),
    }
    // Nothing about that stops it from syncing a chain: it is a diagnostic, not
    // a state.
    assert_eq!(node.height(), 0);
}

#[test]
fn the_genesis_block_registers_the_founder_and_mines_the_allocation_once() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[11u8; 32]);
    let mut node = devnet.node("genesis", 12, Some(&founder));
    let founder_address = address_of(&founder);

    // The registration goes into the pool; the claim is the proposer's own
    // business, so the node adds it while building the block.  Both land in
    // block 1, which is the only block that can issue the genesis allocation.
    next_block_time(&mut node);
    let registration = register_tx(&founder, "founder@gmail.com", "INVITE-GENESIS", node.protocol_time());
    node.submit_transaction(registration)
        .expect("the registration is poolable");
    assert_eq!(node.height(), 0);

    assert!(node.mine_once().is_some(), "the genesis block is produced");
    let hash = node.head();
    assert_eq!(node.height(), 1);
    assert_eq!(node.head(), hash);

    let block = node.block_at(1).unwrap();
    assert_eq!(block.transactions.len(), 2, "the registration and the genesis claim");
    assert!(matches!(block.transactions[0].kind, TxKind::Register { .. }));
    assert!(matches!(block.transactions[1].kind, TxKind::Claim(_)));

    let state = node.head_state();
    assert!(state.genesis_issued);
    assert_eq!(state.treasury, Some(founder_address), "the genesis wallet is the treasury");
    assert_eq!(state.total_claims, 1);
    let account = state.account(&founder_address).unwrap();
    assert!(account.genesis_claimed);
    let reward = node.mining_info().reward_per_claim;
    assert_eq!(reward, Amount::from_grains(166_666_666), "the initial claim rate");
    assert_eq!(
        account.balance,
        GENESIS_ALLOCATION.checked_add(reward).unwrap()
    );
    assert_eq!(state.issued_supply, account.balance);
    assert_eq!(state.mining_pool, Amount::ZERO, "the allocation is not a gas-fee share");

    let events = node.drain_events();
    assert!(
        events.iter().any(|event| matches!(
            event,
            NodeEvent::GenesisIssued { account, amount }
                if *account == founder_address && *amount == GENESIS_ALLOCATION
        )),
        "the node reported the genesis issuance: {:?}",
        events
    );

    // The genesis wallet is the treasury, and the allocation is issued once:
    // registering a second account changes nothing about it, and the founder's
    // next claim is an ordinary claim paid the ordinary rate.
    let second = Keypair::from_seed(&[13u8; 32]);
    register_account(&mut node, &second, "second");
    let second_address = address_of(&second);
    let second_account = node.head_state().account(&second_address).unwrap();
    assert_eq!(second_account.balance, Amount::ZERO, "an account is created empty");
    assert!(!second_account.genesis_claimed);
    assert_eq!(node.head_state().treasury, Some(founder_address));
    assert_eq!(node.head_state().total_claims, 1, "only the founder has claimed");

    advance(&mut node, CLAIM_INTERVAL_SECS);
    assert_eq!(node.head_state().total_claims, 2);
    assert_eq!(node.head_state().treasury, Some(founder_address));
    assert_eq!(
        node.head_state().account(&founder_address).unwrap().balance,
        GENESIS_ALLOCATION.checked_add(reward).unwrap().checked_add(reward).unwrap(),
        "the second claim paid the ordinary rate, not a second allocation"
    );
    assert_eq!(
        node.head_state().issued_supply.grains(),
        GENESIS_ALLOCATION.grains() + reward.grains() * 2
    );
}

#[test]
fn claims_are_paced_by_protocol_time_and_the_daily_window() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[21u8; 32]);
    let mut node = devnet.node("pacing", 22, Some(&founder));
    let founder_address = address_of(&founder);

    register_account(&mut node, &founder, "pacer");
    assert_eq!(node.height(), 1);
    assert_eq!(node.head_state().total_claims, 1);
    let first_claim_at = node.head_state().last_timestamp;

    // The next four hours are protocol time, and the chain has to be walked
    // there: 60 seconds per block.  Stop one block short of the interval.
    advance(&mut node, CLAIM_INTERVAL_SECS - 60);
    assert_eq!(
        node.head_state().total_claims,
        1,
        "no claim before the interval has elapsed ({})",
        node.head_state().last_timestamp - first_claim_at
    );
    assert!(node.head_state().last_timestamp < first_claim_at + CLAIM_INTERVAL_SECS);

    mine_step(&mut node);
    assert_eq!(node.head_state().total_claims, 2, "the claim after the interval applies");
    let account = node.head_state().account(&founder_address).unwrap();
    assert_eq!(account.claims_today, 2);
    assert_eq!(account.last_claim_sequence, 2);
    let second_claim_at = account.last_claim_at;
    assert!(second_claim_at >= first_claim_at + CLAIM_INTERVAL_SECS);

    // Six claims fit in a protocol day.  Walk to exactly 24 hours after the
    // first claim and watch the window roll over: the seventh claim is accepted
    // with a reset counter, not refused.
    advance(&mut node, 24 * 3_600 - CLAIM_INTERVAL_SECS);
    let account = node.head_state().account(&founder_address).unwrap();
    assert!(
        account.claims_today <= MAX_CLAIMS_PER_DAY,
        "the protocol never pays more than {} claims per day: {}",
        MAX_CLAIMS_PER_DAY,
        account.claims_today
    );
    assert_eq!(account.last_claim_at - first_claim_at, 24 * 3_600);
    assert_eq!(account.last_claim_sequence, 7, "the seventh claim is in the new day");
    assert_eq!(account.claims_today, 1);
    assert_eq!(node.head_state().total_claims, 7);
}

#[test]
fn a_transfer_moves_value_and_splits_the_gas_fee_forty_sixty() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[31u8; 32]);
    let mut node = devnet.node("transfer", 32, Some(&founder));
    let founder_address = address_of(&founder);

    register_account(&mut node, &founder, "payer");
    // A second claim block, so the transfer lands in a block whose only
    // transaction is the transfer.
    advance(&mut node, CLAIM_INTERVAL_SECS);
    assert_eq!(node.head_state().total_claims, 2);

    let recipient = Keypair::from_seed(&[33u8; 32]);
    let recipient_address = address_of(&recipient);
    register_account(&mut node, &recipient, "payee");

    let amount = Amount::parse("5").unwrap();
    let nonce = node.head_state().expected_nonce(&founder_address);
    let transfer = Transaction::sign(
        NETWORK,
        nonce,
        TxKind::Transfer {
            to: recipient_address,
            amount,
        },
        &founder,
    );
    let fee = obs_mempool::transaction_fee(&transfer);
    assert!(fee.grains() > 0, "the gas fee is never zero");
    assert!(fee.grains() <= obs_chain::params::MAX_GAS_FEE.grains());
    node.submit_transaction(transfer).expect("the transfer is poolable");

    let before = node.head_state().clone();
    assert!(mine(&mut node), "the transfer block applies");
    let after = node.head_state();

    assert_eq!(after.account(&recipient_address).unwrap().balance, amount);
    assert_eq!(
        after.account(&founder_address).unwrap().balance,
        before
            .account(&founder_address)
            .unwrap()
            .balance
            .checked_sub(amount)
            .unwrap()
            .checked_sub(fee)
            .unwrap()
    );
    let (validator_share, pool_share) = obs_chain::params::split_gas_fee(fee);
    assert_eq!(
        after.validator_pool,
        before.validator_pool.checked_add(validator_share).unwrap()
    );
    assert_eq!(
        after.mining_pool,
        before.mining_pool.checked_add(pool_share).unwrap()
    );
    assert_eq!(
        validator_share.grains() + pool_share.grains(),
        fee.grains(),
        "the whole fee is distributed, with no rounding loss"
    );
    assert_eq!(validator_share.grains(), fee.grains() * 40 / 100);
    assert_eq!(pool_share.grains(), fee.grains() * 60 / 100);
    // The recipient's own claim was not paid for by the transfer.
    assert_eq!(after.total_claims, before.total_claims);
}

#[test]
fn a_node_whose_account_is_not_registered_cannot_force_a_block() {
    let devnet = Devnet::launch();
    let stranger = Keypair::from_seed(&[41u8; 32]);
    let mut node = devnet.node("stranger", 42, Some(&stranger));
    // The chain's proposer rule refuses every block this node could build, and
    // the node refuses to mine around it instead of inventing an alternative.
    assert_eq!(node.mine_once(), None);
    assert_eq!(node.height(), 0);
    assert!(
        node.recent_events(10)
            .iter()
            .any(|event| matches!(event, NodeEvent::BlockRejected { rule, .. } if rule == "block_proposer")),
        "the refusal is reported with the rule that caught it"
    );
}

#[test]
fn a_tampered_block_is_refused_with_the_rule_that_caught_it() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[51u8; 32]);
    let mut node = devnet.node("tamper", 52, Some(&founder));
    register_account(&mut node, &founder, "tampered");
    assert_eq!(node.height(), 1);

    let mut outcome = obs_node::StepOutcome::default();
    let timestamp = node.head_state().last_timestamp + 60;
    let block = node
        .head_state()
        .build_block(&founder, timestamp, vec![], vec![])
        .expect("the block builds");

    // A block whose signature does not match its header: caught first, because
    // a node must not even look at data the producer did not sign.
    let mut unsigned = block.clone();
    unsigned.signature = [0u8; 64];
    let refused = node.accept_block(None, unsigned, &mut outcome, false);
    assert!(refused.is_err());
    assert_eq!(refused.unwrap_err(), "block_signature");

    // A block whose proposer *signed* a false state root: structurally perfect,
    // and still refused, because the applied state hashes to something else.
    let mut forged = block.clone();
    forged.header.state_root = obs_primitives::hash::Hash32::from_bytes([9u8; 32]);
    forged.sign(&founder);
    assert!(forged.verify_proposer_signature());
    let refused = node.accept_block(None, forged, &mut outcome, false);
    assert!(refused.is_err());
    assert_eq!(refused.unwrap_err(), "block_state_root");
    assert_eq!(node.height(), 1, "the chain did not move");

    // A claim whose declared protocol time is not the block's: the third
    // timestamp rule.  The nonce is the account's next nonce, so nothing else
    // about the transaction is wrong.
    let mut wrong_time = block.clone();
    wrong_time.transactions = vec![claim_tx(&founder, 2, 3, timestamp - 30)];
    wrong_time.header.tx_root = wrong_time.compute_tx_root();
    let probe = node.head_state().clone();
    let detail = probe
        .apply_txs_preview(&wrong_time.transactions, timestamp)
        .err()
        .map(|error| error.rule)
        .unwrap_or_default();
    assert_eq!(detail, "timestamp_protocol_claim");

    // The untampered block still applies, so the refusals above were about the
    // tampering and not about this node being unable to accept blocks.
    let accepted = node.accept_block(None, block, &mut outcome, false);
    assert!(accepted.is_ok(), "{:?}", accepted.err());
    assert_eq!(node.height(), 2);
}

// ---------------------------------------------------------------------------
// Peers
// ---------------------------------------------------------------------------

/// A node running its loop on a background thread, with a handle for tests.
struct Running {
    stop: Arc<AtomicBool>,
    handle: Option<std::thread::JoinHandle<()>>,
    node: Arc<Mutex<Node>>,
}

impl Running {
    fn start(node: Node) -> Running {
        let stop = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&stop);
        let shared = Arc::new(Mutex::new(node));
        let inner = Arc::clone(&shared);
        let handle = std::thread::spawn(move || {
            while !flag.load(Ordering::Relaxed) {
                if let Ok(mut node) = inner.lock() {
                    node.step();
                }
                std::thread::sleep(Duration::from_millis(2));
            }
        });
        Running {
            stop,
            handle: Some(handle),
            node: shared,
        }
    }

    fn with<T>(&self, f: impl FnOnce(&mut Node) -> T) -> T {
        let mut node = self.node.lock().unwrap();
        f(&mut node)
    }
}

impl Drop for Running {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(handle) = self.handle.take() {
            let _ = handle.join();
        }
    }
}

fn wait_until(timeout: Duration, mut check: impl FnMut() -> bool) -> bool {
    let deadline = Instant::now() + timeout;
    while Instant::now() < deadline {
        if check() {
            return true;
        }
        std::thread::sleep(Duration::from_millis(10));
    }
    check()
}

#[test]
fn two_nodes_sync_blocks_over_real_tcp_peers() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[62u8; 32]);
    let miner = Running::start(devnet.node("miner", 61, Some(&founder)));
    let miner_addr = miner.with(|node| node.listen_addr());
    let follower = Running::start(
        Node::open(devnet.config("follower", 63).with_peers(vec![miner_addr])).unwrap(),
    );

    register_account_in(&miner, &founder, "syncminer");
    assert_eq!(miner.with(|node| node.height()), 1);

    assert!(
        wait_until(Duration::from_secs(20), || {
            !miner.with(|node| node.peer_status()).is_empty()
                && !follower.with(|node| node.peer_status()).is_empty()
        }),
        "the two nodes connect"
    );

    // Walk the miner's protocol time forward four hours: that is 240 blocks and
    // a claim, all of which the follower must receive, validate and apply.
    miner.with(|node| advance(node, CLAIM_INTERVAL_SECS + 60));
    let target_height = miner.with(|node| node.height());
    let target_head = miner.with(|node| node.head());
    let target_state_root = miner.with(|node| node.head_state().state_root());
    assert!(target_height >= 200, "the miner advanced protocol time: {}", target_height);
    assert_eq!(miner.with(|node| node.head_state().total_claims), 2);

    assert!(
        wait_until(Duration::from_secs(30), || {
            follower.with(|node| node.head()) == target_head
        }),
        "the follower reached the miner's head: follower height {} target {}",
        follower.with(|node| node.height()),
        target_height
    );
    assert_eq!(
        follower.with(|node| node.head_state().state_root()),
        target_state_root,
        "the follower's state matches the miner's root"
    );
    assert_eq!(
        follower.with(|node| node.height()),
        target_height,
        "the follower is at the same height"
    );
}

fn register_account_in(node: &Running, key: &Keypair, name: &str) {
    node.with(|node| register_account(node, key, name));
}

#[test]
fn a_forged_block_from_a_peer_is_validated_and_refused() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[71u8; 32]);
    let mut node = devnet.node("validate", 72, Some(&founder));
    register_account(&mut node, &founder, "validator");

    let mut outcome = obs_node::StepOutcome::default();
    let attacker = Keypair::from_seed(&[73u8; 32]);
    let timestamp = node.head_state().last_timestamp + 30;
    // A well-formed block whose proposer simply is not allowed to propose: the
    // attacker signs the header itself, so the signature verifies and only the
    // proposer rule stands in the way.
    let mut forged = node
        .head_state()
        .build_block(&founder, timestamp, vec![], vec![])
        .expect("the honest block builds");
    forged.header.proposer = attacker.public_key();
    forged.sign(&attacker);
    assert!(forged.verify_proposer_signature());
    let refused = node.accept_block(Some([9u8; 32]), forged, &mut outcome, false);
    assert_eq!(refused.unwrap_err(), "block_proposer");
    assert_eq!(outcome.blocks_rejected, 1);
    assert_eq!(node.height(), 1);
}

// ---------------------------------------------------------------------------
// HTTP API
// ---------------------------------------------------------------------------

struct Api {
    api: Arc<NodeApi>,
    addr: SocketAddr,
    stop: Arc<AtomicBool>,
}

impl Drop for Api {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

impl Api {
    fn start(node: Node) -> Api {
        let api = Arc::new(NodeApi::new(node));
        let server = Server::bind(("127.0.0.1", free_port()), ServerConfig::default()).unwrap();
        let addr = server.local_addr();
        let stop = Arc::new(AtomicBool::new(false));
        let handler: Arc<dyn Handler> = api.clone();
        let flag = Arc::clone(&stop);
        std::thread::spawn(move || {
            let _ = server.serve(handler, flag);
        });
        Api { api, addr, stop }
    }

    fn base(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn get(&self, path: &str) -> Json {
        let client = Client::with_timeout(Duration::from_secs(5));
        json_body(&client.get(&format!("{}{}", self.base(), path)).unwrap()).unwrap()
    }

    fn get_response(&self, path: &str) -> obs_rpc::http::Response {
        Client::with_timeout(Duration::from_secs(5))
            .get(&format!("{}{}", self.base(), path))
            .unwrap()
    }

    fn post(&self, path: &str, body: &Json) -> obs_rpc::http::Response {
        Client::with_timeout(Duration::from_secs(5))
            .post_json(&format!("{}{}", self.base(), path), body)
            .unwrap()
    }

    fn with_node<T>(&self, f: impl FnOnce(&mut Node) -> T) -> T {
        let shared = self.api.node();
        let mut node = shared.lock().unwrap();
        f(&mut node)
    }
}

/// A devnet with a registered, claim-holding founder, served over HTTP.
fn api_devnet(name: &str, seed: u8) -> (Api, Keypair) {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[seed.wrapping_add(1); 32]);
    let mut node = devnet.node(name, seed, Some(&founder));
    register_account(&mut node, &founder, name);
    (Api::start(node), founder)
}

#[test]
fn the_api_serves_chain_views_and_never_balances_by_address() {
    let (api, founder) = api_devnet("api", 81);
    let founder_address = address_of(&founder);

    let status = api.get("/api/v1/status");
    assert_eq!(status.get("chain_id").unwrap().as_i128(), Some(NETWORK.chain_id as i128));
    assert_eq!(status.get("height").unwrap().as_i128(), Some(1));
    assert_eq!(status.get("head").unwrap().as_str().unwrap().len(), 64);
    assert_eq!(status.get("protocol_version").unwrap().as_i128(), Some(1));
    assert_eq!(status.get("issued_supply").unwrap().as_str(), Some("100000.000166666666"));
    assert_eq!(status.get("max_supply").unwrap().as_str(), Some("21000000"));

    let supply = api.get("/api/v1/supply");
    assert_eq!(supply.get("max_supply").unwrap().as_str(), Some("21000000"));
    assert_eq!(supply.get("genesis_issued").unwrap().as_bool(), Some(true));
    assert_eq!(supply.get("genesis_allocation").unwrap().as_str(), Some("100000"));
    assert_eq!(supply.get("mining_pool").unwrap().as_str(), Some("0"));

    let mining = api.get("/api/v1/mining");
    assert_eq!(mining.get("reward_per_claim").unwrap().as_str(), Some("0.000166666666"));
    assert_eq!(mining.get("active_miners").unwrap().as_i128(), Some(1));
    assert_eq!(mining.get("max_claims_per_day").unwrap().as_i128(), Some(6));
    assert_eq!(mining.get("interval_secs").unwrap().as_i128(), Some(14_400));
    assert_eq!(mining.get("genesis_claim_issued").unwrap().as_bool(), Some(true));

    let params = api.get("/api/v1/params");
    assert_eq!(params.get("validator_bond").unwrap().as_str(), Some("50"));
    assert_eq!(params.get("validator_fee_share_percent").unwrap().as_i128(), Some(40));
    assert_eq!(params.get("mining_fee_share_percent").unwrap().as_i128(), Some(60));
    assert_eq!(params.get("max_invites_per_account").unwrap().as_i128(), Some(5));
    assert_eq!(params.get("max_block_drift_secs").unwrap().as_i128(), Some(60));
    assert_eq!(params.get("mtp_window").unwrap().as_i128(), Some(11));

    let blocks = api.get("/api/v1/blocks?limit=5");
    assert_eq!(blocks.get("count").unwrap().as_i128(), Some(1));
    let first = blocks.get("blocks").unwrap().as_array().unwrap()[0].clone();
    assert_eq!(first.get("height").unwrap().as_i128(), Some(1));
    let proposer = first.get("proposer").unwrap().as_str().unwrap();
    assert!(proposer.contains("..."), "the proposer is masked: {}", proposer);
    assert_eq!(proposer, mask(&founder_address));
    assert!(!proposer.contains(&founder_address.to_string_canonical()));

    let block = api.get("/api/v1/blocks/1");
    assert_eq!(block.get("height").unwrap().as_i128(), Some(1));
    assert_eq!(block.get("transactions").unwrap().as_i128(), Some(2));
    let tx_ids = block.get("transaction_ids").unwrap().as_array().unwrap();
    assert_eq!(tx_ids.len(), 2);
    let tx = api.get(&format!("/api/v1/transactions/{}", tx_ids[0].as_str().unwrap()));
    assert_eq!(tx.get("status").unwrap().as_str(), Some("confirmed"));
    assert_eq!(tx.get("kind").unwrap().as_str(), Some("register"));
    assert!(tx.get("sender").unwrap().as_str().unwrap().contains("..."));

    let unknown = api.get(&format!("/api/v1/transactions/{}", "11".repeat(32)));
    assert_eq!(unknown.get("error").unwrap().get("code").unwrap().as_str(), Some("transaction_not_found"));

    // The privacy contract: no balance by address, anywhere.
    for path in [
        "/api/v1/wallet/obs1xyz/balance".to_string(),
        format!("/api/v1/accounts/{}", founder_address),
        format!("/api/v1/balance/{}", founder_address),
        format!("/api/v1/address/{}", founder_address),
    ] {
        assert_eq!(api.get_response(&path).status.code(), 404, "{} must not exist", path);
    }
}

#[test]
fn the_api_proves_ownership_and_accepts_signed_transactions() {
    let (api, founder) = api_devnet("proof", 91);
    let founder_address = address_of(&founder);

    // Proving the key gets the balance; the balance never appears elsewhere.
    let nonce = "test-nonce-1";
    let preimage = obs_node::rpc::account_proof_preimage(NETWORK.chain_id, &founder_address, nonce);
    let signature = founder.sign(&preimage);
    let body = Json::obj([
        ("address".to_string(), Json::Str(founder_address.to_string())),
        ("nonce".to_string(), Json::Str(nonce.to_string())),
        (
            "signature".to_string(),
            Json::Str(obs_crypto::encoding::hex_encode(&signature)),
        ),
    ]);
    let proof = json_body(&api.post("/api/v1/account/proof", &body)).unwrap();
    assert_eq!(proof.get("address").unwrap().as_str(), Some(founder_address.to_string().as_str()));
    assert_eq!(
        proof.get("balance").unwrap().as_str(),
        Some("100000.000166666666"),
        "the genesis allocation plus the genesis claim"
    );
    assert_eq!(proof.get("genesis_claimed").unwrap().as_bool(), Some(true));
    assert_eq!(proof.get("invites_remaining").unwrap().as_i128(), Some(5));
    assert_eq!(proof.get("claims_today").unwrap().as_i128(), Some(1));
    assert_eq!(proof.get("claimable_now").unwrap().as_bool(), Some(false));
    assert_eq!(
        proof.get("next_nonce").unwrap().as_i128(),
        Some(3),
        "the genesis block spent nonces 1 and 2 (registration and claim)"
    );

    // A forged proof reveals nothing.
    let forged = Json::obj([
        ("address".to_string(), Json::Str(founder_address.to_string())),
        ("nonce".to_string(), Json::Str(nonce.to_string())),
        ("signature".to_string(), Json::Str("00".repeat(64))),
    ]);
    let response = api.post("/api/v1/account/proof", &forged);
    assert_eq!(response.status.code(), 403);
    assert!(
        !String::from_utf8_lossy(&response.body).contains("100000"),
        "a refused proof must not leak the balance"
    );

    // Submitting a signed transfer: the API validates and pools it, and the
    // chain pays it out when the block is mined.
    let recipient = Keypair::from_seed(&[93u8; 32]);
    let recipient_address = address_of(&recipient);
    api.with_node(|node| register_account(node, &recipient, "apirecipient"));

    let amount = Amount::parse("12.5").unwrap();
    let nonce = api.with_node(|node| node.head_state().expected_nonce(&founder_address));
    let transfer = Transaction::sign(
        NETWORK,
        nonce,
        TxKind::Transfer {
            to: recipient_address,
            amount,
        },
        &founder,
    );
    let body = Json::obj([(
        "transaction".to_string(),
        Json::Str(obs_crypto::encoding::hex_encode(&transfer.to_bytes())),
    )]);
    let accepted = json_body(&api.post("/api/v1/transactions", &body)).unwrap();
    assert_eq!(accepted.get("accepted").unwrap().as_bool(), Some(true));
    assert_eq!(
        accepted.get("id").unwrap().as_str(),
        Some(transfer.id().0.to_hex().as_str())
    );

    // A resubmission is refused as a duplicate; garbage is a bad request; a
    // transaction for another chain is refused rather than quietly mined.
    assert_eq!(api.post("/api/v1/transactions", &body).status.code(), 422);
    let garbage = Json::obj([("transaction".to_string(), Json::Str("not-hex".to_string()))]);
    assert_eq!(api.post("/api/v1/transactions", &garbage).status.code(), 400);
    let wrong_chain = Transaction::sign(
        obs_primitives::network::TESTNET,
        nonce + 1,
        TxKind::Transfer {
            to: recipient_address,
            amount,
        },
        &founder,
    );
    let body = Json::obj([(
        "transaction".to_string(),
        Json::Str(obs_crypto::encoding::hex_encode(&wrong_chain.to_bytes())),
    )]);
    assert_eq!(api.post("/api/v1/transactions", &body).status.code(), 422);

    api.with_node(|node| assert!(mine(node), "the transfer block applies"));
    let recipient_balance = api.with_node(|node| {
        node.head_state()
            .account(&recipient_address)
            .unwrap()
            .balance
    });
    assert_eq!(recipient_balance, amount);
}

#[test]
fn the_api_never_publishes_full_addresses_or_key_material() {
    let (api, founder) = api_devnet("mask", 101);
    let full = address_of(&founder).to_string_canonical();
    for path in [
        "/api/v1/status",
        "/api/v1/supply",
        "/api/v1/params",
        "/api/v1/mining",
        "/api/v1/blocks",
        "/api/v1/blocks/1",
        "/api/v1/validators",
        "/api/v1/mempool",
        "/api/v1/peers",
        "/api/v1/events",
    ] {
        let body = String::from_utf8_lossy(&api.get_response(path).body).to_string();
        assert!(!body.contains(&full), "{} must not publish a full address", path);
        assert!(!body.contains("-----BEGIN"), "{} must not publish key material", path);
        assert!(!body.contains("seed"), "{} must not publish seed material", path);
    }
}

#[test]
fn the_api_reports_pool_events_and_peers() {
    let (api, _founder) = api_devnet("pool", 111);

    // Pool a registration that has not been mined: the pool view shows it.
    let other = Keypair::from_seed(&[113u8; 32]);
    api.with_node(|node| {
        let at = node.protocol_time();
        let tx = register_tx(&other, "pooled@gmail.com", "INVITE-POOLED", at);
        node.submit_transaction(tx).unwrap();
    });

    let pool = api.get("/api/v1/mempool");
    assert_eq!(pool.get("transactions").unwrap().as_i128(), Some(1));
    assert!(pool.get("total_fees").unwrap().as_str().is_some());
    let sample = pool.get("sample").unwrap().as_array().unwrap();
    assert_eq!(sample[0].get("kind").unwrap().as_str(), Some("register"));

    let peers = api.get("/api/v1/peers");
    assert_eq!(peers.get("count").unwrap().as_i128(), Some(0));

    let events = api.get("/api/v1/events");
    assert!(events.get("requests").unwrap().as_i128().unwrap() >= 3);
    let text = events.get("events").unwrap().to_string();
    assert!(text.contains("genesis_issued"), "the node's events are visible: {}", text);
    assert!(text.contains("transaction_accepted"), "pool admissions are visible: {}", text);

    let validators = api.get("/api/v1/validators");
    assert_eq!(validators.get("active").unwrap().as_i128(), Some(0));
    assert_eq!(validators.get("validators").unwrap().as_array().unwrap().len(), 0);
}
