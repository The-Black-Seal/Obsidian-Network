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

use obs_chain::block::Attestation;
use obs_chain::params::{CLAIM_INTERVAL_SECS, MAX_CLAIMS_PER_DAY};
use obs_chain::state::GenesisConfig;
use obs_chain::{Claim, InviteAuthorization, Transaction, TxKind};
use obs_crypto::ed25519::Keypair;
use obs_wallet::Wallet;
use obs_node::rpc::NodeApi;
use obs_node::{Node, NodeConfig, NodeEvent};
use obs_p2p::protocol::MAX_BLOCKS_PER_MESSAGE;
use obs_primitives::address::{mask, Address};
use obs_primitives::identity::canonical_gmail;
use obs_primitives::json::Json;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION};
use obs_primitives::network::{Network, DEVNET};
use obs_rpc::client::{json_body, Client};
use obs_rpc::server::{Handler, Server, ServerConfig};

const NETWORK: Network = DEVNET;
/// A wallet phrase for tests that need a real derived identity, including the
/// node key a validator attests with (derived separately from the wallet key,
/// as the protocol requires).
const PHRASE: &str = "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title";
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
        self.node_with_validator(name, seed, mining_key.unwrap_or(&Keypair::from_seed(&[seed; 32])), &Keypair::from_seed(&[seed.wrapping_add(1); 32]))
    }

    /// A node that mines with one key and attests with a different one, which is
    /// what a real validator is: the bond belongs to the wallet, the attestations
    /// to the node identity.
    fn node_with_validator(
        &self,
        name: &str,
        seed: u8,
        mining_key: &Keypair,
        validator_key: &Keypair,
    ) -> Node {
        let config = self.config(name, seed)
            .with_mining(mining_key.clone())
            .with_validator(validator_key.clone());
        Node::open(config).expect("the node opens")
    }
}

/// Points the node's own clock just past its chain, so the next block it is
/// asked for is inside the protocol's one-second-to-one-minute window.
///
/// A sped-up devnet does in a test what protocol time does on a real network:
/// the clock is only ever used to *ask* for a block, never to judge one.
/// How long a test waits for a network condition to hold.
///
/// Generous on purpose: these tests run on shared machines, and a deadline tuned
/// to an idle one turns a rule into a coin toss.  Every wait returns as soon as
/// the condition holds, so a quiet machine pays nothing for this.
const TEST_DEADLINE: Duration = Duration::from_secs(120);

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

/// Builds this node's validator registration: 50 OBS bonded to a node identity
/// key that is distinct from the wallet key.
fn register_validator_tx(
    wallet: &Keypair,
    node_key: &[u8; 32],
    endpoint: &str,
    nonce: u64,
) -> Transaction {
    Transaction::sign(
        NETWORK,
        nonce,
        TxKind::RegisterValidator {
            node_key: *node_key,
            endpoint: endpoint.to_string(),
        },
        wallet,
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
fn a_claim_submitted_by_a_wallet_is_mined_at_the_time_it_declares() {
    // Mining is not a privilege of the block producer.  Any account may put a
    // claim in the pool, and the claim states the protocol time it belongs to;
    // the chain accepts it in the block stamped with exactly that time.  This is
    // the test that a wallet's claim actually reaches the chain: without the
    // proposer aligning the block's protocol time with a pending claim, a claim
    // written before the block existed could only be mined by luck.
    let devnet = Devnet::launch();
    let producer = Keypair::from_seed(&[51u8; 32]);
    let mut node = devnet.node("claim-pool", 52, Some(&producer));
    register_account(&mut node, &producer, "claimproducer");

    // A second account mines from its own wallet, on the same node.
    let wallet = Keypair::from_seed(&[53u8; 32]);
    register_account(&mut node, &wallet, "claimwallet");
    let address = address_of(&wallet);
    advance(&mut node, CLAIM_INTERVAL_SECS + 60);

    // The wallet reads protocol time and declares it in the claim — the same
    // arithmetic the CLI and the browser wallet use.
    let at = node.protocol_time();
    let state = node.head_state().clone();
    let account = state.account(&address).expect("the wallet is registered").clone();
    assert_eq!(account.claims_today, 0);
    let claim = Transaction::sign(
        NETWORK,
        state.expected_nonce(&address),
        TxKind::Claim(Claim {
            account: address,
            claimed_at: at,
            sequence: account.last_claim_sequence + 1,
        }),
        &wallet,
    );
    let id = claim.id();
    node.submit_transaction(claim).expect("the wallet's claim is poolable");

    // The producer's own clock is five seconds past the claim's time, and the
    // claim's time is inside the window, so the block is stamped where the claim
    // is: the claim's protocol time wins over the wall clock.
    let supply_before = node.head_state().issued_supply;
    set_clock_to(&mut node, at + 5);
    assert!(
        node.mine_once().is_some(),
        "a block must be produced: {:?}",
        node.recent_events(8)
    );

    let head = node.head_state();
    assert_eq!(
        head.last_timestamp, at,
        "the block carrying the claim is stamped with the claim's protocol time"
    );
    let mined = head.account(&address).expect("the wallet is still registered");
    assert_eq!(mined.claims_today, 1, "the claim was applied, not dropped");
    assert_eq!(mined.last_claim_at, at);
    // The reward is the protocol's own number for that moment, and it was issued:
    // this account has mined once and has exactly one claim's value, and the
    // chain's issued supply grew by exactly the same amount.
    let reward = head.mining_reward_at(at);
    assert!(reward.grains() > 0, "a claim is paid");
    assert_eq!(mined.balance, reward);
    assert_eq!(mined.lifetime_rewards, reward);
    assert_eq!(
        head.issued_supply,
        supply_before.checked_add(reward).unwrap(),
        "the claim's issuance is in the chain's supply, and nothing else was issued"
    );
    // And it left the pool: a mined transaction is not re-mined.
    assert!(node.mempool_stats().transactions == 0);
    let _ = id;
}

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

/// A network settles its own genesis moment, and the founder may not register
/// for hours afterwards.  This is the case that used to be a deadlock.
///
/// The first block is the only block that can carry the founder's registration,
/// and protocol time advances at most sixty seconds per block — so a founder who
/// reaches the registration server ten minutes after the epoch needs an
/// authorisation dated *within the chain's reach*, not ten minutes into its
/// future.  Dated in chain time it goes in immediately; this test pins both
/// halves of that: the registration lands, and the genesis allocation is issued.
/// A registered validator that is running must attest, and its attestations must
/// reach the chain.
///
/// The bond, the node identity and the evidence rules are tested in `obs-chain`;
/// what this pins is the *node*: it signs an attestation for each new head it
/// sees, and the next block it proposes carries it, so the chain's uptime record
/// grows from evidence rather than from anything a node says about itself.
/// A node that is restarted must come back to the chain it left.
///
/// This is what a storage layer is for, and it is the difference between a node
/// and a cache: every other test in this file would still pass if nothing were
/// ever written to disk.  A chain that vanishes when its node is restarted is
/// also a chain whose supply, rewards and finality can be quietly rewound, which
/// is why durability is not a flag an operator has to remember.
#[test]
fn a_node_restarts_on_the_chain_it_left() {
    let devnet = Devnet::launch();
    let dir = temp_dir("restart");
    let mining = Keypair::from_seed(&[41u8; 32]);
    let mut config = NodeConfig::new(
        NETWORK,
        dir,
        authority().public_key(),
        Keypair::from_seed(&[42u8; 32]),
    );
    config.genesis = devnet.genesis.clone();
    config.listen_port = free_port();
    config.fsync = false;
    config.block_interval = Duration::from_millis(1);
    let config = config.with_mining(mining.clone());

    let mut node = Node::open(config.clone()).expect("the node opens");
    register_account(&mut node, &mining, "restart");
    for _ in 0..3 {
        assert!(mine_step(&mut node), "blocks are produced");
    }
    let height = node.height();
    let head = node.head_state().last_block_hash;
    let root = node.head_state().state_root();
    let issued = node.head_state().issued_supply;
    assert!(height > 1, "the chain is longer than its genesis");
    drop(node);

    // The genesis a node was started with is a proposal, not the chain's
    // identity: the directory keeps the epoch it was founded with, so the
    // `--genesis-timestamp now` a devnet is started with cannot refound a chain
    // that already exists.  A restart one minute later therefore resumes it.
    let mut restarted = config.clone();
    restarted.genesis.timestamp = config.genesis.timestamp + 60;
    let mut reopened = Node::open(restarted).expect("the node reopens");
    assert_eq!(reopened.height(), height, "the chain resumes at the height it reached");
    assert_eq!(
        reopened.head_state().last_block_hash,
        head,
        "the head is the block the node last accepted"
    );
    assert_eq!(
        reopened.head_state().state_root(),
        root,
        "the state root is recomputed from the replayed blocks, not trusted"
    );
    assert_eq!(
        reopened.head_state().issued_supply,
        issued,
        "no supply is issued again by replaying history"
    );
    assert!(mine_step(&mut reopened), "the restarted node keeps producing blocks");
    assert!(reopened.height() > height);

    // A directory that holds one chain must not quietly serve another.  Pointing
    // a node at it with a different registration authority is the mistake this
    // guards: the node has to refuse, not found a second chain in the same
    // directory.
    drop(reopened);
    let mut wrong = config.clone();
    wrong.genesis.registration_authority = Keypair::from_seed(&[43u8; 32]).public_key();
    match Node::open(wrong) {
        Ok(_) => panic!("a data directory that holds another chain must be refused"),
        Err(error) => {
            let message = format!("{}", error);
            assert!(
                message.contains("holds the chain"),
                "the refusal says which chain the directory holds: {}",
                message
            );
        }
    }
}

#[test]
fn a_running_validator_attests_and_its_attestations_reach_the_chain() {
    let devnet = Devnet::launch();
    // The founder's wallet, and the node identity derived from it.  The protocol
    // requires these to be different keys: an identity that doubles as a wallet
    // would tie attestations to funds.
    let wallet = Wallet::from_phrase(NETWORK, PHRASE, "", 0).unwrap();
    let node_key = wallet.public_keys().node_key;
    let wallet_key = wallet.wallet_keypair().clone();
    let mut node = devnet.node_with_validator("attesting", 32, &wallet_key, &wallet.node_keypair().clone());

    register_account(&mut node, &wallet_key, "attestor");
    let nonce = node
        .head_state()
        .expected_nonce(&address_of(&wallet_key));
    next_block_time(&mut node);
    let registration = register_validator_tx(&wallet_key, &node_key, "127.0.0.1:9220", nonce);
    node.submit_transaction(registration)
        .expect("the bond is poolable");
    assert!(
        node.mine_once().is_some(),
        "the registration block applies: {:?}",
        node.recent_events(8)
    );
    assert!(
        node.head_state().validator(&node_key).is_some(),
        "the validator is registered"
    );

    // Every new head is attested by the running node, and the next block carries
    // the attestation it queued.
    let mut attested_blocks = 0usize;
    for _ in 0..6 {
        if mine_step(&mut node) {
            if let Some(block) = node.block_at(node.height()) {
                if !block.attestations.is_empty() {
                    attested_blocks += 1;
                }
            }
        }
    }

    // A forged attestation must never enter the queue.  It references a real
    // block and a plausible height, and the only thing wrong with it is that
    // nobody signed it — exactly the shape a hostile peer would relay.  If the
    // node queued it, the next block it proposed would carry it and be invalid
    // to every node, including this one.
    let stranger = Keypair::from_seed(&[99u8; 32]);
    let mut forged = Attestation::sign(
        NETWORK.chain_id,
        &stranger,
        node.height(),
        node.head_state().last_block_hash,
        node.head_state().last_slot,
    );
    forged.node_key = Keypair::from_seed(&[98u8; 32]).public_key();
    node.queue_attestation(forged, None);
    assert!(
        mine_step(&mut node),
        "a forged attestation must not poison the node's own next block"
    );

    let record = node
        .head_state()
        .validator(&node_key)
        .cloned()
        .expect("the validator is registered");
    assert!(record.active, "a bonded validator is active");
    assert!(
        attested_blocks > 0,
        "a running validator's attestations must be included in blocks; events: {:?}",
        node.recent_events(10)
    );
    assert!(
        record.attestation_count > 0,
        "the chain's uptime evidence must grow: {} attestations",
        record.attestation_count
    );
    assert!(
        record.last_attested_height > 0,
        "the chain records the last height this validator attested"
    );
    let at = node.head_state().last_timestamp;
    assert!(
        node.head_state().uptime_bp(&node_key, at) > 0,
        "evidence-based uptime must be more than zero once attestations land"
    );
}

#[test]
fn a_founder_registering_long_after_the_epoch_still_founds_the_chain() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[21u8; 32]);
    let mut node = devnet.node("late-funding", 22, Some(&founder));

    // Ten minutes of wall clock pass before the founder gets to it.  The chain
    // has produced nothing, so protocol time is still the genesis moment.
    let genesis_time = node.head_state().last_timestamp;
    set_clock_to(&mut node, unix_now() + 600);
    assert_eq!(node.height(), 0);
    assert!(node.protocol_time() >= genesis_time + 600, "the wall clock moved on");

    // The registration is dated in the chain's time, as the gateway dates it.
    let registration = register_tx(
        &founder,
        "founder@gmail.com",
        "INVITE-LATE",
        node.head_state().last_timestamp,
    );
    node.submit_transaction(registration)
        .expect("the registration is poolable");

    assert!(
        node.mine_once().is_some(),
        "a chain whose founder arrives late must still be able to start: {:?}",
        node.recent_events(8)
    );
    assert_eq!(node.height(), 1);
    assert!(node.head_state().genesis_issued, "the allocation is issued once");
    assert_eq!(
        node.head_state().treasury,
        Some(address_of(&founder)),
        "the genesis wallet is the treasury"
    );
}

/// An authorisation dated beyond what the chain's own time can reach is refused
/// outright: the pool will not take it, and the chain is told why.
///
/// This is the fail-closed half.  A client that dates an authorisation with its
/// own wall clock while the chain has not reached that time produces exactly
/// this transaction, and it is better refused with a rule than accepted and
/// never applied.
#[test]
fn a_registration_dated_beyond_the_chain_is_refused_with_a_rule() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[23u8; 32]);
    let mut node = devnet.node("future-stamp", 24, Some(&founder));

    let genesis_time = node.head_state().last_timestamp;
    // The node's own clock moves ahead, but the chain is still at its epoch and
    // can only reach sixty seconds per block.  An authorisation an hour into the
    // future cannot be part of any block the chain is able to build.
    set_clock_to(&mut node, unix_now() + 600);
    let registration = register_tx(&founder, "late@gmail.com", "INVITE-LATE", genesis_time + 3_600);
    match node.submit_transaction(registration) {
        Ok(_) => panic!("an authorisation from the chain's future must not be pooled"),
        Err(error) => assert!(
            format!("{:?}", error).contains("invite_not_yet_valid"),
            "the refusal names the rule that caught it: {:?}",
            error
        ),
    }
    assert_eq!(node.height(), 0);
    assert!(!node.head_state().genesis_issued, "nothing was minted");
}

/// The subtler half of the same hazard, pinned so it cannot come back silently.
///
/// An authorisation stamped *after the chain's reach but before the node's own
/// clock* passes the pool — the pool judges validity against the present, not
/// against the block that may carry it — and then no block can include it.  On a
/// running chain that costs a delay; on a network's **first** block it would be a
/// deadlock, because block 1 is the only block that can carry the founder's
/// registration.  The state stays clean (height 0, nothing minted, no
/// allocation), which is why the fix belongs at the issuer: the gateway and
/// `obs-cli` date authorisations in the chain's time (see
/// [`a_founder_registering_long_after_the_epoch_still_founds_the_chain`]).
#[test]
fn a_registration_ahead_of_the_chain_but_inside_the_clock_mints_nothing() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[25u8; 32]);
    let mut node = devnet.node("ahead-of-chain", 26, Some(&founder));

    let genesis_time = node.head_state().last_timestamp;
    // Ahead of the chain's reach (epoch + 60), behind the node's clock (+600).
    set_clock_to(&mut node, unix_now() + 600);
    let stamp = genesis_time + 300;
    let registration = register_tx(&founder, "ahead@gmail.com", "INVITE-AHEAD", stamp);
    node.submit_transaction(registration)
        .expect("the pool judges this against the present, and the present has arrived");

    assert!(
        node.mine_once().is_none(),
        "the chain must not produce a block it cannot validate"
    );
    assert_eq!(node.height(), 0, "no block landed");
    assert!(!node.head_state().genesis_issued, "no allocation was minted");
    assert!(
        node.head_state().treasury.is_none(),
        "the treasury is not set by a block that never applied"
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
        wait_until(TEST_DEADLINE, || {
            !miner.with(|node| node.peer_status()).is_empty()
                && !follower.with(|node| node.peer_status()).is_empty()
        }),
        "the two nodes connect"
    );

    // Walk the miner's protocol time forward four hours: that is 240 blocks and
    // a claim, all of which the follower must receive, validate and apply.
    //
    // 240 blocks is also deliberately more than `MAX_BLOCKS_PER_MESSAGE` (128):
    // a batch is bounded by the protocol, so catching up needs several, and a
    // node that stops after the first one is stranded exactly one batch into the
    // chain.  That was a real defect — a second node on a live devnet sat at
    // height 128 forever — so this test exists to keep the catch-up honest.
    miner.with(|node| advance(node, CLAIM_INTERVAL_SECS + 60));
    let target_height = miner.with(|node| node.height());
    assert!(
        target_height > MAX_BLOCKS_PER_MESSAGE as u64,
        "the test must require more than one sync batch: {} blocks",
        target_height
    );
    let target_head = miner.with(|node| node.head());
    let target_state_root = miner.with(|node| node.head_state().state_root());
    assert!(target_height >= 200, "the miner advanced protocol time: {}", target_height);
    assert_eq!(miner.with(|node| node.head_state().total_claims), 2);

    // The miner keeps producing while the follower catches up, so the assertion
    // is on the *prefix* the follower was asked to reach, not on the head: the
    // follower must have applied the miner's block at that exact height.  Block
    // hashes commit to the header, and the header carries the state root, so
    // equal hashes at a height mean equal state there — the stronger claim.
    assert!(
        wait_until(TEST_DEADLINE, || {
            follower.with(|node| node.height() >= target_height)
        }),
        "the follower reached the target height {}: follower at {}",
        target_height,
        follower.with(|node| node.height())
    );
    assert_eq!(
        follower.with(|node| node.canonical_hash(target_height)),
        Some(target_head),
        "the follower's block at the target height is the miner's block"
    );
    assert_eq!(
        follower.with(|node| node.head_state().total_claims),
        2,
        "and it applied the same claims"
    );
    let _ = target_state_root;
}

/// A node that joins an existing chain must catch up past the first batch.
///
/// On a live devnet a second node sat at height 128 forever: it applied the one
/// batch of blocks it had asked for and never asked for another, so it could
/// only ever reach `MAX_BLOCKS_PER_MESSAGE` into a chain that was already
/// hundreds of blocks long.  The other sync test does not catch that — its
/// follower is connected from the start and follows block by block — so this one
/// deliberately builds history *before* anyone joins.
#[test]
fn a_node_that_joins_late_catches_up_across_batches() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[64u8; 32]);
    let miner = Running::start(devnet.node("late-miner", 65, Some(&founder)));
    let miner_addr = miner.with(|node| node.listen_addr());
    register_account_in(&miner, &founder, "lateminer");

    // More than one message's worth of history exists before the joiner starts.
    miner.with(|node| advance(node, 60 * (MAX_BLOCKS_PER_MESSAGE as u64 + 22)));
    let target_height = miner.with(|node| node.height());
    let target_head = miner.with(|node| node.head());
    assert!(
        target_height > MAX_BLOCKS_PER_MESSAGE as u64,
        "the chain must be longer than one sync batch: {}",
        target_height
    );

    let joiner = Running::start(
        Node::open(devnet.config("late-joiner", 66).with_peers(vec![miner_addr])).unwrap(),
    );
    assert!(
        wait_until(TEST_DEADLINE, || {
            joiner.with(|node| node.height() >= target_height)
        }),
        "the late joiner caught up past the first batch: at {} of {}",
        joiner.with(|node| node.height()),
        target_height
    );
    assert_eq!(
        joiner.with(|node| node.canonical_hash(target_height)),
        Some(target_head),
        "and it is on the same chain, block for block"
    );
}

/// A node that joins a network it did not found must learn its genesis.
///
/// The registration authority is what authorises every registration in the
/// chain's history, so a joiner that does not have it cannot validate block 1
/// of a network whose founder registered: on a live devnet the second node sat
/// at height 0 with nothing but orphan rejections, because its record had an
/// all-zero authority and every block it was handed descends from a block it
/// could not accept.  The authority is a *public* parameter of the network, so
/// the handshake carries it, and this test holds the joiner to nothing but the
/// chain's epoch and a peer address — exactly what an operator joining a
/// deployment has.
#[test]
fn a_joiner_learns_the_networks_registration_authority_from_its_peer() {
    let devnet = Devnet::launch();
    let founder = Keypair::from_seed(&[67u8; 32]);
    let miner = Running::start(devnet.node("learning-miner", 68, Some(&founder)));
    let miner_addr = miner.with(|node| node.listen_addr());

    // Block 1 is the founder's registration: it only validates against the
    // network's registration authority, which is the whole point of the test.
    register_account_in(&miner, &founder, "learningminer");
    assert_eq!(miner.with(|node| node.height()), 1);
    assert!(
        miner.with(|node| node.block_at(1).expect("block 1 exists").transactions.len()) >= 1,
        "block 1 must carry the registration, or this test proves nothing"
    );

    // History longer than one sync batch, so learning the genesis and catching
    // up across batches are covered together.
    miner.with(|node| advance(node, 60 * (MAX_BLOCKS_PER_MESSAGE as u64 + 5)));
    let target_height = miner.with(|node| node.height());
    let target_head = miner.with(|node| node.head());
    assert!(target_height > MAX_BLOCKS_PER_MESSAGE as u64);

    let mut config = devnet
        .config("learning-joiner", 69)
        .with_peers(vec![miner_addr]);
    config.genesis.registration_authority = [0u8; 32];
    let joiner_dir = config.data_dir.clone();
    let joiner = Running::start(Node::open(config).expect("the joiner opens"));
    assert_eq!(
        joiner.with(|node| node.config().genesis.registration_authority),
        [0u8; 32],
        "the joiner starts without the authority, as a real one does"
    );

    assert!(
        wait_until(TEST_DEADLINE, || {
            joiner.with(|node| node.height() >= target_height)
        }),
        "the joiner caught up after learning the genesis: at {} of {}",
        joiner.with(|node| node.height()),
        target_height
    );
    assert_eq!(
        joiner.with(|node| node.canonical_hash(target_height)),
        Some(target_head),
        "and it is on the same chain, block for block"
    );
    assert_eq!(
        joiner.with(|node| node.config().genesis.registration_authority),
        devnet.genesis.registration_authority,
        "the joiner adopted the network's registration authority"
    );
    assert!(
        joiner.with(|node| node.recent_events(4096).iter().any(|event| matches!(
            event,
            NodeEvent::GenesisLearned { authority, .. }
                if *authority == devnet.genesis.registration_authority
        ))),
        "the node records that it learned the genesis from a peer"
    );
    // The record on disk is the chain's identity: a restart must not lose what
    // the handshake taught.
    let record = obs_consensus::store::read_genesis(
        joiner_dir.join(obs_consensus::store::genesis_file_name(NETWORK)),
    )
    .expect("the record reads back")
    .expect("the record exists");
    assert_eq!(
        record.registration_authority,
        devnet.genesis.registration_authority
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
        let client = Client::with_timeout(TEST_DEADLINE);
        json_body(&client.get(&format!("{}{}", self.base(), path)).unwrap()).unwrap()
    }

    fn get_response(&self, path: &str) -> obs_rpc::http::Response {
        Client::with_timeout(TEST_DEADLINE)
            .get(&format!("{}{}", self.base(), path))
            .unwrap()
    }

    fn post(&self, path: &str, body: &Json) -> obs_rpc::http::Response {
        Client::with_timeout(TEST_DEADLINE)
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

/// The block listing can be asked for the blocks *below* a height.
///
/// Without it a client can only ever see the newest window, which is what made
/// an index started against a running chain permanently unable to hold the
/// history below its first sync.  The parameter is small; the property it buys
/// is that an index can read the whole chain, and the check that it cannot be
/// asked for nonsense is the one this test spends most of its assertions on.
#[test]
fn the_block_listing_can_be_paged_backwards_through_history() {
    let (api, _founder) = api_devnet("pages", 131);
    api.with_node(|node| {
        for _ in 0..6 {
            mine(node);
        }
    });
    let head = api.get("/api/v1/status").get("height").unwrap().as_i128().unwrap() as u64;
    assert!(head >= 7, "the chain has blocks to page through: {}", head);

    // The default is still the newest window, unchanged.
    let newest = api.get("/api/v1/blocks?limit=2");
    let heights: Vec<u64> = newest
        .get("blocks")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|block| block.get("height").unwrap().as_i128().unwrap() as u64)
        .collect();
    assert_eq!(heights, vec![head, head - 1]);

    // `before` starts the page at that height, walking down: the window an index
    // needs to read history it was not running for.
    let older = api.get(&format!("/api/v1/blocks?limit=3&before={}", head - 2));
    let heights: Vec<u64> = older
        .get("blocks")
        .unwrap()
        .as_array()
        .unwrap()
        .iter()
        .map(|block| block.get("height").unwrap().as_i128().unwrap() as u64)
        .collect();
    assert_eq!(heights, vec![head - 2, head - 3, head - 4]);

    // Paging down to the genesis block and then asking for the block below it
    // gives an empty page rather than an error or a wrapped height.
    let bottom = api.get("/api/v1/blocks?limit=4&before=1");
    assert_eq!(bottom.get("count").unwrap().as_i128(), Some(1));
    assert_eq!(
        bottom.get("blocks").unwrap().as_array().unwrap()[0]
            .get("height")
            .unwrap()
            .as_i128(),
        Some(1)
    );
    let below = api.get("/api/v1/blocks?limit=4&before=0");
    assert_eq!(below.get("count").unwrap().as_i128(), Some(0));
    assert_eq!(below.get("blocks").unwrap().as_array().unwrap().len(), 0);

    // Nonsense is not a cursor: an unparsable or absent `before` is the default
    // window, and a height above the head is clamped to the head.
    for query in ["/api/v1/blocks?limit=2&before=abc", "/api/v1/blocks?limit=2&before=-4"] {
        let page = api.get(query);
        assert_eq!(
            page.get("blocks").unwrap().as_array().unwrap()[0]
                .get("height")
                .unwrap()
                .as_i128(),
            Some(head as i128),
            "{} falls back to the newest window",
            query
        );
    }
    let clamped = api.get(&format!("/api/v1/blocks?limit=1&before={}", head + 1_000));
    assert_eq!(
        clamped.get("blocks").unwrap().as_array().unwrap()[0]
            .get("height")
            .unwrap()
            .as_i128(),
        Some(head as i128)
    );
    // And the page limit is still bounded, whatever `before` says.
    let huge = api.get("/api/v1/blocks?limit=100000&before=1000");
    assert!(huge.get("blocks").unwrap().as_array().unwrap().len() <= 200);
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

/// A configured peer that restarts is dialled again.
///
/// The defect this test exists for: `--peer` was a one-shot dial at startup, so
/// a peer that was not listening at that moment — because it had not started
/// yet, or because it had just been restarted — was never tried again.  The two
/// nodes then stayed apart until somebody restarted one of them by hand, which
/// on a two-host network looks exactly like a chain that has stopped, and is the
/// kind of thing an operator discovers at three in the morning.
///
/// The test does the real thing: a node, a peer that is taken away, and a peer
/// that comes back on the same address.
#[test]
fn a_configured_peer_that_restarts_is_dialled_again() {
    let devnet = Devnet::launch();
    let seed = Keypair::from_seed(&[71u8; 32]);

    let peer = Running::start(devnet.node("restart-peer", 71, Some(&seed)));
    let peer_addr = peer.with(|node| node.listen_addr());

    let follower = Running::start(
        Node::open(devnet.config("restart-follower", 72).with_peers(vec![peer_addr])).unwrap(),
    );
    assert!(
        wait_until(TEST_DEADLINE, || follower
            .with(|node| !node.peer_status().is_empty())),
        "the follower connects to the peer it was told about"
    );

    // The peer goes away.  The follower must notice: a peer list that still
    // claims a dead connection would make the next assertion meaningless.
    drop(peer);
    assert!(
        wait_until(TEST_DEADLINE, || follower
            .with(|node| node.peer_status().is_empty())),
        "the follower notices the peer is gone"
    );

    // The peer comes back on the same address, as a restart does.  The node's
    // identity is new — a restart is a new process — so the connection that
    // forms is a genuinely new one, not a half-open socket that was never
    // cleaned up.
    let mut config = devnet.config("restart-peer-again", 73);
    config.listen_port = peer_addr.port();
    config.mine = true;
    config.mining_key = Some(Keypair::from_seed(&[71u8; 32]));
    let peer_again = Running::start(Node::open(config).unwrap());

    assert!(
        wait_until(TEST_DEADLINE, || follower
            .with(|node| !node.peer_status().is_empty())),
        "the follower reconnects to the restarted peer without being restarted itself"
    );
    assert!(
        wait_until(TEST_DEADLINE, || peer_again
            .with(|node| !node.peer_status().is_empty())),
        "the restarted peer sees the follower too"
    );
}
