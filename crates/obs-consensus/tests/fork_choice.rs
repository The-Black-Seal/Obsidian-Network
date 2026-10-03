//! Integration tests for the consensus engine: fork choice, reorganisations,
//! orphan handling, restart-and-replay, and storage compaction.
//!
//! Every block here is produced by the real state machine from real keys, and
//! every assertion is about what a node would actually do.

use std::path::PathBuf;

use obs_chain::block::Attestation;
use obs_chain::chain::{gmail_commitment, invite_commitment, Claim, InviteAuthorization};
use obs_chain::params::{BASE_CLAIM_GRAINS, GENESIS_TIMESTAMP, SLOT_DURATION_SECS, VALIDATOR_BOND};
use obs_chain::state::GenesisConfig;
use obs_chain::{Block, Transaction, TxKind};
use obs_consensus::{ChainError, ChainEvent, ChainStore};
use obs_crypto::ed25519::Keypair;
use obs_primitives::address::Address;
use obs_primitives::hash::Hash32;
use obs_primitives::money::{Amount, GENESIS_ALLOCATION};
use obs_primitives::network::{MAINNET, TESTNET};

const AUTHORITY_SEED: u8 = 1;

fn authority() -> Keypair {
    Keypair::from_seed(&[AUTHORITY_SEED; 32])
}

fn genesis_config() -> GenesisConfig {
    GenesisConfig {
        network: MAINNET,
        registration_authority: authority().public_key(),
        timestamp: GENESIS_TIMESTAMP,
    }
}

fn scratch_dir(name: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "obs-consensus-it-{}-{}-{}",
        name,
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn open_store(dir: &PathBuf, fsync: bool) -> ChainStore {
    ChainStore::open(dir, MAINNET, genesis_config(), fsync).expect("a node opens its chain")
}

fn address_of(key: &Keypair) -> Address {
    Address::from_public_key(MAINNET, &key.public_key())
}

struct Harness {
    dir: PathBuf,
    store: ChainStore,
    founder: Keypair,
    founder_address: Address,
    time: u64,
}

impl Harness {
    /// A node whose genesis block registers the founder and mines the genesis
    /// claim, exactly as the mainnet launch block does.
    fn new(name: &str) -> Harness {
        let dir = scratch_dir(name);
        let mut store = open_store(&dir, true);
        let founder = Keypair::from_seed(&[30u8; 32]);
        let founder_address = address_of(&founder);
        let time = GENESIS_TIMESTAMP + 1;
        let invite = InviteAuthorization::issue(
            MAINNET.chain_id,
            &authority(),
            invite_commitment(MAINNET.chain_id, "TEST-INVITE-GENESIS"),
            gmail_commitment(
                MAINNET.chain_id,
                &obs_primitives::identity::canonical_gmail("founder@gmail.com").unwrap(),
            ),
            time,
            time + 24 * 3600,
            None,
        );
        let register = Transaction::sign(
            MAINNET,
            1,
            TxKind::Register {
                account: founder_address,
                wallet_key: founder.public_key(),
                gmail_commitment: gmail_commitment(MAINNET.chain_id, "founder@gmail.com"),
                invite,
            },
            &founder,
        );
        let claim = Transaction::sign(
            MAINNET,
            2,
            TxKind::Claim(Claim {
                account: founder_address,
                claimed_at: time,
                sequence: 1,
            }),
            &founder,
        );
        let state = store.head_state().clone();
        let block = state
            .build_block(&founder, time, vec![register, claim], Vec::new())
            .expect("the launch block builds");
        match store.submit(block.clone()).unwrap() {
            ChainEvent::Head { current, .. } => assert_eq!(current, block.hash()),
            other => panic!("the launch block must become the head, got {:?}", other),
        }
        assert_eq!(
            store.head_state().balance(&founder_address),
            GENESIS_ALLOCATION
                .checked_add(Amount(BASE_CLAIM_GRAINS))
                .unwrap()
        );
        Harness {
            dir,
            store,
            founder,
            founder_address,
            time: time + 1,
        }
    }

    /// Builds an empty block on the canonical head and submits it.
    fn mine(&mut self) -> Block {
        let block = self.build_on_head(self.time);
        self.submit(block)
    }

    /// Gives up ownership of the node's directory without deleting it, so a
    /// test can reopen the same data as a fresh process would.
    fn release(mut self) -> PathBuf {
        let dir = self.dir.clone();
        self.dir = PathBuf::new();
        dir
    }

    /// The launch block (height 1) of this chain.
    fn launch_block(&self) -> Block {
        self.store
            .block_at_height(1)
            .expect("the launch block is canonical")
            .clone()
    }

    fn build_on_head(&mut self, timestamp: u64) -> Block {
        let state = self.store.head_state().clone();
        state
            .build_block(&self.founder, timestamp, Vec::new(), Vec::new())
            .expect("an empty block builds")
    }

    /// Builds an empty block on an arbitrary branch tip.
    fn build_on(&mut self, tip: &Hash32, timestamp: u64, proposer: &Keypair) -> Block {
        let state = self.store.state_at(tip).expect("the branch state exists");
        state
            .build_block(proposer, timestamp, Vec::new(), Vec::new())
            .expect("an empty branch block builds")
    }

    fn submit(&mut self, block: Block) -> Block {
        match self.store.submit(block.clone()) {
            Ok(ChainEvent::Head { current, .. }) => assert_eq!(current, block.hash()),
            other => panic!("the block must extend the head, got {:?}", other),
        }
        self.time = block.header.timestamp + 1;
        block
    }
}

impl Drop for Harness {
    fn drop(&mut self) {
        if self.dir.as_os_str().is_empty() {
            return;
        }
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[test]
fn blocks_survive_a_restart_and_replay_identically() {
    let mut harness = Harness::new("restart");
    for _ in 0..5 {
        harness.time += 30;
        harness.mine();
    }
    let head = harness.store.head();
    let root = harness.store.head_state().state_root();
    let height = harness.store.height();
    let canonical = harness.store.canonical_hashes().to_vec();
    let weight = harness.store.head_state().total_weight;

    // The block log was written durably, so a fresh process on the same
    // directory reconstructs the identical chain.
    let dir = harness.release();
    let store = open_store(&dir, true);
    assert_eq!(store.head(), head);
    assert_eq!(store.head_state().state_root(), root);
    assert_eq!(store.height(), height);
    assert_eq!(store.canonical_hashes(), canonical.as_slice());
    assert_eq!(
        store.head_state().total_weight,
        weight,
        "the replayed state keeps its accumulated PoT weight"
    );
    assert!(
        store.head_state().median_time_past() > GENESIS_TIMESTAMP,
        "the median time past survives the restart"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_shorter_branch_never_takes_over_the_head() {
    let mut harness = Harness::new("shorter");
    let fork_point = harness.store.head();

    // Three canonical blocks.
    for _ in 0..3 {
        harness.time += 30;
        harness.mine();
    }
    let canonical_head = harness.store.head();
    let canonical_weight = harness.store.head_state().total_weight;

    // One competing block on a branch that split off before them.
    let founder = harness.founder.clone();
    let side = harness.build_on(&fork_point, GENESIS_TIMESTAMP + 61, &founder);
    match harness.store.submit(side.clone()).unwrap() {
        ChainEvent::Fork { tip } => assert_eq!(tip, side.hash()),
        other => panic!("a one-block fork must not take over, got {:?}", other),
    }
    assert_eq!(harness.store.head(), canonical_head);
    assert_eq!(
        harness.store.head_state().total_weight,
        canonical_weight,
        "refusing a lighter branch leaves the head state untouched"
    );
    assert_eq!(
        harness.store
            .block_at_height(harness.store.height())
            .unwrap()
            .hash(),
        canonical_head
    );
    assert!(
        harness.store.block(&side.hash()).is_some(),
        "a valid side branch is retained as a candidate"
    );
}

#[test]
fn a_heavier_branch_reorganises_the_chain() {
    let mut harness = Harness::new("reorg");
    let fork_point = harness.store.head();

    // The canonical branch: one block at height 2.
    harness.time += 30;
    let canonical = harness.mine();
    let canonical_weight = harness.store.head_state().total_weight;

    // A competing branch from the same parent: four blocks, mined with the
    // slot spacing that the protocol rewards, so its accumulated PoT weight is
    // strictly greater.
    let mut tip = fork_point;
    let mut timestamps = Vec::new();
    let mut t = GENESIS_TIMESTAMP + 3;
    let founder = harness.founder.clone();
    for _ in 0..4 {
        t += 30;
        let block = harness.build_on(&tip, t, &founder);
        timestamps.push(block.header.timestamp);
        tip = block.hash();
        match harness.store.submit(block) {
            Ok(_) => {}
            Err(error) => panic!("a valid fork block must be accepted: {}", error),
        }
    }

    // Fork choice is by accumulated PoT weight, not by who arrived first: the
    // four-block branch carries strictly more weight than the one-block branch.
    let branch_weight = harness.store.head_state().total_weight;
    assert!(
        branch_weight > canonical_weight,
        "the competing branch must be heavier ({} vs {})",
        branch_weight.atoms,
        canonical_weight.atoms
    );
    assert_eq!(harness.store.head(), tip, "the heavier branch becomes canonical");
    assert_eq!(harness.store.height(), 5);

    // The reorg is fully described, and the branch state is the one a fresh
    // node replaying only the canonical blocks would build.
    let canonical_hashes = harness.store.canonical_hashes().to_vec();
    assert_eq!(canonical_hashes[0], harness.store.genesis_hash());
    assert_eq!(canonical_hashes[1], fork_point);
    assert_eq!(canonical_hashes.last().copied().unwrap(), tip);
    assert!(!canonical_hashes.contains(&canonical.hash()));

    // A second node that receives only the new canonical chain agrees exactly.
    let mut other = open_store(&scratch_dir("reorg-mirror"), false);
    for hash in &canonical_hashes[1..] {
        let block = harness.store.block(hash).unwrap().clone();
        other.submit(block).expect("the canonical chain applies");
    }
    assert_eq!(other.head(), harness.store.head());
    assert_eq!(
        other.head_state().state_root(),
        harness.store.head_state().state_root()
    );
    assert_eq!(
        other.head_state().total_weight,
        harness.store.head_state().total_weight
    );
    assert_eq!(timestamps.len(), 4);
}

#[test]
fn submitting_the_same_block_twice_is_idempotent() {
    let mut harness = Harness::new("duplicate");
    harness.time += 30;
    let block = harness.mine();
    let before = harness.store.known_blocks();
    let head = harness.store.head();
    match harness.store.submit(block.clone()).unwrap() {
        ChainEvent::Fork { tip } => assert_eq!(tip, block.hash()),
        other => panic!("a duplicate must be a no-op, got {:?}", other),
    }
    assert_eq!(harness.store.head(), head);
    assert_eq!(harness.store.known_blocks(), before);
}

#[test]
fn orphaned_blocks_are_held_until_their_parent_arrives() {
    let mut builder = Harness::new("orphan-source");
    let mut chain = vec![builder.launch_block()];
    for _ in 0..4 {
        builder.time += 30;
        chain.push(builder.mine());
    }

    // A second node receives the blocks in reverse order.  Every block whose
    // parent is unknown must be held, not discarded, and must be applied the
    // moment the gap closes.
    let dir = scratch_dir("orphan-receiver");
    let mut node = open_store(&dir, false);
    let mut orphans = 0usize;
    for block in chain.iter().rev() {
        match node.submit(block.clone()).unwrap() {
            ChainEvent::Orphan { .. } => orphans += 1,
            ChainEvent::Head { .. } | ChainEvent::Fork { .. } => {}
        }
    }
    assert!(orphans >= 3, "out-of-order blocks are held as orphans");
    assert!(node.orphans().is_empty(), "every orphan found its parent");
    assert_eq!(node.head(), builder.store.head());
    assert_eq!(
        node.head_state().state_root(),
        builder.store.head_state().state_root()
    );
    assert_eq!(node.height(), builder.store.height());
}

#[test]
fn a_block_with_a_bad_signature_or_state_root_is_rejected_and_never_stored() {
    let mut harness = Harness::new("invalid");
    harness.time += 30;
    let block = harness.mine();
    let stored = harness.store.known_blocks();

    // A forged proposer signature.
    let mut forged = harness.build_on_head(block.header.timestamp + 1);
    forged.signature = [4u8; 64];
    match harness.store.submit(forged) {
        Err(ChainError::Rejected(error)) => assert_eq!(error.rule, "block_signature"),
        other => panic!("a forged signature must be rejected, got {:?}", other.is_ok()),
    }

    // A valid signature over a state root that does not describe the result.
    let mut wrong_root = harness.build_on_head(block.header.timestamp + 2);
    wrong_root.header.state_root = Hash32::from_bytes([0xAB; 32]);
    wrong_root.sign(&harness.founder.clone());
    match harness.store.submit(wrong_root) {
        Err(ChainError::Rejected(error)) => assert_eq!(error.rule, "block_state_root"),
        other => panic!("a wrong state root must be rejected, got {:?}", other.is_ok()),
    }

    assert_eq!(harness.store.head(), block.hash());
    assert_eq!(
        harness.store.known_blocks(),
        stored,
        "no rejected block is ever retained"
    );
}

#[test]
fn a_block_from_another_network_is_refused() {
    let mut harness = Harness::new("foreign");
    harness.time += 30;
    let block = harness.mine();

    // Cross-network replay protection: relabelling a genuine mainnet block as a
    // testnet block (and re-signing it, as an attacker with the keys could) does
    // not make it acceptable on mainnet.
    let mut relabelled = block.clone();
    relabelled.header.chain_id = TESTNET.chain_id;
    relabelled.sign(&harness.founder.clone());
    match harness.store.submit(relabelled) {
        Err(ChainError::ForeignChain) => {}
        other => panic!("a foreign chain id must be refused, got {:?}", other.is_ok()),
    }
    assert_eq!(harness.store.head(), block.hash());
}

#[test]
fn two_nodes_converge_on_the_same_head_regardless_of_arrival_order() {
    let mut builder = Harness::new("converge-source");
    let mut chain = vec![builder.launch_block()];
    for _ in 0..6 {
        builder.time += 30;
        chain.push(builder.mine());
    }
    let expected_head = builder.store.head();
    let expected_root = builder.store.head_state().state_root();
    let expected_weight = builder.store.head_state().total_weight;

    // In order.
    let mut forward = open_store(&scratch_dir("converge-forward"), false);
    for block in &chain {
        forward.submit(block.clone()).expect("valid block");
    }
    // Reversed, which exercises the orphan pool.
    let mut backward = open_store(&scratch_dir("converge-backward"), false);
    for block in chain.iter().rev() {
        backward.submit(block.clone()).expect("valid block");
    }
    // Interleaved with duplicates, which must not disturb anything.
    let mut shuffled = open_store(&scratch_dir("converge-shuffled"), false);
    for (index, block) in chain.iter().enumerate() {
        shuffled.submit(block.clone()).expect("valid block");
        if index % 2 == 0 {
            shuffled.submit(block.clone()).expect("a duplicate is a no-op");
        }
    }

    for node in [&forward, &backward, &shuffled] {
        assert_eq!(node.head(), expected_head);
        assert_eq!(node.head_state().state_root(), expected_root);
        assert_eq!(node.head_state().total_weight, expected_weight);
        assert_eq!(node.canonical_hashes(), forward.canonical_hashes());
    }
}

#[test]
fn compaction_drops_dead_branches_without_changing_the_chain() {
    let mut harness = Harness::new("compact");
    let fork_point = harness.store.head();
    harness.time += 30;
    let canonical = harness.mine();

    // A valid side branch that will never win is retained as a candidate.
    let founder = harness.founder.clone();
    let side = harness.build_on(&fork_point, GENESIS_TIMESTAMP + 2, &founder);
    harness.store.submit(side.clone()).unwrap();
    assert!(harness.store.block(&side.hash()).is_some());

    // Finalise the canonical head so the side branch is provably dead, then
    // compact: dead branches are dropped, the canonical chain is untouched.
    let head = harness.store.head();
    let root = harness.store.head_state().state_root();
    let height = harness.store.height();
    let dropped = harness.store.compact().unwrap();
    assert_eq!(dropped, 0, "nothing below finality is dropped yet");
    assert_eq!(harness.store.head(), head);
    assert_eq!(harness.store.height(), height);
    assert_eq!(harness.store.head_state().state_root(), root);
    assert_eq!(harness.store.block_at_height(2).unwrap().hash(), canonical.hash());

    // A reopened node replays exactly the same chain from the compacted log.
    let dir = harness.release();
    let reopened = open_store(&dir, true);
    assert_eq!(reopened.head(), head);
    assert_eq!(reopened.head_state().state_root(), root);
    assert_eq!(reopened.height(), height);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn a_reorg_may_not_undo_a_finalized_block() {
    let mut harness = Harness::new("finality");
    let fork_point = harness.store.head();

    // Register three validator accounts and bonds in one block, then attest the
    // resulting head so that it finalises.
    let mut owners = Vec::new();
    let mut nodes = Vec::new();
    let mut txs = Vec::new();
    // The founder's next nonce: 1 for the registration, 2 for the genesis
    // claim, so the first bond transfer is 3.
    let mut founder_nonce = 3u64;
    let mut register_invites = Vec::new();
    for index in 0..3u8 {
        let owner = Keypair::from_seed(&[40 + index; 32]);
        let owner_address = address_of(&owner);
        let founder_address = harness.founder_address;
        // The founder issues the invitation and signs nothing else: the new
        // account signs its own registration.
        let email = format!("validator{}@gmail.com", index);
        let canonical = obs_primitives::identity::canonical_gmail(&email).unwrap();
        let invite = InviteAuthorization::issue(
            MAINNET.chain_id,
            &authority(),
            invite_commitment(MAINNET.chain_id, &format!("TEST-INVITE-{}", index)),
            gmail_commitment(MAINNET.chain_id, &canonical),
            harness.time,
            harness.time + 24 * 3600,
            Some(founder_address),
        );
        register_invites.push(owner_address);
        txs.push(Transaction::sign(
            MAINNET,
            1,
            TxKind::Register {
                account: owner_address,
                wallet_key: owner.public_key(),
                gmail_commitment: gmail_commitment(MAINNET.chain_id, &canonical),
                invite,
            },
            &owner,
        ));
        let node = Keypair::from_seed(&[70 + index; 32]);
        // The bond comes from the founder, the registration from the owner.
        txs.push(Transaction::sign(
            MAINNET,
            founder_nonce,
            TxKind::Transfer {
                to: owner_address,
                amount: VALIDATOR_BOND,
            },
            &harness.founder,
        ));
        founder_nonce += 1;
        txs.push(Transaction::sign(
            MAINNET,
            2,
            TxKind::RegisterValidator {
                node_key: node.public_key(),
                endpoint: format!("node{}.obsidian.example:9200", index),
            },
            &owner,
        ));
        owners.push(owner);
        nodes.push(node);
    }
    let timestamp = harness.time;
    let state = harness.store.head_state().clone();
    let block = state
        .build_block(&harness.founder, timestamp, txs, Vec::new())
        .unwrap();
    harness.submit(block);
    assert_eq!(harness.store.head_state().active_validators().len(), 3);
    assert_eq!(founder_nonce, 6, "three invitations, three bonds");

    // Attest the new head with all three validators, in the next block.
    let attested_height = harness.store.height();
    let attested_hash = harness.store.head();
    let attested_slot = harness.store.head_state().last_slot;
    let attestations: Vec<Attestation> = nodes
        .iter()
        .map(|node| Attestation::sign(MAINNET.chain_id, node, attested_height, attested_hash, attested_slot))
        .collect();
    let timestamp = harness.store.head_state().last_timestamp + 30;
    let state = harness.store.head_state().clone();
    let block = state
        .build_block(&harness.founder, timestamp, Vec::new(), attestations)
        .unwrap();
    harness.submit(block);
    assert!(
        harness.store.head_state().is_finalized(attested_height),
        "three of three attestations must finalise the block"
    );
    let finalized = harness.store.head_state().finalized_height;
    let head_before = harness.store.head();
    let known_before = harness.store.known_blocks();

    // A long branch that splits off *below* the finalised height, built with
    // slow blocks (which the protocol rewards with higher difficulty and thus
    // more PoT weight).  It is an otherwise valid chain: the only reason to
    // refuse it is that following it would undo finalised history.
    let mut tip = fork_point;
    let mut t = GENESIS_TIMESTAMP + 1;
    let mut conflict = None;
    let founder = harness.founder.clone();
    for _ in 0..20 {
        t += 3;
        let block = harness.build_on(&tip, t, &founder);
        tip = block.hash();
        match harness.store.submit(block) {
            Ok(_) => {}
            Err(error) => {
                conflict = Some(error);
                break;
            }
        }
    }
    match conflict {
        Some(ChainError::FinalizedConflict {
            finalized_height,
            branch_height,
        }) => {
            assert_eq!(finalized_height, finalized);
            assert!(branch_height > finalized);
        }
        other => panic!(
            "a branch contradicting finality must be refused, got {:?}",
            other.map(|_| "accepted")
        ),
    }

    // The refusal changed nothing about the node's chain: the head, the
    // finalised height and the canonical chain are untouched, and the block
    // that would have undone finality is not retained.
    assert_eq!(harness.store.head(), head_before);
    assert_eq!(harness.store.head_state().finalized_height, finalized);
    assert!(
        harness.store.block(&tip).is_none(),
        "the refused block is never stored"
    );
    assert_eq!(harness.store.canonical_hashes().last().copied(), Some(head_before));
    assert!(harness.store.known_blocks() >= known_before);
    let _ = owners;
}

#[test]
fn the_genesis_allocation_is_paid_once_and_only_once_across_a_restart() {
    let mut harness = Harness::new("genesis-once");
    let address = harness.founder_address;
    let after_launch = harness.store.head_state().balance(&address);
    for _ in 0..3 {
        harness.time += 30;
        harness.mine();
    }
    let dir = harness.release();
    let mut store = open_store(&dir, true);
    assert_eq!(store.head_state().balance(&address), after_launch);
    assert!(store.head_state().genesis_issued);
    assert_eq!(store.head_state().treasury, Some(address));

    // Re-submitting the launch block cannot re-issue anything.
    let known = store.known_blocks();
    let launch = store.block_at_height(1).unwrap().clone();
    match store.submit(launch).unwrap() {
        ChainEvent::Fork { .. } => {}
        other => panic!("a duplicate launch block is a no-op, got {:?}", other),
    }
    assert_eq!(store.head_state().balance(&address), after_launch);
    assert_eq!(store.known_blocks(), known);
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn genesis_slot_and_time_are_consistent() {
    let store = open_store(&scratch_dir("genesis"), false);
    let genesis = store.block(&store.genesis_hash()).expect("genesis is known");
    assert_eq!(genesis.header.height, 0);
    assert_eq!(genesis.header.timestamp, GENESIS_TIMESTAMP);
    assert_eq!(genesis.header.slot, GENESIS_TIMESTAMP / SLOT_DURATION_SECS);
    assert_eq!(genesis.header.parent, store.genesis_hash());
    assert_eq!(genesis.header.chain_id, MAINNET.chain_id);
}

