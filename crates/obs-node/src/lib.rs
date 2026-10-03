//! # obs-node — the Obsidian full node
//!
//! A node is the meeting point of everything else in the workspace, and it is
//! deliberately the only place where they meet:
//!
//! ```text
//!   obs-p2p  ──blocks, transactions, attestations──▶  obs-node  ──▶  obs-consensus (fork choice, storage)
//!   obs-rpc  ◀──read-only views, submission────────┘        │
//!                                                            ├──▶  obs-mempool   (policy)
//!                                                            └──▶  obs-chain     (validation, state)
//! ```
//!
//! ## The loop
//!
//! [`Node::step`] is one iteration of the node's life: drain the peers, apply
//! what validates, relay what was accepted, maybe produce a block, and expire
//! stale pool entries.  Nothing in the node invents state — it only moves data
//! between the layers above, and each layer enforces its own rules.
//!
//! ## What a node will not do
//!
//! * It will not accept a block that [`obs_chain`] rejects, whatever the peer
//!   says and however many peers say it.  A block that fails validation is
//!   dropped and the peer is told why.
//! * It will not accept a transaction the pool refuses, whether it arrived over
//!   the API or from a peer.
//! * It will not build a block it would reject: the candidate list is applied to
//!   a *probe* copy of the state first, and the built block still has to pass
//!   `apply_block` like any other.
//! * It will not mine for an account it does not hold the key for.  A node
//!   holds keys only for the accounts its operator owns.
//!
//! ## Protocol time
//!
//! Block timestamps come from the node's clock, but never freely: a candidate
//! timestamp is clamped into `[head + 1, head + MAX_BLOCK_DRIFT_SECS]`, and the
//! chain re-checks it against median time past.  A node with a badly wrong clock
//! can therefore be *late*, but it cannot drag the network's time forwards.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod rpc;

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use obs_chain::block::Attestation;
use obs_chain::chain::{Claim, TxId};
use obs_chain::params::{
    ATTESTATION_WINDOW_BLOCKS, CLAIM_INTERVAL_SECS, GENESIS_TIMESTAMP,
    MAX_ATTESTATIONS_PER_BLOCK, MAX_BLOCK_DRIFT_SECS,
    MAX_CLAIMS_PER_DAY, MAX_INVITES_PER_ACCOUNT, MAX_TXS_PER_BLOCK, MIN_BLOCK_SPACING_SECS,
    PROTOCOL_DAY_SECS, PROTOCOL_VERSION, SLOT_DURATION_SECS, UNBONDING_PERIOD_SECS,
};
use obs_chain::state::GenesisConfig;
use obs_chain::{Block, ChainState, Transaction, TxKind};
use obs_consensus::{ChainError, ChainEvent, ChainStore, Reorg};
use obs_crypto::ed25519::Keypair;
use obs_mempool::{transaction_fee, Mempool, MempoolConfig, MempoolError, MempoolStats};
use obs_p2p::protocol::{GetBlocks, NetMessage, Reject, RejectCode, Status, MAX_BLOCKS_PER_MESSAGE};
use obs_p2p::{PeerConfig, PeerEvent, PeerManager, PeerStatus};
use obs_primitives::address::Address;
use obs_primitives::hash::Hash32;
use obs_primitives::money::Amount;
use obs_primitives::network::{Network, MAINNET};

/// How a node is configured.
#[derive(Clone)]
pub struct NodeConfig {
    /// Network this node runs.
    pub network: Network,
    /// Directory holding the block log and the head pointer.
    pub data_dir: PathBuf,
    /// Genesis configuration (registration authority, genesis time).
    pub genesis: GenesisConfig,
    /// This node's identity key for peer connections.  Distinct from every
    /// wallet key; operators normally also use it as the validator node key so
    /// that attestations are attributable.
    pub node_key: Keypair,
    /// Port to accept peers on.  Port `0` lets the operating system choose.
    pub listen_port: u16,
    /// Flush every accepted block to disk before reporting it.
    pub fsync: bool,
    /// Maximum established peers.
    pub max_peers: usize,
    /// Peer addresses to dial at startup.
    pub peers: Vec<SocketAddr>,
    /// Produce blocks.  A node that does not mine still validates and relays.
    pub mine: bool,
    /// Wallet key the node mines with.  Its account must be registered before
    /// the node can propose; the chain enforces that, not the node.
    pub mining_key: Option<Keypair>,
    /// Node identity key registered on-chain as a validator, if this node
    /// attests.  Keep it distinct from [`NodeConfig::mining_key`]: a validator's
    /// node identity must not be its wallet key.
    pub validator_key: Option<Keypair>,
    /// Pool limits.
    pub mempool: MempoolConfig,
    /// How often the node proposes a block when mining.  The protocol's slot
    /// spacing is the floor; this paces block production between steps.
    pub block_interval: Duration,
}

impl core::fmt::Debug for NodeConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("NodeConfig")
            .field("network", &self.network.name)
            .field("data_dir", &self.data_dir)
            .field("listen_port", &self.listen_port)
            .field("mine", &self.mine)
            .field("mining_key", &self.mining_key.is_some())
            .field("validator_key", &self.validator_key.is_some())
            .field("peers", &self.peers.len())
            .finish_non_exhaustive()
    }
}

impl NodeConfig {
    /// A node for `network` with the protocol defaults.
    pub fn new(
        network: Network,
        data_dir: impl Into<PathBuf>,
        registration_authority: [u8; 32],
        node_key: Keypair,
    ) -> NodeConfig {
        NodeConfig {
            network,
            data_dir: data_dir.into(),
            genesis: GenesisConfig {
                network,
                registration_authority,
                timestamp: GENESIS_TIMESTAMP,
            },
            node_key,
            listen_port: obs_p2p::DEFAULT_PORT,
            fsync: true,
            max_peers: 32,
            peers: Vec::new(),
            mine: false,
            mining_key: None,
            validator_key: None,
            mempool: MempoolConfig::default(),
            block_interval: Duration::from_secs(5),
        }
    }

    /// A mainnet node with the protocol defaults.
    pub fn mainnet(
        data_dir: impl Into<PathBuf>,
        registration_authority: [u8; 32],
        node_key: Keypair,
    ) -> NodeConfig {
        NodeConfig::new(MAINNET, data_dir, registration_authority, node_key)
    }

    /// Enables block production with the given wallet key.
    pub fn with_mining(mut self, mining_key: Keypair) -> NodeConfig {
        self.mine = true;
        self.mining_key = Some(mining_key);
        self
    }

    /// Enables attestation signing with the given node identity key.
    pub fn with_validator(mut self, validator_key: Keypair) -> NodeConfig {
        self.validator_key = Some(validator_key);
        self
    }

    /// Pins the network's genesis timestamp.
    ///
    /// A chain's protocol time advances at most [`MAX_BLOCK_DRIFT_SECS`] per
    /// block, so a network's genesis epoch *is* its launch moment: the first
    /// block can only carry a timestamp within a minute of genesis.  Mainnet's
    /// epoch is a protocol constant (fixed at the launch ceremony); testnet,
    /// devnet and staging pin their own when the network is created, and every
    /// node of that network must be configured with the same value or it is
    /// simply on a different chain (the genesis hash differs, so peers refuse
    /// each other).
    pub fn with_genesis_timestamp(mut self, timestamp: u64) -> NodeConfig {
        self.genesis.timestamp = timestamp;
        self
    }

    /// Sets the peer list to dial at startup.
    pub fn with_peers(mut self, peers: Vec<SocketAddr>) -> NodeConfig {
        self.peers = peers;
        self
    }

    /// Sets the listening port.
    pub fn with_listen_port(mut self, port: u16) -> NodeConfig {
        self.listen_port = port;
        self
    }

    /// Sets how often the node proposes blocks.
    pub fn with_block_interval(mut self, interval: Duration) -> NodeConfig {
        self.block_interval = interval;
        self
    }
}

/// Things a node reports to its operator and to the API layer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeEvent {
    /// The head moved.
    Head {
        /// New head hash.
        hash: Hash32,
        /// New head height.
        height: u64,
        /// True when the move replaced a previous branch.
        reorg: bool,
        /// Transactions in the block that moved the head.
        transactions: usize,
        /// True when this node proposed the block.
        ours: bool,
    },
    /// A block was refused.
    BlockRejected {
        /// Hash of the refused block.
        hash: Hash32,
        /// Consensus rule that refused it.
        rule: String,
    },
    /// A transaction entered the pool.
    TransactionAccepted {
        /// Transaction id.
        id: Hash32,
    },
    /// A transaction was refused.
    TransactionRejected {
        /// Transaction id.
        id: Hash32,
        /// Machine-readable reason (pool error name or consensus rule).
        reason: String,
    },
    /// A peer connected.
    PeerConnected {
        /// Peer node identity.
        node_key: [u8; 32],
    },
    /// A connection attempt failed before a peer existed.
    PeerRejected {
        /// Why.
        reason: String,
    },
    /// A peer disconnected.
    PeerDisconnected {
        /// Peer node identity.
        node_key: [u8; 32],
        /// Why.
        reason: String,
    },
    /// A block was produced by this node.
    Mined {
        /// Block hash.
        hash: Hash32,
        /// Block height.
        height: u64,
        /// Number of transactions included.
        transactions: usize,
        /// Whether the block carried this node's mining claim.
        claimed: bool,
    },
    /// The genesis allocation was issued in a block this node accepted.
    GenesisIssued {
        /// Account that received it.
        account: Address,
        /// Amount issued.
        amount: Amount,
    },
    /// This node's clock is far enough past the chain's genesis epoch that no
    /// first block could ever be produced from genesis with it.
    ///
    /// The chain's timestamps move at most 60 seconds per block, so a network
    /// must be launched at its genesis epoch.  A node that sees this event is
    /// either configured for the wrong network, has a badly wrong clock, or is
    /// trying to start a chain whose epoch has passed: it can still *sync* and
    /// validate from peers, but it cannot found the network.
    GenesisEpochGap {
        /// The chain's genesis timestamp.
        genesis_timestamp: u64,
        /// This node's clock, at the moment it noticed.
        clock: u64,
    },
    /// A validator's attestation was queued for inclusion.
    AttestationQueued {
        /// Attesting node identity.
        node_key: [u8; 32],
        /// Height attested.
        height: u64,
    },
}

/// What one [`Node::step`] did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct StepOutcome {
    /// Peer events handled.
    pub peer_events: usize,
    /// Blocks accepted (including blocks on side branches).
    pub blocks_accepted: usize,
    /// Blocks refused.
    pub blocks_rejected: usize,
    /// Transactions accepted into the pool.
    pub transactions_accepted: usize,
    /// Transactions refused.
    pub transactions_rejected: usize,
    /// Attestations received.
    pub attestations: usize,
    /// True when this step produced a block.
    pub mined: bool,
}

/// Why a node could not start.
#[derive(Debug)]
pub enum NodeError {
    /// The chain store could not be opened.
    Chain(ChainError),
    /// The peer service could not start.
    Peer(std::io::Error),
    /// The configured data directory could not be created.
    DataDir(std::io::Error),
}

impl core::fmt::Display for NodeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            NodeError::Chain(error) => write!(f, "chain storage: {}", error),
            NodeError::Peer(error) => write!(f, "peer service: {}", error),
            NodeError::DataDir(error) => write!(f, "data directory: {}", error),
        }
    }
}

impl std::error::Error for NodeError {}

/// The node's view of the protocol clock.
#[derive(Debug, Clone, Default)]
pub struct Clock {
    offset_secs: i64,
}

impl Clock {
    /// Wall-clock time shifted by an explicit offset.  Used by tests and by
    /// operators running a node in a time-shifted sandbox; the chain still
    /// enforces its own limits.
    pub fn with_offset(offset_secs: i64) -> Clock {
        Clock { offset_secs }
    }

    /// The current Unix time, with the offset applied.
    pub fn unix_now(&self) -> u64 {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs() as i64)
            .unwrap_or(0);
        (now + self.offset_secs).max(0) as u64
    }

    /// The offset applied to wall-clock time.
    pub fn offset_secs(&self) -> i64 {
        self.offset_secs
    }
}

/// A full node.
pub struct Node {
    config: NodeConfig,
    store: ChainStore,
    mempool: Mempool,
    peers: PeerManager,
    clock: Clock,
    shutdown: Arc<AtomicBool>,
    events: Vec<NodeEvent>,
    /// Attestations waiting to be included in a block this node proposes.
    pending_attestations: Vec<Attestation>,
    /// Per-peer sync requests in flight, so a chatty peer cannot make the node
    /// ask for the same range over and over.
    syncing: BTreeMap<[u8; 32], u64>,
    /// When this node last produced a block.
    last_block_at: Option<Instant>,
}

impl Node {
    /// Opens or creates a node.
    pub fn open(mut config: NodeConfig) -> Result<Node, NodeError> {
        std::fs::create_dir_all(&config.data_dir).map_err(NodeError::DataDir)?;
        let store = ChainStore::open(
            &config.data_dir,
            config.network,
            config.genesis.clone(),
            config.fsync,
        )
        .map_err(NodeError::Chain)?;
        // The store is the authority on which chain this data directory holds:
        // it writes the genesis down when it founds one and reads it back
        // afterwards, so `--genesis-timestamp now` on a restart resumes the
        // existing chain instead of re-founding it.  The node adopts what the
        // store has, so every answer it gives about its epoch is about the
        // chain it is actually running.
        config.genesis = store.genesis().clone();
        let peer_config = PeerConfig::new(
            config.network,
            store.genesis_hash(),
            config.node_key.clone(),
            config.listen_port,
        )
        .with_max_peers(config.max_peers);
        let shutdown = Arc::new(AtomicBool::new(false));
        let peers = PeerManager::bind(peer_config, Arc::clone(&shutdown)).map_err(NodeError::Peer)?;
        let mempool = Mempool::new(config.mempool.clone());
        let mut node = Node {
            config,
            store,
            mempool,
            peers,
            clock: Clock::default(),
            shutdown,
            events: Vec::new(),
            pending_attestations: Vec::new(),
            syncing: BTreeMap::new(),
            last_block_at: None,
        };
        node.peers.set_status(node.store.head(), node.store.height());
        for addr in node.config.peers.clone() {
            node.peers.connect(addr);
        }
        if let Some(gap) = node.genesis_epoch_gap() {
            node.events.push(gap);
        }
        Ok(node)
    }

    // -----------------------------------------------------------------------
    // Access
    // -----------------------------------------------------------------------

    /// The node's configuration.
    pub fn config(&self) -> &NodeConfig {
        &self.config
    }

    /// The chain store.
    pub fn store(&self) -> &ChainStore {
        &self.store
    }

    /// The chain store, mutably (for compaction).
    pub fn store_mut(&mut self) -> &mut ChainStore {
        &mut self.store
    }

    /// The transaction pool.
    pub fn mempool(&self) -> &Mempool {
        &self.mempool
    }

    /// The peer manager.
    pub fn peers(&self) -> &PeerManager {
        &self.peers
    }

    /// The peer manager, mutably (for bans and manual dialling).
    pub fn peers_mut(&mut self) -> &mut PeerManager {
        &mut self.peers
    }

    /// The head state.
    pub fn head_state(&self) -> &ChainState {
        self.store.head_state()
    }

    /// The head hash.
    pub fn head(&self) -> Hash32 {
        self.store.head()
    }

    /// The head height.
    pub fn height(&self) -> u64 {
        self.store.height()
    }

    /// The address this node listens on.
    pub fn listen_addr(&self) -> SocketAddr {
        self.peers.local_addr()
    }

    /// The protocol time this node would use for its next block.
    pub fn protocol_time(&self) -> u64 {
        let head = self.head_state().last_timestamp;
        let now = self.clock.unix_now();
        // Never at or before the head: the chain rejects that, and a node that
        // produced such a block would be punishing its own clock, not the
        // network.
        let spaced = head + MIN_BLOCK_SPACING_SECS;
        now.max(spaced)
    }

    /// The chain's genesis timestamp.
    pub fn genesis_timestamp(&self) -> u64 {
        self.config.genesis.timestamp
    }

    /// Why this node cannot found this chain from its genesis block right now,
    /// or `None` when it can.
    ///
    /// Being unable to *found* a chain is not the same as being unable to join
    /// one: a node in this state still syncs, validates and relays.
    pub fn genesis_epoch_gap(&self) -> Option<NodeEvent> {
        if self.store.height() > 0 {
            return None;
        }
        let genesis = self.genesis_timestamp();
        let clock = self.clock.unix_now();
        if clock > genesis.saturating_add(MAX_BLOCK_DRIFT_SECS) {
            Some(NodeEvent::GenesisEpochGap {
                genesis_timestamp: genesis,
                clock,
            })
        } else {
            None
        }
    }

    /// Replaces the clock offset.
    pub fn set_clock_offset(&mut self, offset_secs: i64) {
        self.clock = Clock::with_offset(offset_secs);
    }

    /// The offset currently applied to wall-clock time.
    pub fn clock_offset(&self) -> i64 {
        self.clock.offset_secs()
    }

    /// Events produced since the last call.
    pub fn drain_events(&mut self) -> Vec<NodeEvent> {
        std::mem::take(&mut self.events)
    }

    /// The most recent events, oldest first.
    pub fn recent_events(&self, limit: usize) -> &[NodeEvent] {
        let start = self.events.len().saturating_sub(limit);
        &self.events[start..]
    }

    /// Pool statistics.
    pub fn mempool_stats(&self) -> MempoolStats {
        self.mempool.stats()
    }

    /// The peer table.
    pub fn peer_status(&self) -> Vec<PeerStatus> {
        self.peers.peers()
    }

    /// The chain's canonical hash at a height.
    pub fn canonical_hash(&self, height: u64) -> Option<Hash32> {
        self.store.canonical_hashes().get(height as usize).copied()
    }

    /// A canonical block by height.
    pub fn block_at(&self, height: u64) -> Option<&Block> {
        self.store.block_at_height(height)
    }

    /// A block by hash, canonical or not.
    pub fn block_by_hash(&self, hash: &Hash32) -> Option<&Block> {
        self.store.block(hash)
    }

    /// Finds a transaction by id: pooled, or in a canonical block.
    pub fn find_transaction(&self, id: &Hash32) -> Option<(Transaction, Option<u64>)> {
        let wanted = TxId(*id);
        if let Some(entry) = self.mempool.entry(&wanted) {
            return Some((entry.tx.clone(), None));
        }
        for height in (1..=self.store.height()).rev() {
            let Some(block) = self.store.block_at_height(height) else {
                continue;
            };
            if let Some(tx) = block.transactions.iter().find(|tx| tx.id() == wanted) {
                return Some((tx.clone(), Some(height)));
            }
        }
        None
    }

    /// The pool's transactions in the order a block producer would try them.
    pub fn pooled_transactions(&self) -> Vec<Transaction> {
        let at = self.protocol_time();
        self.mempool
            .select_for_block(self.head_state(), at, MAX_TXS_PER_BLOCK)
    }

    /// Mining parameters, as the mining page needs them.
    pub fn mining_info(&self) -> MiningInfo {
        let state = self.head_state();
        let at = self.protocol_time();
        MiningInfo {
            reward_per_claim: state.mining_reward_at(at),
            active_miners: state.active_miner_count_at(at),
            claims_issued: state.total_claims,
            interval_secs: CLAIM_INTERVAL_SECS,
            max_claims_per_day: MAX_CLAIMS_PER_DAY,
            genesis_claim_issued: state.genesis_issued,
            treasury: state.treasury,
            mining_pool: state.mining_pool,
            validator_pool: state.validator_pool,
            issued_supply: state.issued_supply,
        }
    }

    // -----------------------------------------------------------------------
    // The loop
    // -----------------------------------------------------------------------

    /// One iteration of the node loop.
    pub fn step(&mut self) -> StepOutcome {
        let mut outcome = StepOutcome::default();
        let events = self.peers.poll(Duration::from_millis(2));
        for event in events {
            outcome.peer_events += 1;
            self.handle_peer_event(event, &mut outcome);
        }
        if self.config.mine && self.should_propose() {
            if self.propose_internal(&mut outcome).is_some() {
                outcome.mined = true;
            }
        }
        self.mempool.expire(self.protocol_time());
        self.peers
            .set_status(self.store.head(), self.store.height());
        outcome
    }

    /// Runs the node loop until `shutdown` is set.
    pub fn run(&mut self, shutdown: &AtomicBool) {
        while !shutdown.load(Ordering::Relaxed) {
            self.step();
        }
    }

    /// Signals the peer service to stop.
    pub fn shutdown(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }

    // -----------------------------------------------------------------------
    // Peer messages
    // -----------------------------------------------------------------------

    fn handle_peer_event(&mut self, event: PeerEvent, outcome: &mut StepOutcome) {
        match event {
            PeerEvent::Connected { node_key, .. } => {
                self.events.push(NodeEvent::PeerConnected { node_key });
                let status = self.local_status();
                self.peers.send(&node_key, NetMessage::Status(status));
            }
            PeerEvent::Disconnected {
                node_key, reason, ..
            } => {
                self.syncing.remove(&node_key);
                self.events.push(NodeEvent::PeerDisconnected {
                    node_key,
                    reason: reason.to_string(),
                });
            }
            PeerEvent::Message { node_key, message } => {
                self.handle_message(node_key, *message, outcome);
            }
            PeerEvent::Rejected { addr, reason, .. } => {
                self.events.push(NodeEvent::PeerRejected {
                    reason: format!("{}: {}", addr, reason),
                });
            }
        }
    }

    fn local_status(&self) -> Status {
        let head = self.head_state();
        Status {
            head: self.store.head(),
            height: head.height,
            weight_atoms: head.total_weight.atoms,
            finalized_height: head.finalized_height,
            mempool_len: self.mempool.len().min(u32::MAX as usize) as u32,
        }
    }

    fn handle_message(&mut self, from: [u8; 32], message: NetMessage, outcome: &mut StepOutcome) {
        match message {
            NetMessage::Status(status) => self.handle_status(from, status),
            NetMessage::GetBlocks(request) => self.handle_get_blocks(from, request),
            NetMessage::Blocks(blocks) => {
                for block in blocks {
                    // A refused block never stops the batch: a peer may have
                    // sent a valid block behind an invalid one.
                    let _ = self.accept_block(Some(from), block, outcome, true);
                }
            }
            NetMessage::Transactions(transactions) => {
                for tx in transactions {
                    match self.accept_transaction(tx.clone()) {
                        Ok(id) => {
                            outcome.transactions_accepted += 1;
                            let _ = id;
                            self.broadcast_except(Some(from), NetMessage::Transactions(vec![tx]));
                        }
                        Err(error) => {
                            outcome.transactions_rejected += 1;
                            let _ = error;
                            // Refusals are reported through `NodeEvent`, but a
                            // peer is not told why: it does not need to know,
                            // and the detail could leak pool policy.
                        }
                    }
                }
            }
            NetMessage::Attestations(attestations) => {
                for attestation in attestations {
                    outcome.attestations += 1;
                    self.queue_attestation(attestation, Some(from));
                }
            }
            NetMessage::Reject(reject) => {
                self.events.push(NodeEvent::PeerRejected {
                    reason: format!("peer refused our message: {} ({:?})", reject.detail, reject.code),
                });
            }
            NetMessage::Ping(_) | NetMessage::Pong(_) => {
                // Handled by the peer manager; the node never sees them.
            }
            NetMessage::Bye(_) | NetMessage::Hello(_) | NetMessage::Auth(_) => {
                // The peer layer decides what to do with these.
            }
        }
    }

    fn handle_status(&mut self, from: [u8; 32], status: Status) {
        let ours = self.store.height();
        // Heavier chain, not merely a different one: fork choice is by PoT
        // weight, so a peer at the same height may still be worth asking.
        let theirs = status.weight_atoms;
        let mine = self.head_state().total_weight.atoms;
        let worth_asking = status.height > ours
            || (status.height == ours && status.head != self.store.head() && theirs > mine);
        if !worth_asking {
            return;
        }
        if self.syncing.get(&from).copied() == Some(status.height) {
            return;
        }
        self.syncing.insert(from, status.height);
        let request = NetMessage::GetBlocks(GetBlocks {
            from_height: ours + 1,
            max_blocks: MAX_BLOCKS_PER_MESSAGE as u32,
        });
        self.peers.send(&from, request);
    }

    fn handle_get_blocks(&mut self, from: [u8; 32], request: GetBlocks) {
        let ours = self.store.height();
        let start = request.from_height.max(1);
        if start > ours || request.max_blocks == 0 {
            self.peers.send(&from, NetMessage::Blocks(Vec::new()));
            return;
        }
        let limit = (request.max_blocks as usize).min(MAX_BLOCKS_PER_MESSAGE);
        let end = ours.min(start.saturating_add(limit as u64 - 1));
        let mut blocks = Vec::new();
        for height in start..=end {
            match self.store.block_at_height(height) {
                Some(block) => blocks.push(block.clone()),
                None => break,
            }
        }
        self.peers.send(&from, NetMessage::Blocks(blocks));
    }

    // -----------------------------------------------------------------------
    // Blocks
    // -----------------------------------------------------------------------

    /// Validates and applies a block, whether it came from a peer or from this
    /// node's own producer.
    ///
    /// Everything here is validated by [`obs_chain`]; the node only decides who
    /// to tell.  Returns the accepted hash, or the rule that refused it.
    pub fn accept_block(
        &mut self,
        from: Option<[u8; 32]>,
        block: Block,
        outcome: &mut StepOutcome,
        relay: bool,
    ) -> Result<Hash32, String> {
        let hash = block.hash();
        // Relaying policy, not consensus: a node does not help spread a block a
        // peer claims is far in the local future.  The block is still applied if
        // it is valid — validity never depends on any node's wall clock — and a
        // block this node produced itself is always relayed.
        let relay = relay
            && (from.is_none()
                || block.header.timestamp
                    <= self
                        .clock
                        .unix_now()
                        .saturating_add(obs_chain::params::LOCAL_FUTURE_SANITY_SECS));
        match self.store.submit(block.clone()) {
            Ok(event) => {
                outcome.blocks_accepted += 1;
                self.apply_chain_event(from, event, &block, relay);
                Ok(hash)
            }
            Err(error) => {
                outcome.blocks_rejected += 1;
                let rule = match &error {
                    ChainError::Rejected(state) => state.rule.to_string(),
                    other => format!("{:?}", other),
                };
                if let Some(from) = from {
                    self.peers.send(
                        &from,
                        NetMessage::Reject(Reject {
                            code: RejectCode::BadBlock,
                            detail: rule.clone(),
                        }),
                    );
                }
                self.events.push(NodeEvent::BlockRejected {
                    hash,
                    rule: rule.clone(),
                });
                Err(rule)
            }
        }
    }

    fn apply_chain_event(
        &mut self,
        from: Option<[u8; 32]>,
        event: ChainEvent,
        block: &Block,
        relay: bool,
    ) {
        match event {
            ChainEvent::Head {
                previous: _,
                current,
                reorg,
            } => {
                let height = self.store.height();
                let transactions = self
                    .store
                    .block(&current)
                    .map(|block| block.transactions.len())
                    .unwrap_or(0);
                self.settle_pool(block);
                self.events.push(NodeEvent::Head {
                    hash: current,
                    height,
                    reorg: reorg.is_some(),
                    transactions,
                    ours: false,
                });
                if let Some(reorg) = reorg.clone() {
                    self.record_reorg(&reorg);
                }
                if relay {
                    self.broadcast_except(from, NetMessage::Blocks(vec![block.clone()]));
                }
                self.report_genesis(&current);
                // A new head is worth attesting to.
                self.attest_if_validator();
            }
            ChainEvent::Fork { .. } => {
                // A valid block on another branch.  The store keeps it and fork
                // choice decides later; the pool must re-check because a
                // competing branch may have consumed the same transactions.
                self.revalidate_pool();
            }
            ChainEvent::Orphan { .. } => {
                self.events.push(NodeEvent::BlockRejected {
                    hash: block.hash(),
                    rule: "orphan: the parent is unknown".to_string(),
                });
            }
        }
    }

    fn record_reorg(&mut self, reorg: &Reorg) {
        // Disconnected blocks put their transactions back; the pool then holds
        // anything the new branch did not include.
        let at = self.protocol_time();
        let mut disconnected = Vec::new();
        for hash in &reorg.disconnected {
            if let Some(block) = self.store.block(hash) {
                disconnected.push(block.clone());
            }
        }
        let state = self.store.head_state().clone();
        self.mempool.on_reorg(&state, disconnected.iter(), at);
        self.revalidate_pool();
    }

    fn settle_pool(&mut self, block: &Block) {
        let state = self.store.head_state().clone();
        self.mempool.on_block_applied(&state, block);
    }

    fn revalidate_pool(&mut self) {
        let at = self.protocol_time();
        let state = self.store.head_state().clone();
        self.mempool.revalidate(&state, at);
    }

    /// Reports the genesis allocation when the block that issued it is applied.
    fn report_genesis(&mut self, hash: &Hash32) {
        let Some(block) = self.store.block(hash).cloned() else {
            return;
        };
        for tx in &block.transactions {
            if let TxKind::Claim(claim) = &tx.kind {
                let issued = self
                    .head_state()
                    .account(&claim.account)
                    .map(|account| account.genesis_claimed)
                    .unwrap_or(false);
                let already = self.events.iter().any(|event| {
                    matches!(event, NodeEvent::GenesisIssued { account, .. } if *account == claim.account)
                });
                if issued && !already {
                    self.events.push(NodeEvent::GenesisIssued {
                        account: claim.account,
                        amount: obs_primitives::money::GENESIS_ALLOCATION,
                    });
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Transactions
    // -----------------------------------------------------------------------

    /// Validates a transaction against the pool and, on success, relays it.
    pub fn submit_transaction(&mut self, tx: Transaction) -> Result<Hash32, MempoolError> {
        let id = self.accept_transaction(tx.clone())?;
        self.broadcast_except(None, NetMessage::Transactions(vec![tx]));
        Ok(id)
    }

    /// Validates a transaction against the pool without relaying it.
    ///
    /// The chain decides validity; the pool only decides whether it is willing
    /// to hold and relay it.
    pub fn accept_transaction(&mut self, tx: Transaction) -> Result<Hash32, MempoolError> {
        let at = self.protocol_time();
        let id = tx.id();
        let state = self.store.head_state().clone();
        match self.mempool.insert(&state, tx, at) {
            Ok(_) => {
                self.events.push(NodeEvent::TransactionAccepted { id: id.0 });
                Ok(id.0)
            }
            Err(error) => {
                let reason = match &error {
                    MempoolError::Invalid(state) => state.rule.to_string(),
                    other => format!("{:?}", other),
                };
                self.events.push(NodeEvent::TransactionRejected {
                    id: id.0,
                    reason,
                });
                Err(error)
            }
        }
    }

    /// The pool's view of a transaction's fee.
    pub fn fee_of(tx: &Transaction) -> Amount {
        transaction_fee(tx)
    }

    // -----------------------------------------------------------------------
    // Attestations
    // -----------------------------------------------------------------------

    /// Adds an attestation to the queue for the next block this node proposes.
    ///
    /// The node does not take the sender's word for anything.  Signature
    /// verification happens here as well as in the state machine, because a
    /// queued attestation is one the node will put into a block it proposes: a
    /// peer that could push a forged one would poison the node's own proposal
    /// and make it build a block every node must reject.  Activity and ordering
    /// are checked by the state machine when the block is applied; queueing is
    /// otherwise only bookkeeping.
    ///
    /// Inclusion follows the chain's own ordering rule: a validator's
    /// attestations must reference strictly increasing heights.  The queue
    /// therefore holds at most one attestation per validator — the newest — so a
    /// block built from it is applicable by construction.  An older attestation
    /// left alongside a newer one for the same validator makes the whole block
    /// invalid (`attestation_order`), which would cost the network every
    /// attestation in it.
    pub fn queue_attestation(&mut self, attestation: Attestation, from: Option<[u8; 32]>) {
        let height = attestation.height;
        if height >= self.store.height() + 1 {
            return;
        }
        if !attestation.verify_signature(self.config.network.chain_id) {
            return;
        }
        if let Some(held) = self
            .pending_attestations
            .iter_mut()
            .find(|held| held.node_key == attestation.node_key)
        {
            if held.height >= height {
                // Already have this one, or a newer one: nothing to add.
                return;
            }
            *held = attestation.clone();
            self.events.push(NodeEvent::AttestationQueued {
                node_key: attestation.node_key,
                height,
            });
            if let Some(from) = from {
                // Relay it, so a proposer that is better connected than we are
                // can include it.
                self.broadcast_except(Some(from), NetMessage::Attestations(vec![attestation]));
            }
            return;
        }
        let duplicate = self.pending_attestations.iter().any(|held| {
            held.node_key == attestation.node_key && held.height == height
        });
        if duplicate {
            return;
        }
        if self.pending_attestations.len() >= MAX_ATTESTATIONS_PER_BLOCK {
            self.pending_attestations.remove(0);
        }
        self.events.push(NodeEvent::AttestationQueued {
            node_key: attestation.node_key,
            height,
        });
        if let Some(from) = from {
            // Relay it, so a proposer that is better connected than we are can
            // include it.
            self.broadcast_except(Some(from), NetMessage::Attestations(vec![attestation.clone()]));
        }
        self.pending_attestations.push(attestation);
    }

    /// Signs this node's own attestation for the current head, if it is an
    /// active validator and has not already attested this head.
    pub fn attest_if_validator(&mut self) -> Option<Attestation> {
        let key = self.config.validator_key.clone()?;
        let node_key = key.public_key();
        let record = self.head_state().validator(&node_key)?;
        if !record.active {
            return None;
        }
        let height = self.store.height();
        if record.last_attested_height >= height {
            return None;
        }
        let hash = self.store.head();
        let slot = self.head_state().last_slot;
        let attestation = Attestation::sign(self.config.network.chain_id, &key, height, hash, slot);
        self.queue_attestation(attestation.clone(), None);
        Some(attestation)
    }

    /// The attestations worth including in the next block this node proposes.
    ///
    /// The filter mirrors the chain's own inclusion rules so a node never
    /// proposes a block the state machine must reject: the attestation must
    /// reference a block below the one being built, and it must be recent
    /// enough to count as evidence that the validator was live
    /// ([`ATTESTATION_WINDOW_BLOCKS`]).
    fn attestations_for_block(&self, state: &ChainState) -> Vec<Attestation> {
        if state.active_validators().is_empty() {
            return Vec::new();
        }
        let building = state.height + 1;
        let mut sorted: Vec<Attestation> = self
            .pending_attestations
            .iter()
            .filter(|attestation| {
                attestation.height < building
                    && building - attestation.height <= ATTESTATION_WINDOW_BLOCKS
            })
            .cloned()
            .collect();
        sorted.sort_by(|left, right| left.node_key.cmp(&right.node_key));
        sorted.dedup_by_key(|attestation| attestation.node_key);
        sorted.truncate(MAX_ATTESTATIONS_PER_BLOCK);
        sorted
    }

    fn broadcast_except(&mut self, except: Option<[u8; 32]>, message: NetMessage) {
        self.peers.broadcast(message, except);
    }

    // -----------------------------------------------------------------------
    // Block production
    // -----------------------------------------------------------------------

    fn should_propose(&self) -> bool {
        if self.config.mining_key.is_none() {
            return false;
        }
        let head = self.head_state();
        if self.clock.unix_now() < head.last_timestamp + MIN_BLOCK_SPACING_SECS {
            return false;
        }
        match self.last_block_at {
            Some(last) => last.elapsed() >= self.config.block_interval,
            None => true,
        }
    }

    /// Produces one block immediately, without waiting for the block interval.
    ///
    /// This is what the operator's `mine` command uses and what tests drive the
    /// chain with.  It is *not* a way around the rules: the block is built,
    /// signed and validated exactly like a scheduled one, the proposer schedule
    /// still applies, and the timestamp clamp still applies.
    pub fn mine_once(&mut self) -> Option<Hash32> {
        let mut outcome = StepOutcome::default();
        let hash = self.propose_internal(&mut outcome)?;
        self.last_block_at = Some(Instant::now());
        Some(hash)
    }

    /// Produces a block if this node is allowed to propose one now.
    pub fn propose(&mut self, outcome: &mut StepOutcome) -> Option<Hash32> {
        let hash = self.propose_internal(outcome)?;
        self.last_block_at = Some(Instant::now());
        Some(hash)
    }

    fn propose_internal(&mut self, outcome: &mut StepOutcome) -> Option<Hash32> {
        let key = self.config.mining_key.clone()?;
        let timestamp = self.candidate_timestamp()?;
        let address = Address::from_public_key(self.config.network, &key.public_key());

        let candidate = {
            let state = self.store.head_state();
            let mut transactions =
                self.mempool
                    .select_for_block(state, timestamp, MAX_TXS_PER_BLOCK);
            if let Some(claim) = self.build_claim(state, &transactions, &address, timestamp) {
                // Appended, so it follows every pooled transaction from the
                // same account and therefore has the nonce the account will
                // actually hold when the claim is applied.
                transactions.push(claim);
            }
            // Never propose something the chain would refuse.
            match state.apply_txs_preview(&transactions, timestamp) {
                Ok(_) => {}
                Err(_) => {
                    transactions.retain(|tx| !matches!(tx.kind, TxKind::Claim(_)));
                    if state.apply_txs_preview(&transactions, timestamp).is_err() {
                        // Even without the claim the candidate does not apply:
                        // the pool and the chain disagree, which is a bug worth
                        // surfacing rather than mining around.  Produce nothing.
                        self.events.push(NodeEvent::BlockRejected {
                            hash: Hash32::ZERO,
                            rule: "candidate_rejected".to_string(),
                        });
                        return None;
                    }
                }
            }
            let attestations = self.attestations_for_block(state);
            match state.build_block(&key, timestamp, transactions, attestations) {
                Ok(block) => block,
                Err(error) => {
                    self.events.push(NodeEvent::BlockRejected {
                        hash: Hash32::ZERO,
                        rule: error.rule.to_string(),
                    });
                    return None;
                }
            }
        };

        let claimed = candidate
            .transactions
            .iter()
            .any(|tx| matches!(tx.kind, TxKind::Claim(_)));
        let height = candidate.header.height;
        let transactions = candidate.transactions.len();
        // What this block carries, so exactly that can be dropped from the queue
        // afterwards — see below.
        let carried: Vec<([u8; 32], u64)> = candidate
            .attestations
            .iter()
            .map(|attestation| (attestation.node_key, attestation.height))
            .collect();
        let hash = match self.accept_block(None, candidate, outcome, true) {
            Ok(hash) => hash,
            Err(_) => return None,
        };
        // Drop only the attestations that were included.  Accepting the block
        // queued this node's own attestation for the *new* head — that is what
        // makes the next block carry evidence — so clearing the whole queue here
        // would throw away the very attestation the chain is waiting for, and a
        // node would attest forever without an attestation ever reaching a
        // block.
        self.pending_attestations.retain(|held| {
            !carried
                .iter()
                .any(|(node_key, height)| *node_key == held.node_key && *height == held.height)
        });
        self.events.push(NodeEvent::Mined {
            hash,
            height,
            transactions,
            claimed,
        });
        Some(hash)
    }

    /// The timestamp the next block may carry.
    ///
    /// Two things decide it, in this order:
    ///
    /// 1. **A claim that is waiting.**  A claim declares the protocol time of the
    ///    block that will contain it — the chain accepts it in that block and no
    ///    other — so when the pool holds a claim whose declared time still fits
    ///    inside the legal window, the proposer stamps its block with that time
    ///    and carries the claim.  This is what makes mining from a wallet work at
    ///    all: the miner's own claim is built for the block's time, but any other
    ///    account's claim was written before this block existed, and only the
    ///    proposer can meet it.  Oldest first, so a claim cannot be starved by
    ///    later ones.
    /// 2. **This node's clock**, clamped to the window `[head + 1, head + 60]`.
    ///    The clamp is the protocol's own rule for how far protocol time may move
    ///    in one block, so a node whose wall clock has drifted (or a chain that
    ///    has been quiet for a while) still produces a block the chain accepts,
    ///    and catches up 60 seconds at a time.
    ///
    /// The window itself is never widened: this function chooses *within* the
    /// rules, so a block it proposes is valid for every other node, and a chain
    /// whose clock is being held back still advances by at least one second per
    /// block.
    fn candidate_timestamp(&self) -> Option<u64> {
        let head = self.head_state();
        let lower = head.last_timestamp + MIN_BLOCK_SPACING_SECS;
        let upper = head.last_timestamp + MAX_BLOCK_DRIFT_SECS;
        if let Some(declared) = self
            .mempool
            .pooled_claim_times()
            .into_iter()
            .find(|declared| *declared >= lower && *declared <= upper)
        {
            return Some(declared);
        }
        let now = self.clock.unix_now();
        if now < lower {
            return None;
        }
        Some(now.min(upper))
    }

    /// Builds this node's mining claim for the block, when the protocol allows
    /// one.
    ///
    /// `pooled` is the pool's template: the claim is judged against the state
    /// the block would have after those transactions, which is what lets the
    /// very first block of a network register the founder and mine the genesis
    /// claim at the same time.
    fn build_claim(
        &self,
        state: &ChainState,
        pooled: &[Transaction],
        address: &Address,
        timestamp: u64,
    ) -> Option<Transaction> {
        let key = self.config.mining_key.clone()?;
        let preview = state.apply_txs_preview(pooled, timestamp).ok()?;
        let account = preview.account(address)?;
        // Mirror the protocol's window arithmetic exactly.
        let window_resets = account.claim_window_start == 0
            || timestamp >= account.claim_window_start.saturating_add(PROTOCOL_DAY_SECS);
        let claims_in_window = if window_resets { 0 } else { account.claims_today };
        if claims_in_window >= MAX_CLAIMS_PER_DAY {
            return None;
        }
        if account.last_claim_sequence > 0 && timestamp < account.last_claim_at + CLAIM_INTERVAL_SECS {
            return None;
        }
        let nonce = preview.expected_nonce(address);
        Some(Transaction::sign(
            self.config.network,
            nonce,
            TxKind::Claim(Claim {
                account: *address,
                claimed_at: timestamp,
                sequence: account.last_claim_sequence + 1,
            }),
            &key,
        ))
    }
}

/// Mining parameters, as the mining page needs them.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningInfo {
    /// Reward for the next accepted claim.
    pub reward_per_claim: Amount,
    /// Miners active within the protocol's activity window.
    pub active_miners: u64,
    /// Claims accepted since the genesis block.
    pub claims_issued: u64,
    /// Minimum seconds between claims.
    pub interval_secs: u64,
    /// Maximum claims in one protocol day.
    pub max_claims_per_day: u64,
    /// Whether the one-time genesis allocation has been issued.
    pub genesis_claim_issued: bool,
    /// The genesis wallet (treasury), once it exists.
    pub treasury: Option<Address>,
    /// Mining-pool balance (the 60% share of gas fees).
    pub mining_pool: Amount,
    /// Validator-reward-pool balance (the 40% share).
    pub validator_pool: Amount,
    /// Total issued supply.
    pub issued_supply: Amount,
}

/// The protocol parameters, for documentation and the developer portal.
///
/// These are read from the compiled protocol constants.  Nothing in the API
/// layer can change them: they are part of the consensus rules, and changing
/// them requires a protocol release and a network upgrade, not a request.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProtocolParameters {
    /// Protocol version.
    pub version: u32,
    /// Chain id.
    pub chain_id: u32,
    /// Seconds per slot.
    pub slot_duration_secs: u64,
    /// Median-time-past window size, in blocks.
    pub mtp_window: usize,
    /// Maximum seconds a block may lead its parent.
    pub max_block_drift_secs: u64,
    /// Claims per protocol day.
    pub max_claims_per_day: u64,
    /// Minimum seconds between claims.
    pub claim_interval_secs: u64,
    /// Validator bond.
    pub validator_bond: Amount,
    /// Unbonding period after deregistration.
    pub unbonding_secs: u64,
    /// Maximum gas fee per transfer.
    pub max_gas_fee: Amount,
    /// Share of each gas fee that goes to the validator pool, in percent.
    pub validator_fee_share_percent: u64,
    /// Share of each gas fee that goes to the mining pool, in percent.
    pub mining_fee_share_percent: u64,
    /// Hard maximum supply.
    pub max_supply: Amount,
    /// Invitations per account.
    pub max_invites_per_account: u64,
}

impl ProtocolParameters {
    /// Reads the parameters from the compiled protocol constants.
    pub fn current(network: Network) -> ProtocolParameters {
        use obs_chain::params::{
            BP_DENOMINATOR, DIFFICULTY_INITIAL_BP, FEE_SHARE_DENOMINATOR, MAX_GAS_FEE,
            MIN_UPTIME_BP, MTP_WINDOW, VALIDATOR_FEE_SHARE_NUMERATOR,
        };
        let _ = (BP_DENOMINATOR, DIFFICULTY_INITIAL_BP, MIN_UPTIME_BP);
        ProtocolParameters {
            version: PROTOCOL_VERSION,
            chain_id: network.chain_id,
            slot_duration_secs: SLOT_DURATION_SECS,
            mtp_window: MTP_WINDOW,
            max_block_drift_secs: MAX_BLOCK_DRIFT_SECS,
            max_claims_per_day: MAX_CLAIMS_PER_DAY,
            claim_interval_secs: CLAIM_INTERVAL_SECS,
            validator_bond: obs_primitives::money::VALIDATOR_BOND,
            unbonding_secs: UNBONDING_PERIOD_SECS,
            max_gas_fee: MAX_GAS_FEE,
            validator_fee_share_percent: VALIDATOR_FEE_SHARE_NUMERATOR as u64,
            mining_fee_share_percent: FEE_SHARE_DENOMINATOR as u64
                - VALIDATOR_FEE_SHARE_NUMERATOR as u64,
            max_supply: obs_primitives::money::MAX_SUPPLY,
            max_invites_per_account: MAX_INVITES_PER_ACCOUNT as u64,
        }
    }
}
