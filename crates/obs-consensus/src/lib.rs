//! Fork choice, reorganisation and durable storage for the canonical chain.
//!
//! [`ChainStore`] is what a node actually runs.  It owns:
//!
//! * the set of known blocks (canonical and side branches), loaded from and
//!   appended to a durable [`BlockLog`];
//! * one [`ChainState`] per known tip, so a new block can be validated against
//!   the branch it actually extends;
//! * the canonical chain and its head, chosen by fork choice;
//! * a bounded orphan pool for blocks whose parent has not arrived yet.
//!
//! Two invariants make multi-node operation deterministic: every node that has
//! seen the same set of blocks computes the same head (fork choice is a total
//! order over branches, not a race), and no node ever reorganises away a
//! finalised block — a branch that would require it is rejected outright.

use std::collections::{BTreeMap, HashMap, HashSet};
use std::path::{Path, PathBuf};

use obs_chain::{Block, ChainState, GenesisConfig, StateError};
use obs_primitives::hash::Hash32;
use obs_primitives::network::Network;

pub mod store;

use crate::store::{BlockLog, StoreError};

/// How many recently used branch states are kept in memory.
///
/// A state is only ever an optimisation: any state can be rebuilt by replaying
/// recorded blocks from an ancestor that is still cached, and the genesis state
/// is always reconstructible.  The cache therefore never affects consensus.
pub const STATE_CACHE_LIMIT: usize = 8;

/// Maximum number of blocks awaiting an unknown parent that a node retains.
pub const MAX_ORPHAN_BLOCKS: usize = 256;

/// Maximum distance, in blocks, a fork may reach backwards when the node has to
/// replay blocks to rebuild a branch state.
pub const MAX_REPLAY_DEPTH: u64 = 100_000;

/// Storage or consensus failure while maintaining the chain.
#[derive(Debug)]
pub enum ChainError {
    /// The durable log could not be read or written.
    Store(StoreError),
    /// The block is invalid under the consensus rules.
    Rejected(StateError),
    /// The block would undo a finalised block.  This is never allowed: finality
    /// is the protocol's strongest guarantee, so a branch that contradicts it
    /// is treated as invalid rather than as a competitor.
    FinalizedConflict {
        /// Finalised height that would have to be rolled back.
        finalized_height: u64,
        /// Height of the conflicting branch.
        branch_height: u64,
    },
    /// The node cannot rebuild the branch state without replaying further than
    /// its retention policy allows.
    BranchTooDeep {
        /// Distance from the nearest cached ancestor.
        depth: u64,
    },
    /// The block does not extend this network's genesis chain.
    ForeignChain,
}

impl core::fmt::Display for ChainError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ChainError::Store(error) => write!(f, "{}", error),
            ChainError::Rejected(error) => write!(f, "block rejected: {}", error),
            ChainError::FinalizedConflict {
                finalized_height,
                branch_height,
            } => write!(
                f,
                "branch at height {} conflicts with finalised height {}",
                branch_height, finalized_height
            ),
            ChainError::BranchTooDeep { depth } => {
                write!(f, "branch state would need {} blocks of replay", depth)
            }
            ChainError::ForeignChain => write!(f, "block does not belong to this chain"),
        }
    }
}

impl std::error::Error for ChainError {}

impl From<std::io::Error> for ChainError {
    fn from(error: std::io::Error) -> Self {
        ChainError::Store(StoreError::Io(error))
    }
}

impl From<StoreError> for ChainError {
    fn from(error: StoreError) -> Self {
        ChainError::Store(error)
    }
}

impl From<StateError> for ChainError {
    fn from(error: StateError) -> Self {
        ChainError::Rejected(error)
    }
}

/// What happened to a block offered to the chain.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ChainEvent {
    /// The block extended (or re-organised) the canonical chain.
    Head {
        /// Head before the change.
        previous: Hash32,
        /// Head after the change.
        current: Hash32,
        /// Present when the change switched branches.
        reorg: Option<Reorg>,
    },
    /// The block is valid and stored, but a heavier branch remains canonical.
    Fork {
        /// Tip of the side branch.
        tip: Hash32,
    },
    /// The block's parent is unknown; it is held until the parent arrives.
    Orphan {
        /// Hash of the orphaned block.
        hash: Hash32,
        /// Missing parent.
        parent: Hash32,
    },
}

/// Description of a branch switch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reorg {
    /// Common ancestor of both branches.
    pub ancestor: Hash32,
    /// Height of the common ancestor.
    pub ancestor_height: u64,
    /// Blocks removed from the canonical chain, oldest first.
    pub disconnected: Vec<Hash32>,
    /// Blocks added to the canonical chain, oldest first.
    pub connected: Vec<Hash32>,
}

/// The chain a node is following: known blocks, branch states and the head.
pub struct ChainStore {
    network: Network,
    genesis: GenesisConfig,
    log: BlockLog,
    log_path: PathBuf,
    fsync: bool,
    blocks: HashMap<Hash32, Block>,
    states: BTreeMap<Hash32, ChainState>,
    canonical: Vec<Hash32>,
    head: Hash32,
    orphans: Vec<Block>,
    /// Guards against re-entering orphan collection while an orphan is being
    /// applied, which keeps the whole cascade iterative instead of recursive.
    collecting: bool,
}

impl ChainStore {
    /// Opens (creating if needed) a node's chain directory and replays
    /// everything already stored.
    pub fn open(
        dir: impl AsRef<Path>,
        network: Network,
        genesis: GenesisConfig,
        fsync: bool,
    ) -> Result<ChainStore, ChainError> {
        let dir = dir.as_ref();
        let log_path = dir.join(crate::store::log_file_name(network));
        let (log, scan) = BlockLog::open(&log_path, fsync)?;

        // A chain's genesis is a fact about the chain, not a value a command line
        // gets to rewrite on restart.  The first open writes it down; every open
        // after that reads it back, so a node resumes the chain it has.  A
        // directory that holds a *different* chain is an error rather than a
        // silent reset — that difference is what "fail closed" means for
        // storage: an operator who starts a node against the wrong data
        // directory, or with the wrong authority key, must not get a valid-looking
        // empty chain instead of their history.
        let genesis_path = dir.join(crate::store::genesis_file_name(network));
        let genesis = match crate::store::read_genesis(&genesis_path)? {
            Some(stored) => {
                if stored.network != network || stored.registration_authority != genesis.registration_authority
                {
                    return Err(ChainError::Store(StoreError::GenesisMismatch {
                        stored: format!(
                            "{} founded at {} for authority {}",
                            stored.network.name,
                            stored.timestamp,
                            Hash32(stored.registration_authority).to_hex()
                        ),
                        started: format!(
                            "{} at {} for authority {}",
                            network.name,
                            genesis.timestamp,
                            Hash32(genesis.registration_authority).to_hex()
                        ),
                    }));
                }
                stored
            }
            None => {
                // A log with blocks but no genesis record is a directory whose
                // chain cannot be reconstructed: the anchor is a hash, and a
                // hash cannot be read back for the epoch that produced it.
                // Guessing an epoch would silently orphan every block in the
                // log, which is exactly the silent reset this record prevents.
                if !scan.blocks.is_empty() {
                    return Err(ChainError::Store(StoreError::GenesisUnrecorded {
                        blocks: scan.blocks.len() as u64,
                    }));
                }
                crate::store::write_genesis(&genesis_path, &genesis)?;
                genesis
            }
        };

        let genesis_hash = genesis_anchor_hash(network, &genesis);
        let mut store = ChainStore {
            network,
            genesis,
            log,
            log_path,
            fsync,
            blocks: HashMap::new(),
            states: BTreeMap::new(),
            canonical: Vec::new(),
            head: Hash32::from_bytes([0u8; 32]),
            orphans: Vec::new(),
            collecting: false,
        };
        let genesis_state = store.fresh_state();
        store.states.insert(genesis_hash, genesis_state);
        store.head = genesis_hash;
        store.canonical = vec![genesis_hash];
        store.blocks.insert(
            genesis_hash,
            Block::genesis(network, obs_chain::params::PROTOCOL_VERSION, genesis.timestamp),
        );

        // Replaying is order-independent: a block whose parent has not been
        // loaded yet is retried after the rest of the log is in memory.  Each
        // block is validated again, exactly as it was when it was first
        // received — a log that contains an invalid block is an error, not
        // something to silently skip.
        let mut pending: Vec<Block> = scan.blocks;
        for _round in 0..3 {
            if pending.is_empty() {
                break;
            }
            // Deterministic order, so a node that is replaying a log that
            // contains branches always applies them in the same sequence.
            pending.sort_by(|left, right| {
                left.header
                    .height
                    .cmp(&right.header.height)
                    .then_with(|| left.hash().0.cmp(&right.hash().0))
            });
            let mut deferred = Vec::new();
            for block in pending.drain(..) {
                match store.submit_inner(block, false) {
                    Ok(ChainEvent::Orphan { .. }) => {}
                    Ok(_) => {}
                    Err(error) => return Err(error),
                }
            }
            // Anything still waiting for a parent gets another chance; the
            // order within a round may have hidden a dependency.
            pending = store.orphans().to_vec();
            if !deferred.is_empty() {
                pending.append(&mut deferred);
            }
        }
        store.orphans.clear();
        store.collecting = false;

        store.recompute_head()?;
        Ok(store)
    }

    /// Builds an in-memory chain from scratch (no files) for tests and for
    /// light clients that only need fork choice.
    pub fn in_memory(
        network: Network,
        genesis: GenesisConfig,
    ) -> Result<ChainStore, ChainError> {
        let dir = std::env::temp_dir().join(format!(
            "obs-chain-{}-{}-{}",
            network.name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_nanos())
                .unwrap_or(0)
        ));
        ChainStore::open(dir, network, genesis, false)
    }

    fn fresh_state(&self) -> ChainState {
        ChainState::new(&self.genesis)
    }

    fn insert_known(&mut self, block: Block) {
        self.blocks.insert(block.hash(), block);
    }

    /// Submits a block for validation and possible inclusion.
    ///
    /// The block is validated against the branch it extends, so a valid block
    /// on a competing branch is *stored* (it may become canonical later) even
    /// when the head does not move.  Invalid blocks are rejected and never
    /// stored — this is what makes the "invalid state roots and signatures are
    /// rejected" invariant hold at the node level, not just in the state layer.
    pub fn submit(&mut self, block: Block) -> Result<ChainEvent, ChainError> {
        self.submit_inner(block, true)
    }

    /// Shared implementation of [`ChainStore::submit`].
    ///
    /// `persist` is false while replaying a log that is already on disk: the
    /// block still has to be validated and applied, but writing it back would
    /// duplicate it.
    fn submit_inner(&mut self, block: Block, persist: bool) -> Result<ChainEvent, ChainError> {
        if block.header.chain_id != self.network.chain_id {
            return Err(ChainError::ForeignChain);
        }
        let hash = block.hash();
        if self.blocks.contains_key(&hash) {
            // Already known: idempotent, and re-applying is never needed.
            return Ok(ChainEvent::Fork { tip: hash });
        }
        let parent_state = match self.state_for(&block.header.parent) {
            Some(state) => state,
            None => {
                if self.blocks.contains_key(&block.header.parent) {
                    // The parent is known but its state cannot be rebuilt: the
                    // node is too far behind its own retention window.
                    let depth = block.header.height.saturating_sub(self.canonical.len() as u64);
                    return Err(ChainError::BranchTooDeep { depth });
                }
                self.remember_orphan(block.clone());
                return Ok(ChainEvent::Orphan {
                    hash,
                    parent: block.header.parent,
                });
            }
        };
        let applied = parent_state.apply_block(&block)?;
        let branch = applied.state;
        let head_state = self
            .states
            .get(&self.head)
            .cloned()
            .expect("the head always has a state");
        let previous = self.head;

        // The candidate must be visible to the ancestry walk so that the fork
        // point can be computed; it is taken back out again if the block turns
        // out to be one the protocol forbids us to follow.
        self.insert_known(block.clone());
        if is_better(&branch, &head_state) {
            if let Some(conflict) = self.finality_conflict(&branch) {
                self.blocks.remove(&hash);
                return Err(conflict);
            }
        }

        self.states.insert(hash, branch.clone());
        if persist {
            // Every accepted block is written to the log.  Durability is what a
            // storage layer owes a chain: what `fsync` chooses is how hard the
            // write is pushed to the platter (one `sync_data` per block versus
            // the operating system's own flush), never whether the block is
            // written at all.  A node that could lose its whole chain by being
            // restarted without a flag is not a node, it is a cache.
            self.log.append(&block)?;
        }

        if is_better(&branch, &head_state) {
            let reorg = self.reorganise(&block)?;
            self.head = hash;
            self.canonical = canonical_path(&self.blocks, hash);
            crate::store::write_head(self.head_path(), &self.head)?;
            self.collect_orphans(hash)?;
            Ok(ChainEvent::Head {
                previous,
                current: hash,
                reorg,
            })
        } else {
            self.prune_states(Some(hash));
            self.collect_orphans(hash)?;
            Ok(ChainEvent::Fork { tip: hash })
        }
    }

    /// Adds every orphan whose parent just became known.
    ///
    /// Iterative: applying an orphan can make further orphans ready, and the
    /// loop keeps draining until no held block can be connected.
    fn collect_orphans(&mut self, parent: Hash32) -> Result<(), ChainError> {
        if self.collecting {
            return Ok(());
        }
        self.collecting = true;
        let mut progressed = HashSet::new();
        progressed.insert(parent);
        loop {
            let ready: Vec<Block> = self
                .orphans
                .iter()
                .filter(|block| progressed.contains(&block.header.parent))
                .cloned()
                .collect();
            if ready.is_empty() {
                self.collecting = false;
                return Ok(());
            }
            self.orphans
                .retain(|block| !ready.iter().any(|candidate| candidate.hash() == block.hash()));
            for block in ready {
                progressed.insert(block.hash());
                // A failure here is a genuine invalid block: drop it, never the
                // rest of the chain.
                let _ = self.submit(block);
            }
        }
    }

    fn remember_orphan(&mut self, block: Block) {
        let hash = block.hash();
        if self.orphans.iter().any(|held| held.hash() == hash) {
            return;
        }
        self.orphans.push(block);
        if self.orphans.len() > MAX_ORPHAN_BLOCKS {
            // Bounded memory: drop the block that has waited longest.
            self.orphans.remove(0);
        }
    }

    /// Would adopting this branch roll back a finalised block?
    fn finality_conflict(&self, branch: &ChainState) -> Option<ChainError> {
        let finalized = self.head_state().finalized_height;
        if finalized == 0 {
            return None;
        }
        let ancestor_height = self.common_ancestor_height(&branch.last_block_hash);
        if ancestor_height < finalized {
            return Some(ChainError::FinalizedConflict {
                finalized_height: finalized,
                branch_height: branch.height,
            });
        }
        None
    }

    /// Height of the last block a branch shares with the canonical chain.
    ///
    /// Walks the branch's parents until it meets the canonical chain, so it
    /// works for any tip that shares this node's genesis.
    fn common_ancestor_height(&self, tip: &Hash32) -> u64 {
        let mut cursor = Some(*tip);
        while let Some(hash) = cursor {
            if let Some(index) = self.canonical.iter().position(|known| known == &hash) {
                return index as u64;
            }
            cursor = self
                .blocks
                .get(&hash)
                .map(|block| block.header.parent)
                .filter(|parent| *parent != hash);
        }
        0
    }

    /// Computes the reorganisation between the current head and a new tip.
    ///
    /// Returns `None` when the new tip simply extends the canonical chain: that
    /// is a plain block, not a reorganisation, and reporting it as one would
    /// make every node tell its operator (and its APIs) that the chain is
    /// reorganising on every block.
    fn reorganise(&self, tip_block: &Block) -> Result<Option<Reorg>, ChainError> {
        let new_path = canonical_path(&self.blocks, tip_block.hash());
        if new_path == self.canonical {
            return Ok(None);
        }
        let common = self
            .canonical
            .iter()
            .zip(new_path.iter())
            .take_while(|(left, right)| left == right)
            .count();
        let disconnected: Vec<Hash32> = self.canonical[common..].to_vec();
        let connected: Vec<Hash32> = new_path[common..].to_vec();
        if disconnected.is_empty() {
            // Nothing was rolled back: the tip extends the canonical chain,
            // however many blocks it adds at once.  A reorganisation is a change
            // of *branch*, and reporting extensions as reorganisations would
            // make every node announce one on every block.
            return Ok(None);
        }
        let ancestor = if common == 0 {
            self.genesis_hash()
        } else {
            self.canonical[common - 1]
        };
        Ok(Some(Reorg {
            ancestor,
            ancestor_height: common as u64,
            disconnected,
            connected,
        }))
    }

    /// Recomputes the canonical head from scratch (used after replay).
    fn recompute_head(&mut self) -> Result<(), ChainError> {
        let tips: Vec<(Hash32, ChainState)> = self
            .states
            .iter()
            .map(|(hash, state)| (*hash, state.clone()))
            .collect();
        let mut best: Option<(Hash32, ChainState)> = None;
        for (hash, state) in tips {
            let better = match &best {
                None => true,
                Some((_, current)) => is_better(&state, current),
            };
            if better {
                best = Some((hash, state));
            }
        }
        if let Some((hash, state)) = best {
            self.head = hash;
            self.canonical = canonical_path(&self.blocks, hash);
            self.states.insert(hash, state);
            crate::store::write_head(self.head_path(), &self.head)?;
        } else {
            self.head = self.genesis_hash();
            self.canonical = vec![self.head];
        }
        Ok(())
    }

    /// The state a block at `hash` was applied to, for building on a branch.
    ///
    /// Returns `None` when the block is unknown or its ancestry is incomplete.
    pub fn state_at(&mut self, hash: &Hash32) -> Option<ChainState> {
        self.state_for(hash)
    }

    /// Rebuilds the state at `hash`, replaying recorded blocks if needed.
    fn state_for(&mut self, hash: &Hash32) -> Option<ChainState> {
        if let Some(state) = self.states.get(hash) {
            return Some(state.clone());
        }
        // Walk up the parent chain collecting the path until a cached state.
        let mut path = Vec::new();
        let mut cursor = *hash;
        loop {
            if self.states.contains_key(&cursor) {
                break;
            }
            let block = self.blocks.get(&cursor)?;
            path.push(cursor);
            if path.len() as u64 > MAX_REPLAY_DEPTH {
                return None;
            }
            // The genesis block is its own parent: there is nothing above it.
            if block.header.parent == cursor {
                return None;
            }
            cursor = block.header.parent;
        }
        let mut state = self.states.get(&cursor)?.clone();
        for hash in path.iter().rev() {
            let block = self.blocks.get(hash)?;
            state = state.apply_block(block).ok()?.state;
        }
        self.states.insert(*hash, state.clone());
        self.prune_states(Some(*hash));
        Some(state)
    }

    /// Keeps the state cache bounded.  The head and the given tip are always
    /// retained; other entries are dropped deterministically (by hash order).
    fn prune_states(&mut self, keep_tip: Option<Hash32>) {
        if self.states.len() <= STATE_CACHE_LIMIT {
            return;
        }
        let mut candidates: Vec<Hash32> = self
            .states
            .keys()
            .copied()
            .filter(|hash| *hash != self.head && Some(*hash) != keep_tip)
            .collect();
        candidates.sort_by(|left, right| {
            // Drop the numerically largest hashes first; the ordering is
            // arbitrary but deterministic, so every node prunes identically.
            right.0.cmp(&left.0)
        });
        for hash in candidates {
            if self.states.len() <= STATE_CACHE_LIMIT {
                break;
            }
            self.states.remove(&hash);
        }
    }

    /// Rewrites the log so that it holds the canonical chain plus every branch
    /// block above the finalised height, dropping dead branches below it.
    ///
    /// Returns the number of blocks removed from the log.
    pub fn compact(&mut self) -> Result<usize, ChainError> {
        let finalized = self.head_state().finalized_height;
        let canonical: HashSet<Hash32> = self.canonical.iter().copied().collect();
        let mut kept: Vec<Block> = Vec::new();
        let mut dropped = 0usize;
        // Canonical blocks in order, then any branch blocks above finality.
        for hash in &self.canonical {
            if *hash == self.genesis_hash() {
                continue;
            }
            if let Some(block) = self.blocks.get(hash) {
                kept.push(block.clone());
            }
        }
        let mut branches: Vec<&Block> = self
            .blocks
            .values()
            .filter(|block| {
                !canonical.contains(&block.hash()) && block.header.height > finalized
            })
            .collect();
        branches.sort_by(|left, right| {
            left.header
                .height
                .cmp(&right.header.height)
                .then_with(|| left.hash().0.cmp(&right.hash().0))
        });
        dropped += self
            .blocks
            .keys()
            .filter(|hash| !canonical.contains(*hash))
            .filter(|hash| {
                self.blocks
                    .get(*hash)
                    .map(|block| block.header.height <= finalized)
                    .unwrap_or(false)
            })
            .count();
        for block in branches {
            kept.push(block.clone());
        }

        let temporary = self.log_path.with_extension("compact");
        {
            let (mut log, _) = BlockLog::open(&temporary, self.fsync)?;
            for block in &kept {
                log.append(block)?;
            }
            log.flush()?;
        }
        std::fs::rename(&temporary, &self.log_path)?;
        let (log, _) = BlockLog::open(&self.log_path, self.fsync)?;
        self.log = log;
        Ok(dropped)
    }

    fn head_path(&self) -> PathBuf {
        self.log_path
            .parent()
            .unwrap_or(Path::new("."))
            .join(crate::store::head_file_name(self.network))
    }

    /// The hash every chain in this network starts from.
    ///
    /// This is the network's genesis anchor — the value a state carries at
    /// height 0 and the parent of the first block.  It is derived from the
    /// chain id, the protocol version and the genesis timestamp, so two
    /// networks can never share it.
    /// The genesis this store was founded with, as read back from its data
    /// directory.  This is the chain's identity; the configuration a process was
    /// started with is only a proposal for a directory that has no chain yet.
    pub fn genesis(&self) -> &GenesisConfig {
        &self.genesis
    }

    pub fn genesis_hash(&self) -> Hash32 {
        genesis_anchor_hash(self.network, &self.genesis)
    }

    /// Current canonical head hash.
    pub fn head(&self) -> Hash32 {
        self.head
    }

    /// State at the canonical head.
    pub fn head_state(&self) -> &ChainState {
        self.states
            .get(&self.head)
            .expect("the head always has a state")
    }

    /// Canonical height (0 is the genesis block).
    pub fn height(&self) -> u64 {
        self.head_state().height
    }

    /// Canonical chain hashes, genesis first.
    pub fn canonical_hashes(&self) -> &[Hash32] {
        &self.canonical
    }

    /// A known block, canonical or not.
    pub fn block(&self, hash: &Hash32) -> Option<&Block> {
        self.blocks.get(hash)
    }

    /// The canonical block at a height.
    pub fn block_at_height(&self, height: u64) -> Option<&Block> {
        self.canonical
            .get(height as usize)
            .and_then(|hash| self.blocks.get(hash))
    }

    /// Blocks held waiting for an unknown parent.
    pub fn orphans(&self) -> &[Block] {
        &self.orphans
    }

    /// Number of blocks known to this node.
    pub fn known_blocks(&self) -> usize {
        self.blocks.len()
    }

    /// Storage path of this node's block log.
    pub fn log_path(&self) -> &Path {
        &self.log_path
    }

    /// The network this chain belongs to.
    pub fn network(&self) -> Network {
        self.network
    }
}

/// Fork choice: which of two branch tips wins.
///
/// Documented and total, so that every node agrees:
///
/// 1. the branch with the greater accumulated PoT weight wins;
/// 2. if weights are equal, the greater height wins;
/// 3. if both are equal, the lexicographically smaller head hash wins (which
///    makes the outcome independent of arrival order).
pub fn is_better(candidate: &ChainState, current: &ChainState) -> bool {
    if candidate.total_weight != current.total_weight {
        return candidate.total_weight > current.total_weight;
    }
    if candidate.height != current.height {
        return candidate.height > current.height;
    }
    candidate.last_block_hash.0 < current.last_block_hash.0
}

/// Reconstructs the chain of hashes ending at `tip`, genesis first.
///
/// Returns just the tip when the ancestry is incomplete, so callers never see a
/// silently truncated chain presented as complete.
fn canonical_path(blocks: &HashMap<Hash32, Block>, tip: Hash32) -> Vec<Hash32> {
    let mut path = Vec::new();
    let mut cursor = Some(tip);
    while let Some(hash) = cursor {
        path.push(hash);
        // The genesis block is its own parent; stop there.
        cursor = blocks
            .get(&hash)
            .map(|block| block.header.parent)
            .filter(|parent| *parent != hash);
    }
    path.reverse();
    path
}

/// Hash identifying the genesis block a state starts from.
fn genesis_anchor_hash(network: Network, genesis: &GenesisConfig) -> Hash32 {
    network.genesis_hash(obs_chain::params::PROTOCOL_VERSION, genesis.timestamp)
}
