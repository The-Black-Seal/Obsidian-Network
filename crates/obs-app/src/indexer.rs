//! The Explorer's indexer.
//!
//! ## Indexer is not authority
//!
//! Everything this module knows came from a node's API, and everything it
//! publishes says which block it came from.  It cannot create a block, approve a
//! claim, mint a coin or change a balance: it has no key, no consensus code and
//! no write path to the node.  If the index disagrees with the chain, the index
//! is wrong — so the API exposes [`Indexer::indexed_height`] next to the node's
//! height, and a visitor can see when the index is behind.
//!
//! ## What is indexed
//!
//! Blocks, transactions and *activity*:
//!
//! * a block: height, hash, parent, time, weight, difficulty, masked proposer,
//!   transaction count, finality;
//! * a transaction: id, kind, the block that carries it, fee, masked sender;
//! * an address: how many claims it has made and which blocks carried them.
//!
//! Deliberately absent: balances, per-account rewards, and whole addresses.
//! [`crate::privacy`] enforces that on the way out; this module does not even
//! collect it, so the data is not there to leak.
//!
//! ## How it follows the chain
//!
//! [`Indexer::sync`] asks the node for its newest blocks, adds the ones it has
//! not seen, fetches each new block's transactions and validators snapshot, and
//! records the height it has reached.  A reorganization is handled by refusing
//! to rewrite history silently: if a height the index already recorded comes
//! back with a different hash, the entry is *replaced* and the reorg is counted
//! and reported, because a block that was in the canonical chain is no longer
//! and pretending it never existed would be untruthful.

use std::collections::BTreeMap;

use obs_primitives::address::{mask, Address};
use obs_primitives::json::Json;
use obs_primitives::network::Network;
use obs_rpc::client::{json_body, Client, ClientError};

use crate::privacy::mask_address;

/// How many blocks of history one sync walks back through.
///
/// Bounded so that a sync cannot hold the index for as long as a chain is long:
/// the backfill walks backwards a slice at a time, and the API reports the range
/// it has covered so far.
const BACKFILL_BATCH: usize = 64;

/// A failure talking to the node.
#[derive(Debug)]
pub enum IndexError {
    /// The node could not be reached or answered badly.
    Transport(String),
    /// The node answered something this indexer does not understand.
    Shape(String),
}

impl core::fmt::Display for IndexError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            IndexError::Transport(detail) => write!(f, "node API: {}", detail),
            IndexError::Shape(detail) => write!(f, "node API answered something unexpected: {}", detail),
        }
    }
}

impl std::error::Error for IndexError {}

impl From<ClientError> for IndexError {
    fn from(error: ClientError) -> IndexError {
        IndexError::Transport(error.to_string())
    }
}

/// One indexed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedBlock {
    /// Height.
    pub height: u64,
    /// Hash.
    pub hash: String,
    /// Parent hash.
    pub parent: String,
    /// State root.
    pub state_root: String,
    /// Protocol timestamp.
    pub timestamp: u64,
    /// Slot.
    pub slot: u64,
    /// PoT weight, in atoms.
    pub weight_atoms: u128,
    /// PoT difficulty, in basis points.
    pub difficulty_bp: u32,
    /// The proposer's *partial* address.
    pub proposer: String,
    /// Transactions this block carries.
    pub transaction_ids: Vec<String>,
    /// Attestations this block carries.
    pub attestations: u64,
    /// Whether the node reports it as final.
    pub finalized: bool,
}

/// One indexed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedTransaction {
    /// Transaction id.
    pub id: String,
    /// Kind name, as the protocol names it.
    pub kind: String,
    /// Height of the block that carries it.
    pub height: u64,
    /// Fee paid, as a decimal string in OBS.
    pub fee: String,
    /// The sender's *partial* address.
    pub sender: String,
    /// Encoded size in bytes.
    pub size_bytes: u64,
}

/// What an address has done, as far as the public record shows.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AddressActivity {
    /// The partial address this record is keyed by.
    pub partial: String,
    /// Claims the address has made.
    pub claims: u64,
    /// Blocks whose proposer this address was.
    pub blocks_proposed: u64,
    /// First appearance, in protocol time.
    pub first_seen: u64,
    /// Most recent appearance, in protocol time.
    pub last_seen: u64,
    /// Heights the address appeared in, newest first, capped.
    pub recent_heights: Vec<u64>,
}

/// One validator's public participation record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IndexedValidator {
    /// Node identity public key (hex).  A validator's identity is a service key,
    /// not a wallet, and the protocol publishes it deliberately.
    pub node_key: String,
    /// The owner's *partial* address.
    pub owner: String,
    /// Bond, as a decimal string in OBS.
    pub bond: String,
    /// Uptime, in basis points.
    pub uptime_bp: u32,
    /// Attestations seen.
    pub attestations: u64,
    /// Blocks proposed.
    pub blocks_proposed: u64,
    /// Slots missed.
    pub missed_slots: u64,
    /// Active right now.
    pub active: bool,
}

/// Network-wide protocol figures.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NetworkSnapshot {
    /// Network name.
    pub network: String,
    /// Chain id.
    pub chain_id: u32,
    /// Node's height.
    pub node_height: u64,
    /// Head hash.
    pub head: String,
    /// State root.
    pub state_root: String,
    /// Protocol time.
    pub protocol_time: u64,
    /// MTP at the head.
    pub median_time_past: u64,
    /// PoT difficulty at the next block, in basis points.
    pub difficulty_bp: u32,
    /// Accumulated PoT weight.
    pub total_weight_atoms: u128,
    /// Issued supply, as a decimal string.
    pub issued_supply: String,
    /// Maximum supply, as a decimal string.
    pub max_supply: String,
    /// Active validators.
    pub active_validators: u64,
    /// Active miners (claimed within the activity window).
    pub active_miners: u64,
    /// Pooled transactions.
    pub pooled_transactions: u64,
    /// Peers.
    pub peers: u64,
}

/// The current mining schedule.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MiningSnapshot {
    /// Reward per claim, as a decimal string.
    pub reward_per_claim: String,
    /// Reward per claim, in grains.
    pub reward_per_claim_grains: u128,
    /// Rate per day, as a decimal string.
    pub daily_rate: String,
    /// Active miners, which set the halving position.
    pub active_miners: u64,
    /// Claims issued since genesis.
    pub claims_issued: u64,
    /// Minimum seconds between claims.
    pub interval_secs: u64,
    /// Maximum claims in a rolling day.
    pub max_claims_per_day: u64,
    /// Whether the genesis claim has been made.
    pub genesis_claim_issued: bool,
}

/// Supply and issuance, at the protocol level.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SupplySnapshot {
    /// Hard maximum supply.
    pub max_supply: String,
    /// Issued so far.
    pub issued_supply: String,
    /// The one-time genesis allocation.
    pub genesis_allocation: String,
    /// Whether the genesis allocation has been issued.
    pub genesis_issued: bool,
    /// The mining pool's balance.
    pub mining_pool: String,
    /// The validator reward pool's balance.
    pub validator_pool: String,
    /// Bonded value.
    pub locked_validator_bonds: String,
    /// Circulating (issued minus the two pools).
    pub circulating: String,
    /// Remaining until the cap.
    pub remaining: String,
}

/// The indexed view of the chain.
pub struct Indexer {
    client: Client,
    node_url: String,
    network: Network,
    blocks: BTreeMap<u64, IndexedBlock>,
    transactions: BTreeMap<String, IndexedTransaction>,
    activity: BTreeMap<String, AddressActivity>,
    validators: Vec<IndexedValidator>,
    /// Deepest height this index has seen.
    pub indexed_height: u64,
    /// The height below which this index has not read yet.
    ///
    /// `None` until the index has seen the chain's tail and learned where its
    /// history begins; `Some(0)` once it has read down to the genesis block.
    /// Anything in between is the backfill's cursor.  This is the field that
    /// makes "the index is behind" an honest statement rather than a guess: the
    /// index can be level with the node's head and still be missing everything
    /// that happened before it started, and those are different facts.
    pub next_missing: Option<u64>,
    /// Blocks replaced because a different block took their height.
    pub reorgs_seen: u64,
    /// Blocks added since the indexer started.
    pub blocks_added: u64,
    /// Times the node has been unreachable.
    pub sync_failures: u64,
    /// Times the backfill asked for history and the node returned none.
    ///
    /// A count above zero while `history_complete` is false means the node will
    /// not serve the blocks below the cursor — an operator's problem, not the
    /// index's, and one the index refuses to paper over.
    pub stalls: u64,
    /// The most recent error, for the operator's page.
    pub last_error: Option<String>,
    /// How many blocks to keep in memory.
    retention: usize,
    /// How many recent appearances to keep per address.
    recent_per_address: usize,
}

impl Indexer {
    /// Creates an indexer pointed at a node's API.
    pub fn new(node_url: impl Into<String>, network: Network) -> Indexer {
        Indexer {
            client: Client::with_timeout(std::time::Duration::from_secs(10)),
            node_url: node_url.into(),
            network,
            blocks: BTreeMap::new(),
            transactions: BTreeMap::new(),
            activity: BTreeMap::new(),
            validators: Vec::new(),
            indexed_height: 0,
            next_missing: None,
            reorgs_seen: 0,
            blocks_added: 0,
            sync_failures: 0,
            stalls: 0,
            last_error: None,
            retention: 5_000,
            recent_per_address: 20,
        }
    }

    /// Caps how many blocks are retained.
    pub fn with_retention(mut self, blocks: usize) -> Indexer {
        self.retention = blocks.max(1);
        self
    }

    /// The network this indexer serves.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The node it follows.
    pub fn node_url(&self) -> &str {
        &self.node_url
    }

    /// Blocks retained, newest first.
    pub fn blocks(&self, limit: usize, offset: usize) -> Vec<IndexedBlock> {
        self.blocks
            .values()
            .rev()
            .skip(offset)
            .take(limit)
            .cloned()
            .collect()
    }

    /// One block, by height or by hash.
    pub fn block(&self, selector: &str) -> Option<IndexedBlock> {
        if let Ok(height) = selector.parse::<u64>() {
            return self.blocks.get(&height).cloned();
        }
        self.blocks
            .values()
            .find(|block| block.hash.eq_ignore_ascii_case(selector))
            .cloned()
    }

    /// One transaction.
    pub fn transaction(&self, id: &str) -> Option<IndexedTransaction> {
        self.transactions.get(&id.to_ascii_lowercase()).cloned()
    }

    /// An address's public *activity*.
    ///
    /// A visitor who knows an address may ask what it has done, but the record is
    /// **keyed by the partial address**: the index never stores an address in
    /// full, so a copy of the index is not a list of participants.  The cost is
    /// that two addresses sharing a partial form would share a record; with the
    /// mask's fixed prefix and suffix that is a collision nobody has ever
    /// observed, and the merged record would still hold only counts.
    pub fn activity(&self, address: &str) -> Option<AddressActivity> {
        self.activity.get(&self.activity_key(address)).cloned()
    }

    /// The key an activity record is stored and looked up under.
    fn activity_key(&self, address: &str) -> String {
        if address.contains("...") {
            return address.to_ascii_lowercase();
        }
        match Address::parse(self.network, address) {
            Ok(parsed) => mask(&parsed).to_ascii_lowercase(),
            Err(_) => address.to_ascii_lowercase(),
        }
    }

    /// The validator set as last seen.
    pub fn validators(&self) -> &[IndexedValidator] {
        &self.validators
    }

    /// How many blocks are indexed.
    pub fn block_count(&self) -> usize {
        self.blocks.len()
    }

    // -----------------------------------------------------------------------
    // Following the chain
    // -----------------------------------------------------------------------

    fn get(&self, path: &str) -> Result<Json, IndexError> {
        let response = self.client.get(&format!("{}{}", self.node_url, path))?;
        if response.status.code() != 200 {
            return Err(IndexError::Transport(format!(
                "{} answered {}",
                path,
                response.status.code()
            )));
        }
        json_body(&response).map_err(IndexError::from)
    }

    /// Reads the network's current figures.
    pub fn status(&self) -> Result<NetworkSnapshot, IndexError> {
        let value = self.get("/api/v1/status")?;
        let number = |name: &str| -> Result<u128, IndexError> {
            value
                .get(name)
                .and_then(Json::as_i128)
                .map(|value| value as u128)
                .ok_or_else(|| IndexError::Shape(format!("status.{} is missing", name)))
        };
        let text = |name: &str| -> Result<String, IndexError> {
            value
                .get(name)
                .and_then(Json::as_str)
                .map(|value| value.to_string())
                .ok_or_else(|| IndexError::Shape(format!("status.{} is missing", name)))
        };
        Ok(NetworkSnapshot {
            network: text("network")?,
            chain_id: number("chain_id")? as u32,
            node_height: number("height")? as u64,
            head: text("head")?,
            state_root: text("state_root")?,
            protocol_time: number("protocol_time")? as u64,
            median_time_past: number("median_time_past")? as u64,
            difficulty_bp: number("pot_difficulty_bp")? as u32,
            total_weight_atoms: number("total_weight_atoms")?,
            issued_supply: text("issued_supply")?,
            max_supply: text("max_supply")?,
            active_validators: number("active_validators")? as u64,
            active_miners: number("active_miners")? as u64,
            pooled_transactions: number("pooled_transactions")? as u64,
            peers: number("peers")? as u64,
        })
    }

    /// Reads the mining schedule.
    pub fn mining(&self) -> Result<MiningSnapshot, IndexError> {
        let value = self.get("/api/v1/mining")?;
        let text = |name: &str| -> Result<String, IndexError> {
            value
                .get(name)
                .and_then(Json::as_str)
                .map(|value| value.to_string())
                .ok_or_else(|| IndexError::Shape(format!("mining.{} is missing", name)))
        };
        let number = |name: &str| -> Result<u128, IndexError> {
            value
                .get(name)
                .and_then(Json::as_i128)
                .map(|value| value as u128)
                .ok_or_else(|| IndexError::Shape(format!("mining.{} is missing", name)))
        };
        Ok(MiningSnapshot {
            reward_per_claim: text("reward_per_claim")?,
            reward_per_claim_grains: number("reward_per_claim_grains")?,
            daily_rate: text("daily_rate")?,
            active_miners: number("active_miners")? as u64,
            claims_issued: number("claims_issued")? as u64,
            interval_secs: number("interval_secs")? as u64,
            max_claims_per_day: number("max_claims_per_day")? as u64,
            genesis_claim_issued: value
                .get("genesis_claim_issued")
                .and_then(Json::as_bool)
                .unwrap_or(false),
        })
    }

    /// Reads supply and issuance.
    pub fn supply(&self) -> Result<SupplySnapshot, IndexError> {
        let value = self.get("/api/v1/supply")?;
        let text = |name: &str| -> Result<String, IndexError> {
            value
                .get(name)
                .and_then(Json::as_str)
                .map(|value| value.to_string())
                .ok_or_else(|| IndexError::Shape(format!("supply.{} is missing", name)))
        };
        Ok(SupplySnapshot {
            max_supply: text("max_supply")?,
            issued_supply: text("issued_supply")?,
            genesis_allocation: text("genesis_allocation")?,
            genesis_issued: value.get("genesis_issued").and_then(Json::as_bool).unwrap_or(false),
            mining_pool: text("mining_pool")?,
            validator_pool: text("validator_pool")?,
            locked_validator_bonds: text("locked_validator_bonds")?,
            circulating: text("circulating")?,
            remaining: text("remaining")?,
        })
    }

    /// Reads the validator set.
    pub fn refresh_validators(&mut self) -> Result<(), IndexError> {
        let value = self.get("/api/v1/validators")?;
        let entries = value
            .get("validators")
            .and_then(Json::as_array)
            .ok_or_else(|| IndexError::Shape("validators.validators is missing".to_string()))?;
        let mut validators = Vec::with_capacity(entries.len());
        for entry in entries {
            let text = |name: &str| entry.get(name).and_then(Json::as_str).unwrap_or_default().to_string();
            let number = |name: &str| entry.get(name).and_then(Json::as_i128).unwrap_or(0) as u64;
            validators.push(IndexedValidator {
                node_key: text("node_key"),
                owner: text("owner"),
                bond: text("bond"),
                uptime_bp: number("uptime_bp") as u32,
                attestations: number("attestations"),
                blocks_proposed: number("blocks_proposed"),
                missed_slots: number("missed_slots"),
                active: entry.get("active").and_then(Json::as_bool).unwrap_or(false),
            });
        }
        self.validators = validators;
        Ok(())
    }

    /// Follows the chain: adds blocks the index has not seen.
    ///
    /// Returns how many blocks were added.  This is the whole write path, and it
    /// writes only to the index.
    pub fn sync(&mut self) -> Result<usize, IndexError> {
        let result = self.sync_inner();
        match &result {
            Ok(_) => {
                self.last_error = None;
            }
            Err(error) => {
                self.sync_failures += 1;
                self.last_error = Some(error.to_string());
            }
        }
        result
    }

    fn sync_inner(&mut self) -> Result<usize, IndexError> {
        let mut added = self.sync_recent()?;
        added += self.backfill(BACKFILL_BATCH)?;
        if added > 0 {
            self.refresh_validators()?;
        }
        Ok(added)
    }

    /// How many blocks of history one `sync` is willing to read.
    ///
    /// Bounded on purpose.  A chain can be older than any index, and a sync that
    /// tried to read all of it would hold the index's lock for as long as the
    /// chain is long — so the backfill walks backwards a slice at a time and is
    /// honest about the range it has covered so far.
    fn backfill(&mut self, batch: usize) -> Result<usize, IndexError> {
        let Some(below) = self.next_missing else {
            // The tail has not been read yet: nothing to walk back from.
            return Ok(0);
        };
        if below == 0 {
            return Ok(0);
        }
        let page = self.get(&format!("/api/v1/blocks?limit={}&before={}", batch, below))?;
        let summaries = page
            .get("blocks")
            .and_then(Json::as_array)
            .ok_or_else(|| IndexError::Shape("blocks.blocks is missing".to_string()))?;
        let mut added = 0usize;
        let mut lowest = below;
        // Oldest first, so the activity timeline is built in the right order and
        // the cursor only ever moves towards the genesis block.
        for summary in summaries.iter().rev() {
            let height = summary
                .get("height")
                .and_then(Json::as_i128)
                .ok_or_else(|| IndexError::Shape("block.height is missing".to_string()))?
                as u64;
            lowest = lowest.min(height);
            if self.blocks.contains_key(&height) {
                continue;
            }
            let block = self.fetch_block(height)?;
            self.record_block(block);
            added += 1;
        }
        if self.blocks.contains_key(&1) || lowest == 1 {
            // The genesis block is in hand: there is nothing below it, and the
            // history from block 1 up has been read.
            self.next_missing = Some(0);
        } else if lowest < below {
            self.next_missing = Some(lowest.saturating_sub(1));
        } else {
            // The page carried nothing below the cursor, so the walk cannot move
            // — and this is *not* the end of history.  A node that answers the
            // newest window whatever it is asked for would otherwise be mistaken
            // for a chain that begins where the index happened to start, and the
            // index would report a complete history it has never read.  So the
            // cursor stays where it is, the stall is counted, and the status
            // route keeps saying the history is incomplete.
            self.stalls += 1;
            self.last_error = Some(format!(
                "the node returned no blocks below {}: the index cannot read further back",
                below
            ));
        }
        Ok(added)
    }

    /// Reads the newest blocks — the window the index follows continuously — and
    /// learns, the first time it sees them, how far back the history goes.
    fn sync_recent(&mut self) -> Result<usize, IndexError> {
        // Fetch the recent blocks the node is willing to hand over in one call.
        let recent = self.get("/api/v1/blocks?limit=32")?;
        let summaries = recent
            .get("blocks")
            .and_then(Json::as_array)
            .ok_or_else(|| IndexError::Shape("blocks.blocks is missing".to_string()))?;
        let mut added = 0usize;
        // Oldest first, so the activity timeline is built in the right order.
        for summary in summaries.iter().rev() {
            let height = summary
                .get("height")
                .and_then(Json::as_i128)
                .ok_or_else(|| IndexError::Shape("block.height is missing".to_string()))?
                as u64;
            if self.blocks.contains_key(&height) {
                continue;
            }
            let block = self.fetch_block(height)?;
            self.record_block(block);
            added += 1;
        }
        // An index that has just started is level with the node's head and has
        // read none of the blocks below it.  Now that its oldest block is known,
        // everything under it is the backfill's work.
        if self.next_missing.is_none() {
            if let Some(oldest) = self.blocks.keys().next().copied() {
                self.next_missing = Some(oldest.saturating_sub(1));
            }
        }
        Ok(added)
    }

    /// The lowest block this index holds, or 0 when it holds none.
    pub fn indexed_from(&self) -> u64 {
        self.blocks.keys().next().copied().unwrap_or(0)
    }

    /// Whether the index has *read* every block from the genesis block up.
    ///
    /// This is a fact about reading, not about holding: retention can drop old
    /// blocks from memory on a long chain, and `indexed_from` is the range the
    /// explorer answers about.  What this field refuses to do is call a partial
    /// chain complete — an index level with the head and holding the newest
    /// window is not a whole explorer, and the API says which of the two it is.
    pub fn history_complete(&self) -> bool {
        // `Some(0)` is the sentinel the backfill sets only when it has held the
        // genesis block; `None` means it has not read the tail yet.
        self.next_missing == Some(0)
    }

    fn fetch_block(&self, height: u64) -> Result<IndexedBlock, IndexError> {
        let value = self.get(&format!("/api/v1/blocks/{}", height))?;
        let text = |name: &str| -> Result<String, IndexError> {
            value
                .get(name)
                .and_then(Json::as_str)
                .map(|value| value.to_string())
                .ok_or_else(|| IndexError::Shape(format!("block.{} is missing", name)))
        };
        let number = |name: &str| -> Result<u128, IndexError> {
            value
                .get(name)
                .and_then(Json::as_i128)
                .map(|value| value as u128)
                .ok_or_else(|| IndexError::Shape(format!("block.{} is missing", name)))
        };
        let transaction_ids = value
            .get("transaction_ids")
            .and_then(Json::as_array)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| id.as_str().map(|text| text.to_string()))
                    .collect()
            })
            .unwrap_or_default();
        Ok(IndexedBlock {
            height: number("height")? as u64,
            hash: text("hash")?,
            parent: text("parent")?,
            state_root: text("state_root")?,
            timestamp: number("timestamp")? as u64,
            slot: number("slot")? as u64,
            weight_atoms: number("weight_atoms")?,
            difficulty_bp: number("difficulty_bp")? as u32,
            proposer: text("proposer")?,
            transaction_ids,
            attestations: number("attestations")? as u64,
            finalized: value.get("finalized").and_then(Json::as_bool).unwrap_or(false),
        })
    }

    fn record_block(&mut self, block: IndexedBlock) {
        // A height that already exists with a different hash is a reorg: the
        // index says so rather than rewriting history quietly.
        let replaced = self
            .blocks
            .get(&block.height)
            .map(|previous| previous.clone());
        if let Some(previous) = replaced {
            if previous.hash == block.hash {
                return;
            }
            self.reorgs_seen += 1;
            self.forget_block(&previous);
        }
        let proposer_partial = block.proposer.clone();
        let height = block.height;
        for id in &block.transaction_ids {
            if let Ok(transaction) = self.fetch_transaction(id, block.height) {
                // A claim is counted where it is *recorded*, not where it is
                // asked about: the earlier shape of this code counted claims in
                // a method no caller used, so every address in the explorer
                // reported "claims: 0" — including the address that claimed the
                // genesis allocation.  A figure that is always zero is not a
                // privacy feature, it is a bug with a privacy story.
                if transaction.kind == "claim" {
                    let sender = transaction.sender.clone();
                    self.note_claim(&sender, block.height, block.timestamp);
                }
                self.transactions.insert(id.to_ascii_lowercase(), transaction);
            }
        }
        self.bump_activity(&proposer_partial, block.height, block.timestamp, true);
        self.blocks.insert(height, block);
        self.blocks_added += 1;
        if self.blocks.len() > self.retention {
            let oldest = *self.blocks.keys().next().unwrap_or(&0);
            if let Some(evicted) = self.blocks.remove(&oldest) {
                self.forget_block(&evicted);
            }
        }
        if height > self.indexed_height {
            self.indexed_height = height;
        }
    }

    fn forget_block(&mut self, block: &IndexedBlock) {
        for id in &block.transaction_ids {
            self.transactions.remove(&id.to_ascii_lowercase());
        }
    }

    fn fetch_transaction(&self, id: &str, height: u64) -> Result<IndexedTransaction, IndexError> {
        let value = self.get(&format!("/api/v1/transactions/{}", id))?;
        let sender = value
            .get("sender")
            .and_then(Json::as_str)
            .map(|text| text.to_string())
            .unwrap_or_else(|| "obs1...".to_string());
        // The node already masks senders; re-mask defensively so an indexer
        // pointed at a node that does not cannot publish a whole address.
        let sender = if sender.contains("...") {
            sender
        } else {
            mask_address(&parse_address(self.network, &sender).unwrap_or_else(|| {
                Address::from_public_key(self.network, &[0u8; 32])
            }))
        };
        Ok(IndexedTransaction {
            id: id.to_ascii_lowercase(),
            kind: value
                .get("kind")
                .and_then(Json::as_str)
                .unwrap_or("unknown")
                .to_string(),
            height,
            fee: value
                .get("fee")
                .and_then(Json::as_str)
                .unwrap_or("0")
                .to_string(),
            sender,
            size_bytes: value.get("size_bytes").and_then(Json::as_i128).unwrap_or(0) as u64,
        })
    }

    fn bump_activity(&mut self, address: &str, height: u64, timestamp: u64, proposed: bool) {
        let key = self.activity_key(address);
        let recent_per_address = self.recent_per_address;
        let entry = self.activity.entry(key).or_insert_with(|| AddressActivity {
            partial: mask_text(address),
            claims: 0,
            blocks_proposed: 0,
            first_seen: timestamp,
            last_seen: timestamp,
            recent_heights: Vec::new(),
        });
        if proposed {
            entry.blocks_proposed += 1;
        }
        if timestamp > 0 {
            if entry.first_seen == 0 || timestamp < entry.first_seen {
                entry.first_seen = timestamp;
            }
            if timestamp > entry.last_seen {
                entry.last_seen = timestamp;
            }
        }
        // Newest first, and holding the *highest* heights rather than the last
        // ones recorded.  The difference only shows when an index reads history
        // backwards: if the cap kept whatever arrived most recently, a backfill
        // would end with a "recent" list naming the genesis blocks — the exact
        // opposite of what the field says it is.
        if !entry.recent_heights.contains(&height) {
            entry.recent_heights.push(height);
        }
        entry.recent_heights.sort_unstable_by(|left, right| right.cmp(left));
        entry.recent_heights.truncate(recent_per_address);
    }

    /// Records a claim against an address's activity.
    ///
    /// Claims are the mining side of the public record: *that* an address mined
    /// is public, how much it holds is not.  The address arrives as the node
    /// publishes it — masked — which is also the key activity is stored under,
    /// so the explorer never has to hold a whole address to count what it did.
    fn note_claim(&mut self, published: &str, height: u64, timestamp: u64) {
        let key = self.activity_key(published);
        self.bump_activity(&key, height, timestamp, false);
        if let Some(entry) = self.activity.get_mut(&key) {
            entry.claims += 1;
        }
    }

    /// How many addresses the index has seen activity for.
    pub fn address_count(&self) -> usize {
        self.activity.len()
    }
}

fn mask_text(address: &str) -> String {
    match parse_address(obs_primitives::network::MAINNET, address) {
        Some(address) => mask(&address),
        None => address.to_string(),
    }
}

fn parse_address(network: Network, text: &str) -> Option<Address> {
    Address::parse(network, text).ok()
}
