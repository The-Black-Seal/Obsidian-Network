//! The Obsidian Network state machine.
//!
//! [`ChainState`] is a complete, deterministic snapshot of everything the
//! protocol knows.  `apply_block` takes such a snapshot plus one block and
//! returns either an error or a **new** snapshot — it never mutates the input,
//! so a rejected block cannot leave a partially-applied state behind.  Every
//! invalid or unknown input fails closed.
//!
//! Rules implemented here and nowhere else:
//!
//! * block position, proof-of-time weight, PoT difficulty and proposer
//!   authorisation (including the time-bounded bootstrap rule),
//! * the three timestamp rules (see [`crate::validate`]),
//! * transaction validity: chain binding, signature, nonce, balance, fee,
//! * mining claims: 4-hour interval, six-per-protocol-day cap, genesis
//!   allocation exactly once, halving schedule, supply cap,
//! * registration: invitation authorisation, single-use invitations, one
//!   account per canonical Gmail, zero starting balance,
//! * validators: 50 OBS bond, distinct node identity key, evidence-based
//!   uptime, 48-hour unbonding, equivocation handling,
//! * the 40/60 gas split and epoch validator reward distribution.
//!
//! Nothing in this module can be influenced by a client, a browser, an API key
//! or a node operator: the only inputs are the parent state and the block.

use std::collections::BTreeMap;

use obs_primitives::address::Address;
use obs_primitives::codec::Encode;
use obs_primitives::hash::{merkle_root, Hash32};
use obs_primitives::money::{Amount, MAX_SUPPLY};
use obs_primitives::network::Network;

use crate::block::{Attestation, Block};
use crate::chain::{Account, Claim, ExitReason, InviteRecord, TxId, TxKind, ValidatorRecord};
use crate::mining::{active_miner_count, reward_for_claim};
use crate::params::{
    MAX_TXS_PER_BLOCK,
    BOOTSTRAP_SLOTS, CLAIM_INTERVAL_SECS, DIFFICULTY_INITIAL_BP, DIFFICULTY_WINDOW_BLOCKS,
    EPOCH_SLOTS, FINALITY_QUORUM_DENOMINATOR, FINALITY_QUORUM_NUMERATOR, GENESIS_ALLOCATION,
    GENESIS_BLOCK_HEIGHT, MAX_CLAIMS_PER_DAY, MAX_INVITES_PER_ACCOUNT, MAX_NODE_ENDPOINT_LEN,
    MAX_VALIDATORS, MIN_UPTIME_BP, MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL, PROTOCOL_DAY_SECS,
    PROTOCOL_VERSION, SLOT_DURATION_SECS, STATE_HISTORY_BLOCKS,
    UNBONDING_PERIOD_SECS, VALIDATOR_BOND, VALIDATOR_REWARD_EPOCH_SLOTS, gas_fee_for,
    split_gas_fee,
};
use crate::pot::{
    PoTWeight, median_time_past, next_difficulty_bp, proposer_for_slot, raw_difficulty_bp,
    slots_between, weight_of_block,
};
use crate::tx::Transaction;
use crate::validate::{check_claim_protocol_time, check_timestamp_rules};

/// A rule violation.  `rule` is a stable machine-readable identifier (tests,
/// logs and APIs assert on it); `detail` is human-readable and never contains
/// secrets.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StateError {
    /// Machine-readable rule identifier, e.g. `claim_interval`.
    pub rule: &'static str,
    /// Human-readable explanation.
    pub detail: String,
}

impl StateError {
    /// Builds an error.
    pub fn new(rule: &'static str, detail: impl Into<String>) -> StateError {
        StateError {
            rule,
            detail: detail.into(),
        }
    }
}

impl core::fmt::Display for StateError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}: {}", self.rule, self.detail)
    }
}

impl std::error::Error for StateError {}

/// Genesis configuration for a network.
///
/// The genesis configuration contains **no secrets**: the registration
/// authority public key, the network and the genesis timestamp.  The
/// registration authority can only authorise new empty accounts (see
/// [`crate::chain::InviteAuthorization`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GenesisConfig {
    /// Network this chain runs.
    pub network: Network,
    /// Public key of the registration authority (the server that holds the
    /// invitation codes and the Gmail/password/MFA accounts).
    pub registration_authority: [u8; 32],
    /// Genesis protocol timestamp.
    pub timestamp: u64,
}

/// One bookkeeping entry produced by applying a block or transaction.  These
/// entries are what the Explorer and the APIs report; they are derived from
/// consensus, never an alternative source of truth.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LedgerEntry {
    /// Machine-readable entry kind (`register`, `claim`, `genesis`, `transfer`,
    /// `fee`, `bond`, `unbond`, `validator_reward`, `attestation`, `finality`,
    /// `equivocation`).
    pub kind: &'static str,
    /// Account the entry refers to, when there is one.
    pub account: Option<Address>,
    /// Value moved, when the entry moves value.
    pub amount: Amount,
    /// Human-readable detail.  Never contains secrets, keys or addresses other
    /// than those already public on-chain.
    pub detail: String,
}

/// Everything a block changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockEffects {
    /// Height of the applied block.
    pub height: u64,
    /// Hash of the applied block.
    pub hash: Hash32,
    /// Number of transactions applied.
    pub transactions: usize,
    /// Number of attestations applied.
    pub attestations: usize,
    /// Total gas fees collected in this block.
    pub fees: Amount,
    /// Value issued by mining in this block.
    pub mining_issued: Amount,
    /// Genesis allocation issued by this block, if any.
    pub genesis_issued: Option<Amount>,
    /// Validator rewards distributed at this block, if it closed an epoch.
    pub validator_rewards: Amount,
    /// Total issued supply after the block.
    pub issued_supply: Amount,
    /// PoT weight accumulated by this block.
    pub weight: PoTWeight,
    /// Highest finalised height known after this block.
    pub finalized_height: u64,
    /// Bookkeeping entries, in application order.
    pub entries: Vec<LedgerEntry>,
}

/// The result of applying a block: the new state and what changed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Applied {
    /// State after the block.
    pub state: ChainState,
    /// Effects of the block.
    pub effects: BlockEffects,
}

/// Which checks a state transition must perform.
///
/// `Build` is the block-*production* path: the header is not signed yet and the
/// state root it will commit to is exactly what the build is trying to
/// discover, so those two checks are skipped on the dry run.  `Commit` is the
/// consensus path and performs every check, including both of them.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Phase {
    Build,
    Commit,
}

/// Result of applying one transaction: the fee it paid, the mining value it
/// issued (always zero for non-claim transactions) and the genesis allocation
/// if it triggered one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
struct TxOutcome {
    fee: Amount,
    mining_issued: Amount,
    genesis_issued: Option<Amount>,
}

/// Complete protocol state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChainState {
    /// Network identity.
    pub network: Network,
    /// Registration authority public key.
    pub registration_authority: [u8; 32],
    /// Height of the most recent block.
    pub height: u64,
    /// Hash of the most recent block.
    pub last_block_hash: Hash32,
    /// Protocol timestamp of the most recent block.
    pub last_timestamp: u64,
    /// Slot of the most recent block.
    pub last_slot: u64,
    /// PoT difficulty that the *next* block must carry, in basis points.
    pub last_difficulty_bp: u32,
    /// Accumulated PoT weight of the whole chain.
    pub total_weight: PoTWeight,
    /// Total issued supply (genesis allocation + mining issuance).  Fees and
    /// rewards only ever redistribute issued value.
    pub issued_supply: Amount,
    /// Accounts by address.
    pub accounts: BTreeMap<Address, Account>,
    /// Validators by node identity key.
    pub validators: BTreeMap<[u8; 32], ValidatorRecord>,
    /// Canonical Gmail commitment → account, enforcing one account per Gmail.
    pub gmail_bindings: BTreeMap<Hash32, Address>,
    /// Redeemed invitation commitments.
    pub invite_redemptions: BTreeMap<Hash32, InviteRecord>,
    /// Genesis wallet (the treasury): the account of the first genesis claim.
    pub treasury: Option<Address>,
    /// True once the genesis allocation has been issued.
    pub genesis_issued: bool,
    /// Total number of accepted claims.
    pub total_claims: u64,
    /// Mining pool: 60% of every gas fee, funding future mining issuance costs.
    pub mining_pool: Amount,
    /// Validator reward pool: 40% of every gas fee.
    pub validator_pool: Amount,
    /// Highest finalised height.
    pub finalized_height: u64,
    /// Height → timestamp, retained for the difficulty and MTP windows.
    pub timestamps: BTreeMap<u64, u64>,
    /// Height → block hash, retained for attestation and fork-window checks.
    pub block_hashes: BTreeMap<u64, Hash32>,
    /// (height, node key) → attested block hash, for equivocation evidence.
    pub attestation_index: BTreeMap<(u64, [u8; 32]), Hash32>,
    /// Height → (distinct attesting validators, block hash), for finality.
    pub attestation_counts: BTreeMap<u64, (u64, Hash32)>,
    /// Blocks applied in the current validator-reward epoch.
    pub epoch_blocks: u64,
    /// Attestations per validator in the current epoch.
    pub epoch_attested: BTreeMap<[u8; 32], u64>,
    /// Attested weight per validator in the current epoch.
    pub epoch_weight: BTreeMap<[u8; 32], u128>,
}

impl ChainState {
    /// Creates the genesis state for a network.
    pub fn new(config: &GenesisConfig) -> ChainState {
        let genesis_hash = config
            .network
            .genesis_hash(PROTOCOL_VERSION, config.timestamp);
        let mut timestamps = BTreeMap::new();
        timestamps.insert(0, config.timestamp);
        let mut block_hashes = BTreeMap::new();
        block_hashes.insert(0, genesis_hash);
        ChainState {
            network: config.network,
            registration_authority: config.registration_authority,
            height: 0,
            last_block_hash: genesis_hash,
            last_timestamp: config.timestamp,
            last_slot: config.timestamp / SLOT_DURATION_SECS,
            last_difficulty_bp: DIFFICULTY_INITIAL_BP,
            total_weight: PoTWeight::ZERO,
            issued_supply: Amount::ZERO,
            accounts: BTreeMap::new(),
            validators: BTreeMap::new(),
            gmail_bindings: BTreeMap::new(),
            invite_redemptions: BTreeMap::new(),
            treasury: None,
            genesis_issued: false,
            total_claims: 0,
            mining_pool: Amount::ZERO,
            validator_pool: Amount::ZERO,
            finalized_height: 0,
            timestamps,
            block_hashes,
            attestation_index: BTreeMap::new(),
            attestation_counts: BTreeMap::new(),
            epoch_blocks: 0,
            epoch_attested: BTreeMap::new(),
            epoch_weight: BTreeMap::new(),
        }
    }

    // -----------------------------------------------------------------------
    // Read-only accessors
    // -----------------------------------------------------------------------

    /// Balance of an account, or zero when the account does not exist.
    pub fn balance(&self, address: &Address) -> Amount {
        self.accounts
            .get(address)
            .map(|account| account.balance)
            .unwrap_or(Amount::ZERO)
    }

    /// Account record, if it exists.
    pub fn account(&self, address: &Address) -> Option<&Account> {
        self.accounts.get(address)
    }

    /// Validator record by node identity key.
    pub fn validator(&self, node_key: &[u8; 32]) -> Option<&ValidatorRecord> {
        self.validators.get(node_key)
    }

    /// Node identity keys of the active validator set, in canonical order
    /// (ascending node key).  This ordering is part of proposer scheduling.
    pub fn active_validators(&self) -> Vec<[u8; 32]> {
        self.validators
            .iter()
            .filter(|(_, record)| record.is_active())
            .map(|(key, _)| *key)
            .collect()
    }

    /// Total value locked in validator bonds.
    pub fn locked_bonds(&self) -> Amount {
        let total: u128 = self
            .validators
            .values()
            .map(|record| record.bond.grains())
            .sum();
        Amount(total)
    }

    /// Median time past of the retained recent blocks.
    pub fn median_time_past(&self) -> u64 {
        let stamps: Vec<u64> = self.timestamps.values().copied().collect();
        median_time_past(&stamps).unwrap_or(self.last_timestamp)
    }

    /// Number of miners active at a protocol time.
    pub fn active_miner_count_at(&self, at: u64) -> u64 {
        active_miner_count(self.accounts.values().map(|a| &a.last_claim_at), at)
    }

    /// The mining reward a claim accepted at `at` would pay.
    pub fn mining_reward_at(&self, at: u64) -> Amount {
        reward_for_claim(self.active_miner_count_at(at))
    }

    /// Deterministic Obsidian Validator Score (0..=100).
    ///
    /// Four evidence-based components, no self-reported input:
    /// * uptime (40): the fraction of blocks in the current epoch attested,
    /// * participation (30): attestations relative to blocks since registration,
    /// * efficiency (20): attestations relative to attestation opportunities,
    /// * reliability (10): how recently the validator last attested.
    pub fn validator_score(&self, node_key: &[u8; 32], at: u64) -> Option<u32> {
        let record = self.validators.get(node_key)?;
        let uptime_bp = self.uptime_bp(node_key, at);
        let opportunities_since_registration = self
            .height
            .saturating_sub(record.registered_at_height);
        let participation_bp = if opportunities_since_registration == 0 {
            0
        } else {
            (record.attestation_count.min(opportunities_since_registration) * 10_000
                / opportunities_since_registration) as u32
        };
        let opportunities = record.attestation_count + record.missed_slots;
        let efficiency_bp = if opportunities == 0 {
            0
        } else {
            (record.attestation_count * 10_000 / opportunities) as u32
        };
        let since = at.saturating_sub(record.last_attestation_at);
        let reliability_bp = if record.last_attestation_at == 0 {
            0
        } else {
            let missed_slots = since / SLOT_DURATION_SECS;
            10_000u64
                .saturating_sub(missed_slots.saturating_mul(1_000))
                .min(10_000) as u32
        };

        let score = (uptime_bp.min(10_000) * crate::params::SCORE_WEIGHT_UPTIME
            + participation_bp.min(10_000) * crate::params::SCORE_WEIGHT_PARTICIPATION
            + efficiency_bp.min(10_000) * crate::params::SCORE_WEIGHT_EFFICIENCY
            + reliability_bp.min(10_000) * crate::params::SCORE_WEIGHT_RELIABILITY)
            / 10_000;
        Some(score.min(100))
    }

    /// Attestation uptime of a validator in the current epoch, in basis points.
    pub fn uptime_bp(&self, node_key: &[u8; 32], _at: u64) -> u32 {
        let attested = self.epoch_attested.get(node_key).copied().unwrap_or(0);
        let blocks = self.epoch_blocks_in_progress();
        if blocks == 0 {
            return 0;
        }
        ((attested.min(blocks) * 10_000 / blocks) as u32).min(10_000)
    }

    /// Blocks applied so far in the current validator-reward epoch.  This is
    /// exactly the number of attestation opportunities each active validator
    /// had in the epoch, which is why uptime is evidence-based.
    fn epoch_blocks_in_progress(&self) -> u64 {
        self.epoch_blocks
    }

    // -----------------------------------------------------------------------
    // State commitment
    // -----------------------------------------------------------------------

    /// Deterministic Merkle root over the whole state.
    ///
    /// Leaves are emitted in canonical order (accounts by address, validators
    /// by node key, invitations by commitment, Gmail bindings by commitment),
    /// so two nodes with identical state always compute the identical root.
    pub fn state_root(&self) -> Hash32 {
        let mut leaves: Vec<Vec<u8>> = Vec::with_capacity(
            self.accounts.len() + self.validators.len() + self.invite_redemptions.len() + 5,
        );
        for (address, account) in &self.accounts {
            let mut leaf = Vec::with_capacity(1 + 200);
            leaf.push(b'A');
            leaf.extend_from_slice(&address.encoded());
            leaf.extend_from_slice(&account.encoded());
            leaves.push(leaf);
        }
        for record in self.validators.values() {
            let mut leaf = Vec::with_capacity(1 + 256);
            leaf.push(b'V');
            leaf.extend_from_slice(&record.encoded());
            leaves.push(leaf);
        }
        for (commitment, record) in &self.invite_redemptions {
            let mut leaf = Vec::with_capacity(1 + 96);
            leaf.push(b'I');
            leaf.extend_from_slice(&commitment.0);
            leaf.extend_from_slice(&record.encoded());
            leaves.push(leaf);
        }
        for (commitment, address) in &self.gmail_bindings {
            let mut leaf = Vec::with_capacity(1 + 64);
            leaf.push(b'G');
            leaf.extend_from_slice(&commitment.0);
            leaf.extend_from_slice(&address.encoded());
            leaves.push(leaf);
        }
        let mut pools = vec![b'P'];
        pools.extend_from_slice(&self.mining_pool.encoded());
        pools.extend_from_slice(&self.validator_pool.encoded());
        pools.extend_from_slice(&self.issued_supply.encoded());
        pools.extend_from_slice(&self.total_claims.to_le_bytes());
        pools.extend_from_slice(&self.total_weight.atoms.to_le_bytes());
        pools.extend_from_slice(&self.finalized_height.to_le_bytes());
        leaves.push(pools);
        let mut governance = vec![b'T'];
        governance.extend_from_slice(&self.registration_authority);
        governance.extend_from_slice(
            &self
                .treasury
                .map(|address| address.encoded())
                .unwrap_or_default(),
        );
        governance.push(u8::from(self.genesis_issued));
        leaves.push(governance);
        merkle_root(&leaves)
    }

    // -----------------------------------------------------------------------
    // Invariants
    // -----------------------------------------------------------------------

    /// Checks the protocol invariants that must hold in every reachable state.
    ///
    /// Called after every block; a violation aborts the block instead of
    /// corrupting the chain.
    pub fn check_invariants(&self) -> Result<(), StateError> {
        if self.issued_supply.grains() > MAX_SUPPLY.grains() {
            return Err(StateError::new(
                "supply_cap",
                format!(
                    "issued supply {} exceeds the hard cap {}",
                    self.issued_supply.to_decimal_string(),
                    MAX_SUPPLY.to_decimal_string()
                ),
            ));
        }
        let balances: u128 = self
            .accounts
            .values()
            .map(|account| account.balance.grains())
            .sum();
        let accounted = balances
            + self.mining_pool.grains()
            + self.validator_pool.grains()
            + self.locked_bonds().grains();
        if accounted != self.issued_supply.grains() {
            return Err(StateError::new(
                "invariant_conservation",
                format!(
                    "balances+pools+bonds = {} but issued supply = {}",
                    accounted, self.issued_supply.grains()
                ),
            ));
        }
        let claims: u64 = self
            .accounts
            .values()
            .map(|account| account.last_claim_sequence)
            .sum();
        if claims != self.total_claims {
            return Err(StateError::new(
                "invariant_claims",
                format!(
                    "sum of claim sequences {} does not equal total claims {}",
                    claims, self.total_claims
                ),
            ));
        }
        if self.genesis_issued {
            let flagged = self
                .accounts
                .values()
                .filter(|account| account.genesis_claimed)
                .count();
            if flagged != 1 || self.treasury.is_none() {
                return Err(StateError::new(
                    "genesis_once",
                    "the genesis allocation must be issued exactly once and recorded once",
                ));
            }
        } else if self.accounts.values().any(|account| account.genesis_claimed) {
            return Err(StateError::new(
                "genesis_once",
                "an account is flagged as genesis-claimed but no allocation was issued",
            ));
        }
        for record in self.validators.values() {
            if record.active && record.bond != VALIDATOR_BOND {
                return Err(StateError::new(
                    "validator_bond",
                    "an active validator does not hold the full bond",
                ));
            }
            if record.node_key == record.owner_key {
                return Err(StateError::new(
                    "validator_key_reuse",
                    "a validator's node key equals its wallet key",
                ));
            }
        }
        if self.validators.len() > MAX_VALIDATORS {
            return Err(StateError::new(
                "invariant_validators",
                "validator set exceeds the protocol bound",
            ));
        }
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Block application
    // -----------------------------------------------------------------------

    /// Assembles a candidate block for the next height.
    ///
    /// This is the only supported way to *produce* a block: it fills in every
    /// consensus field from protocol rules (height, slot, parent, difficulty,
    /// PoT weight, transaction and attestation roots, post-state root) and then
    /// signs the header with the proposer's node key.  A node, the CLI miner
    /// and the tests all use it, so a produced block is always structurally
    /// identical to what the protocol requires, and it still has to pass
    /// [`ChainState::apply_block`].
    ///
    /// Passing a proposer that the schedule does not select for the slot
    /// produces a block that [`ChainState::apply_block`] rejects — building
    /// grants no authority.
    pub fn build_block(
        &self,
        proposer: &obs_crypto::ed25519::Keypair,
        timestamp: u64,
        transactions: Vec<Transaction>,
        mut attestations: Vec<Attestation>,
    ) -> Result<Block, StateError> {
        if transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(StateError::new(
                "block_structure",
                format!(
                    "cannot build a block with {} transactions, the protocol maximum is {}",
                    transactions.len(),
                    MAX_TXS_PER_BLOCK
                ),
            ));
        }
        // Attestations are canonically ordered by node key: identical sets from
        // different nodes always produce the identical attestation root.
        attestations.sort_by(|a, b| a.node_key.cmp(&b.node_key));

        let height = self.height + 1;
        let difficulty_bp = self.expected_difficulty_bp(height)?;
        let active = self.active_validators();
        let slot_gap = self.slot_gap(timestamp);
        let weight_atoms = weight_of_block(
            slot_gap,
            attestations.len(),
            active.len(),
            difficulty_bp,
        );

        let mut block = Block {
            header: crate::block::BlockHeader {
                version: PROTOCOL_VERSION,
                chain_id: self.network.chain_id,
                height,
                slot: timestamp / SLOT_DURATION_SECS,
                parent: self.last_block_hash,
                state_root: Hash32::ZERO,
                tx_root: Hash32::ZERO,
                attestation_root: Hash32::ZERO,
                timestamp,
                difficulty_bp,
                weight_atoms,
                proposer: proposer.public_key(),
            },
            transactions,
            attestations,
            signature: [0u8; 64],
        };
        block.header.tx_root = block.compute_tx_root();
        block.header.attestation_root = block.compute_attestation_root();

        // Dry run against a copy to discover the resulting state root.  The
        // state root is a commitment to state only, so it cannot depend on the
        // header that carries it.
        let mut probe = self.clone();
        probe.apply_block_in_place(&block, Phase::Build)?;
        block.header.state_root = probe.state_root();

        block.sign(proposer);
        Ok(block)
    }

    /// Applies a block, returning the new state and its effects.
    ///
    /// On any error the original state is untouched.
    pub fn apply_block(&self, block: &Block) -> Result<Applied, StateError> {
        let mut working = self.clone();
        let effects = working.apply_block_in_place(block, Phase::Commit)?;
        Ok(Applied {
            state: working,
            effects,
        })
    }

    fn apply_block_in_place(
        &mut self,
        block: &Block,
        phase: Phase,
    ) -> Result<BlockEffects, StateError> {
        let header = &block.header;

        // --- Structure and content roots --------------------------------
        block
            .check_structure()
            .map_err(|reason| StateError::new("block_structure", reason))?;

        if block.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(StateError::new(
                "block_structure",
                format!(
                    "block carries {} transactions, the protocol maximum is {}",
                    block.transactions.len(),
                    MAX_TXS_PER_BLOCK
                ),
            ));
        }

        // --- Position ----------------------------------------------------
        if header.chain_id != self.network.chain_id {
            return Err(StateError::new(
                "block_chain_id",
                "block belongs to a different network",
            ));
        }
        if header.height != self.height + 1 {
            return Err(StateError::new(
                "block_height",
                format!(
                    "block height {} does not follow {}",
                    header.height, self.height
                ),
            ));
        }
        if header.parent != self.last_block_hash {
            return Err(StateError::new(
                "block_parent",
                "block does not extend this chain head",
            ));
        }

        // --- Timestamp rules 1 and 2 -------------------------------------
        check_timestamp_rules(self.last_timestamp, self.median_time_past(), header.timestamp)?;

        // --- PoT difficulty ---------------------------------------------
        let expected_difficulty = self.expected_difficulty_bp(header.height)?;
        if header.difficulty_bp != expected_difficulty {
            return Err(StateError::new(
                "block_difficulty",
                format!(
                    "block carries PoT difficulty {} but {} is required",
                    header.difficulty_bp, expected_difficulty
                ),
            ));
        }

        // --- PoT weight --------------------------------------------------
        let active_validators = self.active_validators();
        let expected_weight = weight_of_block(
            self.slot_gap(header.timestamp),
            block.attestations.len(),
            active_validators.len(),
            header.difficulty_bp,
        );
        if header.weight_atoms != expected_weight {
            return Err(StateError::new(
                "block_weight",
                format!(
                    "block claims PoT weight {} but the protocol computes {}",
                    header.weight_atoms, expected_weight
                ),
            ));
        }

        // --- Proposer authorisation and signature ------------------------
        self.check_proposer(block, &active_validators)?;
        if phase == Phase::Commit && !block.verify_proposer_signature() {
            return Err(StateError::new(
                "block_signature",
                "the scheduled proposer's signature does not verify",
            ));
        }

        let mut entries: Vec<LedgerEntry> = Vec::new();

        // --- Matured unbonds --------------------------------------------
        let mut matured: Vec<(Address, Amount)> = Vec::new();
        for record in self.validators.values_mut() {
            if !record.active
                && record.bond.grains() > 0
                && header.timestamp >= record.unbonding_ends_at
                && record.unbonding_ends_at > 0
            {
                matured.push((record.owner, record.bond));
                record.bond = Amount::ZERO;
            }
        }
        for (owner, bond) in matured {
            self.credit(owner, bond)?;
            entries.push(LedgerEntry {
                kind: "unbond",
                account: Some(owner),
                amount: bond,
                detail: "validator bond returned after the 48-hour unbonding period".to_string(),
            });
        }

        // --- Transactions ------------------------------------------------
        let mut fees = Amount::ZERO;
        let mut mining_issued = Amount::ZERO;
        let mut genesis_issued: Option<Amount> = None;
        let mut seen_ids: Vec<TxId> = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            let id = tx.id();
            if seen_ids.contains(&id) {
                return Err(StateError::new(
                    "tx_duplicate",
                    "the block contains the same transaction twice",
                ));
            }
            seen_ids.push(id);
            let applied = self.apply_tx_in_place(tx, header.timestamp, header.height, &mut entries)?;
            fees = fees.checked_add(applied.fee).ok_or_else(|| {
                StateError::new("invariant_conservation", "fee accounting overflowed")
            })?;
            mining_issued = mining_issued.checked_add(applied.mining_issued).ok_or_else(|| {
                StateError::new("invariant_conservation", "mining issuance overflowed")
            })?;
            if let Some(genesis) = applied.genesis_issued {
                genesis_issued = Some(genesis);
            }
        }

        // --- Attestations -------------------------------------------------
        let mut equivocations: Vec<[u8; 32]> = Vec::new();
        for attestation in &block.attestations {
            if let Some(node_key) = self.apply_attestation_in_place(attestation, header, &mut entries)?
            {
                equivocations.push(node_key);
            }
        }
        for node_key in equivocations {
            self.punish_equivocation(&node_key, header.timestamp, &mut entries);
        }

        // --- Validator accounting ----------------------------------------
        //
        // Written from block content only: a validator is credited with the
        // block when the signed header names it as proposer, and charged one
        // missed opportunity when the block does not carry its attestation.
        // Neither number is ever taken from a node's own report.
        //
        // A header's proposer is whichever key signed it: in scheduled mode the
        // slot schedule names a validator's *node identity*, while during the
        // bootstrap window a registered account's *wallet key* may propose.  The
        // bond belongs to the wallet and the attestations to the node identity
        // (the protocol requires them to differ), so a validator is credited
        // when either of its keys proposed.  Matching the node key alone left a
        // bootstrap validator that proposed every block reading
        // `blocks_proposed: 0` on the live devnet while its `attestations` and
        // `missed_slots` moved: the evidence existed, the attribution did not.
        for record in self.validators.values_mut() {
            if record.is_active()
                && (record.node_key == header.proposer || record.owner_key == header.proposer)
            {
                record.blocks_proposed = record.blocks_proposed.saturating_add(1);
            }
        }
        let carrying: Vec<[u8; 32]> = block
            .attestations
            .iter()
            .map(|attestation| attestation.node_key)
            .collect();
        for (node_key, record) in self.validators.iter_mut() {
            // A validator registered by this very block had no opportunity to
            // attest anything: its first opportunity is the next block.
            if record.is_active()
                && record.registered_at_height < header.height
                && !carrying.contains(node_key)
            {
                record.missed_slots = record.missed_slots.saturating_add(1);
            }
        }

        // --- Finality -----------------------------------------------------
        self.update_finality(&active_validators);

        // --- Position update ---------------------------------------------
        self.height = header.height;
        self.last_block_hash = block.hash();
        self.last_timestamp = header.timestamp;
        self.last_slot = header.slot;
        self.total_weight = self.total_weight.checked_add(PoTWeight::from_atoms(header.weight_atoms));
        self.timestamps.insert(header.height, header.timestamp);
        self.block_hashes.insert(header.height, self.last_block_hash);
        self.prune_history();
        self.last_difficulty_bp = self.difficulty_for_next_block(header.height)?;

        // --- Epoch close --------------------------------------------------
        self.epoch_blocks += 1;
        let validator_rewards = self.maybe_distribute_validator_epoch(header.timestamp, &mut entries)?;

        // --- Consensus commitment and invariants --------------------------
        let computed_root = self.state_root();
        if phase == Phase::Commit && computed_root != header.state_root {
            return Err(StateError::new(
                "block_state_root",
                format!(
                    "block commits to state root {} but the applied state hashes to {}",
                    header.state_root.to_hex(),
                    computed_root.to_hex()
                ),
            ));
        }
        self.check_invariants()?;

        Ok(BlockEffects {
            height: header.height,
            hash: self.last_block_hash,
            transactions: block.transactions.len(),
            attestations: block.attestations.len(),
            fees,
            mining_issued,
            genesis_issued,
            validator_rewards,
            issued_supply: self.issued_supply,
            weight: PoTWeight::from_atoms(header.weight_atoms),
            finalized_height: self.finalized_height,
            entries,
        })
    }

    /// PoT difficulty that a block at `height` must carry.
    ///
    /// Difficulty only changes at epoch boundaries, where the observed block
    /// cadence over the difficulty window is folded into the moving average:
    ///
    /// ```text
    /// expected_span = 32 * 30 seconds
    /// observed_span = timestamp(height-1) - timestamp(height-32)
    /// raw           = clamp(10_000 * expected / observed, 6_666, 15_000)
    /// difficulty    = clamp((7 * previous + raw) / 8, 6_666, 15_000)
    /// ```
    pub fn expected_difficulty_bp(&self, height: u64) -> Result<u32, StateError> {
        if height == 0 || height % EPOCH_SLOTS != 0 {
            return Ok(self.last_difficulty_bp);
        }
        let window = DIFFICULTY_WINDOW_BLOCKS as u64;
        let start_height = height.saturating_sub(window);
        let start_timestamp = *self.timestamps.get(&start_height).ok_or_else(|| {
            StateError::new(
                "block_difficulty",
                "difficulty window block is outside the retained history",
            )
        })?;
        let observed_span = self.last_timestamp.saturating_sub(start_timestamp);
        let expected_span = window * SLOT_DURATION_SECS;
        let raw = raw_difficulty_bp(expected_span, observed_span);
        Ok(next_difficulty_bp(self.last_difficulty_bp, raw))
    }

    fn difficulty_for_next_block(&self, applied_height: u64) -> Result<u32, StateError> {
        self.expected_difficulty_bp(applied_height + 1)
    }

    /// Decides whether a block was proposed by an authorised key.
    ///
    /// Two modes, both deterministic and both documented:
    ///
    /// * **Scheduled mode** — the chain has at least
    ///   [`MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL`] active validators and is past
    ///   the bootstrap window.  The proposer of a slot is selected by
    ///   [`proposer_for_slot`] from the active set, so exactly one key is
    ///   authorised per slot and nobody can choose their slot.
    /// * **Bootstrap mode** — the network is new (height ≤ `BOOTSTRAP_SLOTS`)
    ///   or has no active validator at all.  A registered account, or the
    ///   wallet key of an account registered by the block itself (the very
    ///   first block), may propose.  This grants no minting power: the genesis
    ///   allocation still goes to whichever valid claim the protocol applies
    ///   first, at its fixed size, and every other rule is unchanged.  It exists
    ///   so a new network can start and so a network whose validators all left
    ///   cannot be halted permanently.
    fn check_proposer(
        &self,
        block: &Block,
        active_validators: &[[u8; 32]],
    ) -> Result<(), StateError> {
        let scheduled_mode = active_validators.len() >= MIN_VALIDATORS_FOR_SCHEDULED_PROPOSAL
            && block.header.height > BOOTSTRAP_SLOTS;
        if scheduled_mode {
            let index = proposer_for_slot(
                block.header.chain_id,
                &block.header.parent,
                block.header.slot,
                active_validators.len(),
            )
            .ok_or_else(|| StateError::new("block_proposer", "proposer selection failed"))?;
            if active_validators[index] != block.header.proposer {
                return Err(StateError::new(
                    "block_proposer",
                    "block was not proposed by the validator scheduled for this slot",
                ));
            }
            return Ok(());
        }
        // Bootstrap window: any active validator node key, any registered
        // account wallet key, or — in the very first block — the wallet key of
        // an account that this same block registers may propose.  This is
        // permissionless (no key is privileged), time-bounded
        // (BOOTSTRAP_SLOTS), and documented; it exists only so a brand-new
        // network can produce blocks before three validators exist.  It grants
        // no minting power: the genesis allocation still goes to whichever
        // valid claim the protocol applies first, at its fixed size.
        let is_validator = active_validators
            .iter()
            .any(|key| *key == block.header.proposer);
        let is_account = self
            .accounts
            .values()
            .any(|account| account.wallet_key == block.header.proposer);
        let registers_itself = self.accounts.is_empty()
            && block.transactions.iter().any(|tx| match &tx.kind {
                TxKind::Register { wallet_key, .. } => *wallet_key == block.header.proposer,
                _ => false,
            });
        if !(is_validator || is_account || registers_itself) {
            return Err(StateError::new(
                "block_proposer",
                "during bootstrap only a registered account or active validator may propose",
            ));
        }
        Ok(())
    }

    fn prune_history(&mut self) {
        let keep_from = self.height.saturating_sub(STATE_HISTORY_BLOCKS - 1);
        self.timestamps.retain(|height, _| *height >= keep_from);
        self.block_hashes.retain(|height, _| *height >= keep_from);
        self.attestation_index
            .retain(|(height, _), _| *height >= keep_from);
        self.attestation_counts
            .retain(|height, _| *height >= keep_from);
    }

    // -----------------------------------------------------------------------
    // Transactions
    // -----------------------------------------------------------------------

    /// Validates a transaction against this state without changing it.
    ///
    /// Used by the mempool and by API pre-checks; the authoritative path is
    /// still `apply_block`.
    pub fn check_tx(&self, tx: &Transaction, at: u64) -> Result<(), StateError> {
        self.apply_txs_preview(std::slice::from_ref(tx), at).map(|_| ())
    }

    /// Applies a sequence of transactions to a copy of this state and returns
    /// the resulting state, leaving this one untouched.
    ///
    /// This is how a node or a builder checks a *batch* of transactions — the
    /// transactions of one account in nonce order, or a candidate block — before
    /// any of them exist on chain.  It grants no authority: whatever is built
    /// from it is validated again by every node when the block is applied.
    pub fn apply_txs_preview(
        &self,
        transactions: &[Transaction],
        at: u64,
    ) -> Result<ChainState, StateError> {
        if transactions.len() > MAX_TXS_PER_BLOCK {
            return Err(StateError::new(
                "block_structure",
                "too many transactions for one block",
            ));
        }
        let mut probe = self.clone();
        let mut entries = Vec::new();
        let mut seen: Vec<TxId> = Vec::with_capacity(transactions.len());
        for tx in transactions {
            let id = tx.id();
            if seen.contains(&id) {
                return Err(StateError::new(
                    "tx_duplicate",
                    "the same transaction appears twice",
                ));
            }
            seen.push(id);
            probe.apply_tx_in_place(tx, at, self.height + 1, &mut entries)?;
        }
        Ok(probe)
    }

    /// The nonce the next transaction from this account must carry: the
    /// account's on-chain nonce plus one, or 1 for an account that does not
    /// exist yet.
    pub fn expected_nonce(&self, address: &Address) -> u64 {
        self.accounts
            .get(address)
            .map(|account| account.last_nonce + 1)
            .unwrap_or(1)
    }

    /// Applies a sequence of transactions to a copy of this state and returns
    /// the result, without touching this state.
    ///
    fn account_mut(&mut self, address: &Address) -> Result<&mut Account, StateError> {
        self.accounts.get_mut(address).ok_or_else(|| {
            StateError::new(
                "account_missing",
                "the account behind this transaction does not exist",
            )
        })
    }

    fn credit(&mut self, address: Address, amount: Amount) -> Result<(), StateError> {
        let account = self.account_mut(&address)?;
        account.balance = account.balance.checked_add(amount).ok_or_else(|| {
            StateError::new("invariant_conservation", "balance overflow while crediting")
        })?;
        Ok(())
    }

    fn debit(&mut self, address: &Address, amount: Amount) -> Result<(), StateError> {
        let account = self.account_mut(address)?;
        account.balance = account.balance.checked_sub(amount).ok_or_else(|| {
            StateError::new(
                "tx_insufficient_funds",
                "the account cannot cover this amount plus the gas fee",
            )
        })?;
        Ok(())
    }

    fn issue(&mut self, amount: Amount) -> Result<(), StateError> {
        let new_total = self
            .issued_supply
            .checked_add(amount)
            .ok_or_else(|| StateError::new("supply_cap", "supply accounting overflowed"))?;
        if new_total.grains() > MAX_SUPPLY.grains() {
            return Err(StateError::new(
                "supply_cap",
                "issuing this amount would exceed the 21,000,000 OBS hard cap",
            ));
        }
        self.issued_supply = new_total;
        Ok(())
    }

    fn apply_tx_in_place(
        &mut self,
        tx: &Transaction,
        at: u64,
        height: u64,
        entries: &mut Vec<LedgerEntry>,
    ) -> Result<TxOutcome, StateError> {
        let mut outcome = TxOutcome {
            fee: Amount::ZERO,
            mining_issued: Amount::ZERO,
            genesis_issued: None,
        };

        if tx.chain_id != self.network.chain_id {
            return Err(StateError::new(
                "tx_chain_id",
                "transaction is signed for a different network",
            ));
        }
        if !tx.verify_signature() {
            return Err(StateError::new(
                "tx_signature",
                "transaction signature does not verify",
            ));
        }
        let sender = tx
            .sender()
            .ok_or_else(|| StateError::new("tx_chain_id", "unknown chain id in transaction"))?;

        // Nonce: strictly the account's next nonce.  This is what makes a
        // transaction impossible to replay, on top of the chain binding.
        let expected_nonce = match self.accounts.get(&sender) {
            Some(account) => account.last_nonce + 1,
            None => 1,
        };
        if tx.nonce != expected_nonce {
            return Err(StateError::new(
                "tx_nonce",
                format!(
                    "transaction nonce {} is not the expected next nonce {}",
                    tx.nonce, expected_nonce
                ),
            ));
        }

        match &tx.kind {
            TxKind::Register {
                account,
                wallet_key,
                gmail_commitment,
                invite,
            } => {
                if *account != sender {
                    return Err(StateError::new(
                        "tx_sender",
                        "a registration must be signed by the account it creates",
                    ));
                }
                if wallet_key != &tx.public_key {
                    return Err(StateError::new(
                        "tx_sender",
                        "the registered wallet key is not the signing key",
                    ));
                }
                if self.accounts.contains_key(account) {
                    return Err(StateError::new(
                        "account_exists",
                        "this account is already registered",
                    ));
                }
                if self.gmail_bindings.contains_key(gmail_commitment) {
                    return Err(StateError::new(
                        "gmail_duplicate",
                        "this Gmail identity already has an account",
                    ));
                }
                // The invitation is bound to one canonical Gmail identity: the
                // registration server committed to it when it verified the
                // address, so a client cannot spend an invitation on a
                // different identity or register a second account for the same
                // Gmail under a different spelling.
                if invite.gmail_commitment != *gmail_commitment {
                    return Err(StateError::new(
                        "invite_gmail",
                        "the invitation authorises a different Gmail identity",
                    ));
                }
                if invite.authority_key != self.registration_authority {
                    return Err(StateError::new(
                        "invite_authority",
                        "the invitation was not authorised by this network's registration authority",
                    ));
                }
                if !invite.verify_signature(self.network.chain_id) {
                    return Err(StateError::new(
                        "invite_signature",
                        "the invitation authorisation signature does not verify",
                    ));
                }
                if at < invite.issued_at {
                    return Err(StateError::new(
                        "invite_not_yet_valid",
                        "the invitation authorisation is not valid yet",
                    ));
                }
                if at > invite.expires_at {
                    return Err(StateError::new(
                        "invite_expired",
                        "the invitation authorisation has expired",
                    ));
                }
                if self.invite_redemptions.contains_key(&invite.commitment) {
                    return Err(StateError::new(
                        "invite_redeemed",
                        "this invitation has already been used",
                    ));
                }
                let mut issuer_budget_slot = 0u32;
                if let Some(issuer) = invite.issuer {
                    let issuer_account = self.accounts.get(&issuer).ok_or_else(|| {
                        StateError::new(
                            "invite_unknown",
                            "the issuing account does not exist",
                        )
                    })?;
                    if issuer_account.invites_issued >= MAX_INVITES_PER_ACCOUNT {
                        return Err(StateError::new(
                            "invite_budget",
                            "the issuing account has used all five invitations",
                        ));
                    }
                    issuer_budget_slot = issuer_account.invites_issued + 1;
                }
                let record = InviteRecord {
                    commitment: invite.commitment,
                    redeemed_by: *account,
                    redeemed_at: at,
                    ordinal: issuer_budget_slot,
                };
                self.invite_redemptions.insert(invite.commitment, record);
                if let Some(issuer) = invite.issuer {
                    if let Some(issuer_account) = self.accounts.get_mut(&issuer) {
                        issuer_account.invites_issued += 1;
                    }
                }
                self.gmail_bindings.insert(*gmail_commitment, *account);
                self.accounts.insert(
                    *account,
                    Account {
                        address: *account,
                        wallet_key: *wallet_key,
                        recovery_key: None,
                        gmail_commitment: *gmail_commitment,
                        balance: Amount::ZERO,
                        last_nonce: tx.nonce,
                        registered_at: at,
                        ..Account::default()
                    },
                );
                entries.push(LedgerEntry {
                    kind: "register",
                    account: Some(*account),
                    amount: Amount::ZERO,
                    detail: "account registered; starting balance is exactly zero".to_string(),
                });
            }

            TxKind::Claim(claim) => {
                let genesis = self.apply_claim_in_place(&sender, claim, at, height, entries)?;
                outcome.mining_issued = genesis.mining;
                outcome.genesis_issued = genesis.genesis;
            }

            TxKind::Transfer { to, amount } => {
                if amount.is_zero() {
                    return Err(StateError::new(
                        "tx_amount_zero",
                        "a transfer must move a non-zero amount",
                    ));
                }
                if *to == sender {
                    return Err(StateError::new(
                        "tx_self_transfer",
                        "a transfer to the sender's own address is not a payment",
                    ));
                }
                let fee = gas_fee_for(*amount);
                let total = amount.checked_add(fee).ok_or_else(|| {
                    StateError::new("tx_insufficient_funds", "amount plus fee overflows")
                })?;
                if self.balance(&sender) < total {
                    return Err(StateError::new(
                        "tx_insufficient_funds",
                        "the account cannot cover this amount plus the gas fee",
                    ));
                }
                self.debit(&sender, total)?;
                self.credit(*to, *amount)?;
                let (validator_share, pool_share) = split_gas_fee(fee);
                self.validator_pool = self
                    .validator_pool
                    .checked_add(validator_share)
                    .ok_or_else(|| {
                        StateError::new("invariant_conservation", "validator pool overflow")
                    })?;
                self.mining_pool = self
                    .mining_pool
                    .checked_add(pool_share)
                    .ok_or_else(|| {
                        StateError::new("invariant_conservation", "mining pool overflow")
                    })?;
                outcome.fee = fee;
                entries.push(LedgerEntry {
                    kind: "transfer",
                    account: Some(sender),
                    amount: *amount,
                    detail: "transfer of value".to_string(),
                });
                entries.push(LedgerEntry {
                    kind: "fee",
                    account: Some(sender),
                    amount: fee,
                    detail: format!(
                        "gas fee {} to the protocol pools ({} validator, {} mining)",
                        fee.to_decimal_string(),
                        validator_share.to_decimal_string(),
                        pool_share.to_decimal_string()
                    ),
                });
            }

            TxKind::RegisterValidator { node_key, endpoint } => {
                if self.validators.len() >= MAX_VALIDATORS {
                    return Err(StateError::new(
                        "invariant_validators",
                        "the validator set is full",
                    ));
                }
                if *node_key == tx.public_key {
                    return Err(StateError::new(
                        "validator_key_reuse",
                        "the node identity key must be different from the wallet key",
                    ));
                }
                if self.validators.contains_key(node_key) {
                    return Err(StateError::new(
                        "validator_exists",
                        "this node identity key is already registered",
                    ));
                }
                if endpoint.len() > MAX_NODE_ENDPOINT_LEN
                    || endpoint.is_empty()
                    || !endpoint
                        .bytes()
                        .all(|byte| byte.is_ascii_graphic() || byte == b'.' || byte == b':')
                {
                    return Err(StateError::new(
                        "validator_endpoint",
                        "the endpoint must be at most 128 printable ASCII characters",
                    ));
                }
                if self.balance(&sender) < VALIDATOR_BOND {
                    return Err(StateError::new(
                        "validator_bond",
                        "registering a validator requires the 50 OBS bond",
                    ));
                }
                self.debit(&sender, VALIDATOR_BOND)?;
                self.validators.insert(
                    *node_key,
                    ValidatorRecord {
                        owner: sender,
                        owner_key: tx.public_key,
                        node_key: *node_key,
                        bond: VALIDATOR_BOND,
                        registered_at: at,
                        registered_at_height: height,
                        attested_weight: 0,
                        last_attestation_at: 0,
                        last_attested_height: 0,
                        attestation_count: 0,
                        missed_slots: 0,
                        blocks_proposed: 0,
                        active: true,
                        unbonding_ends_at: 0,
                        exit_reason: None,
                    },
                );
                entries.push(LedgerEntry {
                    kind: "bond",
                    account: Some(sender),
                    amount: VALIDATOR_BOND,
                    detail: "validator registered; 50 OBS bond locked".to_string(),
                });
            }

            TxKind::DeregisterValidator => {
                let record = self
                    .validators
                    .values_mut()
                    .find(|record| record.owner == sender && record.active)
                    .ok_or_else(|| {
                        StateError::new(
                            "validator_not_found",
                            "this account does not own an active validator",
                        )
                    })?;
                record.active = false;
                record.exit_reason = Some(ExitReason::Deregistered);
                record.unbonding_ends_at = at + UNBONDING_PERIOD_SECS;
                entries.push(LedgerEntry {
                    kind: "validator_exit",
                    account: Some(sender),
                    amount: Amount::ZERO,
                    detail: "validator deregistered; the bond returns after 48 hours".to_string(),
                });
            }
        }

        // The nonce is consumed by every applied transaction.
        if let Some(account) = self.accounts.get_mut(&sender) {
            account.last_nonce = tx.nonce;
        }
        Ok(outcome)
    }

    fn apply_claim_in_place(
        &mut self,
        sender: &Address,
        claim: &Claim,
        at: u64,
        height: u64,
        entries: &mut Vec<LedgerEntry>,
    ) -> Result<ClaimOutcome, StateError> {
        // Rule 3: the claim's protocol time is the block's protocol time.
        check_claim_protocol_time(claim.claimed_at, at)?;
        if &claim.account != sender {
            return Err(StateError::new(
                "claim_account",
                "a claim must be signed by the account that receives it",
            ));
        }

        let active_miners = self.active_miner_count_at(at);
        let reward = reward_for_claim(active_miners);

        let (last_sequence, last_claim_at, window_start_field, claims_today) = {
            let account = self.account_mut(sender)?;
            (
                account.last_claim_sequence,
                account.last_claim_at,
                account.claim_window_start,
                account.claims_today,
            )
        };
        let expected_sequence = last_sequence + 1;
        if claim.sequence != expected_sequence {
            return Err(StateError::new(
                "claim_sequence",
                format!(
                    "claim sequence {} is not the expected next sequence {}",
                    claim.sequence, expected_sequence
                ),
            ));
        }
        if last_sequence > 0 {
            let earliest = last_claim_at.saturating_add(CLAIM_INTERVAL_SECS);
            if at < earliest {
                return Err(StateError::new(
                    "claim_interval",
                    format!(
                        "the next claim may only be accepted at protocol time {} (4-hour interval)",
                        earliest
                    ),
                ));
            }
        }
        let window_resets = window_start_field == 0
            || at >= window_start_field.saturating_add(PROTOCOL_DAY_SECS);
        let window_start = if window_resets { at } else { window_start_field };
        let claims_in_window = if window_resets { 0 } else { claims_today };
        if claims_in_window >= MAX_CLAIMS_PER_DAY {
            return Err(StateError::new(
                "claim_daily_cap",
                "the protocol-day limit of six claims has been reached",
            ));
        }

        // Genesis: the first valid claim in the genesis block receives the
        // 100,000 OBS allocation exactly once and becomes the treasury.
        let mut genesis_credit = Amount::ZERO;
        if height == GENESIS_BLOCK_HEIGHT && !self.genesis_issued {
            genesis_credit = GENESIS_ALLOCATION;
            self.genesis_issued = true;
            self.treasury = Some(*sender);
        }

        let issuance = reward.checked_add(genesis_credit).ok_or_else(|| {
            StateError::new("supply_cap", "claim issuance overflowed")
        })?;
        self.issue(issuance)?;

        let account = self.account_mut(sender)?;
        account.balance = account.balance.checked_add(issuance).ok_or_else(|| {
            StateError::new("invariant_conservation", "balance overflow while crediting a claim")
        })?;
        account.lifetime_rewards = account
            .lifetime_rewards
            .checked_add(issuance)
            .ok_or_else(|| StateError::new("invariant_conservation", "lifetime rewards overflow"))?;
        account.last_claim_sequence = claim.sequence;
        account.last_claim_at = at;
        account.claims_today = claims_in_window + 1;
        account.claim_window_start = window_start;
        if genesis_credit.grains() > 0 {
            account.genesis_claimed = true;
        }
        self.total_claims += 1;

        if genesis_credit.grains() > 0 {
            entries.push(LedgerEntry {
                kind: "genesis",
                account: Some(*sender),
                amount: genesis_credit,
                detail: "genesis allocation of 100,000 OBS; this account is the Genesis Wallet (treasury)"
                    .to_string(),
            });
        }
        entries.push(LedgerEntry {
            kind: "claim",
            account: Some(*sender),
            amount: reward,
            detail: format!(
                "mining claim accepted at protocol time {} with {} active miners",
                at, active_miners
            ),
        });

        Ok(ClaimOutcome {
            mining: reward,
            genesis: if genesis_credit.grains() > 0 {
                Some(genesis_credit)
            } else {
                None
            },
        })
    }

    /// Applies one attestation.  Returns the node key of a validator that
    /// equivocated, if this attestation is conflicting evidence.
    fn apply_attestation_in_place(
        &mut self,
        attestation: &Attestation,
        header: &crate::block::BlockHeader,
        entries: &mut Vec<LedgerEntry>,
    ) -> Result<Option<[u8; 32]>, StateError> {
        if !attestation.verify_signature(self.network.chain_id) {
            return Err(StateError::new(
                "attestation_signature",
                "an attestation signature does not verify",
            ));
        }
        let (active, last_attested_height, owner) = {
            let record = self
                .validators
                .get(&attestation.node_key)
                .ok_or_else(|| {
                    StateError::new(
                        "attestation_unknown_validator",
                        "an attestation comes from an unknown node identity key",
                    )
                })?;
            (record.active, record.last_attested_height, record.owner)
        };
        if !active {
            return Err(StateError::new(
                "attestation_inactive",
                "an attestation comes from a validator that is not active",
            ));
        }
        // Equivocation evidence first: two signed attestations from the same
        // validator for the same height with different block hashes are
        // provable conflict, regardless of whether this node holds the other
        // block.  Both signatures exist, so this is evidence, not an
        // accusation, and it is the only uptime-adjacent rule that removes a
        // validator.
        if let Some(previous) = self
            .attestation_index
            .get(&(attestation.height, attestation.node_key))
        {
            if previous != &attestation.block_hash {
                return Ok(Some(attestation.node_key));
            }
            return Err(StateError::new(
                "attestation_duplicate",
                "the same validator attested the same block twice",
            ));
        }
        // The attested block must be one this node retained, and the hash must
        // match exactly: an attestation for an unknown or different block is
        // invalid rather than silently ignored.
        let known_hash = self
            .block_hashes
            .get(&attestation.height)
            .copied()
            .ok_or_else(|| {
                StateError::new(
                    "attestation_unknown_block",
                    "an attestation refers to a block outside the retained history",
                )
            })?;
        if known_hash != attestation.block_hash {
            return Err(StateError::new(
                "attestation_unknown_block",
                "an attestation refers to a block hash that is not on this chain",
            ));
        }
        if attestation.height >= header.height {
            return Err(StateError::new(
                "attestation_unknown_block",
                "an attestation must reference a block below the block that carries it",
            ));
        }

        if attestation.height <= last_attested_height && last_attested_height != 0 {
            return Err(StateError::new(
                "attestation_order",
                "a validator's attestations must follow increasing block heights",
            ));
        }
        if header.height.saturating_sub(attestation.height) > crate::params::ATTESTATION_WINDOW_BLOCKS
        {
            return Err(StateError::new(
                "attestation_stale",
                format!(
                    "an attestation for block {} cannot be included in block {}; \
                     the window is {} blocks",
                    attestation.height,
                    header.height,
                    crate::params::ATTESTATION_WINDOW_BLOCKS
                ),
            ));
        }

        let active_count = self.validators.values().filter(|v| v.is_active()).count() as u128;
        let per_validator = if active_count == 0 {
            0
        } else {
            crate::params::BLOCK_WEIGHT_ATOMS / active_count
        };

        self.attestation_index
            .insert((attestation.height, attestation.node_key), attestation.block_hash);
        let record = self
            .validators
            .get_mut(&attestation.node_key)
            .expect("validator checked above");
        record.attestation_count += 1;
        record.last_attestation_at = header.timestamp;
        record.last_attested_height = attestation.height;
        record.attested_weight = record.attested_weight.saturating_add(per_validator);

        *self.epoch_attested.entry(attestation.node_key).or_insert(0) += 1;
        *self
            .epoch_weight
            .entry(attestation.node_key)
            .or_insert(0u128) += per_validator;

        let count = self
            .attestation_counts
            .entry(attestation.height)
            .or_insert((0, attestation.block_hash));
        if count.1 == attestation.block_hash {
            count.0 += 1;
        }
        entries.push(LedgerEntry {
            kind: "attestation",
            account: Some(owner),
            amount: Amount::ZERO,
            detail: format!("attestation for height {}", attestation.height),
        });
        Ok(None)
    }

    fn punish_equivocation(
        &mut self,
        node_key: &[u8; 32],
        at: u64,
        entries: &mut Vec<LedgerEntry>,
    ) {
        if let Some(record) = self.validators.get_mut(node_key) {
            record.active = false;
            record.exit_reason = Some(ExitReason::Equivocation);
            record.unbonding_ends_at = at + UNBONDING_PERIOD_SECS;
            entries.push(LedgerEntry {
                kind: "equivocation",
                account: Some(record.owner),
                amount: Amount::ZERO,
                detail: "conflicting attestations were included in a block; the validator was removed from the set"
                    .to_string(),
            });
        }
    }

    /// Advances the finalised height from attestation evidence.
    ///
    /// A height is finalised when at least `ceil(2n/3)` of the `n` active
    /// validators attested *that* block and the block is on this chain (which
    /// the state machine verified when it accepted each attestation).  Finality
    /// is monotone: it only ever moves to the highest such height above the
    /// current one, so it can never be rolled back by later blocks.
    fn update_finality(&mut self, active_validators: &[[u8; 32]]) {
        if active_validators.is_empty() {
            return;
        }
        let count = active_validators.len() as u64;
        let quorum = (count * FINALITY_QUORUM_NUMERATOR + FINALITY_QUORUM_DENOMINATOR - 1)
            / FINALITY_QUORUM_DENOMINATOR;
        let mut best = self.finalized_height;
        for (height, (attestations, _)) in &self.attestation_counts {
            if *height > best && *attestations >= quorum {
                best = *height;
            }
        }
        self.finalized_height = best;
    }

    /// Is the block at this height finalised?
    pub fn is_finalized(&self, height: u64) -> bool {
        height <= self.finalized_height
    }

    /// Protocol time of a retained block, if it is still in the window.
    pub fn block_timestamp(&self, height: u64) -> Option<u64> {
        self.timestamps.get(&height).copied()
    }

    /// Lag, in slots, between the chain head and the highest finalised block.
    /// Reported by node health checks and the Explorer; never consensus.
    pub fn finality_lag_slots(&self) -> u64 {
        match self.block_timestamp(self.finalized_height) {
            Some(timestamp) => slots_between(timestamp, self.last_timestamp),
            None => self.last_slot,
        }
    }

    /// Closes a validator-reward epoch, distributing the pool to validators
    /// whose *evidence-based* uptime meets the 50% floor, in proportion to the
    /// weight they attested.  Returns the value distributed.
    fn maybe_distribute_validator_epoch(
        &mut self,
        at: u64,
        entries: &mut Vec<LedgerEntry>,
    ) -> Result<Amount, StateError> {
        if self.height == 0 || self.height % VALIDATOR_REWARD_EPOCH_SLOTS != 0 {
            return Ok(Amount::ZERO);
        }
        let pool = self.validator_pool;
        if pool.is_zero() {
            self.reset_epoch();
            return Ok(Amount::ZERO);
        }
        let blocks = self.epoch_blocks.max(1);
        let mut eligible: Vec<([u8; 32], u128)> = Vec::new();
        let mut total_weight: u128 = 0;
        for (node_key, record) in &self.validators {
            if !record.active {
                continue;
            }
            let attested = self.epoch_attested.get(node_key).copied().unwrap_or(0);
            let uptime_bp = (attested.min(blocks) * 10_000 / blocks) as u32;
            if uptime_bp < MIN_UPTIME_BP {
                continue;
            }
            let weight = self.epoch_weight.get(node_key).copied().unwrap_or(0);
            if weight == 0 {
                continue;
            }
            total_weight += weight;
            eligible.push((*node_key, weight));
        }
        let mut distributed = Amount::ZERO;
        if total_weight > 0 {
            for (node_key, weight) in &eligible {
                let share = Amount(pool.grains() * weight / total_weight);
                if share.is_zero() {
                    continue;
                }
                let owner = self
                    .validators
                    .get(node_key)
                    .map(|record| record.owner);
                if let Some(owner) = owner {
                    self.credit(owner, share)?;
                    distributed = distributed.checked_add(share).ok_or_else(|| {
                        StateError::new("invariant_conservation", "reward overflow")
                    })?;
                    entries.push(LedgerEntry {
                        kind: "validator_reward",
                        account: Some(owner),
                        amount: share,
                        detail: format!(
                            "epoch validator reward for {} attested weight at protocol time {}",
                            weight, at
                        ),
                    });
                }
            }
        }
        self.validator_pool = self.validator_pool.checked_sub(distributed).ok_or_else(|| {
            StateError::new("invariant_conservation", "validator pool underflow")
        })?;
        self.reset_epoch();
        Ok(distributed)
    }

    fn reset_epoch(&mut self) {
        self.epoch_blocks = 0;
        self.epoch_attested.clear();
        self.epoch_weight.clear();
    }

    /// Slots between two protocol timestamps, clamped to the protocol maximum.
    pub fn slot_gap(&self, to_timestamp: u64) -> u64 {
        let gap = slots_between(self.last_timestamp, to_timestamp);
        gap.clamp(1, crate::params::MAX_SLOT_GAP)
    }
}

struct ClaimOutcome {
    mining: Amount,
    genesis: Option<Amount>,
}

