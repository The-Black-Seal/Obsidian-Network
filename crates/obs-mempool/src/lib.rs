//! # obs-mempool — the transaction pool
//!
//! The pool is *policy*, not consensus.  It decides which valid transactions a
//! node is willing to relay and in which order a block producer should try
//! them; it can never make an invalid transaction valid, and a block built from
//! a pool template is still validated from scratch by every other node.
//!
//! ## Admission
//!
//! A transaction is admitted only when every one of these holds:
//!
//! 1. It is no larger than [`MempoolConfig::max_tx_bytes`].
//! 2. It is not already pooled (compared by transaction id).
//! 3. The chain accepts it — chain id, signature, nonce, claim rules, funds and
//!    gas, through the same `check_tx` the block path uses.  If the only reason
//!    the chain refuses it is that its nonce is ahead of the head, the pool
//!    checks whether the transactions it depends on are already pooled and
//!    validates the whole queued sequence together.
//! 4. Its nonce is not already used by a *different* pooled transaction, unless
//!    it pays a strictly higher fee — the standard replacement rule, on the
//!    same nonce only.
//! 5. The sender has fewer than [`MempoolConfig::max_per_account`] pooled
//!    transactions.
//! 6. There is room, or the new transaction pays a strictly better fee than the
//!    worst transaction that can be evicted.  Eviction is dependency aware: a
//!    transaction another pooled transaction needs in order to apply is never
//!    evicted, because dropping it would silently invalidate the sequence
//!    behind it.
//!
//! ## Templates
//!
//! [`Mempool::select_for_block`] returns a deterministic list: highest fee
//! first across accounts, nonce order within an account, and each candidate is
//! checked against a probe copy of the state that already includes the
//! candidates before it.  The result always applies.
//!
//! ## Determinism
//!
//! Every decision is made from the transaction id, the fee and the protocol
//! state — never from arrival order, wall-clock time or iteration order.  Two
//! nodes holding the same pool and the same head propose byte-for-byte
//! identical blocks.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::collections::BTreeMap;

use obs_chain::params::MAX_TXS_PER_BLOCK;
use obs_chain::{Block, ChainState, StateError, Transaction, TxId, TxKind};
use obs_primitives::address::Address;
use obs_primitives::money::Amount;

/// Pool limits.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolConfig {
    /// Maximum pooled transactions.  Never more than one block can hold, since
    /// anything above that could not be mined in a single block anyway.
    pub max_transactions: usize,
    /// Maximum pooled transactions per sender.
    pub max_per_account: usize,
    /// Maximum encoded size of a single transaction.
    pub max_tx_bytes: usize,
    /// How long a transaction may wait, in protocol seconds.
    pub expiry_secs: u64,
}

impl Default for MempoolConfig {
    fn default() -> Self {
        MempoolConfig {
            max_transactions: MAX_TXS_PER_BLOCK,
            max_per_account: 64,
            max_tx_bytes: 64 * 1024,
            expiry_secs: 3_600,
        }
    }
}

/// Why a transaction was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MempoolError {
    /// The chain rejected it: this is the authoritative answer.
    Invalid(StateError),
    /// The transaction is larger than the pool accepts.
    TooLarge {
        /// Size of the encoded transaction.
        bytes: usize,
        /// Configured maximum.
        max: usize,
    },
    /// The identical transaction is already pooled.
    Duplicate(TxId),
    /// The transaction's nonce is ahead of the queue: the transactions it
    /// depends on are not pooled, so it cannot be applied yet.
    NonceGap {
        /// First nonce the pool could accept next.
        expected: u64,
        /// Nonce the transaction declares.
        got: u64,
    },
    /// Another transaction with the same sender and nonce is pooled, and this
    /// one does not pay a strictly higher fee.
    NonceConflict {
        /// Nonce both transactions use.
        nonce: u64,
    },
    /// The sender already has the maximum number of pooled transactions.
    AccountFull {
        /// Sender address.
        address: Address,
        /// Configured limit.
        limit: usize,
    },
    /// The pool is full and this transaction is not better than anything in it.
    PoolFull {
        /// Configured limit.
        limit: usize,
    },
}

impl core::fmt::Display for MempoolError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MempoolError::Invalid(error) => write!(f, "rejected by the chain: {}", error),
            MempoolError::TooLarge { bytes, max } => write!(
                f,
                "transaction of {} bytes exceeds the {} byte limit",
                bytes, max
            ),
            MempoolError::Duplicate(id) => {
                write!(f, "transaction {} is already pooled", id.0.to_hex())
            }
            MempoolError::NonceGap { expected, got } => write!(
                f,
                "nonce {} is queued ahead of the pool: {} is expected next",
                got, expected
            ),
            MempoolError::NonceConflict { nonce } => {
                write!(f, "nonce {} is already used by a pooled transaction", nonce)
            }
            MempoolError::AccountFull { address, limit } => write!(
                f,
                "account {} already has {} pooled transactions",
                obs_primitives::address::mask(address),
                limit
            ),
            MempoolError::PoolFull { limit } => {
                write!(f, "the pool is full ({} transactions)", limit)
            }
        }
    }
}

impl std::error::Error for MempoolError {}

/// A pooled transaction and the policy metadata attached to it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Entry {
    /// Transaction id.
    pub id: TxId,
    /// The transaction itself.
    pub tx: Transaction,
    /// Sender address.
    pub sender: Address,
    /// Gas fee paid to the validator pool, in grains.
    pub fee: Amount,
    /// Amount leaving the sender (transfer amount plus fee).
    pub spend: Amount,
    /// Encoded size in bytes.
    pub bytes: usize,
    /// Protocol time at which the pool accepted it.
    pub received_at: u64,
}

/// Pool occupancy, for monitoring and for the node's RPC surface.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MempoolStats {
    /// Pooled transactions.
    pub transactions: usize,
    /// Distinct senders with pooled transactions.
    pub accounts: usize,
    /// Total encoded bytes.
    pub bytes: usize,
    /// Total fees the pooled transactions would pay.
    pub total_fees: Amount,
    /// Transactions removed for any reason since the pool was created.
    pub dropped: u64,
    /// Transactions replaced by a higher-fee transaction on the same nonce.
    pub replaced: u64,
    /// Configured capacities.
    pub max_transactions: usize,
}

/// A bounded, deterministic transaction pool.
#[derive(Debug, Clone)]
pub struct Mempool {
    config: MempoolConfig,
    entries: BTreeMap<TxId, Entry>,
    dropped: u64,
    replaced: u64,
}

impl Mempool {
    /// Creates an empty pool.
    pub fn new(config: MempoolConfig) -> Mempool {
        Mempool {
            config,
            entries: BTreeMap::new(),
            dropped: 0,
            replaced: 0,
        }
    }

    /// The pool's configuration.
    pub fn config(&self) -> &MempoolConfig {
        &self.config
    }

    /// Number of pooled transactions.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// True when the pool holds nothing.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// Occupancy.
    pub fn stats(&self) -> MempoolStats {
        let mut senders: Vec<Address> = Vec::new();
        for entry in self.entries.values() {
            if !senders.contains(&entry.sender) {
                senders.push(entry.sender);
            }
        }
        MempoolStats {
            transactions: self.entries.len(),
            accounts: senders.len(),
            bytes: self.entries.values().map(|entry| entry.bytes).sum(),
            total_fees: self.total_fees(),
            dropped: self.dropped,
            replaced: self.replaced,
            max_transactions: self.config.max_transactions,
        }
    }

    /// Total fees pooled transactions would pay.
    pub fn total_fees(&self) -> Amount {
        let mut total = Amount::ZERO;
        for entry in self.entries.values() {
            total = total.checked_add(entry.fee).unwrap_or(Amount(u128::MAX));
        }
        total
    }

    /// Is this transaction pooled?
    pub fn contains(&self, id: &TxId) -> bool {
        self.entries.contains_key(id)
    }

    /// Looks up a pooled transaction.
    pub fn entry(&self, id: &TxId) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// All pooled transactions, ordered by id.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// How many transactions this sender has pooled.
    pub fn account_len(&self, account: &Address) -> usize {
        self.entries
            .values()
            .filter(|entry| &entry.sender == account)
            .count()
    }

    /// What this sender has already committed to pooled transactions.
    pub fn account_pending(&self, account: &Address) -> Amount {
        let mut total = Amount::ZERO;
        for entry in self.entries.values().filter(|entry| &entry.sender == account) {
            total = total.checked_add(entry.spend).unwrap_or(Amount(u128::MAX));
        }
        total
    }

    /// The nonce a new transaction from this account should use.
    ///
    /// The first nonce that is neither on the chain already nor held by a
    /// contiguous pooled sequence.
    pub fn next_nonce(&self, state: &ChainState, account: &Address) -> u64 {
        self.next_available_nonce(state, account)
    }

    fn next_available_nonce(&self, state: &ChainState, account: &Address) -> u64 {
        let mut nonce = state.expected_nonce(account);
        loop {
            let taken = self
                .entries
                .values()
                .any(|entry| &entry.sender == account && entry.tx.nonce == nonce);
            if !taken {
                return nonce;
            }
            nonce += 1;
        }
    }

    /// Inserts a transaction.
    pub fn insert(
        &mut self,
        state: &ChainState,
        tx: Transaction,
        at: u64,
    ) -> Result<TxId, MempoolError> {
        let encoded_len = tx.to_bytes().len();
        if encoded_len > self.config.max_tx_bytes {
            return Err(MempoolError::TooLarge {
                bytes: encoded_len,
                max: self.config.max_tx_bytes,
            });
        }
        let id = tx.id();
        if self.entries.contains_key(&id) {
            return Err(MempoolError::Duplicate(id));
        }

        // The chain decides validity.  Everything except "the nonce is ahead of
        // the head" is final; that one case is handled by validating the whole
        // queued sequence below.
        if let Err(error) = state.check_tx(&tx, at) {
            if error.rule != "tx_nonce" {
                return Err(MempoolError::Invalid(error));
            }
        }

        let sender = match tx.sender() {
            Some(sender) => sender,
            None => {
                return Err(MempoolError::Invalid(StateError::new(
                    "tx_sender",
                    "the transaction does not resolve to a sender on this chain",
                )))
            }
        };
        let entry = make_entry(tx, sender, encoded_len, at);
        let expected = self.next_available_nonce(state, &sender);

        if entry.tx.nonce > expected {
            return Err(MempoolError::NonceGap {
                expected,
                got: entry.tx.nonce,
            });
        }
        if entry.tx.nonce < expected {
            // Either a pooled transaction uses this nonce, or the chain has
            // already applied it.
            let conflict = self
                .entries
                .values()
                .find(|existing| existing.sender == sender && existing.tx.nonce == entry.tx.nonce)
                .map(|existing| existing.id);
            match conflict {
                Some(conflict) => {
                    let existing_fee = self.entries[&conflict].fee;
                    if entry.fee <= existing_fee {
                        return Err(MempoolError::NonceConflict {
                            nonce: entry.tx.nonce,
                        });
                    }
                    self.entries.remove(&conflict);
                    self.replaced += 1;
                }
                None => {
                    return Err(MempoolError::Invalid(StateError::new(
                        "tx_nonce",
                        "the nonce has already been used by the chain",
                    )))
                }
            }
        }
        if self.account_len(&sender) >= self.config.max_per_account {
            return Err(MempoolError::AccountFull {
                address: sender,
                limit: self.config.max_per_account,
            });
        }
        if self.entries.len() >= self.config.max_transactions && !self.make_room(&entry) {
            return Err(MempoolError::PoolFull {
                limit: self.config.max_transactions,
            });
        }

        // Validate the transaction *together with* the pooled transactions it
        // depends on.  Individual validity is not enough: a queued sequence
        // must apply as a whole.
        if let Err(error) = self.validate_sequence(state, &entry.tx, at) {
            return Err(MempoolError::Invalid(error));
        }

        self.entries.insert(id, entry);
        Ok(id)
    }

    /// Validates `tx` on top of the pooled transactions it depends on.
    fn validate_sequence(
        &self,
        state: &ChainState,
        tx: &Transaction,
        at: u64,
    ) -> Result<(), StateError> {
        let sender = match tx.sender() {
            Some(sender) => sender,
            None => return Ok(()),
        };
        let first = state.expected_nonce(&sender);
        let mut predecessors: Vec<&Entry> = self
            .entries
            .values()
            .filter(|entry| {
                entry.sender == sender && entry.tx.nonce >= first && entry.tx.nonce < tx.nonce
            })
            .collect();
        predecessors.sort_by_key(|entry| entry.tx.nonce);
        let mut sequence: Vec<Transaction> = predecessors
            .into_iter()
            .map(|entry| entry.tx.clone())
            .collect();
        sequence.push(tx.clone());
        state.apply_txs_preview(&sequence, at)?;
        Ok(())
    }

    /// Frees room for `incoming`, if the pool can spare anything.
    ///
    /// The worst entry is the one with the lowest fee (ties broken by the
    /// largest id) that no other pooled transaction depends on.
    fn make_room(&mut self, incoming: &Entry) -> bool {
        let mut candidates: Vec<Entry> = self
            .entries
            .values()
            .filter(|entry| !self.has_dependent(entry))
            .cloned()
            .collect();
        if candidates.is_empty() {
            return false;
        }
        candidates.sort_by(|left, right| {
            left.fee
                .cmp(&right.fee)
                .then_with(|| right.id.0.cmp(&left.id.0))
        });
        let worst = candidates[0].clone();
        let incoming_is_better = incoming.fee > worst.fee
            || (incoming.fee == worst.fee && incoming.id.0 < worst.id.0);
        if !incoming_is_better {
            return false;
        }
        self.remove_entry(&worst.id);
        self.dropped += 1;
        true
    }

    /// Does any other pooled transaction need this one applied first?
    fn has_dependent(&self, entry: &Entry) -> bool {
        self.entries.values().any(|other| {
            other.sender == entry.sender && other.tx.nonce == entry.tx.nonce + 1
        })
    }

    fn remove_entry(&mut self, id: &TxId) -> Option<Entry> {
        self.entries.remove(id)
    }

    /// Drops a pooled transaction.
    pub fn remove(&mut self, id: &TxId) -> Option<Transaction> {
        self.remove_entry(id).map(|entry| entry.tx)
    }

    /// Drops transactions that have waited longer than the configured expiry.
    ///
    /// Expiry is measured in *protocol* time, never wall-clock time: a node
    /// whose clock is wrong cannot shorten or extend a transaction's life.
    pub fn expire(&mut self, at: u64) -> usize {
        let doomed: Vec<TxId> = self
            .entries
            .values()
            .filter(|entry| at.saturating_sub(entry.received_at) > self.config.expiry_secs)
            .map(|entry| entry.id)
            .collect();
        for id in &doomed {
            self.remove_entry(id);
        }
        self.dropped += doomed.len() as u64;
        doomed.len()
    }

    /// Applies a block: mined transactions leave the pool, and anything the new
    /// state invalidates is dropped.
    ///
    /// Revalidation happens at the block's own protocol time, so a node that
    /// adopts a block cannot use its own clock to invalidate pooled work.
    /// Returns the number of transactions removed.
    pub fn on_block_applied(&mut self, state: &ChainState, block: &Block) -> usize {
        let before = self.entries.len();
        for tx in &block.transactions {
            self.remove_entry(&tx.id());
        }
        self.revalidate(state, block.header.timestamp);
        before.saturating_sub(self.entries.len())
    }

    /// Puts the transactions of disconnected blocks back into the pool.
    ///
    /// A reorg must never lose a transaction that is still valid: it returns to
    /// the pool and competes again.  Returns the number restored.
    pub fn on_reorg<'a>(
        &mut self,
        state: &ChainState,
        disconnected: impl IntoIterator<Item = &'a Block>,
        at: u64,
    ) -> usize {
        let mut restored = 0;
        let blocks: Vec<&Block> = disconnected.into_iter().collect();
        for block in blocks.iter().rev() {
            for tx in &block.transactions {
                if self.insert(state, tx.clone(), at).is_ok() {
                    restored += 1;
                }
            }
        }
        restored
    }

    /// Drops every pooled transaction the head state no longer accepts.
    ///
    /// Returns the number dropped.  This is what keeps a pool honest after a
    /// block from another producer consumed a nonce, spent a balance, or moved
    /// the protocol time past a transaction's assumptions.
    pub fn revalidate(&mut self, state: &ChainState, at: u64) -> usize {
        let doomed: Vec<TxId> = self
            .entries
            .values()
            .filter(|entry| {
                entry.tx.nonce < state.expected_nonce(&entry.sender)
                    || self.validate_sequence(state, &entry.tx, at).is_err()
            })
            .map(|entry| entry.id)
            .collect();
        for id in &doomed {
            self.remove_entry(id);
        }
        self.dropped += doomed.len() as u64;
        doomed.len()
    }

    /// Builds the transaction list for the next block, highest fee first.
    ///
    /// `limit` caps how many transactions the caller wants (the caller may be
    /// enforcing a block size budget); it is itself capped by the protocol's
    /// per-block transaction limit.  Only transactions that apply on top of
    /// everything selected before them are returned, in nonce order per
    /// account.  The result is deterministic: same pool, same state, same list.
    pub fn select_for_block(&self, state: &ChainState, at: u64, limit: usize) -> Vec<Transaction> {
        let limit = limit.min(MAX_TXS_PER_BLOCK);
        let mut candidates: Vec<&Entry> = self.entries.values().collect();
        candidates.sort_by(|left, right| {
            right
                .fee
                .cmp(&left.fee)
                .then_with(|| left.id.0.cmp(&right.id.0))
        });

        let mut selected: Vec<Transaction> = Vec::new();
        let mut probe = state.clone();
        let mut remaining = candidates;
        // Repeated passes: within a pass the highest fee goes first, and a
        // transaction can only be taken once the nonce before it has been.
        // A transaction whose predecessor is cheaper is therefore taken in the
        // next pass, which is what keeps nonce order per account.
        loop {
            let mut progressed = false;
            let mut deferred: Vec<&Entry> = Vec::new();
            for entry in remaining {
                if selected.len() >= limit {
                    deferred.push(entry);
                    continue;
                }
                let expected = probe.expected_nonce(&entry.sender);
                if entry.tx.nonce > expected {
                    // Its predecessors have not been taken yet: try again next
                    // pass, in case one of them is taken later in this one.
                    deferred.push(entry);
                    continue;
                }
                if entry.tx.nonce < expected {
                    // Stale or already applied: it can never go in this block.
                    continue;
                }
                match probe.apply_txs_preview(std::slice::from_ref(&entry.tx), at) {
                    Ok(next) => {
                        probe = next;
                        selected.push(entry.tx.clone());
                        progressed = true;
                    }
                    Err(_) => {
                        // The chain refuses it against the probe.  It stays
                        // pooled for a later attempt rather than blocking the
                        // rest of the template.
                    }
                }
            }
            if !progressed || deferred.is_empty() {
                break;
            }
            remaining = deferred;
        }
        selected
    }
}

fn make_entry(tx: Transaction, sender: Address, bytes: usize, at: u64) -> Entry {
    let fee = transaction_fee(&tx);
    let spend = match &tx.kind {
        TxKind::Transfer { amount, .. } => amount.checked_add(fee).unwrap_or(Amount(u128::MAX)),
        _ => fee,
    };
    Entry {
        id: tx.id(),
        tx,
        sender,
        fee,
        spend,
        bytes,
        received_at: at,
    }
}

/// The gas fee a transaction pays, in grains.
///
/// Only transfers pay gas; every other transaction kind is free, exactly as the
/// chain's own rules enforce.
pub fn transaction_fee(tx: &Transaction) -> Amount {
    match &tx.kind {
        TxKind::Transfer { amount, .. } => obs_chain::params::gas_fee_for(*amount),
        _ => Amount::ZERO,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_pool_cannot_hold_more_than_one_block() {
        let config = MempoolConfig::default();
        assert_eq!(config.max_transactions, MAX_TXS_PER_BLOCK);
        assert!(config.max_per_account < config.max_transactions);
        assert!(config.max_tx_bytes > 0);
        assert!(config.expiry_secs > 0);
    }

    #[test]
    fn errors_format_without_panicking() {
        let error = MempoolError::TooLarge {
            bytes: 70_000,
            max: 65_536,
        };
        assert!(error.to_string().contains("70000"));
        assert!(MempoolError::PoolFull { limit: 4_096 }
            .to_string()
            .contains("4096"));
        assert!(MempoolError::NonceGap {
            expected: 3,
            got: 9
        }
        .to_string()
        .contains('9'));
    }

    #[test]
    fn a_fresh_pool_is_empty() {
        let config = MempoolConfig::default();
        let pool = Mempool::new(config.clone());
        assert!(pool.is_empty());
        assert_eq!(pool.len(), 0);
        assert_eq!(pool.stats().transactions, 0);
        assert_eq!(pool.stats().accounts, 0);
        assert_eq!(pool.stats().max_transactions, config.max_transactions);
        assert_eq!(pool.total_fees(), Amount::ZERO);
    }
}
