//! Blocks, block headers and validator attestations.
//!
//! A block is the unit of consensus progress:
//!
//! * the **header** carries the chain position, the three state commitments
//!   (state root, transaction root, attestation root), protocol time, the PoT
//!   difficulty and weight, and the scheduled proposer's node key,
//! * the **body** carries the transactions and the attestations that the
//!   proposer collected for the parent block,
//! * the **signature** is the proposer's Ed25519 signature over the canonical
//!   header pre-image, which includes the chain id.

use obs_primitives::codec::{Decode, Decoder, Encode};
use obs_primitives::hash::{merkle_root, tagged_preimage, Hash32};

use crate::params::{MAX_ATTESTATIONS_PER_BLOCK, MAX_TXS_PER_BLOCK, tags};
use crate::tx::Transaction;

/// The canonical block header.
///
/// Field order is part of consensus: the encoding is
/// `version, chain_id, height, slot, parent, state_root, tx_root,
/// attestation_root, timestamp, difficulty_bp, weight_atoms, proposer`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockHeader {
    /// Protocol version that produced the block.
    pub version: u32,
    /// Chain id, binding the header to one network.
    pub chain_id: u32,
    /// Height of this block (genesis block is height 0).
    pub height: u64,
    /// Protocol slot index of this block: `floor(timestamp / 30)`.
    pub slot: u64,
    /// Hash of the parent block.
    pub parent: Hash32,
    /// Merkle root of the account state after this block.
    pub state_root: Hash32,
    /// Merkle root of the transactions in this block.
    pub tx_root: Hash32,
    /// Merkle root of the attestations in this block.
    pub attestation_root: Hash32,
    /// Protocol timestamp in seconds since the Unix epoch.
    pub timestamp: u64,
    /// PoT difficulty in basis points.
    pub difficulty_bp: u32,
    /// PoT weight accumulated by this block, in atoms.
    pub weight_atoms: u128,
    /// Node identity key of the scheduled proposer.
    pub proposer: [u8; 32],
}

impl Encode for BlockHeader {
    fn encode(&self, out: &mut Vec<u8>) {
        self.version.encode(out);
        self.chain_id.encode(out);
        self.height.encode(out);
        self.slot.encode(out);
        self.parent.encode(out);
        self.state_root.encode(out);
        self.tx_root.encode(out);
        self.attestation_root.encode(out);
        self.timestamp.encode(out);
        self.difficulty_bp.encode(out);
        self.weight_atoms.encode(out);
        out.extend_from_slice(&self.proposer);
    }
}

impl Decode for BlockHeader {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(BlockHeader {
            version: u32::decode(decoder)?,
            chain_id: u32::decode(decoder)?,
            height: u64::decode(decoder)?,
            slot: u64::decode(decoder)?,
            parent: Hash32::decode(decoder)?,
            state_root: Hash32::decode(decoder)?,
            tx_root: Hash32::decode(decoder)?,
            attestation_root: Hash32::decode(decoder)?,
            timestamp: u64::decode(decoder)?,
            difficulty_bp: u32::decode(decoder)?,
            weight_atoms: u128::decode(decoder)?,
            proposer: <[u8; 32]>::decode(decoder)?,
        })
    }
}

/// A validator's attestation for a specific block.
///
/// Attestations are the *evidence* of validator uptime: they are signed by the
/// validator's node key, recorded in chain state when accepted, and no
/// self-reported uptime value is ever trusted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attestation {
    /// Node identity key of the attesting validator.
    pub node_key: [u8; 32],
    /// Height of the block being attested.
    pub height: u64,
    /// Hash of the block being attested.
    pub block_hash: Hash32,
    /// Slot of the block being attested.
    pub slot: u64,
    /// Ed25519 signature by `node_key`.
    pub signature: [u8; 64],
}

impl Attestation {
    /// The exact bytes signed by the validator.
    pub fn signing_preimage(&self, chain_id: u32) -> Vec<u8> {
        tagged_preimage(
            tags::ATTESTATION_SIGN,
            &[
                &chain_id.to_le_bytes(),
                &self.height.to_le_bytes(),
                &self.slot.to_le_bytes(),
                &self.block_hash.0,
            ],
        )
    }

    /// Builds and signs an attestation with a node identity keypair.
    pub fn sign(
        chain_id: u32,
        node_keypair: &obs_crypto::ed25519::Keypair,
        height: u64,
        block_hash: Hash32,
        slot: u64,
    ) -> Attestation {
        let mut attestation = Attestation {
            node_key: node_keypair.public_key(),
            height,
            block_hash,
            slot,
            signature: [0u8; 64],
        };
        let preimage = attestation.signing_preimage(chain_id);
        attestation.signature = node_keypair.sign(&preimage);
        attestation
    }

    /// Verifies the attestation signature against its own `node_key`.
    pub fn verify_signature(&self, chain_id: u32) -> bool {
        obs_crypto::ed25519::verify(
            &self.node_key,
            &self.signing_preimage(chain_id),
            &self.signature,
        )
    }

    /// Attestation identifier, used for deduplication and as a Merkle leaf.
    pub fn id(&self) -> Hash32 {
        Hash32::tagged(tags::ATTESTATION_SIGN, &[&self.encoded()])
    }
}

impl Encode for Attestation {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node_key);
        self.height.encode(out);
        self.block_hash.encode(out);
        self.slot.encode(out);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for Attestation {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Attestation {
            node_key: <[u8; 32]>::decode(decoder)?,
            height: u64::decode(decoder)?,
            block_hash: Hash32::decode(decoder)?,
            slot: u64::decode(decoder)?,
            signature: <[u8; 64]>::decode(decoder)?,
        })
    }
}

/// A signed block.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Block {
    /// Canonical header.
    pub header: BlockHeader,
    /// Transactions included by the proposer, in the proposer's order (the
    /// transaction root commits to that order).
    pub transactions: Vec<Transaction>,
    /// Attestations for the parent block, sorted by node key.
    pub attestations: Vec<Attestation>,
    /// Proposer signature over [`Block::signing_preimage`].
    pub signature: [u8; 64],
}

impl Block {
    /// Builds the genesis block of a network.
    ///
    /// The genesis block has no transactions, no parent state and no
    /// signature: its hash is derived from the network identity and protocol
    /// version, and every node computes it independently.
    pub fn genesis(
        network: obs_primitives::network::Network,
        protocol_version: u32,
        genesis_time: u64,
    ) -> Block {
        let genesis_hash = network.genesis_hash(protocol_version, genesis_time);
        // Parent of genesis is the genesis hash itself; there is no earlier
        // block to point at, and self-parenting keeps the field total.
        let header = BlockHeader {
            version: protocol_version,
            chain_id: network.chain_id,
            height: 0,
            slot: genesis_time / crate::params::SLOT_DURATION_SECS,
            parent: genesis_hash,
            state_root: Hash32::ZERO,
            tx_root: merkle_root(&[]),
            attestation_root: merkle_root(&[]),
            timestamp: genesis_time,
            difficulty_bp: crate::params::DIFFICULTY_INITIAL_BP,
            weight_atoms: 0,
            proposer: [0u8; 32],
        };
        Block {
            header,
            transactions: Vec::new(),
            attestations: Vec::new(),
            signature: [0u8; 64],
        }
    }

    /// The exact bytes the proposer signs.
    ///
    /// Includes the chain id and the header, which in turn commits to the state
    /// root, transaction root and attestation root — so one signature covers
    /// the entire block content.
    pub fn signing_preimage(&self) -> Vec<u8> {
        tagged_preimage(
            tags::BLOCK_SIGN,
            &[
                &self.header.chain_id.to_le_bytes(),
                &self.header.encoded(),
            ],
        )
    }

    /// Block hash: the domain-separated hash of the canonical header.
    pub fn hash(&self) -> Hash32 {
        Hash32::tagged(tags::BLOCK, &[&self.header.encoded()])
    }

    /// Recomputes the transaction root from the body.
    pub fn compute_tx_root(&self) -> Hash32 {
        let leaves: Vec<Vec<u8>> = self.transactions.iter().map(|tx| tx.encoded()).collect();
        merkle_root(&leaves)
    }

    /// Recomputes the attestation root from the body.
    pub fn compute_attestation_root(&self) -> Hash32 {
        let leaves: Vec<Vec<u8>> = self
            .attestations
            .iter()
            .map(|attestation| attestation.encoded())
            .collect();
        merkle_root(&leaves)
    }

    /// Verifies the proposer signature against the header's proposer key.
    pub fn verify_proposer_signature(&self) -> bool {
        obs_crypto::ed25519::verify(
            &self.header.proposer,
            &self.signing_preimage(),
            &self.signature,
        )
    }

    /// Signs the block with the proposer's node key.
    pub fn sign(&mut self, node_keypair: &obs_crypto::ed25519::Keypair) {
        self.header.proposer = node_keypair.public_key();
        let preimage = self.signing_preimage();
        self.signature = node_keypair.sign(&preimage);
    }

    /// Structural checks that do not require chain state.
    ///
    /// Anything that depends on the parent, the validator set or account
    /// balances is checked by the state machine, which fails closed.
    pub fn check_structure(&self) -> Result<(), &'static str> {
        if self.header.version != crate::params::PROTOCOL_VERSION {
            return Err("unsupported protocol version");
        }
        if self.transactions.len() > MAX_TXS_PER_BLOCK {
            return Err("too many transactions");
        }
        if self.attestations.len() > MAX_ATTESTATIONS_PER_BLOCK {
            return Err("too many attestations");
        }
        if self.header.slot != self.header.timestamp / crate::params::SLOT_DURATION_SECS {
            return Err("slot does not match timestamp");
        }
        if self.compute_tx_root() != self.header.tx_root {
            return Err("transaction root mismatch");
        }
        if self.compute_attestation_root() != self.header.attestation_root {
            return Err("attestation root mismatch");
        }
        // Attestations must be sorted by node key and unique, so that every
        // honest proposer produces the same root for the same set.
        for pair in self.attestations.windows(2) {
            if pair[0].node_key >= pair[1].node_key {
                return Err("attestations are not sorted by node key");
            }
        }
        // Attestations in a block may only attest blocks strictly below it.
        for attestation in &self.attestations {
            if attestation.height >= self.header.height {
                return Err("attestation height is not below block height");
            }
        }
        Ok(())
    }
}

impl Encode for Block {
    fn encode(&self, out: &mut Vec<u8>) {
        self.header.encode(out);
        obs_primitives::codec::Seq(self.transactions.clone()).encode(out);
        obs_primitives::codec::Seq(self.attestations.clone()).encode(out);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for Block {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        let header = BlockHeader::decode(decoder)?;
        let transactions = decoder.read_seq::<Transaction>(MAX_TXS_PER_BLOCK)?;
        let attestations = decoder.read_seq::<Attestation>(MAX_ATTESTATIONS_PER_BLOCK)?;
        let signature = <[u8; 64]>::decode(decoder)?;
        Ok(Block {
            header,
            transactions,
            attestations,
            signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_crypto::ed25519::Keypair;
    use obs_primitives::address::Address;
    use obs_primitives::money::Amount;
    use obs_primitives::network::MAINNET;

    use crate::chain::TxKind;

    fn make_block() -> Block {
        let kp = Keypair::from_seed(&[5u8; 32]);
        let tx = Transaction::sign(
            MAINNET,
            1,
            TxKind::Transfer {
                to: Address::from_public_key(MAINNET, &[6u8; 32]),
                amount: Amount::from_obs(1),
            },
            &Keypair::from_seed(&[4u8; 32]),
        );
        let attestation = Attestation::sign(
            MAINNET.chain_id,
            &Keypair::from_seed(&[8u8; 32]),
            0,
            Hash32::from_bytes([7u8; 32]),
            0,
        );
        let mut block = Block {
            header: BlockHeader {
                version: crate::params::PROTOCOL_VERSION,
                chain_id: MAINNET.chain_id,
                height: 1,
                slot: 60_000_000,
                parent: Hash32::from_bytes([1u8; 32]),
                state_root: Hash32::from_bytes([2u8; 32]),
                tx_root: Hash32::ZERO,
                attestation_root: Hash32::ZERO,
                timestamp: 60_000_000 * crate::params::SLOT_DURATION_SECS,
                difficulty_bp: crate::params::DIFFICULTY_INITIAL_BP,
                weight_atoms: 1_000_000,
                proposer: [0u8; 32],
            },
            transactions: vec![tx],
            attestations: vec![attestation],
            signature: [0u8; 64],
        };
        block.header.tx_root = block.compute_tx_root();
        block.header.attestation_root = block.compute_attestation_root();
        block.sign(&kp);
        block
    }

    #[test]
    fn block_roundtrip_and_hash() {
        let block = make_block();
        let bytes = block.encoded();
        let parsed: Block = obs_primitives::codec::decode_exact(&bytes).unwrap();
        assert_eq!(block, parsed);
        assert_eq!(block.hash(), parsed.hash());
        assert!(block.check_structure().is_ok());
        assert!(block.verify_proposer_signature());
    }

    #[test]
    fn structural_checks_fail_closed() {
        let mut block = make_block();

        // Wrong slot for the timestamp.
        let mut bad = block.clone();
        bad.header.slot += 1;
        assert!(bad.check_structure().is_err());

        // Tampered transaction root.
        let mut bad = block.clone();
        bad.header.tx_root = Hash32::ZERO;
        assert!(bad.check_structure().is_err());

        // Unsorted attestations.
        let mut bad = block.clone();
        bad.attestations.push(bad.attestations[0].clone());
        assert!(bad.check_structure().is_err());

        // Attestation that claims to be at or above the block height.
        let mut bad = block.clone();
        bad.attestations[0].height = block.header.height;
        assert!(bad.check_structure().is_err());

        // Signature invalidated by any header change.
        block.header.weight_atoms += 1;
        assert!(!block.verify_proposer_signature());
    }

    #[test]
    fn attestation_signature_binds_chain_and_block() {
        let kp = Keypair::from_seed(&[9u8; 32]);
        let attestation =
            Attestation::sign(MAINNET.chain_id, &kp, 10, Hash32::from_bytes([3u8; 32]), 4);
        assert!(attestation.verify_signature(MAINNET.chain_id));
        // A different chain id invalidates it: cross-network replay protection.
        assert!(!attestation.verify_signature(obs_primitives::network::TESTNET.chain_id));

        let mut tampered = attestation.clone();
        tampered.block_hash = Hash32::from_bytes([4u8; 32]);
        assert!(!tampered.verify_signature(MAINNET.chain_id));
    }

    #[test]
    fn genesis_block_is_deterministic() {
        let a = Block::genesis(MAINNET, 1, crate::params::GENESIS_TIMESTAMP);
        let b = Block::genesis(MAINNET, 1, crate::params::GENESIS_TIMESTAMP);
        assert_eq!(a.hash(), b.hash());
        assert_eq!(a.header.tx_root, merkle_root(&[]));
        assert!(a.check_structure().is_ok());
        // Testnet has a different genesis hash from mainnet.
        assert_ne!(
            a.hash(),
            Block::genesis(obs_primitives::network::TESTNET, 1, crate::params::GENESIS_TIMESTAMP)
                .hash()
        );
    }
}
