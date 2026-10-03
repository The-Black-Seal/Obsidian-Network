//! Transactions.
//!
//! A transaction is the only way to change chain state.  It binds:
//!
//! * the **chain id**, so a transaction signed for testnet can never be
//!   replayed on mainnet,
//! * a per-sender **nonce**, so a transaction can never be replayed twice,
//! * the exact **body** (recipient, amount, claim, registration), and
//! * the sender's Ed25519 **signature** over the domain-separated pre-image.
//!
//! The transaction identifier is the hash of the canonical encoding of all of
//! those fields together — never a wallet address, never a nonce.

use obs_primitives::address::Address;
use obs_primitives::codec::{Decode, Decoder, Encode};
use obs_primitives::hash::{tagged_preimage, Hash32};
use obs_primitives::network::Network;

use crate::chain::{TxId, TxKind};
use crate::params::tags;

/// A signed transaction.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Transaction {
    /// Chain id this transaction is valid on.
    pub chain_id: u32,
    /// Sender nonce: strictly increasing, starting at 1 for an account's first
    /// transaction.  A transaction is valid only with the sender's next nonce.
    pub nonce: u64,
    /// Transaction body.
    pub kind: TxKind,
    /// Sender's Ed25519 public key.
    pub public_key: [u8; 32],
    /// Ed25519 signature over [`Transaction::signing_preimage`].
    pub signature: [u8; 64],
}

impl Transaction {
    /// Alias for the kind, used by APIs.
    pub fn kind_name(&self) -> &'static str {
        self.kind.name()
    }

    /// Builds and signs a transaction.
    ///
    /// The private key never leaves the caller: this function is used by the
    /// wallet, the CLI and the tests, and the signature it produces is verified
    /// by every node independently.
    pub fn sign(
        network: Network,
        nonce: u64,
        kind: TxKind,
        keypair: &obs_crypto::ed25519::Keypair,
    ) -> Transaction {
        let mut tx = Transaction {
            chain_id: network.chain_id,
            nonce,
            kind,
            public_key: keypair.public_key(),
            signature: [0u8; 64],
        };
        let preimage = tx.signing_preimage();
        tx.signature = keypair.sign(&preimage);
        tx
    }

    /// The exact bytes that are signed.
    ///
    /// Format: `u32_be(len("OBSIDIAN/TX-SIGN/v1")) || tag || 0x00` followed by
    /// length-prefixed `(chain_id, nonce, body)`.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let body = self.kind.encoded();
        tagged_preimage(
            tags::TX_SIGN,
            &[
                &self.chain_id.to_le_bytes(),
                &self.nonce.to_le_bytes(),
                &body,
            ],
        )
    }

    /// Canonical encoding of the whole signed transaction.
    pub fn to_bytes(&self) -> Vec<u8> {
        self.encoded()
    }

    /// Size of the canonical encoding, without allocating it.
    ///
    /// Used by admission policy (the pool's byte ceiling) and by the block
    /// producer when it budgets a block, so neither has to encode first.
    pub fn encoded_len(&self) -> usize {
        let mut out = Vec::with_capacity(256);
        self.encode(&mut out);
        out.len()
    }

    /// Parses a transaction from its canonical encoding, rejecting anything
    /// that is not exactly one well-formed transaction.
    pub fn from_bytes(bytes: &[u8]) -> Result<Transaction, obs_primitives::codec::CodecError> {
        obs_primitives::codec::decode_exact(bytes)
    }

    /// Transaction identifier: the domain-separated hash of the canonical
    /// encoding.
    pub fn id(&self) -> TxId {
        TxId(Hash32::tagged(tags::TX, &[&self.encoded()]))
    }

    /// Verifies the sender's signature.  Returns `false` for any malformed or
    /// forged input; it never panics and never touches state.
    pub fn verify_signature(&self) -> bool {
        obs_crypto::ed25519::verify(&self.public_key, &self.signing_preimage(), &self.signature)
    }

    /// Address derived from the signing key on this transaction's chain.
    pub fn sender(&self) -> Option<Address> {
        let network = Network::by_chain_id(self.chain_id)?;
        Some(Address::from_public_key(network, &self.public_key))
    }

    /// True when the transaction is signed by `address`.
    pub fn is_signed_by(&self, address: &Address) -> bool {
        self.sender().as_ref() == Some(address)
    }
}

impl Encode for Transaction {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.nonce.encode(out);
        self.kind.encode(out);
        out.extend_from_slice(&self.public_key);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for Transaction {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Transaction {
            chain_id: u32::decode(decoder)?,
            nonce: u64::decode(decoder)?,
            kind: TxKind::decode(decoder)?,
            public_key: <[u8; 32]>::decode(decoder)?,
            signature: <[u8; 64]>::decode(decoder)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_crypto::ed25519::Keypair;
    use obs_primitives::money::Amount;
    use obs_primitives::network::{MAINNET, TESTNET};

    fn keypair() -> Keypair {
        Keypair::from_seed(&[11u8; 32])
    }

    #[test]
    fn transaction_roundtrip_and_identity() {
        let kp = keypair();
        let kind = TxKind::Transfer {
            to: Address::from_public_key(MAINNET, &[22u8; 32]),
            amount: Amount::from_obs(3),
        };
        let tx = Transaction::sign(MAINNET, 1, kind, &kp);

        let bytes = tx.to_bytes();
        let parsed = Transaction::from_bytes(&bytes).unwrap();
        assert_eq!(tx, parsed);
        assert_eq!(tx.id(), parsed.id());
        assert!(tx.verify_signature());
        assert!(tx.is_signed_by(&Address::from_public_key(MAINNET, &kp.public_key())));
    }

    #[test]
    fn tampering_is_detected() {
        let kp = keypair();
        let mut tx = Transaction::sign(
            MAINNET,
            1,
            TxKind::Transfer {
                to: Address::from_public_key(MAINNET, &[33u8; 32]),
                amount: Amount::from_obs(1),
            },
            &kp,
        );
        assert!(tx.verify_signature());

        // Change the amount: signature must fail.
        tx.kind = TxKind::Transfer {
            to: Address::from_public_key(MAINNET, &[33u8; 32]),
            amount: Amount::from_obs(2),
        };
        assert!(!tx.verify_signature());

        // Change the nonce: signature must fail.
        let mut tx2 = Transaction::sign(
            MAINNET,
            1,
            TxKind::Transfer {
                to: Address::from_public_key(MAINNET, &[33u8; 32]),
                amount: Amount::from_obs(1),
            },
            &kp,
        );
        tx2.nonce = 2;
        assert!(!tx2.verify_signature());
    }

    #[test]
    fn chain_id_is_bound_by_the_signature() {
        let kp = keypair();
        let kind = TxKind::Transfer {
            to: Address::from_public_key(MAINNET, &[44u8; 32]),
            amount: Amount::from_obs(1),
        };
        let mainnet_tx = Transaction::sign(MAINNET, 1, kind.clone(), &kp);
        // The same body signed for testnet is a different transaction, and the
        // mainnet signature does not verify against testnet's chain id.
        let mut cross = mainnet_tx.clone();
        cross.chain_id = TESTNET.chain_id;
        assert!(!cross.verify_signature());
        assert_ne!(cross.id(), mainnet_tx.id());
    }

    #[test]
    fn sender_is_derived_from_the_signing_key() {
        let kp = keypair();
        let tx = Transaction::sign(MAINNET, 7, TxKind::DeregisterValidator, &kp);
        let sender = tx.sender().unwrap();
        assert_eq!(sender, Address::from_public_key(MAINNET, &kp.public_key()));
        assert!(tx.is_signed_by(&sender));
        assert_eq!(tx.encoded_len(), tx.to_bytes().len());
    }
}
