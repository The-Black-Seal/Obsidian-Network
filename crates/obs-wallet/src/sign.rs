//! What a wallet signs.
//!
//! Every builder here takes the values the protocol actually signs — the chain
//! id comes from the wallet's network, the nonce and the claim sequence come
//! from chain state, and the protocol timestamp comes from the block that will
//! carry the transaction.  A wallet that invented any of them would produce a
//! transaction every node refuses, so there is deliberately no "convenience"
//! overload that guesses.
//!
//! The pre-images are built by `obs-chain`, the same code every node verifies
//! against: a wallet cannot sign a transaction that means one thing to it and
//! another thing to the network.
//!
//! ## Signing out of process
//!
//! [`Request`] is the wire form for a signing service or a hardware signer:
//! a fully described, already-validated transaction plus the exact bytes that
//! must be signed.  The signer returns a signature; nothing else about the
//! wallet ever leaves the device.

use obs_chain::chain::{Claim, InviteAuthorization};
use obs_chain::{Transaction, TxKind};
use obs_primitives::address::Address;
use obs_primitives::codec::Encode;
use obs_primitives::hash::Hash32;
use obs_primitives::money::Amount;

use crate::{Wallet, WalletError};

/// Builds a mining claim.
///
/// `protocol_time` **must** be the timestamp of the block that will include the
/// claim: the chain requires a claim's declared time to equal the block's.
/// `sequence` and `nonce` come from chain state — the account's
/// `last_claim_sequence + 1` and `expected_nonce`.
pub fn claim(
    wallet: &Wallet,
    protocol_time: u64,
    sequence: u64,
    nonce: u64,
) -> Result<Transaction, WalletError> {
    if sequence == 0 {
        return Err(WalletError::Unsupported(
            "claim sequences start at 1; build the claim from chain state".to_string(),
        ));
    }
    Ok(Transaction::sign(
        wallet.network(),
        nonce,
        TxKind::Claim(Claim {
            account: wallet.address(),
            claimed_at: protocol_time,
            sequence,
        }),
        wallet.wallet_keypair(),
    ))
}

/// Builds a transfer.  The fee is the protocol's own calculation, not a
/// caller-supplied number, and the recipient is an address, never a key.
pub fn transfer(
    wallet: &Wallet,
    to: Address,
    amount: Amount,
    nonce: u64,
) -> Result<Transaction, WalletError> {
    if to == wallet.address() {
        return Err(WalletError::Unsupported(
            "a transfer to the sender's own address is not a payment".to_string(),
        ));
    }
    if !to.to_string_canonical().starts_with(wallet.network().address_prefix) {
        return Err(WalletError::Unsupported(format!(
            "the recipient is not a {} address",
            wallet.network().name
        )));
    }
    if amount.is_zero() {
        return Err(WalletError::Unsupported("a transfer must move value".to_string()));
    }
    Ok(Transaction::sign(
        wallet.network(),
        nonce,
        TxKind::Transfer { to, amount },
        wallet.wallet_keypair(),
    ))
}

/// What the registration service must supply before an account can be created.
///
/// The service issues the invitation; the *wallet* signs the registration, which
/// is what makes the account non-custodial from its first moment.
pub struct Registration {
    /// The invitation authorisation, bound to the account's canonical Gmail
    /// commitment and signed by the registration authority.
    pub invite: InviteAuthorization,
    /// Commitment to the canonical Gmail identity.
    pub gmail_commitment: Hash32,
    /// The registration transaction's nonce, which for a new account is 1.
    pub nonce: u64,
}

/// Builds the account registration a new wallet submits after registration.
pub fn register(wallet: &Wallet, registration: Registration) -> Result<Transaction, WalletError> {
    if registration.nonce == 0 {
        return Err(WalletError::Unsupported(
            "a registration's nonce is 1".to_string(),
        ));
    }
    if registration.invite.gmail_commitment != registration.gmail_commitment {
        return Err(WalletError::Unsupported(
            "the invitation authorises a different Gmail identity".to_string(),
        ));
    }
    Ok(Transaction::sign(
        wallet.network(),
        registration.nonce,
        TxKind::Register {
            account: wallet.address(),
            wallet_key: wallet.public_keys().wallet_key,
            gmail_commitment: registration.gmail_commitment,
            invite: registration.invite,
        },
        wallet.wallet_keypair(),
    ))
}

/// Builds a validator registration, bonding the account's own value.
pub fn register_validator(
    wallet: &Wallet,
    endpoint: &str,
    nonce: u64,
) -> Result<Transaction, WalletError> {
    if endpoint.len() > obs_chain::params::MAX_NODE_ENDPOINT_LEN {
        return Err(WalletError::Unsupported(format!(
            "an endpoint may be at most {} bytes",
            obs_chain::params::MAX_NODE_ENDPOINT_LEN
        )));
    }
    Ok(Transaction::sign(
        wallet.network(),
        nonce,
        TxKind::RegisterValidator {
            // The validator identity is a *different key* from the wallet key;
            // the protocol enforces that, and the wallet derives it separately.
            node_key: wallet.public_keys().node_key,
            endpoint: endpoint.to_string(),
        },
        wallet.wallet_keypair(),
    ))
}

/// Builds a validator deregistration.  The bond comes back after the protocol's
/// 48-hour unbonding period, enforced by the chain.
pub fn deregister_validator(wallet: &Wallet, nonce: u64) -> Result<Transaction, WalletError> {
    Ok(Transaction::sign(
        wallet.network(),
        nonce,
        TxKind::DeregisterValidator,
        wallet.wallet_keypair(),
    ))
}

/// Signs an attestation for a block, with the validator node key.
///
/// Attestations are what make uptime evidence-based: a validator says "I saw this
/// block", the signature proves which validator said it, and nobody reports their
/// own uptime.
pub fn attest(
    wallet: &Wallet,
    height: u64,
    block_hash: Hash32,
    slot: u64,
) -> Result<obs_chain::Attestation, WalletError> {
    Ok(obs_chain::Attestation::sign(
        wallet.network().chain_id,
        wallet.node_keypair(),
        height,
        block_hash,
        slot,
    ))
}

/// Signs the account-ownership challenge the node's API verifies.
///
/// The pre-image is domain-separated and bound to the chain and to a nonce the
/// caller chooses, so a signature made for a balance check can never be replayed
/// as a transaction or on another network.
pub fn account_proof(wallet: &Wallet, nonce: &str) -> [u8; 64] {
    let mut out = Vec::with_capacity(64 + nonce.len());
    out.extend_from_slice(b"OBSIDIAN/API/ACCOUNT-PROOF/v1");
    out.extend_from_slice(&wallet.network().chain_id.to_le_bytes());
    out.extend_from_slice(&wallet.address().encoded());
    out.extend_from_slice(nonce.as_bytes());
    wallet.sign_preimage(&out)
}

/// A signed statement that the holder of an account's recovery key wants the
/// registration service to act.
///
/// ## What this is, and what it is not
///
/// Protocol version 1 has no transaction that changes an account's wallet key,
/// so **this intent cannot move funds and cannot restore a lost wallet key**: the
/// chain would have nothing to apply.  What it does is prove, to the registration
/// service, that a request came from the holder of the recovery key rather than
/// from somebody who merely guessed a recovery code — which is what the service
/// records when it re-enrols MFA or resets a password, and what a future protocol
/// version will require in order to authorise a wallet-key rotation on chain.
///
/// The honest statement of the current guarantee, which the documentation repeats:
/// whoever holds the wallet key holds the account's value.  The recovery key
/// protects the *account* (the registration record); it does not, today, protect
/// the *funds*.  Accounts should therefore be treated like any single-key chain
/// address, and the phrase should be backed up accordingly.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryIntent {
    /// Chain the intent is for.
    pub chain_id: u32,
    /// The account whose recovery key signed it.
    pub account: Address,
    /// What is being asked for.
    pub act: String,
    /// A service-supplied nonce, so an intent cannot be replayed.
    pub nonce: String,
    /// Protocol-time instant after which the intent is void.
    pub expires_at: u64,
}

impl RecoveryIntent {
    /// The exact bytes the recovery key signs.
    pub fn signing_preimage(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64 + self.act.len() + self.nonce.len());
        out.extend_from_slice(b"OBSIDIAN/RECOVERY-INTENT/v1");
        out.extend_from_slice(&self.chain_id.to_le_bytes());
        out.extend_from_slice(&self.account.encoded());
        out.extend_from_slice(&self.act.len().to_le_bytes());
        out.extend_from_slice(self.act.as_bytes());
        out.extend_from_slice(self.nonce.as_bytes());
        out.extend_from_slice(&self.expires_at.to_le_bytes());
        out
    }
}

/// Signs a recovery intent with the wallet's recovery key.
pub fn recovery_intent(wallet: &Wallet, intent: &RecoveryIntent) -> [u8; 64] {
    wallet
        .recovery_keypair()
        .sign(&intent.signing_preimage())
}

/// Verifies a recovery intent against an account's recovery key.
///
/// A caller that has the *public* recovery key — a registration service that was
/// told it at enrolment — can verify the intent without holding any secret.
pub fn verify_recovery_intent(
    recovery_key: &[u8; 32],
    intent: &RecoveryIntent,
    signature: &[u8; 64],
) -> bool {
    if intent.chain_id == 0 {
        return false;
    }
    obs_crypto::ed25519::verify(recovery_key, &intent.signing_preimage(), signature)
}

/// A fully described signing request, for a signing service or a hardware
/// signer.
///
/// The request carries the transaction's canonical bytes and the exact pre-image,
/// so a signer does not have to trust (or even understand) the transaction
/// builder: it signs the bytes it is shown, and the network checks the rest.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Request {
    /// Chain the signature is for.
    pub chain_id: u32,
    /// The transaction, in its canonical form.
    pub transaction: Vec<u8>,
    /// The exact bytes that must be signed.
    pub preimage: Vec<u8>,
}

impl Request {
    /// Builds a request from an unsigned transaction.
    ///
    /// The transaction is encoded canonically and its pre-image computed by
    /// `obs-chain`, so the signer and the network agree on every byte.
    pub fn of(tx: &Transaction) -> Request {
        Request {
            chain_id: tx.chain_id,
            transaction: tx.to_bytes(),
            preimage: tx.signing_preimage(),
        }
    }

    /// Applies a signature produced elsewhere, returning the signed transaction.
    ///
    /// The result is *not* trusted because it was requested: the caller (a node,
    /// or the network) verifies it like any other transaction.
    pub fn attach(&self, signature: [u8; 64]) -> Result<Transaction, WalletError> {
        let mut tx = Transaction::from_bytes(&self.transaction)
            .map_err(|error| WalletError::BadKeystore(format!("unreadable transaction: {}", error)))?;
        tx.signature = signature;
        Ok(tx)
    }

    /// Signs the request with a wallet and returns the signed transaction.
    pub fn sign_with(&self, wallet: &Wallet) -> Result<Transaction, WalletError> {
        if self.chain_id != wallet.network().chain_id {
            return Err(WalletError::Unsupported(
                "this request is for a different network".to_string(),
            ));
        }
        self.attach(wallet.sign_preimage(&self.preimage))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::{MAINNET, TESTNET};

    fn wallet() -> Wallet {
        Wallet::from_phrase(
            MAINNET,
            "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title",
            "",
            0,
        )
        .unwrap()
    }

    #[test]
    fn a_claim_carries_the_protocol_time_it_was_built_for() {
        let wallet = wallet();
        let tx = claim(&wallet, 1_800_000_000, 3, 7).unwrap();
        assert_eq!(tx.chain_id, MAINNET.chain_id);
        assert_eq!(tx.nonce, 7);
        assert!(tx.verify_signature());
        match tx.kind {
            TxKind::Claim(claim) => {
                assert_eq!(claim.claimed_at, 1_800_000_000);
                assert_eq!(claim.sequence, 3);
                assert_eq!(claim.account, wallet.address());
            }
            other => panic!("expected a claim, got {:?}", other),
        }
        assert!(claim(&wallet, 1_800_000_000, 0, 7).is_err(), "sequences start at 1");
    }

    #[test]
    fn a_transfer_refuses_the_mistakes_that_waste_a_nonce() {
        let wallet = wallet();
        let other = Wallet::from_phrase(
            MAINNET,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            0,
        )
        .unwrap();
        assert!(transfer(&wallet, other.address(), Amount::from_obs(1), 1).is_ok());
        // Self-transfer, zero value and a foreign-network address are refused
        // before signing, not after paying a fee.
        assert!(transfer(&wallet, wallet.address(), Amount::from_obs(1), 1).is_err());
        assert!(transfer(&wallet, other.address(), Amount::ZERO, 1).is_err());
        let testnet = Wallet::from_phrase(TESTNET, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0).unwrap();
        assert!(transfer(&wallet, testnet.address(), Amount::from_obs(1), 1).is_err());
    }

    #[test]
    fn a_signing_request_round_trips_without_trusting_the_signer() {
        let wallet = wallet();
        let unsigned = claim(&wallet, 1_800_000_000, 1, 1).unwrap();
        let request = Request::of(&unsigned);
        assert_eq!(request.chain_id, MAINNET.chain_id);
        assert!(!request.preimage.is_empty());

        // A signer that only sees the request produces the same signature the
        // wallet does, and the attached transaction verifies.
        let signature = [7u8; 64];
        let attached = request.attach(signature).unwrap();
        assert_eq!(attached.signature, signature);
        assert!(!attached.verify_signature(), "an arbitrary signature must not verify");

        let signed = request.sign_with(&wallet).unwrap();
        assert!(signed.verify_signature());
        assert_eq!(signed.id(), unsigned.id(), "the id does not depend on the signature");

        // A wallet on another network refuses the request outright.
        let testnet = Wallet::from_phrase(TESTNET, "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about", "", 0).unwrap();
        assert!(request.sign_with(&testnet).is_err());
    }

    #[test]
    fn an_account_proof_is_bound_to_the_chain_the_address_and_the_nonce() {
        let wallet = wallet();
        let first = account_proof(&wallet, "nonce-1");
        assert_eq!(first.len(), 64);
        let same = account_proof(&wallet, "nonce-1");
        assert_eq!(first, same);
        assert_ne!(first, account_proof(&wallet, "nonce-2"));
        // The pre-image names the chain, so the same wallet on another network
        // produces a different signature over a different pre-image.
        let testnet = Wallet::from_phrase(TESTNET, "legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth useful legal winner thank year wave sausage worth title", "", 0).unwrap();
        assert_ne!(first, account_proof(&testnet, "nonce-1"));
    }

    #[test]
    fn a_recovery_intent_is_signed_by_the_recovery_key_and_verifies_publicly() {
        let wallet = wallet();
        let intent = RecoveryIntent {
            chain_id: MAINNET.chain_id,
            account: wallet.address(),
            act: "reenrol_mfa".to_string(),
            nonce: "recovery-nonce-1".to_string(),
            expires_at: 1_800_003_600,
        };
        let signature = recovery_intent(&wallet, &intent);
        assert!(verify_recovery_intent(
            &wallet.public_keys().recovery_key,
            &intent,
            &signature
        ));
        // The wallet key and the node key cannot stand in for it.
        assert!(!obs_crypto::ed25519::verify(
            &wallet.public_keys().recovery_key,
            &intent.signing_preimage(),
            &wallet.sign_preimage(&intent.signing_preimage())
        ));
        // Neither can another account's recovery key, nor a replayed nonce.
        let other = Wallet::from_phrase(
            MAINNET,
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about",
            "",
            0,
        )
        .unwrap();
        assert!(!verify_recovery_intent(
            &other.public_keys().recovery_key,
            &intent,
            &signature
        ));
        let replayed = RecoveryIntent {
            nonce: "recovery-nonce-2".to_string(),
            ..intent.clone()
        };
        assert!(!verify_recovery_intent(
            &wallet.public_keys().recovery_key,
            &replayed,
            &signature
        ));
        assert!(!recovery_intent(&wallet, &intent).is_empty());
    }

    #[test]
    fn a_validator_uses_its_node_key_and_never_its_wallet_key() {
        let wallet = wallet();
        let tx = register_validator(&wallet, "node.example:9200", 1).unwrap();
        match tx.kind {
            TxKind::RegisterValidator { node_key, .. } => {
                assert_eq!(node_key, wallet.public_keys().node_key);
                assert_ne!(node_key, wallet.public_keys().wallet_key);
            }
            other => panic!("expected a validator registration, got {:?}", other),
        }
        assert!(register_validator(&wallet, &"x".repeat(200), 1).is_err());

        let attestation = attest(&wallet, 10, Hash32::from_bytes([3u8; 32]), 4).unwrap();
        assert!(attestation.verify_signature(MAINNET.chain_id));
        assert_eq!(attestation.node_key, wallet.public_keys().node_key);
    }
}
