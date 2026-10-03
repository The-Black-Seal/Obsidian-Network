//! Core chain types: accounts, claims, invitations and validator records.

use obs_primitives::address::Address;
use obs_primitives::codec::{Decode, Decoder, Encode};
use obs_primitives::hash::Hash32;
use obs_primitives::money::Amount;

/// Identifier of a transaction or claim: the domain-separated hash of its
/// canonical encoding.
///
/// Identifiers are never wallet addresses and never nonces.  Two objects with
/// the same id are the same object; a node that already holds an id rejects a
/// second object with that id.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct TxId(pub Hash32);

impl TxId {
    /// The raw hash.
    pub fn hash(&self) -> Hash32 {
        self.0
    }
}

impl core::fmt::Display for TxId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{}", self.0.to_hex())
    }
}

impl Encode for TxId {
    fn encode(&self, out: &mut Vec<u8>) {
        self.0.encode(out);
    }
}

impl Decode for TxId {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(TxId(Hash32::decode(decoder)?))
    }
}

/// A mining claim: proof that the account asked for, and was granted, the
/// schedule slot that protocol time assigned to it.
///
/// The claim is *not* a proof of work: there is no puzzle, no nonce search and
/// no hash target.  Its only inputs are the account's identity, the protocol
/// timestamp at which the claim is made and the account's previous claim
/// (sequence).  The block that includes the claim records the protocol time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Claim {
    /// Account receiving the reward (the wallet that signed the claim).
    pub account: Address,
    /// Protocol timestamp of the claim, in seconds since the Unix epoch.
    ///
    /// For a claim included in block `h`, this must equal the block timestamp:
    /// protocol time, not wall-clock time, decides eligibility.
    pub claimed_at: u64,
    /// Sequence number of this claim for the account, starting at 1.
    pub sequence: u64,
}

impl Claim {
    /// Is this the account's first claim?
    pub fn is_first(&self) -> bool {
        self.sequence == 1
    }
}

impl Encode for Claim {
    fn encode(&self, out: &mut Vec<u8>) {
        self.account.encode(out);
        self.claimed_at.encode(out);
        self.sequence.encode(out);
    }
}

impl Decode for Claim {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Claim {
            account: Address::decode(decoder)?,
            claimed_at: u64::decode(decoder)?,
            sequence: u64::decode(decoder)?,
        })
    }
}

/// The persistent account state produced by registration.
///
/// An account exists only after a registration transaction that was itself
/// signed by the account's own key, which by construction proves possession of
/// the private key.  Balances start at exactly zero: registration can never
/// create value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Account {
    /// Wallet address of the account (derived from the wallet public key).
    pub address: Address,
    /// Wallet public key used to sign claims and transactions.
    pub wallet_key: [u8; 32],
    /// Optional second key used only for mining-account recovery rotations.
    pub recovery_key: Option<[u8; 32]>,
    /// Canonical (normalised) Gmail identity this account is bound to.  It is
    /// stored as a hash, never in plaintext.
    pub gmail_commitment: Hash32,
    /// Spendable balance, in grains.  Only the state machine ever changes it,
    /// and no API exposes it publicly (see the Explorer privacy contract).
    pub balance: Amount,
    /// Nonce of the most recently applied transaction, zero before the first.
    pub last_nonce: u64,
    /// Sequence number of the account's most recent accepted claim, zero
    /// before the first claim.
    pub last_claim_sequence: u64,
    /// Protocol timestamp of the most recent accepted claim.
    pub last_claim_at: u64,
    /// Number of claims accepted in the current protocol day window.
    pub claims_today: u64,
    /// Start of the protocol-day window the counter refers to.
    pub claim_window_start: u64,
    /// Total value ever credited to this account from mining or genesis.
    pub lifetime_rewards: Amount,
    /// Number of invitations this account has issued (maximum five).
    pub invites_issued: u32,
    /// Registration timestamp (protocol time).
    pub registered_at: u64,
    /// True once this account has been credited with the genesis allocation.
    pub genesis_claimed: bool,
}

impl Default for Account {
    fn default() -> Self {
        Account {
            address: Address::from_parts(
                obs_primitives::network::MAINNET,
                1,
                [0u8; obs_primitives::address::ADDRESS_PAYLOAD_LEN],
            ),
            wallet_key: [0u8; 32],
            recovery_key: None,
            gmail_commitment: Hash32::ZERO,
            balance: Amount::ZERO,
            last_nonce: 0,
            last_claim_sequence: 0,
            last_claim_at: 0,
            claims_today: 0,
            claim_window_start: 0,
            lifetime_rewards: Amount::ZERO,
            invites_issued: 0,
            registered_at: 0,
            genesis_claimed: false,
        }
    }
}

impl Encode for Account {
    fn encode(&self, out: &mut Vec<u8>) {
        self.address.encode(out);
        out.extend_from_slice(&self.wallet_key);
        self.recovery_key.encode(out);
        self.gmail_commitment.encode(out);
        self.balance.encode(out);
        self.last_nonce.encode(out);
        self.last_claim_sequence.encode(out);
        self.last_claim_at.encode(out);
        self.claims_today.encode(out);
        self.claim_window_start.encode(out);
        self.lifetime_rewards.encode(out);
        self.invites_issued.encode(out);
        self.registered_at.encode(out);
        self.genesis_claimed.encode(out);
    }
}

impl Decode for Account {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Account {
            address: Address::decode(decoder)?,
            wallet_key: <[u8; 32]>::decode(decoder)?,
            recovery_key: Option::<[u8; 32]>::decode(decoder)?,
            gmail_commitment: Hash32::decode(decoder)?,
            balance: Amount::decode(decoder)?,
            last_nonce: u64::decode(decoder)?,
            last_claim_sequence: u64::decode(decoder)?,
            last_claim_at: u64::decode(decoder)?,
            claims_today: u64::decode(decoder)?,
            claim_window_start: u64::decode(decoder)?,
            lifetime_rewards: Amount::decode(decoder)?,
            invites_issued: u32::decode(decoder)?,
            registered_at: u64::decode(decoder)?,
            genesis_claimed: bool::decode(decoder)?,
        })
    }
}

/// An invitation redemption record.
///
/// Invitations are single-use.  The state stores the *commitment* (a salted
/// hash) of the invitation code, the account that redeemed it and the protocol
/// timestamp of redemption.  The plaintext code is never written to chain
/// state, never logged and never returned by any API.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteRecord {
    /// Commitment to the invitation code.
    pub commitment: Hash32,
    /// Account that redeemed the invitation.
    pub redeemed_by: Address,
    /// Protocol time of redemption.
    pub redeemed_at: u64,
    /// Ordinal of the invitation inside the issuing account's budget.
    pub ordinal: u32,
}

impl Encode for InviteRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        self.commitment.encode(out);
        self.redeemed_by.encode(out);
        self.redeemed_at.encode(out);
        self.ordinal.encode(out);
    }
}

impl Decode for InviteRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(InviteRecord {
            commitment: Hash32::decode(decoder)?,
            redeemed_by: Address::decode(decoder)?,
            redeemed_at: u64::decode(decoder)?,
            ordinal: u32::decode(decoder)?,
        })
    }
}

/// Reason a validator left the set.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    /// The operator deregistered voluntarily.
    Deregistered,
    /// The session key was found signing conflicting attestations.
    Equivocation,
    /// The operator's bond fell below the minimum (never happens today; kept
    /// so that the state format is forward compatible).
    BondBelowMinimum,
}

impl ExitReason {
    fn code(self) -> u8 {
        match self {
            ExitReason::Deregistered => 1,
            ExitReason::Equivocation => 2,
            ExitReason::BondBelowMinimum => 3,
        }
    }

    fn from_code(code: u8) -> Option<ExitReason> {
        match code {
            1 => Some(ExitReason::Deregistered),
            2 => Some(ExitReason::Equivocation),
            3 => Some(ExitReason::BondBelowMinimum),
            _ => None,
        }
    }
}

/// A validator record.
///
/// The **node identity key** is deliberately distinct from the wallet key: a
/// validator session key signs attestations and proposals, while the wallet key
/// owns the bond and can rotate or withdraw it.  Compromise of one does not
/// compromise the other.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ValidatorRecord {
    /// Wallet address that owns the bond and the reward share.
    pub owner: Address,
    /// Wallet key of the owner at registration time.
    pub owner_key: [u8; 32],
    /// Node identity public key (never the wallet key).
    pub node_key: [u8; 32],
    /// Bond currently locked (always [`obs_primitives::money::VALIDATOR_BOND`]
    /// while registered).
    pub bond: Amount,
    /// Protocol time of registration.
    pub registered_at: u64,
    /// Height at which the validator registered.
    pub registered_at_height: u64,
    /// Cumulative weight contributed by this validator (self-reported fields
    /// are never used; this is derived from accepted attestations).
    pub attested_weight: u128,
    /// Protocol timestamp of the most recent accepted attestation.
    pub last_attestation_at: u64,
    /// Height of the most recent block attested by this validator.
    pub last_attested_height: u64,
    /// Number of attestations accepted since registration.
    pub attestation_count: u64,
    /// Number of scheduled slots this validator failed to attest.
    pub missed_slots: u64,
    /// Number of proposals this validator produced that were accepted.
    pub blocks_proposed: u64,
    /// True while the validator is in the active set.
    pub active: bool,
    /// Protocol time at which the bond becomes spendable after deregistration.
    pub unbonding_ends_at: u64,
    /// Why the validator left the set, if it did.
    pub exit_reason: Option<ExitReason>,
}

impl ValidatorRecord {
    /// Returns true when the record is a live member of the validator set.
    pub fn is_active(&self) -> bool {
        self.active
    }
}

impl Encode for ValidatorRecord {
    fn encode(&self, out: &mut Vec<u8>) {
        self.owner.encode(out);
        out.extend_from_slice(&self.owner_key);
        out.extend_from_slice(&self.node_key);
        self.bond.encode(out);
        self.registered_at.encode(out);
        self.registered_at_height.encode(out);
        self.attested_weight.encode(out);
        self.last_attestation_at.encode(out);
        self.last_attested_height.encode(out);
        self.attestation_count.encode(out);
        self.missed_slots.encode(out);
        self.blocks_proposed.encode(out);
        self.active.encode(out);
        self.unbonding_ends_at.encode(out);
        match self.exit_reason {
            None => out.push(0),
            Some(reason) => {
                out.push(1);
                out.push(reason.code());
            }
        }
    }
}

impl Decode for ValidatorRecord {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        let owner = Address::decode(decoder)?;
        let owner_key = <[u8; 32]>::decode(decoder)?;
        let node_key = <[u8; 32]>::decode(decoder)?;
        let bond = Amount::decode(decoder)?;
        let registered_at = u64::decode(decoder)?;
        let registered_at_height = u64::decode(decoder)?;
        let attested_weight = u128::decode(decoder)?;
        let last_attestation_at = u64::decode(decoder)?;
        let last_attested_height = u64::decode(decoder)?;
        let attestation_count = u64::decode(decoder)?;
        let missed_slots = u64::decode(decoder)?;
        let blocks_proposed = u64::decode(decoder)?;
        let active = bool::decode(decoder)?;
        let unbonding_ends_at = u64::decode(decoder)?;
        let exit_reason = match decoder.read_u8()? {
            0 => None,
            1 => Some(
                ExitReason::from_code(decoder.read_u8()?)
                    .ok_or(obs_primitives::codec::CodecError::InvalidValue("exit reason"))?,
            ),
            _ => return Err(obs_primitives::codec::CodecError::InvalidValue("exit reason tag")),
        };
        Ok(ValidatorRecord {
            owner,
            owner_key,
            node_key,
            bond,
            registered_at,
            registered_at_height,
            attested_weight,
            last_attestation_at,
            last_attested_height,
            attestation_count,
            missed_slots,
            blocks_proposed,
            active,
            unbonding_ends_at,
            exit_reason,
        })
    }
}

/// A single-use authorisation to create exactly one account.
///
/// The **invitation code itself never touches the chain, the node, source
/// control or a log.**  The registration server (which holds the invitation
/// codes) holds an Ed25519 *registration authority* key whose public key is
/// fixed in the network's genesis configuration.  To let a person register, the
/// server signs this authorisation; the chain verifies the signature and
/// enforces single use, expiry and (when an issuer is named) the five-invite
/// budget.
///
/// The authority key can do exactly one thing: authorise the creation of an
/// otherwise empty account.  It cannot move value, change a balance, alter
/// timing, fees, rewards, supply or validator scheduling — there is no code
/// path that would let it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InviteAuthorization {
    /// Commitment to the invitation code: `tagged_hash("OBSIDIAN/INVITE/v1",
    /// chain_id || code)`.  Only the commitment reaches the chain.
    pub commitment: Hash32,
    /// Commitment to the **canonical Gmail identity** the invitation was issued
    /// for.  The registration server canonicalises the address it verified
    /// (lower-case, dots removed from the local part, `+tags` removed,
    /// `googlemail.com` mapped to `gmail.com`) and commits to the result; the
    /// chain then requires the registration to use exactly that commitment, so
    /// an invitation cannot be spent on a different identity and one Gmail
    /// identity can never hold two accounts.
    pub gmail_commitment: Hash32,
    /// Protocol time at which the authorisation was issued.
    pub issued_at: u64,
    /// Protocol time after which the authorisation is no longer valid.
    pub expires_at: u64,
    /// Account whose invitation budget this authorisation consumes, when the
    /// invitation was issued by an existing account (the genesis invitation has
    /// no issuer and is accounted for by the network itself).
    pub issuer: Option<Address>,
    /// Public key of the registration authority that signed this authorisation.
    pub authority_key: [u8; 32],
    /// Ed25519 signature over [`InviteAuthorization::signing_preimage`].
    pub signature: [u8; 64],
}

impl InviteAuthorization {
    /// The exact bytes the registration authority signs.
    pub fn signing_preimage(&self, chain_id: u32) -> Vec<u8> {
        let issuer = self
            .issuer
            .map(|address| address.encoded())
            .unwrap_or_default();
        obs_primitives::hash::tagged_preimage(
            crate::params::tags::INVITE_SIGN,
            &[
                &chain_id.to_le_bytes(),
                &self.commitment.0,
                &self.gmail_commitment.0,
                &self.issued_at.to_le_bytes(),
                &self.expires_at.to_le_bytes(),
                &issuer,
            ],
        )
    }

    /// Verifies the authority signature (structure and cryptography only; the
    /// state machine additionally checks expiry, single use and the issuer's
    /// budget).
    pub fn verify_signature(&self, chain_id: u32) -> bool {
        obs_crypto::ed25519::verify(
            &self.authority_key,
            &self.signing_preimage(chain_id),
            &self.signature,
        )
    }

    /// Signs an authorisation with the authority keypair.
    #[allow(clippy::too_many_arguments)]
    pub fn issue(
        chain_id: u32,
        authority_keypair: &obs_crypto::ed25519::Keypair,
        commitment: Hash32,
        gmail_commitment: Hash32,
        issued_at: u64,
        expires_at: u64,
        issuer: Option<Address>,
    ) -> InviteAuthorization {
        let mut authorization = InviteAuthorization {
            commitment,
            gmail_commitment,
            issued_at,
            expires_at,
            issuer,
            authority_key: authority_keypair.public_key(),
            signature: [0u8; 64],
        };
        let preimage = authorization.signing_preimage(chain_id);
        authorization.signature = authority_keypair.sign(&preimage);
        authorization
    }
}

impl Encode for InviteAuthorization {
    fn encode(&self, out: &mut Vec<u8>) {
        self.commitment.encode(out);
        self.gmail_commitment.encode(out);
        self.issued_at.encode(out);
        self.expires_at.encode(out);
        self.issuer.encode(out);
        out.extend_from_slice(&self.authority_key);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for InviteAuthorization {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(InviteAuthorization {
            commitment: Hash32::decode(decoder)?,
            gmail_commitment: Hash32::decode(decoder)?,
            issued_at: u64::decode(decoder)?,
            expires_at: u64::decode(decoder)?,
            issuer: Option::<Address>::decode(decoder)?,
            authority_key: <[u8; 32]>::decode(decoder)?,
            signature: <[u8; 64]>::decode(decoder)?,
        })
    }
}

/// Commitment of an invitation code.
///
/// The code is never stored or transmitted by the protocol; only this
/// commitment is.  Invitation codes generated by the network carry at least 128
/// bits of entropy, so publishing commitments does not reveal codes.
pub fn invite_commitment(chain_id: u32, code: &str) -> Hash32 {
    Hash32::tagged(
        crate::params::tags::INVITE,
        &[&chain_id.to_le_bytes(), code.as_bytes()],
    )
}

/// Commitment of a canonical Gmail identity.
///
/// Canonicalisation (lower-casing, removing dots from the local part, removing
/// `+tags`, mapping `googlemail.com` to `gmail.com`) happens before this call,
/// in the registration layer.  The chain stores only the commitment, which is
/// what makes "one Gmail address, one account" enforceable in consensus without
/// the chain ever learning an email address.
pub fn gmail_commitment(chain_id: u32, canonical_gmail: &str) -> Hash32 {
    Hash32::tagged(
        crate::params::tags::GMAIL,
        &[&chain_id.to_le_bytes(), canonical_gmail.as_bytes()],
    )
}

/// Kind of a transaction body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TxKind {
    /// Register a new account.  Signed by the new account's wallet key, and
    /// additionally authorised by the registration authority's invitation
    /// authorisation.
    Register {
        /// The account being created.
        account: Address,
        /// Key that will sign the account's future transactions.
        wallet_key: [u8; 32],
        /// Commitment to the canonical Gmail identity.
        gmail_commitment: Hash32,
        /// Single-use invitation authorisation.
        invite: InviteAuthorization,
    },
    /// A mining claim.
    Claim(Claim),
    /// A plain transfer of value between accounts.
    Transfer {
        /// Recipient.
        to: Address,
        /// Amount, in grains.
        amount: Amount,
    },
    /// Register a validator and lock the 50 OBS bond.
    RegisterValidator {
        /// Node identity public key (distinct from the wallet key).
        node_key: [u8; 32],
        /// Human-readable endpoint, for operators and the portal only.
        endpoint: String,
    },
    /// Deregister a validator; the bond is returned after 48 hours.
    DeregisterValidator,
}

impl TxKind {
    /// Numeric tag used in the canonical encoding.
    pub fn tag(&self) -> u8 {
        match self {
            TxKind::Register { .. } => 0,
            TxKind::Claim(_) => 1,
            TxKind::Transfer { .. } => 2,
            TxKind::RegisterValidator { .. } => 3,
            TxKind::DeregisterValidator => 4,
        }
    }

    /// Human-readable name used by APIs and the explorer.
    pub fn name(&self) -> &'static str {
        match self {
            TxKind::Register { .. } => "register",
            TxKind::Claim(_) => "claim",
            TxKind::Transfer { .. } => "transfer",
            TxKind::RegisterValidator { .. } => "validator_register",
            TxKind::DeregisterValidator => "validator_deregister",
        }
    }
}

impl Encode for TxKind {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.tag());
        match self {
            TxKind::Register {
                account,
                wallet_key,
                gmail_commitment,
                invite,
            } => {
                account.encode(out);
                out.extend_from_slice(wallet_key);
                gmail_commitment.encode(out);
                invite.encode(out);
            }
            TxKind::Claim(claim) => claim.encode(out),
            TxKind::Transfer { to, amount } => {
                to.encode(out);
                amount.encode(out);
            }
            TxKind::RegisterValidator { node_key, endpoint } => {
                out.extend_from_slice(node_key);
                endpoint.encode(out);
            }
            TxKind::DeregisterValidator => {}
        }
    }
}

impl Decode for TxKind {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        match decoder.read_u8()? {
            0 => Ok(TxKind::Register {
                account: Address::decode(decoder)?,
                wallet_key: <[u8; 32]>::decode(decoder)?,
                gmail_commitment: Hash32::decode(decoder)?,
                invite: InviteAuthorization::decode(decoder)?,
            }),
            1 => Ok(TxKind::Claim(Claim::decode(decoder)?)),
            2 => Ok(TxKind::Transfer {
                to: Address::decode(decoder)?,
                amount: Amount::decode(decoder)?,
            }),
            3 => Ok(TxKind::RegisterValidator {
                node_key: <[u8; 32]>::decode(decoder)?,
                endpoint: String::decode(decoder)?,
            }),
            4 => Ok(TxKind::DeregisterValidator),
            tag => Err(obs_primitives::codec::CodecError::InvalidValue(match tag {
                5..=255 => "transaction tag",
                _ => "transaction tag",
            })),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::codec::{decode_exact, Encode};
    use obs_primitives::network::MAINNET;

    fn sample_claim() -> Claim {
        Claim {
            account: Address::from_parts(MAINNET, 1, [7u8; 20]),
            claimed_at: 1_800_000_000,
            sequence: 3,
        }
    }

    #[test]
    fn claim_roundtrip() {
        let claim = sample_claim();
        let encoded = claim.encoded();
        let decoded: Claim = decode_exact(&encoded).unwrap();
        assert_eq!(claim, decoded);
    }

    #[test]
    fn tx_kinds_roundtrip() {
        let kinds = vec![
            TxKind::Register {
                account: Address::from_parts(MAINNET, 1, [1u8; 20]),
                wallet_key: [2u8; 32],
                gmail_commitment: Hash32::from_bytes([3u8; 32]),
                invite: InviteAuthorization::issue(
                    MAINNET.chain_id,
                    &obs_crypto::ed25519::Keypair::from_seed(&[9u8; 32]),
                    Hash32::from_bytes([4u8; 32]),
                    Hash32::from_bytes([3u8; 32]),
                    1_700_000_000,
                    1_700_003_600,
                    None,
                ),
            },
            TxKind::Claim(sample_claim()),
            TxKind::Transfer {
                to: Address::from_parts(MAINNET, 1, [5u8; 20]),
                amount: Amount::from_obs(12),
            },
            TxKind::RegisterValidator {
                node_key: [6u8; 32],
                endpoint: "obs-node.example:9200".to_string(),
            },
            TxKind::DeregisterValidator,
        ];
        for kind in kinds {
            let encoded = kind.encoded();
            let decoded: TxKind = decode_exact(&encoded).unwrap();
            assert_eq!(kind, decoded);
        }
    }

    #[test]
    fn validator_records_roundtrip() {
        let record = ValidatorRecord {
            owner: Address::from_parts(MAINNET, 1, [9u8; 20]),
            owner_key: [1u8; 32],
            node_key: [2u8; 32],
            bond: obs_primitives::money::VALIDATOR_BOND,
            registered_at: 1_800_000_000,
            registered_at_height: 12,
            attested_weight: 123_456_789,
            last_attestation_at: 1_800_000_030,
            last_attested_height: 42,
            attestation_count: 17,
            missed_slots: 1,
            blocks_proposed: 4,
            active: true,
            unbonding_ends_at: 0,
            exit_reason: Some(ExitReason::Deregistered),
        };
        let encoded = record.encoded();
        let decoded: ValidatorRecord = decode_exact(&encoded).unwrap();
        assert_eq!(record, decoded);
    }
}
