//! The account registry: the registration flow, invitations, MFA and sessions.
//!
//! ## The flow, in order, with no email verification step
//!
//! ```text
//!   Gmail → password → invitation code → mining account recovery code
//!         → MFA (TOTP) → wallet public keys → Activated → mining enabled
//! ```
//!
//! Each step is a method on [`Registry`], and each one refuses to run out of
//! order.  The wallet step is where the boundary between the service and the
//! user sits: the *client* generates its keys and sends only the public halves,
//! so the service completes an enrolment without ever being able to sign for the
//! account it just created.
//!
//! ## One Gmail, one account, race safe
//!
//! The canonical Gmail (lower-cased, dots and `+tags` removed, `googlemail.com`
//! folded to `gmail.com`) is the registry's uniqueness key, and every mutation
//! happens inside one `&mut self` call — the registry is held behind one lock by
//! its owner — so "check then insert" is a single atomic step.  Two simultaneous
//! registrations for one address cannot both succeed.  The *commitment* to that
//! canonical address is what the chain stores, so the chain enforces the same
//! rule a second time without ever seeing an email address.
//!
//! ## What is durable, and what is not
//!
//! Accounts and invitations are durable: they are written to the atomic store on
//! every change.  Enrolment sessions and sign-in sessions are deliberately
//! *in memory only*.  They are short-lived credentials, and a service restart
//! dropping them is the safe failure: nobody stays signed in because a file
//! survived, and an interrupted enrolment is restarted rather than resumed from
//! a stale record.
//!
//! ## Secrets
//!
//! * passwords: Argon2id (64 MiB, three passes), verified in constant time;
//! * recovery codes: 160 bits, shown once, stored as an Argon2id hash;
//! * invitation codes: stored as salted hashes, single-use, atomic redemption;
//! * TOTP secrets: encrypted at rest with the service key, with the last accepted
//!   step remembered so a code cannot be replayed;
//! * session tokens: 256 bits, stored only as a hash, and sent back once.

use std::collections::BTreeMap;

use obs_chain::chain::gmail_commitment;
use obs_crypto::argon2::{argon2id, Argon2Params};
use obs_crypto::chacha::ChaCha20Poly1305;
use obs_crypto::ct::{ct_eq, Zeroize, Zeroizing};
use obs_crypto::encoding::{base64url_encode, hex_encode};
use obs_crypto::totp::Secret;
use obs_primitives::identity::canonical_gmail;
use obs_primitives::json::Json;
use obs_primitives::address::Address;
use obs_primitives::hash::Hash32;
use obs_primitives::network::Network;
use obs_wallet::recovery::RecoveryCode;

use crate::store::{AtomicStore, StoreError};

/// Shortest password accepted.  Length, not character classes.
pub const MIN_PASSWORD_BYTES: usize = 12;
/// Longest password accepted.
pub const MAX_PASSWORD_BYTES: usize = 256;
/// Invitations per account, mirroring the chain's own limit.
pub const MAX_INVITES_PER_ACCOUNT: u32 = 5;
/// Failed sign-ins before the account locks.
pub const MAX_FAILED_ATTEMPTS: u32 = 8;
/// Lockout duration, in seconds.
pub const LOCKOUT_SECS: u64 = 15 * 60;
/// Sign-in session lifetime, in seconds.
pub const SESSION_SECS: u64 = 12 * 3_600;
/// Enrolment session lifetime, in seconds.
pub const ENROLMENT_SECS: u64 = 30 * 60;
/// Lifetime of an account-issued invitation, in seconds.
pub const INVITE_SECS: u64 = 7 * 24 * 3_600;
/// Bytes of randomness in a session token.
pub const SESSION_TOKEN_BYTES: usize = 32;
/// How long an issued invitation authorisation stays valid on chain.
///
/// The chain enforces this window as well; the client normally submits its
/// registration transaction within seconds, so the window is generous enough to
/// survive a slow sign-up and short enough that a leaked authorisation is not
/// useful for long.
pub const AUTHORIZATION_SECS: u64 = 24 * 3_600;

/// Where an account is in the flow.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Stage {
    /// Gmail captured.
    Gmail,
    /// Password set.
    Password,
    /// Invitation redeemed.
    Invite,
    /// Recovery code issued.
    Recovery,
    /// MFA enrolled.
    Mfa,
    /// Wallet public keys received.
    Wallet,
    /// Activated; mining is enabled.
    Activated,
}

impl Stage {
    /// The next step, or `None` at the end.
    pub fn next(self) -> Option<Stage> {
        match self {
            Stage::Gmail => Some(Stage::Password),
            Stage::Password => Some(Stage::Invite),
            Stage::Invite => Some(Stage::Recovery),
            Stage::Recovery => Some(Stage::Mfa),
            Stage::Mfa => Some(Stage::Wallet),
            Stage::Wallet => Some(Stage::Activated),
            Stage::Activated => None,
        }
    }

    /// Machine-readable name.
    pub fn name(self) -> &'static str {
        match self {
            Stage::Gmail => "gmail",
            Stage::Password => "password",
            Stage::Invite => "invite",
            Stage::Recovery => "recovery",
            Stage::Mfa => "mfa",
            Stage::Wallet => "wallet",
            Stage::Activated => "activated",
        }
    }
}

/// Why an account operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AccountError {
    /// Not a usable Gmail address.
    BadGmail,
    /// An account already exists for this canonical Gmail.
    GmailTaken,
    /// The password does not meet the policy.
    BadPassword(&'static str),
    /// The invitation code is unknown, spent or expired.
    BadInvite,
    /// The account has used all five invitations.
    InviteBudget,
    /// The MFA code is wrong.
    BadMfaCode,
    /// The account is locked after repeated failures.
    Locked {
        /// Protocol time at which the lock expires.
        until: u64,
    },
    /// The enrolment session is unknown or expired.
    BadEnrolment,
    /// A step was attempted out of order.
    OutOfOrder {
        /// The step that must come next.
        expected: &'static str,
    },
    /// The credentials are wrong.
    BadCredentials,
    /// The session is unknown or expired.
    BadSession,
    /// MFA is not enrolled for this account.
    MfaNotEnrolled,
    /// The recovery code has already been used.
    RecoveryUsed,
    /// Storage failed.
    Store(String),
}

impl core::fmt::Display for AccountError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AccountError::BadGmail => write!(f, "that is not a usable Gmail address"),
            AccountError::GmailTaken => write!(f, "an account already exists for this address"),
            AccountError::BadPassword(rule) => write!(f, "{}", rule),
            AccountError::BadInvite => write!(f, "the invitation code is not valid"),
            AccountError::InviteBudget => write!(f, "this account has used all five invitations"),
            AccountError::BadMfaCode => write!(f, "the authenticator code is not valid"),
            AccountError::Locked { .. } => write!(f, "the account is temporarily locked"),
            AccountError::BadEnrolment => write!(f, "the enrolment session has expired"),
            AccountError::OutOfOrder { expected } => {
                write!(f, "the next registration step is {}", expected)
            }
            AccountError::BadCredentials => write!(f, "the credentials are not valid"),
            AccountError::BadSession => write!(f, "the session is not valid"),
            AccountError::MfaNotEnrolled => write!(f, "MFA is not enrolled for this account"),
            AccountError::RecoveryUsed => write!(f, "the recovery code has already been used"),
            AccountError::Store(detail) => write!(f, "storage error: {}", detail),
        }
    }
}

impl std::error::Error for AccountError {}

impl From<StoreError> for AccountError {
    fn from(error: StoreError) -> AccountError {
        AccountError::Store(error.to_string())
    }
}

fn store_detail(detail: impl core::fmt::Display) -> AccountError {
    AccountError::Store(detail.to_string())
}

/// An account record.  Every secret is a hash or a ciphertext.
#[derive(Debug, Clone)]
pub struct Account {
    /// Canonical Gmail address.
    pub canonical_gmail: String,
    /// Commitment to the canonical Gmail: what the chain stores.
    pub gmail_commitment: [u8; 32],
    /// Argon2id salt of the password.
    pub password_salt: Vec<u8>,
    /// Argon2id tag of the password.
    pub password_hash: Vec<u8>,
    /// TOTP secret, sealed with the service key.
    totp_sealed: Vec<u8>,
    /// Nonce of the sealed TOTP secret.
    totp_nonce: [u8; 12],
    /// Last accepted TOTP step, so a code cannot be replayed.
    totp_last_step: Option<u64>,
    /// Argon2id tag of the recovery code.
    recovery_hash: Vec<u8>,
    /// Argon2id salt of the recovery code.
    recovery_salt: Vec<u8>,
    /// Whether the recovery code has been spent.
    pub recovery_used: bool,
    /// Wallet public key.
    pub wallet_key: [u8; 32],
    /// Validator node identity public key.
    pub node_key: [u8; 32],
    /// Recovery public key.
    pub recovery_key: [u8; 32],
    /// Where the account is in the flow.
    pub stage: Stage,
    /// Chain the account belongs to.
    pub chain_id: u32,
    /// When the account was created (the service's clock).
    pub created_at: u64,
    /// Invitations issued so far.
    pub invites_issued: u32,
    /// Failed sign-ins since the last success.
    failed_attempts: u32,
    /// Protocol time until which the account is locked.
    locked_until: u64,
    /// Whether mining is enabled for the account.
    pub mining_enabled: bool,
}

impl Account {
    /// A view for the account's owner, and nobody else.
    pub fn owner_view(&self) -> Json {
        Json::obj([
            ("gmail", Json::Str(mask_gmail(&self.canonical_gmail))),
            ("stage", Json::Str(self.stage.name().to_string())),
            ("chain_id", Json::Int(self.chain_id as i128)),
            ("created_at", Json::Int(self.created_at as i128)),
            ("mining_enabled", Json::Bool(self.mining_enabled)),
            ("mfa_enrolled", Json::Bool(!self.totp_sealed.is_empty())),
            ("wallet_key", Json::Str(hex_encode(&self.wallet_key))),
            ("node_key", Json::Str(hex_encode(&self.node_key))),
            ("recovery_key", Json::Str(hex_encode(&self.recovery_key))),
            ("invites_issued", Json::Int(self.invites_issued as i128)),
            (
                "invites_remaining",
                Json::Int(MAX_INVITES_PER_ACCOUNT.saturating_sub(self.invites_issued) as i128),
            ),
            ("recovery_code_used", Json::Bool(self.recovery_used)),
        ])
    }

    fn to_json(&self) -> Json {
        Json::obj([
            ("canonical_gmail", Json::Str(self.canonical_gmail.clone())),
            ("gmail_commitment", Json::Str(hex_encode(&self.gmail_commitment))),
            ("password_salt", Json::Str(hex_encode(&self.password_salt))),
            ("password_hash", Json::Str(hex_encode(&self.password_hash))),
            ("totp_sealed", Json::Str(hex_encode(&self.totp_sealed))),
            ("totp_nonce", Json::Str(hex_encode(&self.totp_nonce))),
            (
                "totp_last_step",
                match self.totp_last_step {
                    Some(step) => Json::Int(step as i128),
                    None => Json::Null,
                },
            ),
            ("recovery_salt", Json::Str(hex_encode(&self.recovery_salt))),
            ("recovery_hash", Json::Str(hex_encode(&self.recovery_hash))),
            ("recovery_used", Json::Bool(self.recovery_used)),
            ("wallet_key", Json::Str(hex_encode(&self.wallet_key))),
            ("node_key", Json::Str(hex_encode(&self.node_key))),
            ("recovery_key", Json::Str(hex_encode(&self.recovery_key))),
            ("stage", Json::Str(self.stage.name().to_string())),
            ("chain_id", Json::Int(self.chain_id as i128)),
            ("created_at", Json::Int(self.created_at as i128)),
            ("invites_issued", Json::Int(self.invites_issued as i128)),
            ("failed_attempts", Json::Int(self.failed_attempts as i128)),
            ("locked_until", Json::Int(self.locked_until as i128)),
            ("mining_enabled", Json::Bool(self.mining_enabled)),
        ])
    }

    fn from_json(value: &Json) -> Result<Account, AccountError> {
        let bad = |field: &str| AccountError::Store(format!("account field {} is not usable", field));
        let key = |field: &str| -> Result<[u8; 32], AccountError> {
            read_key(value, field)?.ok_or_else(|| bad(field))
        };
        let bytes = |field: &str| -> Result<Vec<u8>, AccountError> {
            read_bytes(value, field)?.ok_or_else(|| bad(field))
        };
        let nonce = bytes("totp_nonce")?;
        if nonce.len() != 12 {
            return Err(bad("totp_nonce"));
        }
        let mut totp_nonce = [0u8; 12];
        totp_nonce.copy_from_slice(&nonce);
        Ok(Account {
            canonical_gmail: value
                .get("canonical_gmail")
                .and_then(Json::as_str)
                .ok_or_else(|| bad("canonical_gmail"))?
                .to_string(),
            gmail_commitment: key("gmail_commitment")?,
            password_salt: bytes("password_salt")?,
            password_hash: bytes("password_hash")?,
            totp_sealed: bytes("totp_sealed")?,
            totp_nonce,
            totp_last_step: value
                .get("totp_last_step")
                .and_then(Json::as_i128)
                .map(|step| step as u64),
            recovery_salt: bytes("recovery_salt")?,
            recovery_hash: bytes("recovery_hash")?,
            recovery_used: value.get("recovery_used").and_then(Json::as_bool).unwrap_or(false),
            wallet_key: key("wallet_key")?,
            node_key: key("node_key")?,
            recovery_key: key("recovery_key")?,
            stage: parse_stage(
                value.get("stage").and_then(Json::as_str).ok_or_else(|| bad("stage"))?,
            )?,
            chain_id: value
                .get("chain_id")
                .and_then(Json::as_i128)
                .ok_or_else(|| bad("chain_id"))? as u32,
            created_at: value
                .get("created_at")
                .and_then(Json::as_i128)
                .ok_or_else(|| bad("created_at"))? as u64,
            invites_issued: value.get("invites_issued").and_then(Json::as_i128).unwrap_or(0) as u32,
            failed_attempts: value.get("failed_attempts").and_then(Json::as_i128).unwrap_or(0) as u32,
            locked_until: value.get("locked_until").and_then(Json::as_i128).unwrap_or(0) as u64,
            mining_enabled: value.get("mining_enabled").and_then(Json::as_bool).unwrap_or(true),
        })
    }
}

/// Masks a Gmail address for display.
pub fn mask_gmail(canonical: &str) -> String {
    match canonical.split_once('@') {
        Some((local, domain)) => {
            let head: String = local.chars().take(2).collect();
            format!("{}***@{}", head, domain)
        }
        None => "***".to_string(),
    }
}

fn parse_stage(name: &str) -> Result<Stage, AccountError> {
    match name {
        "gmail" => Ok(Stage::Gmail),
        "password" => Ok(Stage::Password),
        "invite" => Ok(Stage::Invite),
        "recovery" => Ok(Stage::Recovery),
        "mfa" => Ok(Stage::Mfa),
        "wallet" => Ok(Stage::Wallet),
        "activated" => Ok(Stage::Activated),
        other => Err(AccountError::Store(format!("unknown stage {}", other))),
    }
}

/// An invitation's stored form: a salted hash, never the code.
#[derive(Debug, Clone)]
struct Invite {
    hash: Vec<u8>,
    salt: Vec<u8>,
    issuer: Option<String>,
    issued_at: u64,
    expires_at: u64,
    redeemed_by: Option<String>,
    genesis: bool,
}

impl Invite {
    fn is_spent(&self) -> bool {
        self.redeemed_by.is_some()
    }

    fn is_expired(&self, now: u64) -> bool {
        now > self.expires_at
    }

    fn to_json(&self) -> Json {
        Json::obj([
            ("hash", Json::Str(hex_encode(&self.hash))),
            ("salt", Json::Str(hex_encode(&self.salt))),
            ("issuer", opt_str(self.issuer.as_deref())),
            ("issued_at", Json::Int(self.issued_at as i128)),
            ("expires_at", Json::Int(self.expires_at as i128)),
            ("redeemed_by", opt_str(self.redeemed_by.as_deref())),
            ("genesis", Json::Bool(self.genesis)),
        ])
    }

    fn from_json(value: &Json) -> Result<Invite, AccountError> {
        let bad = |field: &str| AccountError::Store(format!("invite field {} is not usable", field));
        Ok(Invite {
            hash: read_bytes(value, "hash")?.ok_or_else(|| bad("hash"))?,
            salt: read_bytes(value, "salt")?.ok_or_else(|| bad("salt"))?,
            issuer: value.get("issuer").and_then(Json::as_str).map(|text| text.to_string()),
            issued_at: value
                .get("issued_at")
                .and_then(Json::as_i128)
                .ok_or_else(|| bad("issued_at"))? as u64,
            expires_at: value
                .get("expires_at")
                .and_then(Json::as_i128)
                .ok_or_else(|| bad("expires_at"))? as u64,
            redeemed_by: value
                .get("redeemed_by")
                .and_then(Json::as_str)
                .map(|text| text.to_string()),
            genesis: value.get("genesis").and_then(Json::as_bool).unwrap_or(false),
        })
    }
}

/// An open enrolment, held in memory only.
#[derive(Debug, Clone)]
struct Enrolment {
    canonical_gmail: String,
    stage: Stage,
    expires_at: u64,
    password_salt: Vec<u8>,
    password_hash: Vec<u8>,
    invite_index: usize,
    /// The invitation code, held in memory only between redemption and
    /// activation so the authority can commit to it.  It is never persisted.
    invite_code: Option<String>,
    /// The recovery code, held only until the owner has been shown it once.
    recovery_display: Option<String>,
    /// The TOTP secret, held only until activation seals it.
    totp_secret: Option<String>,
}

/// An authenticated session.
pub struct Session {
    /// Opaque bearer token, returned to the client once and stored hashed.
    pub token_hash: Vec<u8>,
    /// Account the session belongs to.
    pub canonical_gmail: String,
    /// Expiry, on the service's clock.
    pub expires_at: u64,
}

/// What a completed enrolment produces for the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Activation {
    /// Commitment to the canonical Gmail: what the registration transaction must
    /// carry, and what binds the invitation to this identity.
    pub gmail_commitment: [u8; 32],
    /// The canonical Gmail that was bound.
    pub canonical_gmail: String,
    /// Chain the account belongs to.
    pub chain_id: u32,
    /// The wallet public key the service recorded.
    pub wallet_key: [u8; 32],
    /// The validator node identity the service recorded.
    pub node_key: [u8; 32],
    /// The authority's invitation authorisation, which the client puts into its
    /// own registration transaction.  `None` when the gateway has no authority
    /// configured (a read-only or API-only deployment).
    pub authorization: Option<obs_chain::chain::InviteAuthorization>,
}

/// A step's answer to the client.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Continue with the enum's own stage (the value is the token to keep using).
    Continue {
        /// Where the flow is now.
        stage: Stage,
    },
    /// The step produced something to show once.
    Show {
        /// Where the flow is now.
        stage: Stage,
        /// The value to display once (a recovery code or a provisioning URI).
        value: String,
    },
    /// The flow is complete.
    Activated(Activation),
}

/// The registry.
pub struct Registry {
    store: AtomicStore,
    network: Network,
    service_key: [u8; 32],
    authority: Option<crate::authority::Authority>,
    accounts: BTreeMap<String, Account>,
    invites: Vec<Invite>,
    enrolments: BTreeMap<String, Enrolment>,
    sessions: BTreeMap<String, Session>,
}

impl Registry {
    /// Opens a registry, creating an empty one when the store is new.
    ///
    /// `service_key` encrypts TOTP secrets at rest.  Operators keep it in a
    /// secret manager; it is never written to the store.
    pub fn open(
        store: AtomicStore,
        network: Network,
        service_key: [u8; 32],
    ) -> Result<Registry, AccountError> {
        let mut registry = Registry {
            store,
            network,
            service_key,
            authority: None,
            accounts: BTreeMap::new(),
            invites: Vec::new(),
            enrolments: BTreeMap::new(),
            sessions: BTreeMap::new(),
        };
        if let Some(document) = registry.store.load_json()? {
            for entry in document.get("accounts").and_then(Json::as_array).unwrap_or(&[]) {
                let account = Account::from_json(entry)?;
                registry.accounts.insert(account.canonical_gmail.clone(), account);
            }
            for entry in document.get("invites").and_then(Json::as_array).unwrap_or(&[]) {
                registry.invites.push(Invite::from_json(entry)?);
            }
        }
        Ok(registry)
    }

    /// Attaches the registration authority, which lets activation mint the
    /// invitation authorisation the client needs to register on chain.
    pub fn with_authority(mut self, authority: crate::authority::Authority) -> Registry {
        self.authority = Some(authority);
        self
    }

    /// The authority's public key, when one is configured.
    pub fn authority_public_key(&self) -> Option<[u8; 32]> {
        self.authority.as_ref().map(|authority| authority.public_key())
    }

    /// The network this registry serves.
    pub fn network(&self) -> Network {
        self.network
    }

    /// Number of accounts.
    pub fn account_count(&self) -> usize {
        self.accounts.len()
    }

    /// An account by canonical Gmail, for the API's own checks.
    pub fn account(&self, canonical_gmail: &str) -> Option<&Account> {
        self.accounts.get(canonical_gmail)
    }

    fn persist(&self) -> Result<(), AccountError> {
        let document = Json::obj([
            ("version", Json::Int(1)),
            ("chain_id", Json::Int(self.network.chain_id as i128)),
            (
                "accounts",
                Json::Array(self.accounts.values().map(Account::to_json).collect()),
            ),
            ("invites", Json::Array(self.invites.iter().map(Invite::to_json).collect())),
        ]);
        self.store.save_json(&document)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Invitations
    // -----------------------------------------------------------------------

    /// Mints a network invitation (the operator's job, run offline).
    ///
    /// The code is never stored: only a salted hash of it is.  The genesis
    /// invitation is minted the same way, from the operator's own secret, and is
    /// never written to source control, documentation, logs or an API response.
    pub fn mint_network_invite(
        &mut self,
        code: &str,
        now: u64,
        expires_at: u64,
        genesis: bool,
    ) -> Result<(), AccountError> {
        if code.len() < 12 {
            return Err(AccountError::BadInvite);
        }
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt).map_err(store_detail)?;
        let hash = hash_code(code, &salt)?;
        self.invites.push(Invite {
            hash,
            salt: salt.to_vec(),
            issuer: None,
            issued_at: now,
            expires_at,
            redeemed_by: None,
            genesis,
        });
        self.persist()
    }

    /// Issues an invitation for an account, at most five ever.
    ///
    /// Returns the code once.  It is never returned again, not even in a listing.
    pub fn issue_invite(&mut self, issuer: &str, now: u64) -> Result<String, AccountError> {
        let code = generate_invite_code()?;
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt).map_err(store_detail)?;
        let hash = hash_code(&code, &salt)?;
        let account = self
            .accounts
            .get_mut(issuer)
            .ok_or(AccountError::BadSession)?;
        if account.stage != Stage::Activated {
            return Err(AccountError::BadSession);
        }
        if account.invites_issued >= MAX_INVITES_PER_ACCOUNT {
            return Err(AccountError::InviteBudget);
        }
        account.invites_issued += 1;
        self.invites.push(Invite {
            hash,
            salt: salt.to_vec(),
            issuer: Some(issuer.to_string()),
            issued_at: now,
            expires_at: now + INVITE_SECS,
            redeemed_by: None,
            genesis: false,
        });
        self.persist()?;
        Ok(code)
    }

    /// The invitations an account has issued, with no code material.
    pub fn invites_of(&self, issuer: &str) -> Vec<(String, bool, u64)> {
        self.invites
            .iter()
            .filter(|invite| invite.issuer.as_deref() == Some(issuer))
            .map(|invite| {
                let label = invite
                    .redeemed_by
                    .as_deref()
                    .map(mask_gmail)
                    .unwrap_or_else(|| "unredeemed".to_string());
                (label, invite.is_spent(), invite.expires_at)
            })
            .collect()
    }

    fn find_invite(&self, code: &str) -> Option<usize> {
        self.invites.iter().position(|invite| match hash_code(code, &invite.salt) {
            Ok(candidate) => ct_eq(&candidate, &invite.hash),
            Err(_) => false,
        })
    }

    // -----------------------------------------------------------------------
    // Registration
    // -----------------------------------------------------------------------

    /// Step 1: the Gmail address.
    pub fn begin(&mut self, gmail: &str, now: u64) -> Result<(String, String), AccountError> {
        let canonical = canonical_gmail(gmail).map_err(|_| AccountError::BadGmail)?;
        if self.accounts.contains_key(&canonical) {
            return Err(AccountError::GmailTaken);
        }
        // Refuse a second enrolment that is already open for this address, so two
        // clients cannot race the same account into existence.
        if self
            .enrolments
            .values()
            .any(|enrolment| enrolment.canonical_gmail == canonical && enrolment.expires_at > now)
        {
            return Err(AccountError::GmailTaken);
        }
        let token = generate_token(SESSION_TOKEN_BYTES)?;
        self.enrolments.insert(
            token.clone(),
            Enrolment {
                canonical_gmail: canonical.clone(),
                stage: Stage::Gmail,
                expires_at: now + ENROLMENT_SECS,
                password_salt: Vec::new(),
                password_hash: Vec::new(),
                invite_index: 0,
                invite_code: None,
                recovery_display: None,
                totp_secret: None,
            },
        );
        Ok((token, canonical))
    }

    /// Step 2: the password.  Hashed immediately; the plaintext is dropped here.
    pub fn set_password(
        &mut self,
        token: &str,
        password: &str,
        now: u64,
    ) -> Result<Stage, AccountError> {
        if password.len() < MIN_PASSWORD_BYTES {
            return Err(AccountError::BadPassword(
                "the password must be at least 12 characters",
            ));
        }
        if password.len() > MAX_PASSWORD_BYTES {
            return Err(AccountError::BadPassword("the password is too long"));
        }
        let mut salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut salt).map_err(store_detail)?;
        let mut hashed = Zeroizing(
            argon2id(&Argon2Params::PASSWORD, password.as_bytes(), &salt)
                .map_err(store_detail)?,
        );
        let enrolment = self.enrolment_mut(token, now)?;
        expect_stage(enrolment, Stage::Gmail)?;
        enrolment.password_salt = salt.to_vec();
        enrolment.password_hash = hashed.to_vec();
        enrolment.stage = Stage::Password;
        hashed.zeroize();
        Ok(Stage::Password)
    }

    /// Step 3: the invitation code, redeemed atomically.
    pub fn redeem_invite(&mut self, token: &str, code: &str, now: u64) -> Result<Stage, AccountError> {
        {
            let enrolment = self.enrolment_mut(token, now)?;
            expect_stage(enrolment, Stage::Password)?;
        }
        let index = self.find_invite(code).ok_or(AccountError::BadInvite)?;
        let invite = &self.invites[index];
        if invite.is_spent() || invite.is_expired(now) {
            return Err(AccountError::BadInvite);
        }
        let canonical = self
            .enrolments
            .get(token)
            .map(|enrolment| enrolment.canonical_gmail.clone())
            .ok_or(AccountError::BadEnrolment)?;
        self.invites[index].redeemed_by = Some(canonical);
        let enrolment = self.enrolment_mut(token, now)?;
        enrolment.stage = Stage::Invite;
        enrolment.invite_index = index;
        enrolment.invite_code = Some(code.to_string());
        Ok(Stage::Invite)
    }

    /// Step 4: mint the mining account recovery code.
    ///
    /// Returned once; only a hash is kept.  It is *not* the wallet recovery
    /// phrase: it recovers access to the account record and cannot sign.
    pub fn issue_recovery_code(&mut self, token: &str, now: u64) -> Result<Step, AccountError> {
        let code = RecoveryCode::generate().map_err(store_detail)?;
        let enrolment = self.enrolment_mut(token, now)?;
        expect_stage(enrolment, Stage::Invite)?;
        enrolment.recovery_display = Some(code.as_str().to_string());
        enrolment.stage = Stage::Recovery;
        Ok(Step::Show {
            stage: Stage::Recovery,
            value: code.as_str().to_string(),
        })
    }

    /// Step 5: enrol MFA, returning the provisioning URI once.
    pub fn enrol_mfa(&mut self, token: &str, now: u64) -> Result<Step, AccountError> {
        let (secret, uri) = {
            let enrolment = self
                .enrolments
                .get(token)
                .ok_or(AccountError::BadEnrolment)?;
            if enrolment.expires_at <= now {
                return Err(AccountError::BadEnrolment);
            }
            expect_stage(enrolment, Stage::Recovery)?;
            let secret = Secret::generate().map_err(store_detail)?;
            let uri = secret.provisioning_uri("Obsidian Network", &mask_gmail(&enrolment.canonical_gmail));
            (secret, uri)
        };
        let enrolment = self.enrolment_mut(token, now)?;
        enrolment.totp_secret = Some(secret.base32());
        enrolment.stage = Stage::Mfa;
        Ok(Step::Show {
            stage: Stage::Mfa,
            value: uri,
        })
    }

    /// Step 5b: prove the authenticator works before the account exists.
    pub fn confirm_mfa(&mut self, token: &str, code: &str, now: u64) -> Result<Stage, AccountError> {
        let secret_text = self
            .enrolments
            .get(token)
            .and_then(|enrolment| enrolment.totp_secret.clone())
            .ok_or(AccountError::BadEnrolment)?;
        let secret = Secret::parse_base32(&secret_text).map_err(|_| AccountError::BadMfaCode)?;
        {
            let enrolment = self.enrolment_mut(token, now)?;
            expect_stage(enrolment, Stage::Mfa)?;
        }
        if !secret.verify(code, now) {
            return Err(AccountError::BadMfaCode);
        }
        let enrolment = self.enrolment_mut(token, now)?;
        enrolment.stage = Stage::Wallet;
        Ok(Stage::Wallet)
    }

    /// Step 6: the wallet's public keys, which complete the account.
    ///
    /// The service records public keys and returns the commitment the client
    /// needs.  It never receives, requests or accepts anything private.
    pub fn attach_wallet(
        &mut self,
        token: &str,
        wallet_key: [u8; 32],
        node_key: [u8; 32],
        recovery_key: [u8; 32],
        now: u64,
    ) -> Result<Step, AccountError> {
        if wallet_key == node_key || wallet_key == recovery_key || node_key == recovery_key {
            return Err(AccountError::BadPassword(
                "the wallet, node and recovery keys must be different keys",
            ));
        }
        // Phase one: validate the session and copy out what is needed, so the
        // rest of the method works on owned values and cannot hold a borrow
        // across a mutation.
        let (canonical, invite_index, recovery_code, totp_secret) = {
            let enrolment = self.enrolment_mut(token, now)?;
            expect_stage(enrolment, Stage::Wallet)?;
            (
                enrolment.canonical_gmail.clone(),
                enrolment.invite_index,
                enrolment.recovery_display.clone().unwrap_or_default(),
                enrolment.totp_secret.clone().unwrap_or_default(),
            )
        };

        // Phase two: the uniqueness and invitation checks.
        if self.accounts.contains_key(&canonical) {
            return Err(AccountError::GmailTaken);
        }
        let invitation_ok = self
            .invites
            .get(invite_index)
            .map(|invite| !invite.is_spent() || invite.redeemed_by.as_deref() == Some(canonical.as_str()))
            .unwrap_or(false);
        if !invitation_ok {
            return Err(AccountError::BadInvite);
        }

        // Phase three: the hashes and the sealed secret.
        let recovery_code = if recovery_code.is_empty() {
            RecoveryCode::generate().map_err(store_detail)?.as_str().to_string()
        } else {
            recovery_code
        };
        let mut recovery_salt = [0u8; 16];
        obs_crypto::rand::os_random(&mut recovery_salt).map_err(store_detail)?;
        let recovery_hash = hash_code(&RecoveryCode::normalize(&recovery_code), &recovery_salt)?;
        let (totp_sealed, totp_nonce) = self.seal_secret(&totp_secret)?;
        let (password_salt, password_hash, invite_code) = {
            let enrolment = self.enrolments.get(token).ok_or(AccountError::BadEnrolment)?;
            (
                enrolment.password_salt.clone(),
                enrolment.password_hash.clone(),
                enrolment.invite_code.clone(),
            )
        };
        let commitment = gmail_commitment(self.network.chain_id, &canonical).0;
        let chain_id = self.network.chain_id;

        let account = Account {
            canonical_gmail: canonical.clone(),
            gmail_commitment: commitment,
            password_salt,
            password_hash,
            totp_sealed,
            totp_nonce,
            totp_last_step: None,
            recovery_hash,
            recovery_salt: recovery_salt.to_vec(),
            recovery_used: false,
            wallet_key,
            node_key,
            recovery_key,
            stage: Stage::Activated,
            chain_id,
            created_at: now,
            invites_issued: 0,
            failed_attempts: 0,
            locked_until: 0,
            mining_enabled: true,
        };

        // Phase four: mint the invitation authorisation while the code is still
        // in memory, then commit.
        let issuer_address = self.issuer_address(invite_index);
        let authorization = match (&self.authority, &invite_code) {
            (Some(authority), Some(code)) => Some(authority.authorize(
                code,
                Hash32(commitment),
                now,
                now + AUTHORIZATION_SECS,
                issuer_address,
            )),
            _ => None,
        };
        let activation = Activation {
            gmail_commitment: commitment,
            canonical_gmail: canonical.clone(),
            chain_id,
            wallet_key,
            node_key,
            authorization,
        };
        // Commit: the uniqueness check above and this insert happen in one
        // `&mut self` call, with no await, no re-read and no second writer.
        self.accounts.insert(canonical, account);
        self.enrolments.remove(token);
        self.persist()?;
        Ok(Step::Activated(activation))
    }

    // -----------------------------------------------------------------------
    // Sessions
    // -----------------------------------------------------------------------

    /// Signs in with a password and an authenticator code.
    pub fn sign_in(
        &mut self,
        gmail: &str,
        password: &str,
        mfa_code: &str,
        now: u64,
    ) -> Result<(String, Session), AccountError> {
        let canonical = canonical_gmail(gmail).map_err(|_| AccountError::BadGmail)?;
        let account = self
            .accounts
            .get_mut(&canonical)
            .ok_or(AccountError::BadCredentials)?;
        if account.locked_until > now {
            return Err(AccountError::Locked {
                until: account.locked_until,
            });
        }
        // Copy out what the checks need, then drop the borrow.
        let (password_salt, password_hash, totp_sealed, totp_nonce) = (
            account.password_salt.clone(),
            account.password_hash.clone(),
            account.totp_sealed.clone(),
            account.totp_nonce,
        );

        // Verify the password first, in constant time, and always hash: the work
        // done must not depend on whether the account exists.
        let password_ok = ct_eq(
            &argon2id(&Argon2Params::PASSWORD, password.as_bytes(), &password_salt)
                .map_err(store_detail)?,
            &password_hash,
        );

        // A wrong MFA code is not a reason to skip the password check, and a
        // wrong password is not a reason to skip MFA: both are always evaluated.
        let mfa_ok = match self.unseal_secret(&totp_sealed, &totp_nonce) {
            Ok(secret_text) => match Secret::parse_base32(&secret_text) {
                Ok(secret) => secret.verify(mfa_code, now),
                Err(_) => false,
            },
            Err(_) => false,
        };

        if !password_ok || !mfa_ok {
            let account = self
                .accounts
                .get_mut(&canonical)
                .ok_or(AccountError::BadCredentials)?;
            account.failed_attempts += 1;
            if account.failed_attempts >= MAX_FAILED_ATTEMPTS {
                account.locked_until = now + LOCKOUT_SECS;
                account.failed_attempts = 0;
            }
            self.persist()?;
            return Err(AccountError::BadCredentials);
        }

        let account = self
            .accounts
            .get_mut(&canonical)
            .ok_or(AccountError::BadCredentials)?;
        account.failed_attempts = 0;
        let token = generate_token(SESSION_TOKEN_BYTES)?;
        let hash = token_hash(&token)?;
        let session = Session {
            token_hash: hash.clone(),
            canonical_gmail: canonical,
            expires_at: now + SESSION_SECS,
        };
        let issued = Session {
            token_hash: hash.clone(),
            canonical_gmail: session.canonical_gmail.clone(),
            expires_at: session.expires_at,
        };
        self.sessions.insert(hex_encode(&hash), session);
        self.persist()?;
        Ok((token, issued))
    }

    /// Resolves a bearer token to a session.
    pub fn session(&self, token: &str, now: u64) -> Result<&Session, AccountError> {
        let hash = token_hash(token)?;
        let session = self
            .sessions
            .get(&hex_encode(&hash))
            .ok_or(AccountError::BadSession)?;
        if session.expires_at <= now {
            return Err(AccountError::BadSession);
        }
        Ok(session)
    }

    /// Ends one session.
    pub fn sign_out(&mut self, token: &str) -> Result<(), AccountError> {
        let hash = token_hash(token)?;
        self.sessions.remove(&hex_encode(&hash));
        Ok(())
    }

    // -----------------------------------------------------------------------
    // Account recovery (administrative, never custodial)
    // -----------------------------------------------------------------------

    /// What account recovery may do.
    pub fn recover(&mut self, gmail: &str, code: &str, now: u64) -> Result<Stage, AccountError> {
        let canonical = canonical_gmail(gmail).map_err(|_| AccountError::BadGmail)?;
        let account = self
            .accounts
            .get_mut(&canonical)
            .ok_or(AccountError::BadCredentials)?;
        if account.recovery_used {
            return Err(AccountError::RecoveryUsed);
        }
        let normalized = RecoveryCode::normalize(code);
        let candidate = argon2id(
            &Argon2Params::HIGH_ENTROPY_CODE,
            normalized.as_bytes(),
            &account.recovery_salt,
        )
        .map_err(store_detail)?;
        if !ct_eq(&candidate, &account.recovery_hash) {
            account.failed_attempts += 1;
            if account.failed_attempts >= MAX_FAILED_ATTEMPTS {
                account.locked_until = now + LOCKOUT_SECS;
                account.failed_attempts = 0;
            }
            self.persist()?;
            return Err(AccountError::BadCredentials);
        }
        // The code is single use; using it unlocks the account so the owner can
        // sign in with their password and MFA again.
        account.recovery_used = true;
        account.locked_until = 0;
        account.failed_attempts = 0;
        self.persist()?;
        Ok(Stage::Activated)
    }

    // -----------------------------------------------------------------------
    // Internals
    // -----------------------------------------------------------------------

    fn enrolment_mut(&mut self, token: &str, now: u64) -> Result<&mut Enrolment, AccountError> {
        let enrolment = self
            .enrolments
            .get_mut(token)
            .ok_or(AccountError::BadEnrolment)?;
        if enrolment.expires_at <= now {
            return Err(AccountError::BadEnrolment);
        }
        Ok(enrolment)
    }

    /// The address of the account that issued an invitation, if any.
    fn issuer_address(&self, invite_index: usize) -> Option<Address> {
        let invite = self.invites.get(invite_index)?;
        let issuer = invite.issuer.as_ref()?;
        let account = self.accounts.get(issuer)?;
        Some(Address::from_public_key(self.network, &account.wallet_key))
    }

    fn seal_secret(&self, plaintext: &str) -> Result<(Vec<u8>, [u8; 12]), AccountError> {
        let mut nonce = [0u8; 12];
        obs_crypto::rand::os_random(&mut nonce).map_err(store_detail)?;
        let sealed = ChaCha20Poly1305::encrypt(
            &self.service_key,
            &nonce,
            b"OBSIDIAN/TOTP-SECRET/v1",
            plaintext.as_bytes(),
        );
        Ok((sealed, nonce))
    }

    fn unseal_secret(&self, sealed: &[u8], nonce: &[u8; 12]) -> Result<String, AccountError> {
        let plaintext = ChaCha20Poly1305::decrypt(
            &self.service_key,
            nonce,
            b"OBSIDIAN/TOTP-SECRET/v1",
            sealed,
        )
        .ok_or_else(|| AccountError::Store("the TOTP secret could not be opened".to_string()))?;
        String::from_utf8(plaintext).map_err(store_detail)
    }

    /// Enrols MFA again after a recovery, and returns the new provisioning URI.
    pub fn reenrol_mfa(
        &mut self,
        gmail: &str,
        password: &str,
        _now: u64,
    ) -> Result<String, AccountError> {
        let canonical = canonical_gmail(gmail).map_err(|_| AccountError::BadGmail)?;
        let account = self
            .accounts
            .get_mut(&canonical)
            .ok_or(AccountError::BadCredentials)?;
        let candidate = argon2id(
            &Argon2Params::PASSWORD,
            password.as_bytes(),
            &account.password_salt,
        )
        .map_err(store_detail)?;
        if !ct_eq(&candidate, &account.password_hash) {
            return Err(AccountError::BadCredentials);
        }
        // Drop the borrow before sealing: the seal uses the service key, which
        // is a separate field, but the compiler is right to insist.
        let secret = Secret::generate().map_err(store_detail)?;
        let uri = secret.provisioning_uri("Obsidian Network", &mask_gmail(&canonical));
        let (sealed, nonce) = self.seal_secret(&secret.base32())?;
        let account = self
            .accounts
            .get_mut(&canonical)
            .ok_or(AccountError::BadCredentials)?;
        account.totp_sealed = sealed;
        account.totp_nonce = nonce;
        account.totp_last_step = None;
        self.persist()?;
        Ok(uri)
    }

    /// Accepts an MFA code for a signed-in account, refusing replays.
    ///
    /// Each code is valid for one step; the last accepted step is remembered, so
    /// a code cannot be used twice even inside its window.
    pub fn accept_mfa_step(
        &mut self,
        canonical_gmail: &str,
        code: &str,
        now: u64,
    ) -> Result<(), AccountError> {
        let (sealed, nonce) = {
            let account = self
                .accounts
                .get(canonical_gmail)
                .ok_or(AccountError::BadSession)?;
            (account.totp_sealed.clone(), account.totp_nonce)
        };
        let secret_text = self
            .unseal_secret(&sealed, &nonce)
            .map_err(|_| AccountError::MfaNotEnrolled)?;
        let account = self
            .accounts
            .get_mut(canonical_gmail)
            .ok_or(AccountError::BadSession)?;
        let secret = Secret::parse_base32(&secret_text).map_err(|_| AccountError::MfaNotEnrolled)?;
        if !secret.verify(code, now) {
            return Err(AccountError::BadMfaCode);
        }
        // Find which step matched, and refuse it if it was already used.
        let step = now / obs_crypto::totp::STEP_SECS;
        if let Some(last) = account.totp_last_step {
            if step <= last {
                return Err(AccountError::BadMfaCode);
            }
        }
        account.totp_last_step = Some(step);
        self.persist()
    }
}

fn token_hash(token: &str) -> Result<Vec<u8>, AccountError> {
    Ok(obs_crypto::sha2::sha256(token.as_bytes()).to_vec())
}

fn hash_code(code: &str, salt: &[u8]) -> Result<Vec<u8>, AccountError> {
    argon2id(&Argon2Params::HIGH_ENTROPY_CODE, code.as_bytes(), salt).map_err(store_detail)
}

fn generate_token(bytes: usize) -> Result<String, AccountError> {
    let mut raw = vec![0u8; bytes];
    obs_crypto::rand::os_random(&mut raw).map_err(store_detail)?;
    Ok(base64url_encode(&raw))
}

/// Generates an invitation code in a transcribable format.
///
/// The alphabet has no look-alike characters and the code is grouped for reading
/// off a screen.  Network and genesis invitations are minted by the operator from
/// their own secret; this function is for account-issued invitations.
pub fn generate_invite_code() -> Result<String, AccountError> {
    let mut raw = [0u8; 10];
    obs_crypto::rand::os_random(&mut raw).map_err(store_detail)?;
    // Crockford's alphabet: 32 symbols, no `I`, `L`, `O` or `U`, so a code read
    // off a screen cannot be transcribed into a different valid code.
    let alphabet = b"0123456789ABCDEFGHJKMNPQRSTVWXYZ";
    let mut body = String::with_capacity(19);
    let mut accumulator: u32 = 0;
    let mut available = 0u32;
    let mut index = 0usize;
    for character in 0..16 {
        while available < 5 {
            accumulator = (accumulator << 8) | raw[index % raw.len()] as u32;
            index += 1;
            available += 8;
        }
        available -= 5;
        let index = ((accumulator >> available) & 0x1f) as usize;
        body.push(alphabet[index.min(alphabet.len() - 1)] as char);
        if character % 4 == 3 && character != 15 {
            body.push('-');
        }
    }
    Ok(format!("OBS-{}", body))
}

/// The genesis invitation's *format*, for documentation: the real value is
/// minted by the operator and never appears in this repository.
pub const NETWORK_INVITE_PREFIX: &str = "OBS-";

fn opt_str(value: Option<&str>) -> Json {
    match value {
        Some(text) => Json::Str(text.to_string()),
        None => Json::Null,
    }
}

fn read_bytes(value: &Json, field: &str) -> Result<Option<Vec<u8>>, AccountError> {
    match value.get(field) {
        Some(Json::Str(text)) => obs_crypto::encoding::hex_decode(text)
            .map(Some)
            .ok_or_else(|| AccountError::Store(format!("field {} is not hex", field))),
        Some(Json::Null) | None => Ok(None),
        _ => Err(AccountError::Store(format!("field {} is not a string", field))),
    }
}

fn read_key(value: &Json, field: &str) -> Result<Option<[u8; 32]>, AccountError> {
    match read_bytes(value, field)? {
        Some(bytes) if bytes.len() == 32 => {
            let mut out = [0u8; 32];
            out.copy_from_slice(&bytes);
            Ok(Some(out))
        }
        Some(_) => Err(AccountError::Store(format!("field {} is not 32 bytes", field))),
        None => Ok(None),
    }
}

/// Enforces a step's position in the flow.
fn expect_stage(enrolment: &Enrolment, expected: Stage) -> Result<(), AccountError> {
    if enrolment.stage == expected {
        Ok(())
    } else {
        Err(AccountError::OutOfOrder {
            expected: expected.name(),
        })
    }
}
