//! The Obsidian Network registration gateway.
//!
//! This crate is the *account* side of the network: it is where a person turns a
//! Gmail invitation into an account, where MFA is enrolled and checked, where
//! invitations are issued, and where the invitation authorisation that a client
//! needs in order to register on chain is minted.
//!
//! It deliberately cannot do anything else.  There is no code path here that
//! holds a user's key, signs a user's transaction, moves value, mints a coin,
//! approves a claim, changes a fee or influences consensus — the registration
//! transaction is built and signed by the client's own wallet, and every state
//! change the network recognises is decided by the chain.  A gateway compromise
//! costs accounts and invitations; it does not cost funds.
//!
//! ```text
//!   client wallet ──────────── register tx (signed by the wallet) ───────► node
//!        │                                                                  ▲
//!        │ 1..6 enrolment steps                    invitation authorisation │
//!        ▼                                                                  │
//!   obs-gateway ────────────── signed authorisation ──────────────────────┘
//! ```
//!
//! ## Modules
//!
//! * [`store`] — the atomic, durable document the gateway owns;
//! * [`accounts`] — the registration flow, invitations, MFA and sessions;
//! * [`authority`] — the invitation-authority signing key;
//! * [`api`] — the HTTP surface.

pub mod accounts;
pub mod api;
pub mod authority;
pub mod store;

pub use accounts::{AccountError, Activation, Registry, Stage, Step};
pub use api::Gateway;
pub use authority::{Authority, AuthorityError};
pub use store::{AtomicStore, StoreError};

/// The registration flow, printed for documentation and for the CLI's `--help`.
pub const FLOW: &[&str] = &[
    "gmail",
    "password",
    "invite",
    "recovery-code",
    "mfa",
    "wallet",
    "activated",
];
