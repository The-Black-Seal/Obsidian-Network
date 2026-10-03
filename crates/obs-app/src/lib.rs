//! The Obsidian Network application layer.
//!
//! Layer four of five, in the authority hierarchy:
//!
//! ```text
//!   consensus  ── decides what is true
//!   chain state ── holds what is true
//!   node data  ── reports what is true, and proves it
//!   APIs/index ── read what the node reports, and *only* read   ← this crate
//!   UI         ── shows what the API returns, and can do nothing else
//! ```
//!
//! Everything here is downstream of a node.  The indexer follows a node's API;
//! the Explorer publishes what the index holds under the privacy contract in
//! [`privacy`]; the Developer Portal issues API keys, scopes and rate limits for
//! the same surface.  None of it can create a block, approve a claim, mint a
//! coin, change a fee or move value — there is no code path from here to
//! consensus, by construction, because the crate holds no key and has no write
//! endpoint except the portal's own key management.

pub mod api;
pub mod indexer;
pub mod portal;
pub mod privacy;

/// The gateway's atomic store, reused for the portal's own records.
///
/// The application layer follows the same durability rule as the registration
/// service: one atomically rewritten document per service, holding only what
/// that service owns.  Re-exporting it under a local name keeps the portal's
/// imports honest about where the code lives.
pub use obs_gateway::store as store_shim;

pub use api::{App, AppConfig};
pub use indexer::{IndexError, Indexer};
pub use portal::{Portal, PortalError, Scope};
pub use privacy::{PrivacyViolation, ROUTES};
