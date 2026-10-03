//! # obs-rpc — the Obsidian Network service layer
//!
//! One place where the network's HTTP surface is defined, so that the node RPC
//! endpoint, the public gateway and the static web application all agree on
//! framing, error shapes and hardening headers.
//!
//! * [`http`] — strict HTTP/1.1 parsing and response construction.
//! * [`server`] — a bounded, multi-threaded server plus static file serving.
//! * [`client`] — the blocking client used by the CLI and the tests.
//!
//! The layer carries no authority: every handler it calls must ultimately
//! validate against the blockchain state, which lives in `obs-chain` and
//! `obs-consensus`.
//!
//! ## What "strict" means here
//!
//! * Request lines, header counts, header sizes, bodies and connection counts
//!   are bounded before allocation.
//! * Only `Content-Length` framing is accepted; chunked bodies are refused.
//! * Control characters, `%00`, invalid escapes and `..` path segments are
//!   rejected rather than normalised.
//! * Static files are resolved against a canonical root, so a symlink cannot
//!   escape the document root.
//! * A handler that panics takes down neither the server nor the process: the
//!   connection gets a `500` and the next request is served normally.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod cli;
pub mod client;
pub mod http;
pub mod server;

pub use client::{Client, ClientError};
pub use http::{HttpError, JsonError, Method, Parsed, Parser, Request, Response, Status};
pub use server::{Handler, Peer, Server, ServerConfig, StaticFiles};

/// Version of the HTTP surface, reported by every service.
pub const API_VERSION: &str = "v1";

/// The `Server` header value used by Obsidian services.
pub const SERVER_NAME: &str = "obsidian/1.0";
