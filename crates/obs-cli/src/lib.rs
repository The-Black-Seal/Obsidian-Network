//! `obs-cli` — the command-line client.
//!
//! Five kinds of job, and the crate is split the same way:
//!
//! * [`network`] reads a node: status, blocks, transactions, supply, validators.
//! * [`keys`] and [`wallet`] are the *user's* side: a keystore on this machine,
//!   the user's own password, their own key.  Nothing here ever sends a key or a
//!   phrase anywhere; every signature is made locally.
//! * [`register`] walks the invitation-gated enrolment flow against a
//!   registration service, and the wallet signs the account into existence.
//! * [`devnet`] founds a local development network, because a chain whose first
//!   block must register its own proposer cannot bootstrap itself unattended.
//! * [`operator`] is the service operator's side: the authority key, network
//!   invitations.
//!
//! Two things this binary will not do, on purpose: it will not print a password
//! or a recovery phrase to the terminal unless explicitly asked, and it will not
//! send a secret to a service.  A phrase that scrolls past in a terminal ends up
//! in a scrollback buffer, a CI log and a screenshot; the CLI writes secrets to
//! files with owner-only permissions instead, and says which file.

use std::time::Duration;

use obs_primitives::json::Json;
use obs_primitives::network::Network;
use obs_rpc::cli::Args;
use obs_rpc::client::{json_body, Client, ClientError};

pub mod devnet;
pub mod keys;
pub mod network;
pub mod operator;
pub mod register;
pub mod wallet;

/// Why a command failed.
#[derive(Debug)]
pub enum CliError {
    /// The arguments did not make sense.
    Usage(String),
    /// The service or the filesystem refused.
    Failed(String),
    /// The node or the service could not be reached.
    Transport(String),
}

impl core::fmt::Display for CliError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            CliError::Usage(detail) => write!(f, "{}", detail),
            CliError::Failed(detail) => write!(f, "{}", detail),
            CliError::Transport(detail) => write!(f, "{}", detail),
        }
    }
}

impl std::error::Error for CliError {}

impl From<ClientError> for CliError {
    fn from(error: ClientError) -> CliError {
        CliError::Transport(error.to_string())
    }
}

/// Parsed connection settings, shared by every command.
#[derive(Debug, Clone)]
pub struct Context {
    /// The chain this session is talking to.
    pub network: Network,
    /// The node's API.
    pub node_url: String,
    /// The registration service, when the command needs one.
    pub gateway_url: String,
    /// The HTTP client, with a bounded timeout.
    pub client: Client,
}

impl Context {
    /// Builds the context from the common flags.
    pub fn from_args(args: &Args) -> Result<Context, CliError> {
        let name = args.or("network", "devnet");
        let network = network_by_name(&name).ok_or_else(|| {
            CliError::Usage(format!(
                "--network {} is not a network; use devnet, testnet, staging or mainnet",
                name
            ))
        })?;
        Ok(Context {
            network,
            node_url: args
                .or("node-url", "http://127.0.0.1:7200")
                .trim_end_matches('/')
                .to_string(),
            gateway_url: args
                .or("gateway-url", "http://127.0.0.1:8080")
                .trim_end_matches('/')
                .to_string(),
            client: Client::with_timeout(Duration::from_secs(20)),
        })
    }

    /// GETs a JSON document from the node.
    pub fn node_get(&self, path: &str) -> Result<Json, CliError> {
        let url = format!("{}/api/v1/{}", self.node_url, path.trim_start_matches('/'));
        let response = self.client.get(&url)?;
        if response.status.code() >= 400 {
            return Err(CliError::Failed(refusal(&url, &response)));
        }
        Ok(json_body(&response)?)
    }

    /// POSTs a JSON document to a service and returns the body, or a refusal.
    pub fn post(&self, url: &str, body: &Json) -> Result<Json, CliError> {
        let response = self.client.post_json(url, body)?;
        if response.status.code() >= 400 {
            return Err(CliError::Failed(refusal(url, &response)));
        }
        Ok(json_body(&response)?)
    }

    /// POSTs a JSON document to the node's API.
    pub fn node_post(&self, path: &str, body: &Json) -> Result<Json, CliError> {
        self.post(&format!("{}/api/v1/{}", self.node_url, path.trim_start_matches('/')), body)
    }

    /// The node's protocol time, which is what a claim must be stamped with.
    pub fn protocol_time(&self) -> Result<u64, CliError> {
        let status = self.node_get("status")?;
        status
            .get("protocol_time")
            .and_then(Json::as_u64)
            .ok_or_else(|| CliError::Failed("the node did not report its protocol time".to_string()))
    }
}

fn network_by_name(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(obs_primitives::network::MAINNET),
        "testnet" => Some(obs_primitives::network::TESTNET),
        "devnet" => Some(obs_primitives::network::DEVNET),
        "staging" => Some(obs_primitives::network::STAGING),
        _ => None,
    }
}

/// A refusal, with the service's own error code when it gave one.
///
/// Every service in this workspace reports a refusal the same way —
/// `{"error": {"code", "message", "status"}}` — so the CLI can show the code that
/// the operator will find in the service's own documentation and logs.
fn refusal(url: &str, response: &obs_rpc::http::Response) -> String {
    match json_body(response) {
        Ok(body) => {
            let error = body.get("error");
            let code = error
                .and_then(|error| error.get("code"))
                .and_then(Json::as_str)
                .unwrap_or("refused");
            let message = error
                .and_then(|error| error.get("message"))
                .and_then(Json::as_str)
                .unwrap_or("the request was refused");
            format!("{}: {} ({})", url, message, code)
        }
        Err(_) => format!("{}: refused with status {}", url, response.status.code()),
    }
}

/// The known options every command accepts, so a mistyped flag is caught.
pub const COMMON: &[&str] = &["network", "node-url", "gateway-url", "help!"];

/// A mutable list of known options: the common ones plus a command's own.
pub fn known(extra: &[&'static str]) -> Vec<&'static str> {
    let mut all = COMMON.to_vec();
    for name in extra {
        all.push(name);
    }
    all
}

/// Prints a JSON document in a readable, stable form.
///
/// The output is the service's own JSON, formatted — not a re-description of it.
/// A CLI that summarises is a second, silently diverging implementation of the
/// API; this one shows what the network actually said.
pub fn print_json(json: &Json) {
    print_json_indented(json, 0);
}

fn print_json_indented(json: &Json, depth: usize) {
    let pad = "  ".repeat(depth);
    match json {
        Json::Null => println!("{}null", pad),
        Json::Bool(value) => println!("{}{}", pad, value),
        Json::Int(value) => println!("{}{}", pad, value),
        Json::Str(value) => println!("{}{:?}", pad, value),
        Json::Array(items) => {
            if items.is_empty() {
                println!("{}[]", pad);
                return;
            }
            for item in items {
                print_json_indented(item, depth);
            }
        }
        Json::Object(fields) => {
            for (key, value) in fields {
                match value {
                    Json::Object(_) | Json::Array(_) => {
                        println!("{}{}:", pad, key);
                        print_json_indented(value, depth + 1);
                    }
                    Json::Str(text) => println!("{}{}: {:?}", pad, key, text),
                    other => {
                        let rendered = match other {
                            Json::Int(value) => value.to_string(),
                            Json::Bool(value) => value.to_string(),
                            Json::Null => "null".to_string(),
                            _ => String::new(),
                        };
                        println!("{}{}: {}", pad, key, rendered);
                    }
                }
            }
        }
    }
}

/// A required string field, with a message that names what was missing.
pub fn field<'a>(json: &'a Json, name: &str) -> Result<&'a str, CliError> {
    json.get(name)
        .and_then(Json::as_str)
        .ok_or_else(|| CliError::Failed(format!("the service did not return a {}", name)))
}

/// A required whole-number field.
pub fn number(json: &Json, name: &str) -> Result<u64, CliError> {
    json.get(name)
        .and_then(Json::as_u64)
        .ok_or_else(|| CliError::Failed(format!("the service did not return a {}", name)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn the_context_reads_the_common_flags_and_defaults_to_a_local_devnet() {
        let args = Args::parse("obs-cli", &argv(&[]), COMMON).unwrap();
        let context = Context::from_args(&args).unwrap();
        assert_eq!(context.network.name, "devnet");
        assert_eq!(context.node_url, "http://127.0.0.1:7200");
        assert_eq!(context.gateway_url, "http://127.0.0.1:8080");

        let args = Args::parse(
            "obs-cli",
            &argv(&["--network", "testnet", "--node-url", "http://node.invalid:1/"]),
            COMMON,
        )
        .unwrap();
        let context = Context::from_args(&args).unwrap();
        assert_eq!(context.network.name, "testnet");
        // A trailing slash would produce `//api/v1/status` in every URL.
        assert_eq!(context.node_url, "http://node.invalid:1");

        let args = Args::parse("obs-cli", &argv(&["--network", "moonnet"]), COMMON).unwrap();
        assert!(matches!(Context::from_args(&args), Err(CliError::Usage(_))));
    }

    #[test]
    fn a_refusal_carries_the_services_own_error_code() {
        let response = obs_rpc::http::Response::json(
            obs_rpc::http::Status::FORBIDDEN,
            &Json::obj([
                (
                    "error",
                    Json::obj([
                        ("code", Json::Str("bad_proof".to_string())),
                        (
                            "message",
                            Json::Str("the signature does not prove ownership".to_string()),
                        ),
                    ]),
                ),
            ]),
        );
        let rendered = refusal("http://node/api/v1/account/proof", &response);
        assert!(rendered.contains("bad_proof"), "{}", rendered);
        assert!(rendered.contains("does not prove ownership"), "{}", rendered);
    }
}
