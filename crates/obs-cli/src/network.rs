//! Read-only commands: ask a node what the chain says.
//!
//! These commands do not sign anything and do not hold a key.  They print the
//! node's own JSON, formatted — a block, a transaction, the validator set, the
//! issuance — so that what an operator sees here is exactly what the node
//! reported, not this program's summary of it.

use obs_primitives::json::Json;

use crate::{print_json, CliError, Context};

/// The commands' own options.
pub const OPTIONS: &[&'static str] = &["limit", "q"];

/// The node's network summary.
pub fn status(context: &Context) -> Result<(), CliError> {
    let status = context.node_get("status")?;
    print_json(&status);
    Ok(())
}

/// Issuance: the maximum supply, what is issued, and where it sits.
pub fn supply(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("supply")?);
    Ok(())
}

/// Mining parameters: the reward for the next claim and who is active.
pub fn mining(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("mining")?);
    Ok(())
}

/// The protocol's constants, as the node enforces them.
pub fn params(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("params")?);
    Ok(())
}

/// One block, by height or by hash.
pub fn block(context: &Context, selector: &str) -> Result<(), CliError> {
    print_json(&context.node_get(&format!("blocks/{}", selector))?);
    Ok(())
}

/// One transaction, by id.
pub fn transaction(context: &Context, id: &str) -> Result<(), CliError> {
    print_json(&context.node_get(&format!("transactions/{}", id))?);
    Ok(())
}

/// Recent blocks, newest first.
pub fn blocks(context: &Context, limit: u64) -> Result<(), CliError> {
    print_json(&context.node_get(&format!("blocks?limit={}", limit))?);
    Ok(())
}

/// The validator set, with the evidence behind each validator's score.
pub fn validators(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("validators")?);
    Ok(())
}

/// The pool: transactions accepted but not yet mined.
pub fn mempool(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("mempool")?);
    Ok(())
}

/// Connected peers.
pub fn peers(context: &Context) -> Result<(), CliError> {
    print_json(&context.node_get("peers")?);
    Ok(())
}

/// The node's recent events: what it mined, refused, or learned from peers.
pub fn events(context: &Context, limit: u64) -> Result<(), CliError> {
    print_json(&context.node_get(&format!("events?limit={}", limit))?);
    Ok(())
}

/// Searches by height, block hash or address, the way the explorer does.
pub fn search(context: &Context, query: &str) -> Result<(), CliError> {
    let encoded: String = query
        .bytes()
        .map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                (byte as char).to_string()
            }
            other => format!("%{:02X}", other),
        })
        .collect();
    print_json(&context.node_get(&format!("search?q={}", encoded)).unwrap_or(Json::Null));
    Ok(())
}
