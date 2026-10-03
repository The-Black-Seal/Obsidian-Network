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

/// The four networks this build knows, with the ports each one listens on.
///
/// This is a local table — it asks no node — so an operator can plan a
/// deployment before anything is running.  The ports are the same constants the
/// programs use as defaults (`obs_primitives::network::Network`), which is why a
/// devnet and a testnet can share a host without fighting over a port.
pub fn table() -> String {
    use obs_primitives::network::ALL_NETWORKS;
    let mut out = String::from(
        "networks\n\
         network  chain id  address prefix  node API  peers  interface  service\n",
    );
    for network in ALL_NETWORKS {
        out.push_str(&format!(
            "{:<8} {:<9} {:<15} {:<9} {:<6} {:<10} {}\n",
            network.name,
            network.chain_id,
            network.address_prefix,
            network.api_port,
            network.peer_port,
            network.interface_port,
            network.service_port,
        ));
    }
    out.push_str(
        "\nfounder invitations\n\
         every network is founded once, by whoever holds its first invitation.\n",
    );
    for network in ALL_NETWORKS {
        match network.disposable_invite {
            Some(code) => out.push_str(&format!(
                "{:<8} disposable and published: {}\n",
                network.name, code
            )),
            None => out.push_str(
                "mainnet  held by the operator: minted into the registration service's store \
                 with `invite mint --genesis`\n                 and never written down in this \
                 repository\n",
            ),
        }
    }
    out.push_str(
        "\nmainnet is the only network that carries value; its chain id, genesis and\n\
         key material are distinct from the other three, so a signature or a\n\
         transaction from one is refused by another (see `params`).\n",
    );
    out
}

/// Prints the network table.
pub fn networks() -> Result<(), CliError> {
    print!("{}", table());
    Ok(())
}

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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_table_lists_every_network_with_its_ports() {
        let table = table();
        for network in obs_primitives::network::ALL_NETWORKS {
            assert!(table.contains(network.name), "{} is missing", network.name);
            assert!(
                table.contains(&network.api_port.to_string()),
                "{}'s node API port is missing",
                network.name
            );
            assert!(table.contains(&network.peer_port.to_string()), "{}'s peer port", network.name);
        }
        // Ports are distinct, so two networks can share a host.
        assert!(table.contains("7200") && table.contains("8200") && table.contains("8300"));
        // A test network's invitation is disposable and published; mainnet's line
        // names no code at all, because that code is the operator's and is not a
        // constant anywhere in this source.
        assert!(table.contains("OBS-DEVNET-FOUNDER-0001"));
        let mainnet_lines: Vec<&str> =
            table.lines().filter(|line| line.starts_with("mainnet")).collect();
        assert!(
            mainnet_lines.iter().any(|line| line.contains("held by the operator")),
            "mainnet's invitation line says the operator holds it"
        );
        for line in mainnet_lines {
            assert!(
                !line.contains("OBS-"),
                "no invitation code appears on mainnet's lines: {:?}",
                line
            );
        }
    }
}
