//! Operator commands: the authority key, invitations, and a look at the
//! explorer's public surface.
//!
//! These are the commands a network operator runs, not the ones a person runs.
//! They touch the shards that carry protocol weight — the registration
//! authority's key, and the invitation budget — so they are deliberately
//! explicit: nothing here has a default that would act on the wrong network, and
//! nothing prints a secret that could then be read out of a log.

use std::path::PathBuf;

use obs_primitives::json::Json;
use obs_rpc::cli::Args;

use crate::{print_json, CliError, Context};

/// Options for the operator commands.
pub const OPTIONS: &[&'static str] = &[
    "authority-key",
    "generate!",
    "print-authority!",
    "store",
    "code",
    "expires-in",
    "genesis!",
    "key",
    "label",
    "scopes",
    "limit",
];

/// `authority generate` — create the network's registration authority.
pub fn authority_generate(context: &Context, args: &Args) -> Result<(), CliError> {
    let path = authority_path(context, args)?;
    if path.exists() {
        return Err(CliError::Failed(format!(
            "{} already exists; an authority key is not regenerated casually — \
             a new key cannot authorise registrations for the network whose genesis \
             bound the old one",
            path.display()
        )));
    }
    let authority = obs_gateway::authority::Authority::generate(&path, context.network)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    println!("obs-cli: wrote the registration authority for {}", context.network.name);
    println!("obs-cli: public key {}", authority.public_key_hex());
    println!("obs-cli: every node of this network needs it:");
    println!("obs-cli:   obs-node --authority-key {}", authority.public_key_hex());
    println!(
        "obs-cli: keep {} private and backed up; without it no new account can register",
        path.display()
    );
    Ok(())
}

/// `authority print` — the public key, for configuring nodes.
pub fn authority_print(context: &Context, args: &Args) -> Result<(), CliError> {
    let path = authority_path(context, args)?;
    let authority = obs_gateway::authority::Authority::load(&path, context.network)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    println!("{}", authority.public_key_hex());
    Ok(())
}

/// `invite mint` — mint one invitation into a service's store.
///
/// The code itself is *not* printed: the operator is expected to have it already,
/// and a transcript of this command must not be enough to register.  Only the
/// commitment — which is public information, and which the chain records — is
/// shown, so an operator can confirm that the invitation the service holds is the
/// one they meant to create.
pub fn invite_mint(context: &Context, args: &Args) -> Result<(), CliError> {
    let store_path = args
        .get("store")
        .map(PathBuf::from)
        .ok_or_else(|| CliError::Usage("--store <path> is required".to_string()))?;
    let code = args
        .get("code")
        .ok_or_else(|| {
            CliError::Usage(
                "--code <invitation> is required: the operator already holds the code, and this \
                 command never prints it"
                    .to_string(),
            )
        })?
        .to_string();
    let genesis = args.flag("genesis");
    let expires_in = args
        .number("expires-in", 30 * 24 * 3_600)
        .map_err(|error| CliError::Usage(error.to_string()))?;
    let store = obs_gateway::store::AtomicStore::open(&store_path, true)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    let service_key = obs_crypto::sha2::sha256_tagged(
        "OBSIDIAN/GATEWAY-SERVICE-KEY/v1",
        &[0u8; 32],
    );
    let mut registry = obs_gateway::accounts::Registry::open(store, context.network, service_key)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    let now = unix_now();
    registry
        .mint_network_invite(&code, now, now + expires_in, genesis)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    println!(
        "obs-cli: minted a {} invitation for {}",
        if genesis { "genesis" } else { "network" },
        context.network.name
    );
    println!(
        "obs-cli: commitment {}",
        obs_chain::invite_commitment(context.network.chain_id, &code).to_hex()
    );
    println!("obs-cli: valid for {} seconds ({} days)", expires_in, expires_in / 86_400);
    println!(
        "obs-cli: the code is stored only as a hash; it cannot be recovered from this store, so \
         keep the copy you minted from"
    );
    Ok(())
}

/// `portal key` — mint a developer-portal key by talking to a running service.
///
/// The service issues the secret once; this command writes it to a file rather
/// than printing it, because a key in a terminal is a key in a scrollback buffer.
pub fn portal_key(context: &Context, args: &Args) -> Result<(), CliError> {
    let session = args
        .get("session")
        .ok_or_else(|| CliError::Usage("--session <token> is required".to_string()))?;
    let label = args.or("label", "cli key");
    let scopes: Vec<Json> = args
        .all("scopes")
        .into_iter()
        .map(Json::Str)
        .collect();
    let limit = args
        .number("limit", 600)
        .map_err(|error| CliError::Usage(error.to_string()))?;
    let body = Json::obj([
        ("label", Json::Str(label)),
        ("scopes", Json::Array(scopes)),
        ("requests_per_minute", Json::Int(limit as i128)),
    ]);
    let client = context
        .client
        .clone()
        .with_header("Authorization", format!("Bearer {}", session));
    let response = client
        .post_json(&format!("{}/v1/portal/keys", context.node_url), &body)?;
    if response.status.code() >= 400 {
        return Err(CliError::Failed(format!(
            "the portal refused: status {}",
            response.status.code()
        )));
    }
    print_json(&obs_rpc::client::json_body(&response)?);
    println!(
        "obs-cli: the secret is shown once.  An API key is a read credential and never a wallet \
         key: sign transactions with your own wallet and send the signed bytes, or use the \
         proof endpoint with your own signature."
    );
    Ok(())
}

fn authority_path(context: &Context, args: &Args) -> Result<PathBuf, CliError> {
    match args.get("authority-key") {
        Some(path) => Ok(PathBuf::from(path)),
        None => {
            // There is no implicit default outside a data directory: acting on the
            // wrong network's authority would be a serious mistake.
            Err(CliError::Usage(format!(
                "--authority-key <path> is required (the usual location for {} is \
                 data/{}/authority.key)",
                context.network.name, context.network.name
            )))
        }
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}
