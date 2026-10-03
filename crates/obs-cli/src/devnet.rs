//! Founding a local development network.
//!
//! A fresh chain cannot bootstrap itself, and that is a property of the protocol
//! rather than an oversight: the first block must be proposed by a key it
//! registers itself, so somebody has to hold that key and sign the registration
//! that creates the first account.  On a real network that first account is
//! created by a person going through registration with the genesis invitation.
//!
//! For a development network the CLI does the same thing in one step, so that
//! `obs-node`, `obs-gateway` and the web interface have a chain to talk to within
//! seconds of a checkout:
//!
//! 1. an authority key for the network, generated if this is the first time;
//! 2. a founder wallet, generated here and sealed with a password;
//! 3. the invitation authorisation for that wallet, issued by the authority —
//!    exactly what the registration service issues at its invitation step, and
//!    the reason the CLI needs the authority key to do it;
//! 4. the founder's registration transaction, signed by the founder's own wallet,
//!    handed to the node.  The first block carries it, and because the founder is
//!    also the first claim, that block is the genesis claim: 100,000 OBS to the
//!    genesis wallet, which is the treasury wallet.
//!
//! Everything this writes is a development secret and says so.  A mainnet
//! deployment uses the registration service instead: same transactions, same
//! rules, a real invitation and a real person's Gmail identity.

use std::path::PathBuf;

use obs_chain::{Transaction, TxKind};
use obs_primitives::identity::canonical_gmail;
use obs_primitives::json::Json;
use obs_rpc::cli::Args;

use crate::keys;
use crate::{print_json, CliError, Context};

/// Options for the devnet commands.
pub const OPTIONS: &[&'static str] = &[
    "data-dir",
    "authority-key",
    "keystore",
    "password-file",
    "password",
    "label",
    "phrase-out",
    "invite",
    "gmail",
];

/// The founder's identity on a development network.
///
/// A devnet is disposable and its Gmail identity is a placeholder — no mail is
/// ever sent anywhere, and no real person's address is involved.
const DEVNET_GMAIL: &str = "devnet.founder.obsidian@gmail.com";
const DEVNET_INVITE: &str = "OBS-DEVNET-FOUNDER-0001";

/// Options for `devnet init`.
pub fn init(context: &Context, args: &Args) -> Result<(), CliError> {
    let data_dir = PathBuf::from(args.or("data-dir", &format!("data/{}", context.network.name)));
    let authority_path = PathBuf::from(
        args.get("authority-key")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("authority.key"))
            .to_string_lossy()
            .to_string(),
    );

    // --- the authority -----------------------------------------------------
    let authority = match obs_gateway::authority::Authority::load_or_generate(&authority_path, context.network)
    {
        Ok(authority) => authority,
        Err(error) => return Err(CliError::Failed(error.to_string())),
    };
    println!("obs-cli: authority key  {}", authority_path.display());
    println!("obs-cli: authority      {}", authority.public_key_hex());

    // --- the founder wallet ------------------------------------------------
    let keystore = PathBuf::from(args.or(
        "keystore",
        &data_dir.join("founder.keystore.json").to_string_lossy(),
    ));
    let password = keys::password(args)?;
    let phrase_out = PathBuf::from(
        args.get("phrase-out")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("founder.phrase.txt"))
            .to_string_lossy()
            .to_string(),
    );
    let label = args.or("label", "devnet founder");
    let wallet = if keystore.exists() {
        // Re-opening an existing devnet: the founder keeps its address, so the
        // account it registers stays the same one.
        keys::open_wallet_with(&keystore, &password, context.network).map_err(|_| {
            CliError::Failed(format!(
                "{} exists but could not be opened with this password; \
                 move it aside to found a new devnet",
                keystore.display()
            ))
        })?
    } else {
        keys::create_wallet(
            context.network,
            &keystore,
            &password,
            &label,
            Some(&phrase_out),
        )?
    };
    println!("obs-cli: founder wallet {}", keystore.display());
    println!("obs-cli: founder phrase {}", phrase_out.display());
    println!("obs-cli: founder address {}", wallet.address());

    // --- the invitation authorisation --------------------------------------
    let gmail = args.or("gmail", DEVNET_GMAIL);
    let canonical = canonical_gmail(&gmail)
        .map_err(|error| CliError::Usage(format!("--gmail: {}", error)))?;
    let invite_code = args.or("invite", DEVNET_INVITE);

    // --- what the node needs to start mining as the founder ----------------
    // The node's identity is the wallet's *node* key and its mining key is the
    // wallet key, both read from the keystore: the keys stay encrypted at rest,
    // and no private key is written out in the clear or passed on a command line.
    // The password file is a development convenience and says so.
    let password_file = PathBuf::from(
        args.get("password-file")
            .map(PathBuf::from)
            .unwrap_or_else(|| data_dir.join("founder.password.txt"))
            .to_string_lossy()
            .to_string(),
    );
    if args.get("password-file").is_none() {
        keys::write_private(&password_file, &format!("{}\n", password))?;
        println!("obs-cli: founder password file {}", password_file.display());
    }

    // --- the registration, if the node is up --------------------------------
    // Last, so the operator has already seen the wallet and the node command even
    // when the node is not running yet.
    let registered = register_founder(context, args, &wallet, &authority, &invite_code, &canonical)?;

    println!();
    match registered {
        Some(id) => println!("obs-cli: founder registered as {} ({})", wallet.address(), id),
        None => println!(
            "obs-cli: the founder is not registered yet: the node was not reachable, or it is \
             not running this devnet's chain"
        ),
    }
    println!("obs-cli: devnet ready");
    println!("obs-cli:    authority  {}", authority.public_key_hex());
    println!("obs-cli:    founder    {}", wallet.address());
    println!("obs-cli:    treasury   {}", wallet.address());
    println!(
        "obs-cli:    start      obs-node --network {} --data-dir {} --genesis-timestamp now \\",
        context.network.name,
        data_dir.join("node").display()
    );
    println!(
        "obs-cli:                    --authority-key {} \\",
        authority.public_key_hex()
    );
    println!(
        "obs-cli:                    --keystore {} --keystore-password-file {} --mine --validator",
        keystore.display(),
        password_file.display()
    );
    println!(
        "obs-cli: the first block carries the founder's registration and the one-time genesis \
         claim of 100,000 OBS, which is the treasury's allocation"
    );
    println!(
        "obs-cli: the founder's phrase is at {} — a development secret, owner-readable only. \
         Never do this on mainnet: there a person registers with a real invitation.",
        phrase_out.display()
    );
    Ok(())
}

/// Prints the founder's expected genesis state, so a script can check it.
pub fn expect_genesis(context: &Context, args: &Args) -> Result<(), CliError> {
    let _ = args;
    let status = context.node_get("status")?;
    let supply = context.node_get("supply")?;
    let body = Json::obj([
        ("network", Json::Str(context.network.name.to_string())),
        ("height", status.get("height").cloned().unwrap_or(Json::Null)),
        ("genesis_issued", supply.get("genesis_issued").cloned().unwrap_or(Json::Null)),
        ("genesis_allocation", supply.get("genesis_allocation").cloned().unwrap_or(Json::Null)),
        ("issued_supply", supply.get("issued_supply").cloned().unwrap_or(Json::Null)),
        ("max_supply", supply.get("max_supply").cloned().unwrap_or(Json::Null)),
    ]);
    print_json(&body);
    Ok(())
}

/// Submits the founder's registration, if the node is reachable and the account
/// does not already exist.
///
/// Founding a devnet is two processes coming up in either order: the node has to
/// be running to accept a transaction, but the node needs the founder's keystore
/// to be able to propose the block that carries it.  So this is idempotent: run
/// the command once to create the keys and see what the node needs, start the
/// node, then run it again to register.  A second run never registers twice — it
/// asks the chain whether the account exists first.
pub fn register_founder(
    context: &Context,
    _args: &Args,
    wallet: &obs_wallet::Wallet,
    authority: &obs_gateway::authority::Authority,
    invite_code: &str,
    canonical: &str,
) -> Result<Option<String>, CliError> {
    match founder_state(context, wallet) {
        Ok(Some(_)) => return Ok(Some("already on chain".to_string())),
        Ok(None) => {}
        Err(detail) => {
            // The node is not there (or not this chain).  Not an error: the
            // operator has to start it before anything can be registered.
            println!("obs-cli: the node did not answer ({})", detail);
            return Ok(None);
        }
    }
    // The authorisation is dated in the *chain's* time, not this machine's: the
    // chain checks `issued_at <= block time`, and protocol time advances at most
    // a minute per block.  A devnet whose founder registers a few minutes after
    // genesis would therefore be un-startable with a wall-clock stamp — the only
    // block that can carry the founder's registration is block 1, and its time
    // can never reach a stamp ten minutes ahead of the chain.  Dated at the
    // head's own time, the registration is includable in the very next block
    // whenever the operator gets to it.
    let chain_time = chain_head_time(context).ok_or_else(|| {
        CliError::Failed(
            "the chain's time is unknown: the node must be running before the founder can register"
                .to_string(),
        )
    })?;
    let authorization = authority.authorize(
        invite_code,
        obs_chain::gmail_commitment(context.network.chain_id, canonical),
        chain_time,
        chain_time + 3_600,
        None,
    );
    let keys = wallet.public_keys();
    let tx = Transaction::sign(
        context.network,
        1,
        TxKind::Register {
            account: wallet.address(),
            wallet_key: keys.wallet_key,
            gmail_commitment: authorization.gmail_commitment,
            invite: authorization,
        },
        wallet.wallet_keypair(),
    );
    let body = Json::obj([("transaction", Json::Str(hex(&tx.to_bytes())))]);
    let answer = context.node_post("transactions", &body)?;
    println!(
        "obs-cli: founder registration {} ({})",
        tx.id().0.to_hex(),
        answer.get("status").and_then(Json::as_str).unwrap_or("pooled")
    );
    println!(
        "obs-cli: the founder holds the network's only invitation; the first block carries this \
         registration, and the founder's first claim is the genesis claim of 100,000 OBS"
    );
    Ok(Some(tx.id().0.to_hex()))
}

/// Asks the chain whether the founder's account exists, by proving ownership of
/// the address.  `Ok(None)` means "the node is there and the account is not".
fn founder_state(
    context: &Context,
    wallet: &obs_wallet::Wallet,
) -> Result<Option<Json>, String> {
    let mut nonce = [0u8; 16];
    obs_crypto::rand::os_random(&mut nonce).map_err(|error| error.to_string())?;
    let nonce = hex(&nonce);
    let signature = obs_wallet::sign::account_proof(wallet, &nonce);
    let body = Json::obj([
        ("address", Json::Str(wallet.address().to_string())),
        ("nonce", Json::Str(nonce)),
        ("signature", Json::Str(hex(&signature))),
    ]);
    let url = format!("{}/api/v1/account/proof", context.node_url);
    let response = context.client.post_json(&url, &body).map_err(|error| error.to_string())?;
    let code = response.status.code();
    let parsed = obs_rpc::client::json_body(&response).map_err(|error| error.to_string())?;
    if code >= 400 {
        let rule = parsed
            .get("error")
            .and_then(|error| error.get("code"))
            .and_then(Json::as_str)
            .unwrap_or("");
        if rule == "account_not_found" {
            return Ok(None);
        }
        return Err(format!("the node refused the proof: {}", rule));
    }
    Ok(Some(parsed))
}

/// The chain's own time: the timestamp of the node's head block.
///
/// Every time the chain checks is protocol time, so this — not the wall clock —
/// is what a registration may be dated with.
pub fn chain_head_time(context: &Context) -> Option<u64> {
    let url = format!("{}/api/v1/status", context.node_url);
    let response = context.client.get(&url).ok()?;
    if response.status.code() != 200 {
        return None;
    }
    let value = obs_rpc::client::json_body(&response).ok()?;
    let time = value.get("last_block_time").and_then(Json::as_i128)?;
    u64::try_from(time).ok().filter(|time| *time > 0)
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn hex(bytes: &[u8]) -> String {
    obs_crypto::encoding::hex_encode(bytes)
}

/// `devnet register` — submit the founder's registration on an existing devnet.
///
/// This is the same idempotent step `devnet init` ends with, on its own, so an
/// operator who started the node after creating the wallet can run it directly.
pub fn register(context: &Context, args: &Args) -> Result<(), CliError> {
    let data_dir = PathBuf::from(args.or("data-dir", &format!("data/{}", context.network.name)));
    let authority_path = args
        .get("authority-key")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("authority.key"));
    let keystore = args
        .get("keystore")
        .map(PathBuf::from)
        .unwrap_or_else(|| data_dir.join("founder.keystore.json"));
    let password = keys::password(args)?;
    let wallet = keys::open_wallet_with(&keystore, &password, context.network)?;
    let authority = obs_gateway::authority::Authority::load(&authority_path, context.network)
        .map_err(|error| CliError::Failed(error.to_string()))?;
    let canonical = canonical_gmail(&args.or("gmail", DEVNET_GMAIL))
        .map_err(|error| CliError::Usage(format!("--gmail: {}", error)))?;
    let invite_code = args.or("invite", DEVNET_INVITE);
    match register_founder(context, args, &wallet, &authority, &invite_code, &canonical)? {
        Some(id) => println!("obs-cli: founder {} is registered ({})", wallet.address(), id),
        None => {
            return Err(CliError::Transport(
                "the node did not answer; start it with the command `devnet init` printed, then \
                 run this again"
                    .to_string(),
            ))
        }
    }
    Ok(())
}
