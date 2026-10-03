//! The user's commands: create a wallet, look at it, mine with it, spend from it.
//!
//! Everything here signs locally.  A balance is asked for by *proving* ownership
//! of the address to the node — the node's `/account/proof` endpoint verifies a
//! signature over a domain-separated challenge — and a transaction leaves this
//! process already signed.  A key, a seed or a phrase is never an argument to an
//! HTTP request anywhere in this module.

use std::path::PathBuf;

use obs_chain::{Claim, Transaction, TxKind};
use obs_primitives::address::Address;
use obs_primitives::json::Json;
use obs_primitives::money::VALIDATOR_BOND;
use obs_rpc::cli::Args;
use obs_wallet::Wallet;

use crate::keys;
use crate::network;
use crate::{field, number, print_json, CliError, Context};

/// Options for the wallet commands.
pub const OPTIONS: &[&'static str] = &[
    "keystore",
    "password-file",
    "password",
    "label",
    "phrase-out",
    "phrase-file",
    "account",
    "to",
    "amount",
    "endpoint",
    "node-key",
    "yes!",
];

/// `wallet new` — create a wallet and seal it to a file.
pub fn new_wallet(context: &Context, args: &Args) -> Result<(), CliError> {
    let path = keys::keystore_path(args)?;
    let password = keys::password(args)?;
    let label = args.or("label", "Obsidian wallet");
    let phrase_out = args.get("phrase-out").map(PathBuf::from);
    let wallet = keys::create_wallet(context.network, &path, &password, &label, phrase_out.as_deref())?;

    println!("obs-cli: wallet written to {}", path.display());
    println!("obs-cli: network       {}", context.network.name);
    println!("obs-cli: address       {}", wallet.address());
    println!("obs-cli: wallet key    {}", hex(&wallet.public_keys().wallet_key));
    println!("obs-cli: node key      {}", hex(&wallet.public_keys().node_key));
    println!("obs-cli: recovery key  {}", hex(&wallet.public_keys().recovery_key));
    match phrase_out {
        Some(path) => println!(
            "obs-cli: recovery phrase written to {} (owner-readable only, keep it offline)",
            path.display()
        ),
        None => println!(
            "obs-cli: no recovery phrase was written.  The phrase cannot be shown later: \
             pass --phrase-out <file> next time if you want a backup of this wallet."
        ),
    }
    println!(
        "obs-cli: the wallet is non-custodial — this file is the only copy, and the \
         password is the only thing that opens it"
    );
    Ok(())
}

/// `wallet recover` — rebuild a wallet from its recovery phrase.
pub fn recover(context: &Context, args: &Args) -> Result<(), CliError> {
    let path = keys::keystore_path(args)?;
    let password = keys::password(args)?;
    let phrase_path = args
        .get("phrase-file")
        .ok_or_else(|| CliError::Usage("--phrase-file <path> is required".to_string()))?;
    let phrase = std::fs::read_to_string(phrase_path)
        .map_err(|error| CliError::Failed(format!("{}: {}", phrase_path, error)))?;
    let account = args.number("account", 0).map_err(|error| CliError::Usage(error.to_string()))?;
    let account = u32::try_from(account).map_err(|_| CliError::Usage("--account is too large".to_string()))?;
    let wallet = Wallet::from_phrase(context.network, phrase.trim(), "", account)
        .map_err(|error| CliError::Failed(format!("the phrase was refused: {}", error)))?;
    if path.exists() {
        if !args.flag("yes") {
            return Err(CliError::Failed(format!(
                "{} already exists; pass --yes to replace it",
                path.display()
            )));
        }
    }
    let keystore = wallet
        .to_keystore(&password, "recovered wallet")
        .map_err(|error| CliError::Failed(format!("the keystore could not be sealed: {}", error)))?;
    keys::write_private(&path, &keystore.to_text())?;
    println!("obs-cli: wallet recovered into {}", path.display());
    println!("obs-cli: address       {}", wallet.address());
    println!("obs-cli: account index {}", account);
    Ok(())
}

/// `wallet address` — the address and the three public keys.
pub fn address(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let keys = wallet.public_keys();
    println!("address       {}", wallet.address());
    println!("wallet_key    {}", hex(&keys.wallet_key));
    println!("node_key      {}", hex(&keys.node_key));
    println!("recovery_key  {}", hex(&keys.recovery_key));
    Ok(())
}

/// `wallet balance` — ask the node, proving ownership of the address.
///
/// This is the only way an account's own value is ever read from the network:
/// the explorer has no balance endpoint at all, and this one requires a signature
/// over a challenge bound to this chain.  A nonce is generated per call, so a
/// proof captured on the wire is useless for another call.
pub fn balance(context: &Context, args: &Args) -> Result<(), CliError> {
    print_json(&prove(context, args)?);
    Ok(())
}

/// The proof call, shared by `balance`, `claim` and `status`.
pub fn prove(context: &Context, args: &Args) -> Result<Json, CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let mut nonce = [0u8; 16];
    obs_crypto::rand::os_random(&mut nonce)
        .map_err(|error| CliError::Failed(format!("no secure randomness: {}", error)))?;
    let nonce = hex(&nonce);
    let signature = sign_proof(&wallet, &nonce);
    let body = Json::obj([
        ("address", Json::Str(wallet.address().to_string())),
        ("nonce", Json::Str(nonce)),
        ("signature", Json::Str(hex(&signature))),
    ]);
    context.node_post("account/proof", &body)
}

/// `wallet claim` — mine one claim.
///
/// The claim is stamped with the node's protocol time, which is the only clock
/// the chain accepts: eligibility (the four-hour interval, the six-a-day cap) is
/// decided by the block that carries the claim, never by this machine's clock.
pub fn claim(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let account = prove(context, args)?;
    // Protocol time, not the wall clock: the chain decides eligibility from the
    // block's timestamp, and the claim declares the time it belongs to.
    let at = context.protocol_time()?;

    if account.get("claimable_now").and_then(Json::as_bool) == Some(false) {
        let next = account.get("next_claim_at").and_then(Json::as_u64).unwrap_or(0);
        let reward = account
            .get("next_claim_reward")
            .and_then(Json::as_str)
            .unwrap_or("0");
        println!("obs-cli: not claimable at protocol time {}", at);
        println!("obs-cli: next claim at     {}", next);
        println!("obs-cli: next claim reward {} OBS", reward);
        println!(
            "obs-cli: eligibility comes from the chain, not from this machine: a claim before \
             that time would be refused"
        );
        return Ok(());
    }

    let sequence = number(&account, "last_claim_sequence")? + 1;
    let nonce = number(&account, "next_nonce")?;
    let tx = Transaction::sign(
        context.network,
        nonce,
        TxKind::Claim(Claim {
            account: wallet.address(),
            claimed_at: at,
            sequence,
        }),
        wallet.wallet_keypair(),
    );
    let reward = account
        .get("next_claim_reward")
        .and_then(Json::as_str)
        .unwrap_or("0");
    submit(context, &tx, &format!("claim {} at protocol time {}", sequence, at))?;
    println!("obs-cli: claim built for protocol time {} (reward {} OBS)", at, reward);
    println!(
        "obs-cli: it is in the node's pool; the block that carries it will be stamped with \
         this exact time"
    );
    Ok(())
}

/// `wallet send` — transfer value, with the protocol's own fee.
pub fn send(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let to = args
        .get("to")
        .ok_or_else(|| CliError::Usage("--to <address> is required".to_string()))?;
    let recipient = Address::parse(context.network, to)
        .map_err(|error| CliError::Usage(format!("--to {}: {}", to, error)))?;
    let amount_text = args
        .get("amount")
        .ok_or_else(|| CliError::Usage("--amount <OBS> is required".to_string()))?;
    let amount = obs_primitives::money::Amount::parse(amount_text)
        .map_err(|error| CliError::Usage(format!("--amount {}: {}", amount_text, error)))?;
    if amount.is_zero() {
        return Err(CliError::Usage("--amount must be more than zero".to_string()));
    }
    let account = prove(context, args)?;
    let nonce = number(&account, "next_nonce")?;
    let balance = obs_primitives::money::Amount::parse(
        field(&account, "balance")?,
    )
    .map_err(|error| CliError::Failed(format!("the node's balance did not parse: {}", error)))?;
    let fee = obs_chain::params::gas_fee_for(amount);
    let total = amount
        .checked_add(fee)
        .ok_or_else(|| CliError::Failed("the amount plus its fee overflows".to_string()))?;
    if balance < total {
        return Err(CliError::Failed(format!(
            "the account holds {} OBS; {} OBS plus a {} OBS fee is more than that",
            balance.to_decimal_string(),
            amount.to_decimal_string(),
            fee.to_decimal_string()
        )));
    }
    let tx = obs_wallet::sign::transfer(&wallet, recipient, amount, nonce)
        .map_err(|error| CliError::Failed(format!("the transfer could not be built: {}", error)))?;
    submit(context, &tx, &format!("transfer of {} OBS to {}", amount.to_decimal_string(), recipient))?;
    println!(
        "obs-cli: fee {} OBS — 40% to the validator pool, 60% to the mining pool, by the protocol's own rule",
        fee.to_decimal_string()
    );
    Ok(())
}

/// `wallet validator register` — bond 50 OBS of the account's own value.
pub fn validator_register(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let endpoint = args.or("endpoint", "");
    let account = prove(context, args)?;
    let balance = obs_primitives::money::Amount::parse(field(&account, "balance")?)
        .map_err(|error| CliError::Failed(format!("the node's balance did not parse: {}", error)))?;
    if balance < VALIDATOR_BOND {
        return Err(CliError::Failed(format!(
            "a validator bond is {} OBS and this account holds {} OBS",
            VALIDATOR_BOND.to_decimal_string(),
            balance.to_decimal_string()
        )));
    }
    let nonce = number(&account, "next_nonce")?;
    let tx = obs_wallet::sign::register_validator(&wallet, &endpoint, nonce)
        .map_err(|error| CliError::Failed(format!("the validator registration could not be built: {}", error)))?;
    submit(context, &tx, "validator registration")?;
    println!(
        "obs-cli: bonding {} OBS from this account; the node identity that attests is a \
         different key, derived from the same wallet",
        VALIDATOR_BOND.to_decimal_string()
    );
    println!("obs-cli: node key      {}", hex(&wallet.public_keys().node_key));
    println!("obs-cli: node address  {}", wallet.node_address());
    Ok(())
}

/// `wallet validator deregister` — start the 48-hour unbonding period.
pub fn validator_deregister(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let account = prove(context, args)?;
    let nonce = number(&account, "next_nonce")?;
    let tx = obs_wallet::sign::deregister_validator(&wallet, nonce)
        .map_err(|error| CliError::Failed(format!("the deregistration could not be built: {}", error)))?;
    submit(context, &tx, "validator deregistration")?;
    println!(
        "obs-cli: the bond returns to this account after the protocol's 48-hour unbonding period"
    );
    Ok(())
}

/// `wallet keys` — the public half of the wallet, in the form the services want.
pub fn public_keys(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let keys = wallet.public_keys();
    let body = Json::obj([
        ("network", Json::Str(context.network.name.to_string())),
        ("address", Json::Str(wallet.address().to_string())),
        ("wallet_key", Json::Str(hex(&keys.wallet_key))),
        ("node_key", Json::Str(hex(&keys.node_key))),
        ("recovery_key", Json::Str(hex(&keys.recovery_key))),
    ]);
    print_json(&body);
    Ok(())
}

/// `wallet chain` — the wallet's own view of the chain: address, proven balance,
/// and what the node would allow next.
pub fn wallet_status(context: &Context, args: &Args) -> Result<(), CliError> {
    let wallet = keys::open_wallet(args, context.network)?;
    let account = prove(context, args)?;
    let status = context.node_get("status")?;
    let merged = Json::obj([
        ("network", Json::Str(context.network.name.to_string())),
        ("chain_id", status.get("chain_id").cloned().unwrap_or(Json::Null)),
        ("address", Json::Str(wallet.address().to_string())),
        ("wallet_key", Json::Str(hex(&wallet.public_keys().wallet_key))),
        ("node_key", Json::Str(hex(&wallet.public_keys().node_key))),
        ("recovery_key", Json::Str(hex(&wallet.public_keys().recovery_key))),
        ("height", status.get("height").cloned().unwrap_or(Json::Null)),
        ("protocol_time", status.get("protocol_time").cloned().unwrap_or(Json::Null)),
        ("account", account),
    ]);
    print_json(&merged);
    Ok(())
}

/// Prints a compact one-line note and then the node's answer.
fn submit(context: &Context, tx: &Transaction, what: &str) -> Result<(), CliError> {
    let id = tx.id();
    let body = Json::obj([("transaction", Json::Str(hex(&tx.to_bytes())))]);
    match context.node_post("transactions", &body) {
        Ok(answer) => {
            println!("obs-cli: {} submitted as {}", what, id.0.to_hex());
            let status = answer
                .get("status")
                .and_then(Json::as_str)
                .unwrap_or("pooled");
            println!("obs-cli: the node answered {}", status);
            Ok(())
        }
        Err(error) => Err(CliError::Failed(format!(
            "{} was refused: {}",
            what, error
        ))),
    }
}

fn sign_proof(wallet: &Wallet, nonce: &str) -> [u8; 64] {
    obs_wallet::sign::account_proof(wallet, nonce)
}

fn hex(bytes: &[u8]) -> String {
    obs_crypto::encoding::hex_encode(bytes)
}

/// The address the CLI says it will use, for scripts that only want that.
pub fn address_of(wallet: &Wallet) -> Address {
    wallet.address()
}

/// Re-exported for the `devnet` module, which prints the same summary.
pub fn summary(context: &Context, wallet: &Wallet) -> Json {
    let _ = network::status(context);
    Json::obj([
        ("address", Json::Str(wallet.address().to_string())),
        ("network", Json::Str(context.network.name.to_string())),
    ])
}
