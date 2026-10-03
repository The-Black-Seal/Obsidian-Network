//! The `obs-cli` entry point: parse, dispatch, report.
//!
//! Every command is one function in one module; this file only decides which one
//! runs and turns its error into an exit code.  Two conventions the whole CLI
//! follows:
//!
//! * **An unknown flag is an error**, never ignored.  A mistyped `--amount` must
//!   not silently transfer something else.
//! * **Secrets go to files, not to the terminal** ([`obs_cli::keys`]), unless a
//!   command is explicitly asked to print one.

use std::process::ExitCode;

use obs_cli::{devnet, keys, network, operator, register, wallet, wallet::*, CliError, Context, COMMON};
use obs_rpc::cli::Args;

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    if argv.is_empty() {
        print!("{}", usage());
        return ExitCode::from(2);
    }
    let command = argv[0].clone();
    let rest = &argv[1..];

    // A command's own options, plus the flags every command accepts.
    let options: Vec<&'static str> = match command.as_str() {
        "status" | "supply" | "mining" | "params" | "block" | "tx" | "blocks"
        | "validators" | "mempool" | "peers" | "events" | "search" => network::OPTIONS.to_vec(),
        "wallet" | "balance" | "claim" | "send" | "validator" | "recover" => wallet::OPTIONS.to_vec(),
        "register" | "sign-in" | "account" | "invite" => register::OPTIONS.to_vec(),
        "devnet" => devnet::OPTIONS.to_vec(),
        "authority" | "portal" => operator::OPTIONS.to_vec(),
        "keys" => keys::WALLET_OPTIONS.to_vec(),
        "help" | "--help" | "-h" => COMMON.to_vec(),
        other => {
            eprintln!("obs-cli: unknown command {:?}", other);
            eprint!("{}", usage());
            return ExitCode::from(2);
        }
    };
    let known = obs_cli::known(&options);
    let args = match Args::parse("obs-cli", rest, &known) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("obs-cli: {}", error);
            return ExitCode::from(2);
        }
    };
    if args.flag("help") || command == "help" {
        print!("{}", usage());
        return ExitCode::SUCCESS;
    }

    let context = match Context::from_args(&args) {
        Ok(context) => context,
        Err(error) => {
            eprintln!("obs-cli: {}", error);
            return ExitCode::from(2);
        }
    };

    let outcome = match (command.as_str(), sub(&argv)) {
        // Network: read what the node reports.
        ("status", _) => network::status(&context),
        ("supply", _) => network::supply(&context),
        ("mining", _) => network::mining(&context),
        ("params", _) => network::params(&context),
        ("validators", _) => network::validators(&context),
        ("mempool", _) => network::mempool(&context),
        ("peers", _) => network::peers(&context),
        ("blocks", _) => limit(&args, 10).and_then(|limit| network::blocks(&context, limit)),
        ("events", _) => limit(&args, 20).and_then(|limit| network::events(&context, limit)),
        ("block", _) => required(&args, "block <height|hash>")
            .and_then(|selector| network::block(&context, &selector)),
        ("tx", _) => required(&args, "tx <id>").and_then(|id| network::transaction(&context, &id)),
        ("search", _) => {
            required(&args, "search <query>").and_then(|query| network::search(&context, &query))
        }

        // Wallet: the user's own keys, locally.
        ("wallet", Some("new")) => new_wallet(&context, &args),
        ("wallet", Some("recover")) => recover(&context, &args),
        ("wallet", Some("address")) => address(&context, &args),
        ("wallet", Some("keys")) => public_keys(&context, &args),
        ("wallet", Some("status")) => wallet_status(&context, &args),
        ("wallet", Some(other)) => Err(usage_error("wallet", other)),
        ("wallet", None) => Err(CliError::Usage(
            "wallet needs a subcommand: new, recover, address, keys, status".to_string(),
        )),
        ("keys", _) => public_keys(&context, &args),
        ("balance", _) => balance(&context, &args),
        ("claim", _) => claim(&context, &args),
        ("send", _) => send(&context, &args),
        ("recover", _) => recover(&context, &args),
        ("validator", Some("register")) => validator_register(&context, &args),
        ("validator", Some("deregister")) => validator_deregister(&context, &args),
        ("validator", Some(other)) => Err(usage_error("validator", other)),
        ("validator", None) => Err(CliError::Usage(
            "validator needs a subcommand: register, deregister".to_string(),
        )),

        // Registration: against a service, with the wallet signing.
        ("register", _) => register::register(&context, &args),
        ("sign-in", _) => register::sign_in(&context, &args),
        ("account", _) => register::account(&context, &args),
        ("invite", Some("issue")) => register::issue_invite(&context, &args),
        ("invite", Some("mint")) => operator::invite_mint(&context, &args),
        ("invite", Some(other)) => Err(usage_error("invite", other)),
        ("invite", None) => Err(CliError::Usage(
            "invite needs a subcommand: issue (your own budget), mint (an operator's)".to_string(),
        )),

        // Operator: the authority, a devnet, portal keys.
        ("authority", Some("generate")) => operator::authority_generate(&context, &args),
        ("authority", Some("print")) => operator::authority_print(&context, &args),
        ("authority", Some(other)) => Err(usage_error("authority", other)),
        ("authority", None) => Err(CliError::Usage(
            "authority needs a subcommand: generate, print".to_string(),
        )),
        ("devnet", Some("init")) => devnet::init(&context, &args),
        ("devnet", Some("register")) => devnet::register(&context, &args),
        ("devnet", Some("expect-genesis")) => devnet::expect_genesis(&context, &args),
        ("devnet", Some(other)) => Err(usage_error("devnet", other)),
        ("devnet", None) => Err(CliError::Usage("devnet needs a subcommand: init, expect-genesis".to_string())),
        ("portal", Some("key")) => operator::portal_key(&context, &args),
        ("portal", Some(other)) => Err(usage_error("portal", other)),
        ("portal", None) => Err(CliError::Usage("portal needs a subcommand: key".to_string())),
        ("help", _) => Ok(()),
        (other, _) => Err(CliError::Usage(format!("unknown command {:?}", other))),
    };

    match outcome {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("obs-cli: {}", error);
            match error {
                CliError::Usage(_) => ExitCode::from(2),
                CliError::Failed(_) | CliError::Transport(_) => ExitCode::from(1),
            }
        }
    }
}

/// The subcommand, if the command takes one.
fn sub(argv: &[String]) -> Option<&str> {
    argv.get(1).map(|value| value.as_str()).filter(|value| !value.starts_with('-'))
}

fn required(args: &Args, what: &str) -> Result<String, CliError> {
    args.positional()
        .last()
        .cloned()
        .or_else(|| args.get("q").map(|value| value.to_string()))
        .ok_or_else(|| CliError::Usage(format!("{} is required", what)))
}

fn limit(args: &Args, default: u64) -> Result<u64, CliError> {
    args.number("limit", default)
        .map(|value| value.clamp(1, 100))
        .map_err(|error| CliError::Usage(error.to_string()))
}

fn usage_error(command: &str, subcommand: &str) -> CliError {
    CliError::Usage(format!("{} has no subcommand {:?}", command, subcommand))
}

fn usage() -> String {
    "obs-cli — the Obsidian Network command-line client

Usage: obs-cli <command> [subcommand] [options]

Read the network
  status                     the node's summary: height, head, protocol time, supply
  supply                     issuance: maximum, issued, pools, remaining
  mining                     the reward for the next claim and who is active
  params                     the protocol constants the node enforces
  blocks [--limit n]         recent blocks, newest first
  block <height|hash>        one block, with its transactions
  tx <id>                    one transaction
  validators                 the validator set and the evidence behind each score
  mempool                    transactions accepted but not yet mined
  peers                      connected peers
  events [--limit n]         what the node mined, refused or learned
  search <query>             by height, block hash or address

Your wallet (local, non-custodial)
  wallet new --keystore <file> [--phrase-out <file>] [--label s]
  wallet recover --keystore <file> --phrase-file <file>
  wallet address --keystore <file>
  wallet keys --keystore <file>
  wallet status --keystore <file>          address, proven account state, chain head
  balance --keystore <file>                proves ownership, then reads your own value
  claim --keystore <file>                  one mining claim, stamped with protocol time
  send --keystore <file> --to <address> --amount <OBS>
  validator register --keystore <file> [--endpoint <url>]
  validator deregister --keystore <file>

Account registration (six steps, no email code)
  register --gmail <a@gmail.com> --invite <code> --keystore <file> [--phrase-out <file>]
  sign-in --gmail <a@gmail.com> --code <TOTP> --session-out <file>
  account --session-out <file>
  invite issue --session-out <file>        spend one of your five invitations

Operator
  devnet init --data-dir <dir> [--keystore <file>] [--password-file <file>]
  devnet register --data-dir <dir> [--keystore <file>] [--password-file <file>]
  devnet expect-genesis
  authority generate --authority-key <file>
  authority print --authority-key <file>
  invite mint --store <file> --code <code> [--genesis] [--expires-in <secs>]
  portal key --session <token> [--label s] [--scopes s] [--limit n]

Common options
  --network <devnet|testnet|staging|mainnet>   default devnet
  --node-url <url>                             default http://127.0.0.1:7200
  --gateway-url <url>                          default http://127.0.0.1:8080
  --password-file <path>                       keystore password (or OBS_WALLET_PASSWORD)

A password is never taken as an argument, and a recovery phrase is never printed
unless you name a file for it: arguments are visible to other processes, and a
phrase in a terminal ends up in the scrollback buffer.
"
    .to_string()
}
