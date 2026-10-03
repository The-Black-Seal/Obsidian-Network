//! `obs-gateway` — run the registration service.
//!
//! ```text
//!   obs-gateway --generate-authority --authority-key ./authority.key --network devnet
//!   obs-gateway --authority-key ./authority.key --network mainnet --port 8080
//!   obs-gateway --mint-invite OBS-ABCD-EFGH-JKMP-QRST --store ./accounts.json
//! ```
//!
//! The service exists for two jobs, and its flags are grouped by them:
//!
//! 1. **Accounts.**  Run the invitation-gated enrolment flow, sign-in with MFA,
//!    account recovery, and the invitation budget.  That is the server.
//! 2. **The invitation authority.**  Mint network invitations, and sign the
//!    authorisations that let a client's own wallet register on chain.  The
//!    authority's key is a real secret: it lives in its own file, written with
//!    owner-only permissions, and the service refuses to start without it rather
//!    than inventing a new identity that the network's genesis does not know.
//!
//! Invitations are minted on the command line, not over HTTP: an operator hands
//! a code to a person, out of band.  The code is never echoed, never logged and
//! never stored — only its hash is — so a transcript of the mint command gives
//! nothing away, and the operator is expected to have the code already.

use std::process::ExitCode;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;

use obs_gateway::accounts::Registry;
use obs_gateway::api::Gateway;
use obs_gateway::authority::Authority;
use obs_gateway::store::AtomicStore;
use obs_primitives::network::{Network, DEVNET, MAINNET, STAGING, TESTNET};
use obs_rpc::cli::Args;
use obs_rpc::server::{Server, ServerConfig};

const KNOWN: &[&str] = &[
    "bind",
    "network",
    "store",
    "authority-key",
    "service-key",
    "generate-authority!",
    "mint-invite",
    "mint-genesis-invite",
    "expires-in",
    "print-authority!",
    "port",
    "help!",
];

/// Where a service listens.
///
/// `0.0.0.0` is the default because a node or an interface is usually reached
/// from another machine; a deployment that puts a TLS terminator in front of a
/// service binds it to `127.0.0.1` instead, so the port is not reachable from
/// the network at all.  An address that does not parse is refused rather than
/// handed to the socket layer, because a mistyped bind address that silently
/// became "every interface" is a security bug, not a typo.
fn bind_address(args: &Args, default: &str) -> Result<String, String> {
    let given = args.or("bind", default);
    match given.trim().parse::<std::net::IpAddr>() {
        Ok(address) => Ok(address.to_string()),
        Err(_) => Err(format!(
            "--bind {:?} is not an IP address; use 127.0.0.1 to keep this port local, or \
             0.0.0.0 to accept connections from the network",
            given
        )),
    }
}

fn usage() -> String {

    "obs-gateway — the Obsidian Network registration service

Usage: obs-gateway [options]

  --network <name>            devnet (default), testnet, staging, mainnet
  --store <path>              account store (default ./data/<network>/accounts.json)
  --authority-key <path>      the invitation-authority key file (default ./data/<network>/authority.key)
  --service-key <hex32>       key that seals TOTP secrets at rest
                              (default: derived from the authority key file)
  --bind <ip>                 address to listen on (default 0.0.0.0; use
                              127.0.0.1 when a TLS proxy is in front)
  --port <n>                  listen port (default per network: mainnet 8180,
                              testnet 8183, staging 8185, devnet 8080)

  --generate-authority        create the authority key file and exit
  --print-authority           print the authority's public key and exit
  --mint-invite <CODE>        mint a single-use invitation for this network and exit
  --mint-genesis-invite <CODE> mint the one network invitation a new network starts with
  --expires-in <secs>         how long a minted invitation stays valid (default 30 days)

  --help                      this text

The authority key is what binds an invitation to the identity it was issued for.
Keep it out of source control and back it up: without it, no new account can be
registered on this network.  Invitation codes are stored only as hashes, so a
minted code that is lost must be minted again.
"
    .to_string()
}

fn network_by_name(name: &str) -> Option<Network> {
    match name {
        "mainnet" => Some(MAINNET),
        "testnet" => Some(TESTNET),
        "devnet" => Some(DEVNET),
        "staging" => Some(STAGING),
        _ => None,
    }
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse("obs-gateway", &argv, KNOWN) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };
    if args.flag("help") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    let network = match network_by_name(&args.or("network", "devnet")) {
        Some(network) => network,
        None => {
            eprintln!("obs-gateway: --network must be devnet, testnet, staging or mainnet");
            return ExitCode::from(2);
        }
    };
    let default_dir = format!("data/{}", network.name);
    let store_path = match args.path("store", Some(&format!("{}/accounts.json", default_dir))) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(2);
        }
    };
    let authority_path = match args.path("authority-key", Some(&format!("{}/authority.key", default_dir)))
    {
        Ok(path) => path,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(2);
        }
    };

    // --- the authority ---------------------------------------------------
    let authority = if args.flag("generate-authority") {
        match Authority::generate(&authority_path, network) {
            Ok(authority) => {
                println!("obs-gateway: wrote the registration authority for {}", network.name);
                println!("obs-gateway: public key {}", authority.public_key_hex());
                println!(
                    "obs-gateway: pass this to every node of the network: obs-node --authority-key {}",
                    authority.public_key_hex()
                );
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("obs-gateway: {}", error);
                return ExitCode::from(1);
            }
        }
    } else {
        match Authority::load(&authority_path, network) {
            Ok(authority) => authority,
            Err(error) => {
                eprintln!("obs-gateway: {}", error);
                return ExitCode::from(1);
            }
        }
    };

    if args.flag("print-authority") {
        println!("{}", authority.public_key_hex());
        return ExitCode::SUCCESS;
    }

    // The service key seals reversible secrets (TOTP) at rest.  Deriving it from
    // the authority key file means one secret to protect instead of two, and an
    // operator can still supply their own.
    let service_key = match args.hex32("service-key") {
        Ok(Some(key)) => key,
        Ok(None) => obs_crypto::sha2::sha256_tagged(
            "OBSIDIAN/GATEWAY-SERVICE-KEY/v1",
            &authority.public_key(),
        ),
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(2);
        }
    };

    let store = match AtomicStore::open(&store_path, true) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(1);
        }
    };
    let mut registry = match Registry::open(store, network, service_key) {
        Ok(registry) => registry,
        Err(error) => {
            eprintln!("obs-gateway: the account store could not be opened: {}", error);
            return ExitCode::from(1);
        }
    };

    // --- operator commands ------------------------------------------------
    let minted = if let Some(code) = args.get("mint-invite") {
        Some((code.to_string(), false, args.number("expires-in", 30 * 24 * 3_600)))
    } else {
        args.get("mint-genesis-invite")
            .map(|code| (code.to_string(), true, args.number("expires-in", 365 * 24 * 3_600)))
    };
    if let Some((code, genesis, expires)) = minted {
        let expires_in = match expires {
            Ok(value) => value,
            Err(error) => {
                eprintln!("obs-gateway: {}", error);
                return ExitCode::from(2);
            }
        };
        let now = unix_now();
        match registry.mint_network_invite(&code, now, now + expires_in, genesis) {
            Ok(()) => {
                // Note what is *not* printed: the code itself.  The operator has
                // it; a transcript of this command must not.
                println!(
                    "obs-gateway: minted a {} invitation for {}",
                    if genesis { "genesis" } else { "network" },
                    network.name
                );
                println!(
                    "obs-gateway: commitment {}",
                    obs_chain::invite_commitment(network.chain_id, &code).to_hex()
                );
                println!(
                    "obs-gateway: valid until {} ({})",
                    now + expires_in,
                    obs_rpc::http::http_date(now + expires_in)
                );
                println!("obs-gateway: store {}", store_path.display());
                println!(
                    "obs-gateway: the code itself is not printed and is stored only as a hash"
                );
                return ExitCode::SUCCESS;
            }
            Err(error) => {
                eprintln!("obs-gateway: the invitation could not be minted: {}", error);
                return ExitCode::from(1);
            }
        }
    }

    // --- the service ------------------------------------------------------
    let bind = match bind_address(&args, "0.0.0.0") {
        Ok(bind) => bind,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(2);
        }
    };
    let port = match args.port("port", network.service_port) {
        Ok(port) => port,
        Err(error) => {
            eprintln!("obs-gateway: {}", error);
            return ExitCode::from(2);
        }
    };
    // One registry, one lock, one writer: the gateway and anything else in this
    // deployment that needs to read accounts share this handle.
    let registry = Arc::new(std::sync::Mutex::new(registry.with_authority(authority)));
    let gateway = Arc::new(Gateway::from_shared(Arc::clone(&registry), network));

    println!("obs-gateway: {} (chain id {})", network.name, network.chain_id);
    println!("obs-gateway: account store {}", store_path.display());
    println!("obs-gateway: authority key {}", authority_path.display());
    println!(
        "obs-gateway: authority     {}",
        registry
            .lock()
            .map(|registry| registry
                .authority_public_key()
                .map(|key| obs_crypto::encoding::hex_encode(&key))
                .unwrap_or_else(|| "(none)".to_string()))
            .unwrap_or_else(|_| "(unavailable)".to_string())
    );
    println!("obs-gateway: accounts      {}", registry.lock().map(|r| r.account_count()).unwrap_or(0));
    println!("obs-gateway: listening     http://{}:{}", bind, port);
    println!("obs-gateway: flow          gmail → password → invite → recovery code → mfa → wallet → activated");
    println!("obs-gateway: secrets are hashed at rest; recovery and invitation codes are shown once");

    let shutdown = Arc::new(AtomicBool::new(false));
    let server = match Server::bind((bind.as_str(), port), ServerConfig::default()) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("obs-gateway: the service could not bind port {}: {}", port, error);
            return ExitCode::from(1);
        }
    };
    match server.serve(gateway as Arc<dyn obs_rpc::server::Handler>, Arc::clone(&shutdown)) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("obs-gateway: the service stopped: {}", error);
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod usage_tests {
    use super::*;

    /// Every flag the help text offers must be a flag the parser accepts.
    ///
    /// Two operator commands in this workspace were documented and unusable —
    /// `obs-app --logo-source` and `obs-cli invite mint --store` — for exactly
    /// this reason: the help text and the accepted-flag list were written in
    /// different places, and nothing compared them.  This compares them.
    #[test]
    fn every_flag_in_the_help_text_is_accepted() {
        let text = usage();
        let mut checked = 0;
        for word in text.split(|c: char| c.is_whitespace() || c == '(' || c == ')' || c == ',') {
            let Some(flag) = word.strip_prefix("--") else { continue };
            let flag = flag.trim_end_matches(|c: char| !(c.is_ascii_alphanumeric() || c == '-'));
            if flag.is_empty() || flag == "help" {
                continue;
            }
            let boolean = format!("{}!", flag);
            assert!(
                KNOWN.contains(&flag) || KNOWN.contains(&boolean.as_str()),
                "the help text offers --{} but the parser does not accept it",
                flag
            );
            checked += 1;
        }
        assert!(checked >= 5, "the help text names too few flags to be the real one");
    }
}
