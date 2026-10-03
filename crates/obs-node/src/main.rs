//! `obs-node` — run a full node.
//!
//! ```text
//!   obs-node --network devnet --data-dir ./data/devnet --mine-seed <hex32>
//!   obs-node --network mainnet --data-dir /var/lib/obsidian --peer host:9220 --fsync
//! ```
//!
//! The node is the authority's edge: it holds chain state, validates every block
//! and transaction it sees, serves the node API, and talks to peers.  Everything
//! else in the network — the registration service, the explorer, the wallet —
//! reads what a node says and can change none of it.
//!
//! ## What the flags mean, and why some of them are deliberately awkward
//!
//! * `--network` selects a chain.  Each network has its own chain id, its own
//!   genesis and its own database directory; a node started with the wrong
//!   network is on a different chain, and peers on the other one will refuse it.
//! * `--genesis-timestamp` pins the network's epoch.  Protocol time advances
//!   *through blocks*, at most a minute per block, so a network's genesis is its
//!   launch moment: a devnet started with an epoch in the past cannot produce a
//!   block at all, and this binary says so rather than looping quietly.
//! * `--mine-seed` is a private key in hex on the command line, which is only
//!   appropriate for a development network.  A production miner keeps its key in
//!   a keystore and starts the node without one.
//! * `--data-dir` is the node's own store.  Losing it means resyncing from peers;
//!   it is never shared between networks.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use obs_crypto::ed25519::Keypair;
use obs_crypto::encoding::hex_encode;
use obs_node::rpc::NodeApi;
use obs_node::{Node, NodeConfig};
use obs_primitives::network::{Network, DEVNET, MAINNET, STAGING, TESTNET};
use obs_rpc::cli::Args;
use obs_rpc::server::{Server, ServerConfig};

const KNOWN: &[&str] = &[
    "network",
    "data-dir",
    "api-port",
    "listen-port",
    "genesis-timestamp",
    "authority-key",
    "node-seed",
    "mine-seed",
    "keystore",
    "keystore-password-file",
    "mine!",
    "validator!",
    "peer",
    "block-interval-ms",
    "fsync!",
    "help!",
];

fn usage() -> String {
    format!(
        "obs-node — run an Obsidian Network full node

Usage: obs-node [options]

  --network <name>           devnet (default), testnet, staging, mainnet
  --data-dir <path>          chain store directory (default ./data/<network>)
  --api-port <n>             node API port (default 7200)
  --listen-port <n>          peer port (default 9220)
  --genesis-timestamp <t>    the network's epoch: unix seconds, or `now` (default: the
                             network's configured epoch — for a new devnet, use `now`)
  --authority-key <hex32>    registration authority public key for this network
  --node-seed <hex32>        this node's identity key (default: derived from the data directory)
  --mine-seed <hex32>        mine with this wallet key (development only)
  --keystore <path>          a wallet keystore: its node key becomes this node's
                             identity, and with --mine its wallet key mines
  --keystore-password-file <path>  the password for --keystore, read from a file
  --mine                     mine with the keystore's wallet key
  --validator                attest as a validator with the node identity
  --peer <host:port>         dial a peer at startup (repeatable)
  --block-interval-ms <n>    how often to consider proposing (default 5000)
  --fsync                    flush every write to disk
  --help                     this text

Protocol time is a chain quantity: it advances at most 60 seconds per block, so
a network's genesis timestamp is its launch moment.  Start a devnet with the
default (now) and it will produce blocks; start one with an epoch in the past and
it will tell you, rather than waiting forever for a block that cannot be made.
"
    )
}

/// Opens a wallet keystore, refusing a wallet from another network.
fn opening_wallet(
    path: &str,
    password: &str,
    network: Network,
) -> Result<obs_wallet::Wallet, String> {
    let text = std::fs::read_to_string(path).map_err(|error| format!("{}: {}", path, error))?;
    let keystore = obs_wallet::keystore::Keystore::from_text(&text)
        .map_err(|error| format!("{}: {}", path, error))?;
    if keystore.network() != network {
        return Err(format!(
            "{} holds a {} wallet, but this node runs {}",
            path,
            keystore.network().name,
            network.name
        ));
    }
    keystore
        .open(password)
        .map_err(|error| format!("{}: {}", path, error))
}

fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_secs())
        .unwrap_or(0)
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

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse("obs-node", &argv, KNOWN) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("obs-node: {}", error);
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
            eprintln!("obs-node: --network must be devnet, testnet, staging or mainnet");
            return ExitCode::from(2);
        }
    };

    // The data directory defaults to one directory per network, so a machine
    // running two of them cannot mix their stores up.
    let default_data_dir = format!("data/{}", network.name);
    let data_dir = match args.path("data-dir", Some(&default_data_dir)) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };

    let authority = match args.hex32("authority-key") {
        Ok(Some(key)) => key,
        Ok(None) => {
            // Without a registration authority no invitation can be authorised,
            // so registration on this node would be impossible.  That is a
            // legitimate configuration for a read-only or mining-only node, but
            // it must be said out loud.
            eprintln!(
                "obs-node: no --authority-key given: this node will accept no registration \
                 transaction, because it cannot verify an invitation authorisation"
            );
            [0u8; 32]
        }
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };

    let node_seed = match args.hex32("node-seed") {
        Ok(seed) => seed,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };
    let mining_seed = match args.hex32("mine-seed") {
        Ok(seed) => seed,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };

    let api_port = match args.port("api-port", 7200) {
        Ok(port) => port,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };
    let listen_port = match args.port("listen-port", obs_p2p::DEFAULT_PORT) {
        Ok(port) => port,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };
    let interval_ms = match args.number("block-interval-ms", 5_000) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("obs-node: {}", error);
            return ExitCode::from(2);
        }
    };
    let peers: Vec<std::net::SocketAddr> = args
        .all("peer")
        .iter()
        .filter_map(|peer| match peer.parse() {
            Ok(address) => Some(address),
            Err(_) => {
                eprintln!("obs-node: --peer {} is not a host:port address", peer);
                None
            }
        })
        .collect();
    if peers.len() != args.all("peer").len() {
        return ExitCode::from(2);
    }

    // A wallet keystore, when the operator supplied one.  The node's identity is
    // the wallet's *node* key — a key derived for attesting, kept distinct from
    // the wallet key that holds value — and with `--mine` the wallet key mines.
    // The key stays encrypted at rest: nothing here writes a private key to a
    // plaintext file or takes one from the command line.
    let wallet = match args.get("keystore") {
        Some(path) => {
            let password = match args.get("keystore-password-file") {
                Some(password_path) => match std::fs::read_to_string(password_path) {
                    Ok(text) => text.trim_end_matches(['\n', '\r']).to_string(),
                    Err(error) => {
                        eprintln!("obs-node: --keystore-password-file {}: {}", password_path, error);
                        return ExitCode::from(1);
                    }
                },
                None => match std::env::var("OBS_WALLET_PASSWORD") {
                    Ok(password) if !password.is_empty() => password,
                    _ => {
                        eprintln!(
                            "obs-node: --keystore needs a password: pass \
                             --keystore-password-file <path> or set OBS_WALLET_PASSWORD"
                        );
                        return ExitCode::from(2);
                    }
                },
            };
            match opening_wallet(path, &password, network) {
                Ok(wallet) => Some(wallet),
                Err(message) => {
                    eprintln!("obs-node: {}", message);
                    return ExitCode::from(1);
                }
            }
        }
        None => None,
    };
    let keystore_node_key = wallet.as_ref().map(|wallet| wallet.node_keypair().clone());
    let keystore_mining_key = wallet.as_ref().map(|wallet| wallet.wallet_keypair().clone());

    // The node identity is a *separate key* from any wallet, exactly as the
    // protocol requires: an identity that doubles as a wallet would tie
    // attestations to funds.
    let node_key = match (&node_seed, keystore_node_key) {
        (Some(seed), _) => Keypair::from_seed(seed),
        (None, Some(key)) => key,
        (None, None) => match load_or_create_identity(&data_dir) {
            Ok(key) => key,
            Err(message) => {
                eprintln!("obs-node: {}", message);
                return ExitCode::from(1);
            }
        },
    };

    let mut config = NodeConfig::new(network, &data_dir, authority, node_key.clone());
    config.listen_port = listen_port;
    config.fsync = args.flag("fsync");
    config.peers = peers;
    config.block_interval = Duration::from_millis(interval_ms.max(1));
    // `--genesis-timestamp now` is the honest shorthand for "found this network
    // at this moment"; a devnet that starts any other way cannot make a block,
    // because protocol time advances at most a minute per block from its epoch.
    match args.get("genesis-timestamp") {
        Some("now") => config.genesis.timestamp = unix_now(),
        Some(value) => match value.parse::<u64>() {
            Ok(timestamp) if timestamp > 0 => config.genesis.timestamp = timestamp,
            _ => {
                eprintln!("obs-node: --genesis-timestamp expects unix seconds or `now`");
                return ExitCode::from(2);
            }
        },
        None => {}
    }
    if args.flag("validator") {
        config = config.with_validator(node_key.clone());
    }
    if let Some(seed) = mining_seed {
        config = config.with_mining(Keypair::from_seed(&seed));
    } else if args.flag("mine") {
        match keystore_mining_key {
            Some(key) => config = config.with_mining(key),
            None => {
                eprintln!("obs-node: --mine needs a key to mine with: pass --keystore <path>");
                return ExitCode::from(2);
            }
        }
    }

    let node = match Node::open(config) {
        Ok(node) => node,
        Err(error) => {
            eprintln!("obs-node: the node could not start: {}", error);
            return ExitCode::from(1);
        }
    };

    // The genesis-epoch check: a chain cannot produce its first block until its
    // own clock has reached its epoch, and protocol time itself barely moves
    // without blocks.  A node whose epoch is in the past can never catch up, so
    // it is a configuration error worth reporting before the loop starts.
    if let Some(event) = node.genesis_epoch_gap() {
        eprintln!("obs-node: {}", describe_event(&event));
        eprintln!(
            "obs-node: this node is on a chain whose genesis epoch has passed; it cannot \
             produce a block.  Start the network with --genesis-timestamp set to now (a new \
             devnet), or join the existing network instead of founding a new one."
        );
        return ExitCode::from(1);
    }

    let api = Arc::new(NodeApi::new(node));
    let address = node_address(&api);

    println!("obs-node: {} (chain id {})", network.name, network.chain_id);
    println!("obs-node: data directory  {}", data_dir.display());
    println!("obs-node: node identity   {}", hex_encode(&node_key.public_key()));
    println!("obs-node: node address    {}", address);
    println!("obs-node: peer port       {}", listen_port);
    println!("obs-node: api             http://127.0.0.1:{}/api/v1/status", api_port);
    println!(
        "obs-node: mining          {}",
        if api.node().lock().map(|node| node.config().mine).unwrap_or(false) {
            "enabled"
        } else {
            "disabled"
        }
    );
    println!("obs-node: protocol time advances through blocks; press Ctrl-C to stop");

    // The API and the node loop run together: the loop on a thread of its own,
    // the API on the main thread so a Ctrl-C always stops the whole process.
    let shutdown = Arc::new(AtomicBool::new(false));
    let loop_shutdown = Arc::clone(&shutdown);
    let loop_api = Arc::clone(&api);
    let node_thread = std::thread::spawn(move || {
        let node = loop_api.node();
        loop {
            if loop_shutdown.load(Ordering::Relaxed) {
                break;
            }
            let outcome = match node.lock() {
                Ok(mut node) => node.step(),
                Err(_) => break,
            };
            let _ = outcome;
            std::thread::sleep(Duration::from_millis(50));
        }
    });

    let server = match Server::bind(("0.0.0.0", api_port), ServerConfig::default()) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("obs-node: the API could not bind port {}: {}", api_port, error);
            shutdown.store(true, Ordering::Relaxed);
            let _ = node_thread.join();
            return ExitCode::from(1);
        }
    };
    let served = server.serve(api as Arc<dyn obs_rpc::server::Handler>, Arc::clone(&shutdown));
    shutdown.store(true, Ordering::Relaxed);
    let _ = node_thread.join();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("obs-node: the API stopped: {}", error);
            ExitCode::from(1)
        }
    }
}

/// The node's address, for the startup banner: derived from its identity key.
fn node_address(api: &Arc<NodeApi>) -> String {
    let handle = api.node();
    let node = match handle.lock() {
        Ok(node) => node,
        Err(_) => return "(unavailable)".to_string(),
    };
    let identity = node.config().node_key.public_key();
    obs_primitives::address::Address::from_public_key(node.config().network, &identity).to_string()
}

fn describe_event(event: &obs_node::NodeEvent) -> String {
    format!("{:?}", event)
}

/// Loads the node's identity key from its data directory, creating one on first
/// start.
///
/// The identity is the key that signs attestations and identifies the node to
/// its peers.  It is not a wallet, it never holds value, and it is stored with
/// owner-only permissions because an identity that can be borrowed is a
/// validator that can be impersonated.
fn load_or_create_identity(
    data_dir: &std::path::Path,
) -> Result<Keypair, String> {
    let path = data_dir.join("node-identity.key");
    if let Ok(text) = std::fs::read_to_string(&path) {
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if let Some(hex) = line.strip_prefix("seed ") {
                let bytes = obs_crypto::encoding::hex_decode(hex.trim())
                    .ok_or_else(|| format!("{}: the seed is not hex", path.display()))?;
                if bytes.len() != 32 {
                    return Err(format!("{}: the seed must be 32 bytes", path.display()));
                }
                let mut seed = [0u8; 32];
                seed.copy_from_slice(&bytes);
                let keypair = Keypair::from_seed(&seed);
                seed.fill(0);
                return Ok(keypair);
            }
        }
        return Err(format!("{}: no seed line", path.display()));
    }

    let mut seed = [0u8; 32];
    obs_crypto::rand::os_random(&mut seed).map_err(|error| format!("no secure randomness: {}", error))?;
    let keypair = Keypair::from_seed(&seed);
    let document = format!(
        "# Obsidian Network node identity.  This key signs attestations; it holds no\n\
         # value and must never be the same key as a wallet.  Keep it private.\n\
         seed {}\n\
         public {}\n",
        hex_encode(&seed),
        hex_encode(&keypair.public_key())
    );
    seed.fill(0);
    std::fs::create_dir_all(data_dir).map_err(|error| format!("{}: {}", data_dir.display(), error))?;
    write_private(&path, &document)?;
    println!("obs-node: created a node identity at {}", path.display());
    Ok(keypair)
}

fn write_private(path: &std::path::Path, document: &str) -> Result<(), String> {
    use std::io::Write;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options
        .open(path)
        .map_err(|error| format!("{}: {}", path.display(), error))?;
    file.write_all(document.as_bytes())
        .map_err(|error| format!("{}: {}", path.display(), error))?;
    Ok(())
}
