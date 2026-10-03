//! `obs-app` — run the Explorer and the Developer Portal.
//!
//! ```text
//!   obs-app --node-url http://127.0.0.1:7200 --port 8081 --static-dir web
//!   obs-app --node-url http://127.0.0.1:7200 --accounts --authority-key ./authority.key
//! ```
//!
//! This service reads a node and publishes what it finds: blocks, transactions,
//! validator participation, issuance, and — under the privacy contract — address
//! *activity*, never balances.  With `--accounts` it also hosts the registration
//! service in the same process, which is what a small deployment wants: one
//! origin, one session, one place to point a browser at.
//!
//! Three things it deliberately cannot do: create a block, change a balance, or
//! answer a question about somebody's funds.  The first two are impossible
//! because it has no key and no write path; the third is refused by the privacy
//! contract on every response, and by the route table, which has no balance
//! endpoint at all.

use std::process::ExitCode;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use obs_app::api::{App, AppConfig};
use obs_app::logo::LogoSource;
use obs_app::indexer::Indexer;
use obs_app::portal::Portal;
use obs_app::privacy::ROUTES;
use obs_gateway::accounts::Registry;
use obs_gateway::api::Gateway;
use obs_gateway::authority::Authority;
use obs_gateway::store::AtomicStore;
use obs_primitives::network::{Network, DEVNET, MAINNET, STAGING, TESTNET};
use obs_rpc::cli::Args;
use obs_rpc::server::{Server, ServerConfig};

const KNOWN: &[&str] = &[
    "network",
    "port",
    "node-url",
    "store",
    "static-dir",
    "require-key!",
    "accounts!",
    "accounts-store",
    "authority-key",
    "service-key",
    "allowed-origin",
    "sync-ms",
    "print-routes!",
    "help!",
];

fn usage() -> String {
    format!(
        "obs-app — the Obsidian Network Explorer and Developer Portal

Usage: obs-app [options]

  --network <name>       devnet (default), testnet, staging, mainnet
  --node-url <url>       the node to index (default http://127.0.0.1:7200)
  --port <n>             listen port (default 8081)
  --store <path>         developer-portal store (default ./data/<network>/portal.json)
  --static-dir <path>    serve the web interface from here
  --logo-source <url>    fetch the official logo from this URL, server-side
                         (also OBSIDIAN_LOGO_URL; the URL is never sent to a
                         browser and never appears in a log line)

  --require-key          require an API key for explorer reads
  --allowed-origin <o>   extra origin allowed to make state-changing requests (repeatable)

  --accounts             also host the registration service in this process
  --accounts-store <p>   account store (default ./data/<network>/accounts.json)
  --authority-key <path> invitation-authority key file (default ./data/<network>/authority.key)
  --service-key <hex32>  key that seals TOTP secrets at rest

  --sync-ms <n>          how often to follow the node (default 2000)
  --print-routes         print every public route and exit
  --help                 this text

The Explorer publishes blocks, transactions, validator participation and supply,
and address *activity* as partial addresses.  It never publishes a balance: an
account's own state is available only from the node, to a caller who signs the
node's challenge.  {routes} public routes exist, and no other route is served.
",
        routes = ROUTES.len()
    )
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

/// The chain's own time: the timestamp of the node's head block.
///
/// This is the clock the chain checks invitation authorisations against, and the
/// only clock a registration may be dated with.  `None` when the node cannot be
/// reached — the caller then refuses the step instead of guessing, which is the
/// fail-closed behaviour: an authorisation this deployment cannot date correctly
/// is one it must not mint.
fn node_head_time(node_url: &str) -> Option<u64> {
    let client = obs_rpc::client::Client::with_timeout(std::time::Duration::from_secs(4));
    let response = client
        .get(&format!("{}/api/v1/status", node_url.trim_end_matches('/')))
        .ok()?;
    if response.status.code() != 200 {
        return None;
    }
    let value = obs_rpc::client::json_body(&response).ok()?;
    let time = value
        .get("last_block_time")
        .and_then(obs_primitives::json::Json::as_i128)?;
    u64::try_from(time).ok().filter(|time| *time > 0)
}

fn main() -> ExitCode {
    let argv: Vec<String> = std::env::args().skip(1).collect();
    let args = match Args::parse("obs-app", &argv, KNOWN) {
        Ok(args) => args,
        Err(error) => {
            eprintln!("obs-app: {}", error);
            eprintln!("{}", usage());
            return ExitCode::from(2);
        }
    };
    if args.flag("help") {
        println!("{}", usage());
        return ExitCode::SUCCESS;
    }
    if args.flag("print-routes") {
        for route in ROUTES {
            println!(
                "{:<6} {:<42} {}",
                route.method,
                route.path,
                route.scope.unwrap_or("-")
            );
        }
        return ExitCode::SUCCESS;
    }
    let network = match network_by_name(&args.or("network", "devnet")) {
        Some(network) => network,
        None => {
            eprintln!("obs-app: --network must be devnet, testnet, staging or mainnet");
            return ExitCode::from(2);
        }
    };
    let default_dir = format!("data/{}", network.name);
    let port = match args.port("port", 8081) {
        Ok(port) => port,
        Err(error) => {
            eprintln!("obs-app: {}", error);
            return ExitCode::from(2);
        }
    };
    let sync_ms = match args.number("sync-ms", 2_000) {
        Ok(value) => value,
        Err(error) => {
            eprintln!("obs-app: {}", error);
            return ExitCode::from(2);
        }
    };
    let node_url = args.or("node-url", "http://127.0.0.1:7200");
    let portal_path = match args.path("store", Some(&format!("{}/portal.json", default_dir))) {
        Ok(path) => path,
        Err(error) => {
            eprintln!("obs-app: {}", error);
            return ExitCode::from(2);
        }
    };

    let config = AppConfig {
        node_url: node_url.clone(),
        network,
        require_key: args.flag("require-key"),
        allowed_origins: args.all("allowed-origin"),
        static_dir: args.get("static-dir").map(|dir| dir.to_string()),
        // The source may be given as a flag or in the environment.  It is read
        // here and never printed: the type redacts itself, and the start-up line
        // below says only *that* a source is configured.
        logo_source: args
            .get("logo-source")
            .map(|url| url.to_string())
            .or_else(|| std::env::var("OBSIDIAN_LOGO_URL").ok())
            .filter(|url| !url.trim().is_empty())
            .map(LogoSource::new),
        ..AppConfig::default()
    };
    if let Some(dir) = &config.static_dir {
        if !std::path::Path::new(dir).is_dir() {
            eprintln!("obs-app: --static-dir {} is not a directory", dir);
            return ExitCode::from(2);
        }
    }

    let store = match AtomicStore::open(&portal_path, true) {
        Ok(store) => store,
        Err(error) => {
            eprintln!("obs-app: {}", error);
            return ExitCode::from(1);
        }
    };
    let portal = match Portal::open(store) {
        Ok(portal) => portal,
        Err(error) => {
            eprintln!("obs-app: the developer portal store could not be opened: {}", error);
            return ExitCode::from(1);
        }
    };

    let indexer = Indexer::new(node_url.clone(), network);
    let mut app = App::new(config, indexer, portal);

    // Optionally the same process runs the registration service, so a browser
    // sees one origin for sign-up, sign-in, the portal and the explorer.
    if args.flag("accounts") {
        let accounts_path = match args.path(
            "accounts-store",
            Some(&format!("{}/accounts.json", default_dir)),
        ) {
            Ok(path) => path,
            Err(error) => {
                eprintln!("obs-app: {}", error);
                return ExitCode::from(2);
            }
        };
        let authority_path =
            match args.path("authority-key", Some(&format!("{}/authority.key", default_dir))) {
                Ok(path) => path,
                Err(error) => {
                    eprintln!("obs-app: {}", error);
                    return ExitCode::from(2);
                }
            };
        let authority = match Authority::load(&authority_path, network) {
            Ok(authority) => authority,
            Err(error) => {
                eprintln!("obs-app: {}", error);
                return ExitCode::from(1);
            }
        };
        let service_key = match args.hex32("service-key") {
            Ok(Some(key)) => key,
            Ok(None) => obs_crypto::sha2::sha256_tagged(
                "OBSIDIAN/GATEWAY-SERVICE-KEY/v1",
                &authority.public_key(),
            ),
            Err(error) => {
                eprintln!("obs-app: {}", error);
                return ExitCode::from(2);
            }
        };
        let store = match AtomicStore::open(&accounts_path, true) {
            Ok(store) => store,
            Err(error) => {
                eprintln!("obs-app: {}", error);
                return ExitCode::from(1);
            }
        };
        let registry = match Registry::open(store, network, service_key) {
            Ok(registry) => registry.with_authority(authority),
            Err(error) => {
                eprintln!("obs-app: the account store could not be opened: {}", error);
                return ExitCode::from(1);
            }
        };
        let registry = Arc::new(Mutex::new(registry));
        // The chain's own time, for the invitation authorisations the gateway
        // mints.  Read from the node this deployment follows, never from this
        // machine's clock: a chain advances its protocol time at its own pace,
        // and an authorisation dated ahead of it is one the chain cannot accept
        // (see obs_gateway::accounts::Registry::attach_wallet).
        let chain_clock = {
            let node_url = node_url.clone();
            Box::new(move || node_head_time(&node_url))
        };
        let gateway = Arc::new(
            Gateway::from_shared(Arc::clone(&registry), network).with_chain_clock(chain_clock),
        );
        app = app.with_accounts(Arc::clone(&registry)).with_gateway(gateway);
        println!("obs-app: accounts        {}", accounts_path.display());
        println!(
            "obs-app: authority       {}",
            registry
                .lock()
                .map(|registry| registry
                    .authority_public_key()
                    .map(|key| obs_crypto::encoding::hex_encode(&key))
                    .unwrap_or_else(|| "(none)".to_string()))
                .unwrap_or_else(|_| "(unavailable)".to_string())
        );
    }

    let app = Arc::new(app);
    let shutdown = Arc::new(AtomicBool::new(false));

    // The index follows the node on its own thread.  A failure to reach the node
    // is recorded in the index and shown on the status page rather than being
    // fatal: an explorer that is behind is useful; one that exits is not.
    let sync_shutdown = Arc::clone(&shutdown);
    let sync_app = Arc::clone(&app);
    let sync_thread = std::thread::spawn(move || {
        while !sync_shutdown.load(Ordering::Relaxed) {
            let _ = sync_app.sync();
            std::thread::sleep(Duration::from_millis(sync_ms.max(100)));
        }
    });

    println!("obs-app: {} (chain id {})", network.name, network.chain_id);
    println!("obs-app: indexing        {}", node_url);
    println!("obs-app: portal store    {}", portal_path.display());
    println!(
        "obs-app: web interface   {}",
        match &app.config().static_dir {
            Some(dir) => dir.to_string(),
            None => "(api only; pass --static-dir to serve the interface)".to_string(),
        }
    );
    println!("obs-app: api keys        {}", if app.config().require_key { "required for reads" } else { "optional for reads" });
    println!(
        "obs-app: official logo   {}",
        // A file in the static directory wins, so name the one actually there —
        // the served candidates are `logo-official.*`, and reporting a `.png`
        // that does not exist would send an operator looking for the wrong file.
        match (&app.config().static_dir, &app.config().logo_source) {
            (Some(dir), _) if obs_app::logo::installed_file(dir).is_some() => {
                obs_app::logo::installed_file(dir)
                    .map(|(path, _)| path.display().to_string())
                    .unwrap_or_default()
            }
            (_, Some(_)) => "from the configured source (never sent to a browser)".to_string(),
            _ => "none; the interface uses its drawn mark".to_string(),
        }
    );
    println!("obs-app: listening       http://0.0.0.0:{}", port);
    println!("obs-app: routes          {} public routes; none returns a balance", ROUTES.len());

    let server = match Server::bind(("0.0.0.0", port), ServerConfig::default()) {
        Ok(server) => server,
        Err(error) => {
            eprintln!("obs-app: could not bind port {}: {}", port, error);
            shutdown.store(true, Ordering::Relaxed);
            let _ = sync_thread.join();
            return ExitCode::from(1);
        }
    };
    let served = server.serve(
        Arc::clone(&app) as Arc<dyn obs_rpc::server::Handler>,
        Arc::clone(&shutdown),
    );
    shutdown.store(true, Ordering::Relaxed);
    let _ = sync_thread.join();
    match served {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("obs-app: the service stopped: {}", error);
            ExitCode::from(1)
        }
    }
}
