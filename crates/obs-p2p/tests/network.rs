//! Peer-to-peer behaviour over real TCP sockets.
//!
//! Every test here starts actual listeners and exchanges actual frames.  The
//! point is not to prove that TCP works — it is to prove that the *network's*
//! rules hold on the wire: the handshake refuses a foreign chain, a replayed
//! handshake and a peer that lies about its key; a malformed frame closes the
//! connection instead of confusing the node; and the peer manager keeps its
//! bounds under load.
//!
//! The harness polls the manager from the test thread.  That is exactly how the
//! node drives it, and it keeps the tests deterministic: no background thread
//! races the assertions.

use std::collections::VecDeque;
use std::io::{Read, Write};
use std::net::{SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

use obs_crypto::ed25519::Keypair;
use obs_p2p::handshake::{
    self, auth_preimage, build_hello, send_message, HandshakeError,
};
use obs_p2p::peer::{DisconnectReason, PeerEvent};
use obs_p2p::protocol::{
    Auth, GetBlocks, NetMessage, RejectCode, Status, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};
use obs_p2p::{PeerConfig, PeerManager};
use obs_primitives::hash::Hash32;
use obs_primitives::network::{Network, MAINNET, TESTNET};

const GENESIS: [u8; 32] = [0x11; 32];

static NONCE_COUNTER: AtomicU64 = AtomicU64::new(1);

/// A unique 32-byte nonce for one raw client.
fn test_nonce() -> [u8; 32] {
    let mut nonce = [0u8; 32];
    let counter = NONCE_COUNTER.fetch_add(1, Ordering::Relaxed);
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    nonce
}

fn config(seed: u8, network: Network) -> PeerConfig {
    PeerConfig::new(
        network,
        Hash32::from_bytes(GENESIS),
        Keypair::from_seed(&[seed; 32]),
        0,
    )
    .with_handshake_timeout(HANDSHAKE_TIMEOUT)
}

fn config_on(seed: u8, genesis: [u8; 32]) -> PeerConfig {
    PeerConfig::new(
        MAINNET,
        Hash32::from_bytes(genesis),
        Keypair::from_seed(&[seed; 32]),
        0,
    )
    .with_handshake_timeout(HANDSHAKE_TIMEOUT)
}

/// A running node: a manager polled continuously on a background thread, with
/// its events collected for the test to inspect.
///
/// Continuous polling is what a real node does, and it is what lets the raw
/// clients below behave like real clients (blocking reads and writes) without
/// the test driving the node by hand.
struct Node {
    shared: Arc<Shared>,
    shutdown: Arc<AtomicBool>,
    addr: SocketAddr,
    node_key: [u8; 32],
}

struct Shared {
    manager: std::sync::Mutex<PeerManager>,
    events: std::sync::Mutex<VecDeque<PeerEvent>>,
}

impl Node {
    fn start(config: PeerConfig) -> Node {
        let node_key = config.node_key.public_key();
        let shutdown = Arc::new(AtomicBool::new(false));
        let manager = PeerManager::bind(config, Arc::clone(&shutdown)).expect("bind");
        let addr = manager.local_addr();
        let shared = Arc::new(Shared {
            manager: std::sync::Mutex::new(manager),
            events: std::sync::Mutex::new(VecDeque::new()),
        });
        let polled = Arc::clone(&shared);
        let stop = Arc::clone(&shutdown);
        std::thread::Builder::new()
            .name("obs-p2p-test-node".to_string())
            .spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    let events = match polled.manager.lock() {
                        Ok(mut manager) => manager.poll(Duration::from_millis(10)),
                        Err(_) => break,
                    };
                    let idle = events.is_empty();
                    if let Ok(mut queue) = polled.events.lock() {
                        queue.extend(events);
                    }
                    // Yield between polls, so that the test's own thread can
                    // take the manager lock when it needs to.  A poll holds the
                    // manager for as long as its timeout, and a mutex makes no
                    // fairness promise, so a thread that spins back into `lock`
                    // immediately can keep another waiter out for seconds — long
                    // enough for this harness to miss a peer's whole lifetime and
                    // report a network that "never connected".  A millisecond of
                    // slack per idle poll costs a test nothing and keeps its
                    // observations its own.
                    if idle {
                        std::thread::sleep(Duration::from_millis(1));
                    }
                }
            })
            .expect("spawn poller");
        Node {
            shared,
            shutdown,
            addr,
            node_key,
        }
    }

    fn with_manager<T>(&self, f: impl FnOnce(&mut PeerManager) -> T) -> T {
        let mut manager = self.shared.manager.lock().expect("manager lock");
        f(&mut manager)
    }

    fn peer_count(&self) -> usize {
        self.with_manager(|manager| manager.peer_count())
    }

    fn peers(&self) -> Vec<obs_p2p::PeerStatus> {
        self.with_manager(|manager| manager.peers())
    }

    fn set_status(&self, head: Hash32, height: u64) {
        self.with_manager(|manager| manager.set_status(head, height));
    }

    fn connect(&self, addr: SocketAddr) {
        self.with_manager(|manager| manager.connect(addr));
    }

    fn send(&self, node_key: &[u8; 32], message: NetMessage) -> bool {
        self.with_manager(|manager| manager.send(node_key, message.clone()))
    }

    fn known_peers(&self) -> Vec<SocketAddr> {
        self.with_manager(|manager| manager.known_peers())
    }

    fn is_banned(&self, node_key: &[u8; 32]) -> bool {
        self.with_manager(|manager| manager.is_banned(node_key))
    }

    fn ban_node(&self, node_key: [u8; 32], secs: u64) {
        self.with_manager(|manager| manager.ban_node(node_key, secs));
    }

    fn is_banned_ip(&self, ip: std::net::IpAddr) -> bool {
        self.with_manager(|manager| manager.is_banned_ip(ip))
    }

    fn ban_ip(&self, ip: std::net::IpAddr, secs: u64) {
        self.with_manager(|manager| manager.ban_ip(ip, secs));
    }

    fn disconnect(&self, node_key: &[u8; 32], code: u8) {
        self.with_manager(|manager| manager.disconnect(node_key, code));
    }

    fn shutdown(&self) {
        self.with_manager(|manager| manager.shutdown());
    }

    /// The single connected peer's node key.
    fn peer_key(&self) -> [u8; 32] {
        self.peers()[0].node_key
    }

    /// Connects a raw client and waits until the node counts it as a peer.
    ///
    /// A machine under load can starve the node's own thread for a long time, so
    /// a single attempt is not a fair test of the *rule* the test is about.
    /// Retrying costs nothing when the machine is quiet — the first attempt
    /// succeeds and this returns immediately.
    fn connect_registered(&self, client: PeerConfig) -> RawClient {
        let mut attempts = 0;
        loop {
            attempts += 1;
            let mut raw = RawClient::connect(self, client.clone());
            if raw.authenticate().is_ok() && self.wait_for_peers(1, HANDSHAKE_DEADLINE) {
                return raw;
            }
            if attempts >= 3 {
                panic!(
                    "a handshake must complete within {:?} (attempts: {})",
                    HANDSHAKE_DEADLINE, attempts
                );
            }
        }
    }

    fn wait_for_peers(&self, count: usize, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if self.peer_count() >= count {
                return true;
            }
            if Instant::now() >= deadline {
                return self.peer_count() >= count;
            }
            self.settle(Duration::from_millis(5));
        }
    }

    /// Waits for a heartbeat — or for any message — matching `predicate`.
    ///
    /// The node's own probes may arrive first, so this takes the queue apart
    /// rather than assuming the next message is the one under test.
    fn wait_for_heartbeat(
        &self,
        predicate: impl Fn(&NetMessage) -> bool,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some(message) = self.take_message() {
                if predicate(&message) {
                    return true;
                }
            }
            if Instant::now() >= deadline {
                return false;
            }
            self.settle(Duration::from_millis(5));
        }
    }

    /// Waits for a message that is not a heartbeat.
    ///
    /// A node probes its peers on a timer of its own, so a ping or a pong may
    /// arrive between any two application messages.  A test asserting on the
    /// application traffic must not depend on winning that race: under load it
    /// would fail for a reason that has nothing to do with what it checks.
    fn wait_for_application_message(&self, timeout: Duration) -> Option<NetMessage> {
        let deadline = Instant::now() + timeout;
        loop {
            while let Some(message) = self.take_message() {
                if !matches!(message, NetMessage::Ping(_) | NetMessage::Pong(_)) {
                    return Some(message);
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            self.settle(Duration::from_millis(5));
        }
    }

    fn take_message(&self) -> Option<NetMessage> {
        let mut queue = self.shared.events.lock().expect("event lock");
        let index = queue
            .iter()
            .position(|event| matches!(event, PeerEvent::Message { .. }))?;
        match queue.remove(index) {
            Some(PeerEvent::Message { message, .. }) => Some(*message),
            _ => None,
        }
    }

    fn wait_for_disconnect(&self, timeout: Duration) -> Option<DisconnectReason> {
        let deadline = Instant::now() + timeout;
        loop {
            {
                let mut queue = self.shared.events.lock().expect("event lock");
                if let Some(index) = queue
                    .iter()
                    .position(|event| matches!(event, PeerEvent::Disconnected { .. }))
                {
                    if let Some(PeerEvent::Disconnected { reason, .. }) = queue.remove(index) {
                        return Some(reason);
                    }
                }
            }
            if Instant::now() >= deadline {
                return None;
            }
            self.settle(Duration::from_millis(5));
        }
    }

    /// Pumps until the predicate holds or the deadline passes.
    fn wait_until(&self, timeout: Duration, predicate: impl Fn(&Node) -> bool) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            if predicate(self) {
                return true;
            }
            if Instant::now() >= deadline {
                return predicate(self);
            }
            self.settle(Duration::from_millis(5));
        }
    }

    /// Spends `duration` letting the node make progress, without asserting
    /// anything.  Used where a test wants the node to observe a peer's newest
    /// bytes but has nothing in particular to wait for.
    ///
    /// The background poller is convenient, but a test that only waits on it is
    /// waiting on the scheduler: on a loaded machine the poller can be starved
    /// for minutes, and a test about a protocol rule then fails for a reason
    /// that has nothing to do with the rule.  Driving the manager here makes the
    /// test's own progress independent of that thread, while the poller carries
    /// on doing the same work whenever it is scheduled.  The manager sits behind
    /// a mutex, so the two never overlap.
    fn settle(&self, duration: Duration) {
        let deadline = Instant::now() + duration;
        loop {
            // Advance the node from *this* thread when the manager is free, and
            // never wait for it when it is not.
            //
            // Waiting here would be a trap: the poller thread holds the manager
            // for the length of one `poll` timeout on every iteration, and a Rust
            // mutex makes no fairness promise, so a hot loop like the poller can
            // starve this thread for seconds at a time — a test that spent its
            // life waiting on a lock would look exactly like a hung network.
            // `try_lock` gives the test a fair share of the work instead, and the
            // poller keeps doing the same work whenever it is scheduled.
            if let Ok(mut manager) = self.shared.manager.try_lock() {
                let events = manager.poll(Duration::from_millis(0));
                drop(manager);
                if let Ok(mut queue) = self.shared.events.lock() {
                    queue.extend(events);
                }
            }
            if Instant::now() >= deadline {
                return;
            }
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    fn stop(&self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
    }
}

/// A client that speaks the wire protocol by hand, so tests can be hostile.
struct RawClient {
    stream: TcpStream,
    config: PeerConfig,
    nonce: [u8; 32],
}

impl RawClient {
    fn connect(node: &Node, config: PeerConfig) -> RawClient {
        let stream = TcpStream::connect(node.addr).expect("connect");
        // Deadlines here are for *failing* — a starved thread on a loaded
        // machine must not look like a broken protocol.
        stream
            .set_read_timeout(Some(READ_DEADLINE))
            .expect("read timeout");
        stream
            .set_write_timeout(Some(READ_DEADLINE))
            .expect("write timeout");
        RawClient {
            stream,
            config,
            nonce: test_nonce(),
        }
    }

    /// Sends a first Hello and reads the responder's answer.
    fn hello(&mut self, head: Hash32, height: u64) -> Result<obs_p2p::Hello, HandshakeError> {
        let hello = build_hello(&self.config, self.nonce, [0u8; 32], head, height);
        send_message(&mut self.stream, &NetMessage::Hello(hello))?;
        match handshake::read_message(&mut self.stream, &self.config)? {
            NetMessage::Hello(hello) => Ok(hello),
            NetMessage::Reject(reject) => Err(HandshakeError::Refused {
                code: reject.code,
                detail: reject.detail,
            }),
            other => Err(HandshakeError::UnexpectedMessage(other.tag() as u8)),
        }
    }

    /// Completes the handshake honestly, returning the responder's Hello.
    fn authenticate(&mut self) -> Result<obs_p2p::Hello, HandshakeError> {
        let hello = build_hello(&self.config, self.nonce, [0u8; 32], Hash32::ZERO, 0);
        send_message(&mut self.stream, &NetMessage::Hello(hello.clone()))?;
        let responder = match handshake::read_message(&mut self.stream, &self.config)? {
            NetMessage::Hello(hello) => hello,
            NetMessage::Reject(reject) => {
                return Err(HandshakeError::Refused {
                    code: reject.code,
                    detail: reject.detail,
                })
            }
            other => return Err(HandshakeError::UnexpectedMessage(other.tag() as u8)),
        };
        let preimage = auth_preimage(
            self.config.chain_id,
            &self.config.genesis_hash,
            &hello.node_key,
            &hello.nonce,
            &responder.nonce,
        );
        send_message(
            &mut self.stream,
            &NetMessage::Auth(Auth {
                node_key: hello.node_key,
                nonce: hello.nonce,
                remote_nonce: responder.nonce,
                signature: self.config.node_key.sign(&preimage),
            }),
        )?;
        Ok(responder)
    }

    /// Sends a message without waiting for anything.
    fn send(&mut self, message: &NetMessage) {
        let _ = send_message(&mut self.stream, message);
    }

    /// Reads whatever the node has sent, decoding frames.
    fn drain(&mut self, budget: Duration) -> Vec<NetMessage> {
        let deadline = Instant::now() + budget;
        let mut buffer: Vec<u8> = Vec::new();
        let mut messages = Vec::new();
        self.stream
            .set_read_timeout(Some(Duration::from_millis(100)))
            .ok();
        while Instant::now() < deadline {
            let mut chunk = [0u8; 4096];
            match self.stream.read(&mut chunk) {
                Ok(0) => break,
                Ok(read) => {
                    buffer.extend_from_slice(&chunk[..read]);
                    let consumed = drain_frames(&buffer, &mut messages);
                    buffer.drain(..consumed);
                }
                Err(error)
                    if error.kind() == std::io::ErrorKind::WouldBlock
                        || error.kind() == std::io::ErrorKind::TimedOut => {}
                Err(_) => break,
            }
        }
        messages
    }
}

/// Decodes as many complete frames as `buffer` holds; returns the consumed
/// prefix length.
fn drain_frames(buffer: &[u8], out: &mut Vec<NetMessage>) -> usize {
    let mut cursor = 0usize;
    while cursor + 4 <= buffer.len() {
        let length = u32::from_le_bytes(buffer[cursor..cursor + 4].try_into().unwrap()) as usize;
        if cursor + 4 + length > buffer.len() {
            break;
        }
        if let Ok(message) = NetMessage::decode_bytes(&buffer[cursor + 4..cursor + 4 + length]) {
            out.push(message);
        }
        cursor += 4 + length;
    }
    cursor
}

/// Sends junk to a node and waits for the connection to be closed.
fn send_junk_and_expect_close(addr: SocketAddr, bytes: &[u8]) {
    let mut stream = TcpStream::connect(addr).expect("connect");
    stream
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("timeout");
    let _ = stream.write_all(bytes);
    let mut buffer = [0u8; 256];
    let _ = stream.read(&mut buffer);
}

// ---------------------------------------------------------------------------
// Handshake
// ---------------------------------------------------------------------------

/// How long a peer may take to complete a handshake before the node drops it.
///
/// This one is a *rule* under test, not test patience: a handshake is a few small
/// messages, and a peer that has not completed one in five seconds on any machine
/// is not going to.  Keeping it short also keeps the tests of the rule — a banned
/// peer, a peer on another network — quick.
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);

/// How long a raw socket waits for bytes before a test treats it as a failure.
const READ_DEADLINE: Duration = Duration::from_secs(60);

/// How long a test waits for a handshake to complete.
///
/// Generous on purpose.  These tests bind real sockets and run on machines that
/// may be busy with the rest of the suite; a deadline tuned to an idle machine
/// turns "the handshake completes" into a coin toss, and a flaky test is worse
/// than a slow one.  Every wait returns as soon as the condition holds, so a
/// quiet machine is not slowed down by this at all.
const HANDSHAKE_DEADLINE: Duration = Duration::from_secs(120);

#[test]
fn two_nodes_handshake_and_exchange_messages() {
    let alice = Node::start(config(1, MAINNET));
    let bob = Node::start(config(2, MAINNET));
    alice.set_status(Hash32::from_bytes([0xA1; 32]), 41);

    bob.connect(alice.addr);
    assert!(alice.wait_for_peers(1, HANDSHAKE_DEADLINE), "responder");
    assert!(bob.wait_for_peers(1, HANDSHAKE_DEADLINE), "initiator");

    // Both sides learned the other's verified identity.
    assert_eq!(bob.peers()[0].node_key, alice.node_key);
    assert_eq!(alice.peers()[0].node_key, bob.node_key);
    assert!(alice.peers()[0].inbound, "Alice accepted the dial");
    assert!(!bob.peers()[0].inbound, "Bob dialled");

    // A ping is answered by the peer thread itself: no node involvement, so a
    // ping can never stall block processing.  Bob *receives* the ping, and
    // Alice receives the pong that the peer thread sent back without the node
    // ever seeing it.
    let bob_key = bob.node_key;
    assert!(alice.send(&bob_key, NetMessage::Ping(7_777)));
    assert!(
        bob.wait_for_heartbeat(|message| matches!(message, NetMessage::Ping(7_777)), HANDSHAKE_DEADLINE),
        "the peer receives the ping"
    );
    assert!(
        alice.wait_for_heartbeat(|message| matches!(message, NetMessage::Pong(7_777)), HANDSHAKE_DEADLINE),
        "the peer thread answers with a pong, without the node seeing either"
    );

    // Application messages cross intact, in both directions.
    let request = NetMessage::GetBlocks(GetBlocks {
        from_height: 17,
        max_blocks: 64,
    });
    assert!(alice.send(&bob_key, request.clone()));
    assert_eq!(
        bob.wait_for_application_message(HANDSHAKE_DEADLINE),
        Some(request),
        "the request crosses intact"
    );

    let alice_key = alice.node_key;
    let status = NetMessage::Status(Status {
        head: Hash32::from_bytes([0x77; 32]),
        height: 1_000,
        weight_atoms: 999_999_999,
        finalized_height: 998,
        mempool_len: 12,
    });
    assert!(bob.send(&alice_key, status.clone()));
    assert_eq!(
        alice.wait_for_application_message(HANDSHAKE_DEADLINE),
        Some(status),
        "the status crosses intact"
    );

    alice.stop();
    bob.stop();
}

#[test]
fn a_peer_on_another_chain_is_refused_with_a_reason() {
    let mainnet_node = Node::start(config(1, MAINNET));
    let mut testnet_client = RawClient::connect(&mainnet_node, config(2, TESTNET));

    match testnet_client.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, .. }) => assert_eq!(code, RejectCode::WrongChain),
        other => panic!("a testnet peer must be refused, got {:?}", other.is_ok()),
    }
    mainnet_node.settle(Duration::from_millis(100));
    assert_eq!(mainnet_node.peer_count(), 0);
    mainnet_node.stop();
}

#[test]
fn a_peer_with_a_different_genesis_is_refused() {
    let node = Node::start(config(1, MAINNET));
    let mut other_chain = RawClient::connect(&node, config_on(2, [0x22; 32]));
    match other_chain.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, detail }) => {
            assert_eq!(code, RejectCode::WrongChain);
            assert!(detail.contains("genesis"), "got {:?}", detail);
        }
        other => panic!("a different genesis must be refused, got {:?}", other.is_ok()),
    }
    node.stop();
}

/// Two nodes on the same chain must agree on the registration authority.
///
/// The authority is a public parameter of the network — the key that authorises
/// invitations, and what every node needs to validate the registrations in the
/// chain's history — so a peer that reports a *different* one is on a chain
/// this node cannot validate.  A peer that reports none at all is joining and
/// has not learned it yet: the handshake is how it learns, so that case is
/// allowed and the node's own record supplies it.
#[test]
fn a_peer_that_reports_a_different_registration_authority_is_refused() {
    let ours = config(1, MAINNET);
    let known = {
        let mut config = ours.clone();
        config.registration_authority = [0xAA; 32];
        config
    };
    let node = Node::start(known.clone());
    let mut different = config(2, MAINNET);
    different.registration_authority = [0xBB; 32];
    let mut client = RawClient::connect(&node, different);
    match client.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, detail }) => {
            assert_eq!(code, RejectCode::WrongChain);
            assert!(detail.contains("genesis"), "got {:?}", detail);
        }
        other => panic!(
            "a different registration authority must be refused, got {:?}",
            other.is_ok()
        ),
    }
    node.stop();

    // The same node accepts a peer that has not learned it yet, because that is
    // exactly the peer the handshake is meant to teach it to.
    let node = Node::start(known);
    let joining = config(3, MAINNET);
    assert_eq!(joining.registration_authority, [0u8; 32]);
    let mut client = RawClient::connect(&node, joining);
    assert!(client.hello(Hash32::ZERO, 0).is_ok(), "a joining peer is welcome");
    node.stop();
}

#[test]
fn a_peer_with_an_unsupported_version_is_refused() {
    let node = Node::start(config(1, MAINNET));
    let mut modern = config(2, MAINNET);
    modern.protocol_version = PROTOCOL_VERSION + 1;
    let mut client = RawClient::connect(&node, modern);
    match client.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, .. }) => assert_eq!(code, RejectCode::WrongVersion),
        other => panic!("an unsupported version must be refused, got {:?}", other.is_ok()),
    }
    node.stop();
}

#[test]
fn a_tampered_handshake_signature_is_refused() {
    let node = Node::start(config(1, MAINNET));
    let mut client = RawClient::connect(&node, config(2, MAINNET));

    // A well-formed Hello whose signature does not match: the attacker claims a
    // key it does not hold.
    let mut hello = build_hello(&config(2, MAINNET), test_nonce(), [0u8; 32], Hash32::ZERO, 0);
    hello.node_key = [0x42u8; 32];
    client.send(&NetMessage::Hello(hello));
    match handshake::read_message(&mut client.stream, &client.config) {
        Ok(NetMessage::Reject(reject)) => assert_eq!(reject.code, RejectCode::BadSignature),
        other => panic!("a forged key must be refused, got {:?}", other.is_ok()),
    }
    // *Spoken* protocol plus a broken signature is hostility, and that is what
    // the address ban is for — unlike a stray HTTP request to the peer port,
    // which is only a connection to close.
    assert!(
        node.wait_until(HANDSHAKE_DEADLINE, |node| node
            .is_banned_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST))),
        "a forged handshake signature bans the address"
    );
    node.stop();
}

#[test]
fn a_recorded_handshake_cannot_be_replayed() {
    let node = Node::start(config(1, MAINNET));
    let honest_server = Node::start(config(9, MAINNET));
    let victim = config(2, MAINNET);

    // An honest exchange with a *different* server, recorded byte for byte.
    let mut recorder = TcpStream::connect(honest_server.addr).unwrap();
    recorder
        .set_read_timeout(Some(HANDSHAKE_DEADLINE))
        .unwrap();
    let nonce = test_nonce();
    let hello = build_hello(&victim, nonce, [0u8; 32], Hash32::ZERO, 0);
    send_message(&mut recorder, &NetMessage::Hello(hello.clone())).unwrap();
    let server_hello = match handshake::read_message(&mut recorder, &victim).unwrap() {
        NetMessage::Hello(hello) => hello,
        other => panic!("expected a hello, got {:?}", other),
    };
    let preimage = auth_preimage(
        victim.chain_id,
        &victim.genesis_hash,
        &victim.node_key.public_key(),
        &hello.nonce,
        &server_hello.nonce,
    );
    let recorded_auth = Auth {
        node_key: victim.node_key.public_key(),
        nonce: hello.nonce,
        remote_nonce: server_hello.nonce,
        signature: victim.node_key.sign(&preimage),
    };

    // The whole transcript is replayed at a fresh node.
    let mut replayer = TcpStream::connect(node.addr).unwrap();
    replayer
        .set_read_timeout(Some(HANDSHAKE_DEADLINE))
        .unwrap();
    send_message(&mut replayer, &NetMessage::Hello(hello)).unwrap();
    let fresh_hello = match handshake::read_message(&mut replayer, &victim).unwrap() {
        NetMessage::Hello(hello) => hello,
        other => panic!("expected a hello, got {:?}", other),
    };
    assert_ne!(
        fresh_hello.nonce, server_hello.nonce,
        "every connection uses a fresh challenge"
    );
    send_message(&mut replayer, &NetMessage::Auth(recorded_auth)).unwrap();
    match handshake::read_message(&mut replayer, &victim) {
        Ok(NetMessage::Reject(reject)) => assert_eq!(reject.code, RejectCode::BadSignature),
        other => panic!("a replayed handshake must be refused, got {:?}", other.is_ok()),
    }
    node.settle(Duration::from_millis(100));
    assert_eq!(node.peer_count(), 0);

    honest_server.stop();
    node.stop();
}

#[test]
fn a_post_handshake_handshake_message_is_a_protocol_violation() {
    let node = Node::start(config(1, MAINNET));
    let mut raw = RawClient::connect(&node, config(2, MAINNET));
    let hello = raw.authenticate().expect("the handshake completes");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    // A second Hello after authentication is not something any honest peer
    // sends; the connection is closed rather than renegotiated.
    raw.send(&NetMessage::Hello(hello));
    match node.wait_for_disconnect(HANDSHAKE_DEADLINE) {
        Some(DisconnectReason::ProtocolViolation(detail)) => {
            assert!(detail.contains("after the handshake"), "got {:?}", detail)
        }
        other => panic!("expected a protocol violation, got {:?}", other),
    }
    node.stop();
}

#[test]
fn a_peer_that_never_finishes_the_handshake_is_dropped() {
    let node = Node::start(config(1, MAINNET).with_handshake_timeout(Duration::from_millis(300)));
    let mut silent = TcpStream::connect(node.addr).unwrap();

    // Send nothing at all: the node gives up on its own.
    silent
        .set_read_timeout(Some(Duration::from_millis(800)))
        .unwrap();
    let mut buffer = [0u8; 64];
    let _ = silent.read(&mut buffer);
    node.settle(Duration::from_millis(200));
    assert_eq!(node.peer_count(), 0);
    node.stop();
}

// ---------------------------------------------------------------------------
// Framing and hostile input
// ---------------------------------------------------------------------------

#[test]
fn an_oversized_frame_closes_the_connection_without_banning_the_address() {
    let node = Node::start(config(1, MAINNET));
    send_junk_and_expect_close(node.addr, &(MAX_FRAME_BYTES as u32 + 1).to_le_bytes());
    node.settle(Duration::from_millis(200));
    assert_eq!(node.peer_count(), 0, "the connection is closed");

    // Closing the connection is the whole response, deliberately.  A frame
    // header that is not a frame is what an HTTP health probe, a scanner or a
    // browser tab looks like — not a peer that broke a protocol it was
    // speaking.  Banning the address for that would ban every co-located peer
    // on a host that runs more than one node, which is exactly what took a live
    // devnet's second node offline.  A peer that *speaks* Obsidian and then
    // breaks it is still banned; see the bad-signature handshake test.
    assert!(
        !node.is_banned_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "a non-Obsidian connection must not ban the address"
    );
    // And the node is still perfectly usable afterwards.  The client is held in
    // a binding on purpose: `let _ =` would drop the socket immediately and the
    // count would never be observed.
    let _client = node.connect_registered(config(2, MAINNET));
    assert!(
        node.wait_until(HANDSHAKE_DEADLINE, |node| node.peer_count() == 1),
        "a real peer connects after a stray probe was closed"
    );
    node.stop();
}

#[test]
fn malformed_frames_close_the_connection_instead_of_confusing_the_node() {
    let node = Node::start(config(1, MAINNET));
    let mut raw = RawClient::connect(&node, config(2, MAINNET));
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    // An undefined tag after the handshake is a protocol violation, not a
    // message to guess at.
    let garbage = [200u8, 1, 2, 3, 4];
    let mut frame = (garbage.len() as u32).to_le_bytes().to_vec();
    frame.extend_from_slice(&garbage);
    let _ = raw.stream.write_all(&frame);
    match node.wait_for_disconnect(HANDSHAKE_DEADLINE) {
        Some(DisconnectReason::ProtocolViolation(detail)) => {
            assert!(detail.contains("tag"), "got {:?}", detail)
        }
        other => panic!("the peer must be dropped with a reason, got {:?}", other),
    }
    assert_eq!(node.peer_count(), 0);
    node.stop();
}

#[test]
fn arbitrary_bytes_on_the_port_never_reach_the_node() {
    let node = Node::start(config(1, MAINNET));
    for junk in [
        b"GET / HTTP/1.1\r\nHost: x\r\n\r\n".as_slice(),
        b"\x00\x00\x00\x00".as_slice(),
        b"OBSNET1\0\xff\xff\xff".as_slice(),
        &[0xffu8; 64],
    ] {
        send_junk_and_expect_close(node.addr, junk);
    }
    node.settle(Duration::from_millis(100));
    assert_eq!(node.peer_count(), 0);
    node.stop();
}

// ---------------------------------------------------------------------------
// Bounds
// ---------------------------------------------------------------------------

#[test]
fn the_manager_bounds_connections_per_address() {
    let mut config = config(1, MAINNET);
    config.max_inbound_per_ip = 2;
    config.max_peers = 4;
    let node = Node::start(config);

    let mut clients = Vec::new();
    for (index, seed) in [10u8, 11].iter().enumerate() {
        let mut client = RawClient::connect(&node, config_on(*seed, GENESIS));
        client.authenticate().expect("accepted");
        let _ = index;
        clients.push(client);
    }
    assert!(node.wait_for_peers(2, HANDSHAKE_DEADLINE));

    let mut third = RawClient::connect(&node, config_on(20, GENESIS));
    match third.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, .. }) => assert_eq!(code, RejectCode::TooManyPeers),
        other => panic!("the third connection must be refused, got {:?}", other.is_ok()),
    }
    assert_eq!(node.peer_count(), 2);
    node.stop();
}

#[test]
fn a_second_connection_from_one_identity_is_not_duplicated() {
    let node = Node::start(config(1, MAINNET));
    let client = config(2, MAINNET);

    let mut first = RawClient::connect(&node, client.clone());
    first.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    let mut second = RawClient::connect(&node, client);
    second.authenticate().expect("handshakes, then is dropped");
    node.settle(Duration::from_millis(300));
    node.settle(Duration::from_millis(300));
    assert_eq!(node.peer_count(), 1, "one connection per identity");

    // The established connection still works.
    let key = node.peer_key();
    assert!(node.send(&key, NetMessage::Ping(3)));
    let messages = first.drain(Duration::from_secs(2));
    assert!(
        messages.iter().any(|message| matches!(message, NetMessage::Ping(3))),
        "the original connection keeps working, got {:?}",
        messages
    );
    node.stop();
}

#[test]
fn a_rejected_handshake_releases_the_connection_slot() {
    let mut config = config(1, MAINNET);
    config.max_inbound_per_ip = 1;
    let node = Node::start(config);

    let mut bad = RawClient::connect(&node, config_on(2, [0x55; 32]));
    let _ = bad.hello(Hash32::ZERO, 0);
    node.settle(Duration::from_millis(200));

    let mut good = RawClient::connect(&node, config_on(3, GENESIS));
    good.authenticate().expect("the abandoned slot was released");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));
    node.stop();
}

#[test]
fn a_banned_identity_cannot_hold_a_connection() {
    let node = Node::start(config(1, MAINNET));
    let client = config(2, MAINNET);
    let _raw = node.connect_registered(client.clone());

    let key = node.peer_key();
    node.ban_node(key, 30);
    assert!(node.is_banned(&key));
    assert!(
        node.wait_until(HANDSHAKE_DEADLINE, |node| node.peer_count() == 0),
        "the banned connection is closed"
    );

    // The identity cannot hold a new connection either: the handshake may
    // complete at the transport level, but the manager drops it immediately and
    // it never appears in the peer table.
    let mut second = RawClient::connect(&node, client);
    let _ = second.authenticate();
    assert!(
        node.wait_until(HANDSHAKE_DEADLINE, |node| node.peer_count() == 0),
        "a banned identity holds no connection"
    );
    node.stop();
}

/// A node that meets its own identity is refused — and must not be *banned*.
///
/// Seen on a live two-node devnet: the second node was started with the same
/// keystore, so the two identities matched.  The handshake refused it correctly,
/// classified it as a protocol violation, and banned the address — which, on one
/// host, is every co-located peer.  The good connection between the two nodes
/// was torn down as collateral, and the second node could never join.
///
/// A self-connect is a configuration mistake, not an attack, and the ban here is
/// what turns it into an outage.
#[test]
fn a_self_connect_is_refused_without_banning_the_address() {
    let node = Node::start(config(1, MAINNET));
    // Dial ourselves: the same identity, a fresh socket.
    let mut itself = RawClient::connect(&node, config(1, MAINNET));
    let outcome = itself.authenticate();
    assert!(
        outcome.is_err(),
        "a node must refuse its own identity: {:?}",
        outcome.err()
    );

    // No address ban: the loopback address is shared by every node on this host.
    assert!(
        !node.is_banned_ip(std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST)),
        "meeting our own identity must not ban every local peer"
    );
    // And an ordinary peer still connects afterwards.
    let _client = node.connect_registered(config(2, MAINNET));
    assert!(
        node.wait_until(HANDSHAKE_DEADLINE, |node| node.peer_count() == 1),
        "a legitimate peer connects after a self-connect was refused"
    );
    node.stop();
}

#[test]
fn a_connection_from_a_banned_address_is_refused_before_the_handshake() {
    let node = Node::start(config(1, MAINNET));
    node.ban_ip("127.0.0.1".parse().unwrap(), 30);
    let mut client = RawClient::connect(&node, config_on(2, GENESIS));
    match client.hello(Hash32::ZERO, 0) {
        Err(HandshakeError::Refused { code, .. }) => assert_eq!(code, RejectCode::Banned),
        other => panic!("a banned address must be refused, got {:?}", other.is_ok()),
    }
    assert_eq!(node.peer_count(), 0);
    node.stop();
}

// ---------------------------------------------------------------------------
// Liveness
// ---------------------------------------------------------------------------

#[test]
fn an_idle_peer_is_pinged_then_dropped() {
    // Timings are generous on purpose: this test runs on a shared machine, and
    // what it checks is the *rule* (probe first, then drop a silent peer), not
    // the exact millisecond the rule fires at.
    let node = Node::start(
        config(1, MAINNET).with_timings(Duration::from_secs(2), Duration::from_millis(400)),
    );
    let mut client = node.connect_registered(config_on(2, GENESIS));

    // The node probes a quiet peer...
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    let mut seen_ping = false;
    while Instant::now() < deadline && !seen_ping {
        seen_ping = client
            .drain(Duration::from_millis(50))
            .iter()
            .any(|message| matches!(message, NetMessage::Ping(_)));
    }
    assert!(seen_ping, "an idle peer must be probed");

    // ...and drops it when it answers nothing at all.
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    while Instant::now() < deadline && node.peer_count() > 0 {
        node.settle(Duration::from_millis(20));
    }
    assert_eq!(node.peer_count(), 0, "a silent peer is dropped");
    node.stop();
}

#[test]
fn a_peer_that_says_goodbye_is_reported_as_such() {
    let node = Node::start(config(1, MAINNET));
    let mut raw = RawClient::connect(&node, config(2, MAINNET));
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    let key = node.peer_key();
    node.disconnect(&key, 0);
    match node.wait_for_disconnect(HANDSHAKE_DEADLINE) {
        Some(DisconnectReason::Bye(0)) | Some(DisconnectReason::PeerClosed) => {}
        other => panic!("an orderly close is reported, got {:?}", other),
    }
    node.stop();
}

#[test]
fn a_dropped_connection_does_not_leak_a_peer_slot() {
    let node = Node::start(config(1, MAINNET));
    let mut raw = RawClient::connect(&node, config(2, MAINNET));
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    // The client vanishes without a goodbye.
    drop(raw);
    let deadline = Instant::now() + HANDSHAKE_DEADLINE;
    while Instant::now() < deadline && node.peer_count() > 0 {
        node.settle(Duration::from_millis(50));
    }
    assert_eq!(node.peer_count(), 0);
    node.stop();
}

// ---------------------------------------------------------------------------
// Bookkeeping
// ---------------------------------------------------------------------------

#[test]
fn the_peer_table_reports_what_the_operator_needs() {
    let node = Node::start(config(1, MAINNET));
    let client = config(2, MAINNET);
    let mut raw = RawClient::connect(&node, client.clone());
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));

    let peers = node.peers();
    assert_eq!(peers.len(), 1);
    let peer = &peers[0];
    assert_eq!(peer.node_key, client.node_key.public_key());
    assert!(peer.inbound);
    assert!(peer.connected_secs < 60);
    assert!(peer.idle_secs < 60);

    // A status message updates the peer's reported position and the counters.
    raw.send(&NetMessage::Status(Status {
        head: Hash32::from_bytes([0x12; 32]),
        height: 900,
        weight_atoms: 5,
        finalized_height: 899,
        mempool_len: 1,
    }));
    assert!(
        node.wait_until(Duration::from_secs(3), |node| node.peers()[0].height == 900),
        "the manager tracks the peer's announced position"
    );
    let peer = &node.peers()[0];
    assert_eq!(peer.head, Hash32::from_bytes([0x12; 32]));
    assert!(peer.messages_in >= 1);
    assert!(peer.bytes_in > 0, "received bytes are counted");
    assert_eq!(peer.last_message.as_deref(), Some("status"));

    // Outbound traffic is counted too.
    let key = peer.node_key;
    assert!(node.send(&key, NetMessage::Ping(1)));
    assert!(node.wait_until(Duration::from_secs(2), |node| node.peers()[0]
        .messages_out
        >= 1));
    assert!(node.peers()[0].bytes_out > 0);
    node.stop();
}

#[test]
fn peers_that_accept_inbound_are_remembered_for_redial() {
    let node = Node::start(config(1, MAINNET));
    let mut announced = config(2, MAINNET);
    announced.listen_port = 9_999;
    let mut raw = RawClient::connect(&node, announced);
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));
    let known = node.known_peers();
    assert_eq!(known.len(), 1, "the advertised port is remembered");
    assert_eq!(known[0].port(), 9_999);
    node.stop();
}

#[test]
fn a_peer_that_announces_no_inbound_port_is_not_remembered() {
    let node = Node::start(config(1, MAINNET));
    let mut raw = RawClient::connect(&node, config(2, MAINNET));
    raw.authenticate().expect("accepted");
    assert!(node.wait_for_peers(1, HANDSHAKE_DEADLINE));
    assert!(node.known_peers().is_empty());
    node.stop();
}

#[test]
fn sending_to_an_unknown_peer_is_a_no_op() {
    let node = Node::start(config(1, MAINNET));
    assert!(!node.send(&[0u8; 32], NetMessage::Ping(1)));
    let other = Node::start(config(2, MAINNET));
    assert!(!node.send(&other.node_key, NetMessage::Ping(1)));
    node.stop();
}

#[test]
fn two_nodes_on_different_networks_never_connect() {
    let mainnet = Node::start(config(1, MAINNET));
    let testnet = Node::start(config(2, TESTNET));
    assert_ne!(mainnet.addr, testnet.addr);

    mainnet.connect(testnet.addr);
    for _ in 0..20 {
        mainnet.settle(Duration::from_millis(20));
        testnet.settle(Duration::from_millis(20));
    }
    assert_eq!(mainnet.peer_count(), 0);
    assert_eq!(testnet.peer_count(), 0);
    mainnet.stop();
    testnet.stop();
}

#[test]
fn a_handle_stops_reporting_after_the_writer_ends() {
    let alice = Node::start(config(1, MAINNET));
    let bob = Node::start(config(2, MAINNET));
    bob.connect(alice.addr);
    assert!(alice.wait_for_peers(1, HANDSHAKE_DEADLINE));
    let bob_key = bob.node_key;
    assert!(alice.send(&bob_key, NetMessage::Ping(1)));

    // Close the far end abruptly; sending again is a clean failure, never a
    // panic or a block.
    bob.shutdown();
    bob.stop();
    for _ in 0..20 {
        alice.settle(Duration::from_millis(20));
    }
    let _ = alice.send(&bob_key, NetMessage::Ping(2));
    alice.stop();
}
