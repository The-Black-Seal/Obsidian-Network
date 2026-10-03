//! The peer manager: one place that owns every connection a node has.
//!
//! The manager never decides anything about the chain.  It accepts and dials
//! connections, runs their handshakes on dedicated threads, turns them into
//! [`PeerEvent`]s, and keeps a bounded amount of per-peer bookkeeping.  The node
//! drains those events on its own thread and answers them in protocol terms.
//!
//! Bounds, all configurable:
//!
//! * `max_peers` established connections;
//! * `max_inbound_per_ip` simultaneous inbound connections from one address;
//! * temporary bans for peers that break the protocol during or after the
//!   handshake, keyed by node identity *and* by IP address;
//! * a heartbeat that pings idle peers and drops silent ones.

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::net::{IpAddr, Shutdown, SocketAddr, TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use obs_primitives::hash::Hash32;

use crate::handshake::{send_message, Role};
use crate::peer::{self, ConnectionHandle, DisconnectReason, PeerEvent};
use crate::protocol::{NetMessage, Reject, RejectCode};
use crate::PeerConfig;

/// What the node wants its peers to know about it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LocalStatus {
    /// Head block hash.
    pub head: Hash32,
    /// Head height.
    pub height: u64,
}

/// Everything an operator can see about one peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerStatus {
    /// Peer node identity.
    pub node_key: [u8; 32],
    /// Address we see the peer at.
    pub addr: SocketAddr,
    /// True when the peer dialled us.
    pub inbound: bool,
    /// Port the peer listens on, if it accepts inbound.
    pub listen_port: u16,
    /// Head the peer most recently reported.
    pub head: Hash32,
    /// Height the peer most recently reported.
    pub height: u64,
    /// Genesis protocol timestamp the peer reported.
    pub genesis_timestamp: u64,
    /// Registration authority the peer reported, or all-zero bytes when the
    /// peer has not learned its network's genesis yet.
    pub registration_authority: [u8; 32],
    /// Seconds since the connection was established.
    pub connected_secs: u64,
    /// Seconds since the last message arrived.
    pub idle_secs: u64,
    /// Messages received from this peer.
    pub messages_in: u64,
    /// Messages sent to this peer.
    pub messages_out: u64,
    /// Bytes received.
    pub bytes_in: u64,
    /// Bytes sent.
    pub bytes_out: u64,
    /// The most recent message type received.
    pub last_message: Option<String>,
}

#[derive(Debug, Default, Clone)]
struct PeerStats {
    messages_in: u64,
    messages_out: u64,
    bytes_in: u64,
    bytes_out: u64,
    last_seen: Option<Instant>,
    last_message: Option<String>,
    ping_sent: Option<u64>,
    head: Option<Hash32>,
    height: u64,
}

/// The connection manager.
pub struct PeerManager {
    config: PeerConfig,
    listener: TcpListener,
    local_addr: SocketAddr,
    status: Arc<Mutex<LocalStatus>>,
    events_tx: Sender<PeerEvent>,
    events_rx: Receiver<PeerEvent>,
    handles: BTreeMap<[u8; 32], ConnectionHandle>,
    stats: BTreeMap<[u8; 32], PeerStats>,
    node_bans: BTreeMap<[u8; 32], Instant>,
    ip_bans: BTreeMap<IpAddr, Instant>,
    inbound_by_ip: HashMap<IpAddr, usize>,
    dialing: BTreeMap<SocketAddr, Instant>,
    known_addrs: BTreeMap<[u8; 32], SocketAddr>,
    ping_counter: u64,
    shutdown: Arc<AtomicBool>,
}

impl PeerManager {
    /// Binds the listening socket and prepares the manager.
    pub fn bind(config: PeerConfig, shutdown: Arc<AtomicBool>) -> io::Result<PeerManager> {
        let listener = TcpListener::bind(("0.0.0.0", config.listen_port))?;
        let local_addr = listener.local_addr()?;
        listener.set_nonblocking(true)?;
        let mut config = config;
        config.listen_port = local_addr.port();
        let (events_tx, events_rx) = channel();
        let status = Arc::new(Mutex::new(LocalStatus {
            head: Hash32::ZERO,
            height: 0,
        }));
        Ok(PeerManager {
            config,
            listener,
            local_addr,
            status,
            events_tx,
            events_rx,
            handles: BTreeMap::new(),
            stats: BTreeMap::new(),
            node_bans: BTreeMap::new(),
            ip_bans: BTreeMap::new(),
            inbound_by_ip: HashMap::new(),
            dialing: BTreeMap::new(),
            known_addrs: BTreeMap::new(),
            ping_counter: 0,
            shutdown,
        })
    }

    /// The manager's configuration, with `listen_port` filled in.
    pub fn config(&self) -> &PeerConfig {
        &self.config
    }

    /// The address the node accepts connections on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// Records the network's registration authority.
    ///
    /// A node that joined a network it did not found learns this public
    /// parameter from a peer's handshake; recording it here makes every
    /// connection after that refuse a peer that reports a different one.
    pub fn set_registration_authority(&mut self, authority: [u8; 32]) {
        self.config.registration_authority = authority;
    }

    /// Publishes this node's chain position to new peers.
    pub fn set_status(&mut self, head: Hash32, height: u64) {
        if let Ok(mut status) = self.status.lock() {
            status.head = head;
            status.height = height;
        }
    }

    /// Number of established peers.
    pub fn peer_count(&self) -> usize {
        self.handles.len()
    }

    /// Is this node key connected?
    pub fn is_connected(&self, node_key: &[u8; 32]) -> bool {
        self.handles.contains_key(node_key)
    }

    /// Is this IP address banned right now?
    pub fn is_banned_ip(&self, ip: IpAddr) -> bool {
        self.ip_bans
            .get(&ip)
            .map(|until| *until > Instant::now())
            .unwrap_or(false)
    }

    /// Is this node key banned right now?
    pub fn is_banned(&self, node_key: &[u8; 32]) -> bool {
        self.node_bans
            .get(node_key)
            .map(|until| *until > Instant::now())
            .unwrap_or(false)
    }

    /// Bans a peer's node key and closes its connection.
    pub fn ban_node(&mut self, node_key: [u8; 32], secs: u64) {
        self.node_bans
            .insert(node_key, Instant::now() + Duration::from_secs(secs));
        if let Some(handle) = self.handles.get(&node_key) {
            let _ = handle.send(NetMessage::Bye(3));
            handle.close();
        }
    }

    /// Bans an IP address and closes every connection from it.
    pub fn ban_ip(&mut self, ip: IpAddr, secs: u64) {
        self.ip_bans
            .insert(ip, Instant::now() + Duration::from_secs(secs));
        let doomed: Vec<[u8; 32]> = self
            .handles
            .iter()
            .filter(|(_, handle)| handle.info.addr.ip() == ip)
            .map(|(key, _)| *key)
            .collect();
        for key in doomed {
            if let Some(handle) = self.handles.get(&key) {
                let _ = handle.send(NetMessage::Bye(3));
                handle.close();
            }
        }
    }

    /// How long a dial may stay unanswered before it is forgotten.
    ///
    /// Wall-clock generous relative to `connect_timeout`: this is not a
    /// deadline, it is a leak detector.
    fn dial_expiry(&self) -> Duration {
        self.config.connect_timeout * 4
    }

    /// Forgets dials that never reported an outcome, so a lost event cannot
    /// make an address permanently un-dialable.
    fn expire_dials(&mut self) {
        let now = Instant::now();
        let expiry = self.dial_expiry();
        self.dialing
            .retain(|_, started| now.duration_since(*started) < expiry);
    }

    /// Dials a peer, unless it is already connected, already being dialled, or
    /// banned.
    ///
    /// The address is the one the operator gave.  Callers that re-dial on a
    /// timer should expect the *connection* to record wherever the peer turned
    /// out to be, which is why this method — and not the caller — decides
    /// whether a dial is already in flight.
    pub fn connect(&mut self, addr: SocketAddr) {
        self.expire_dials();
        if self.dialing.contains_key(&addr) || self.handles.len() >= self.config.max_peers {
            return;
        }
        if self
            .ip_bans
            .get(&addr.ip())
            .map(|until| *until > Instant::now())
            .unwrap_or(false)
        {
            return;
        }
        if self.handles.values().any(|handle| handle.info.addr == addr) {
            return;
        }
        self.dialing.insert(addr, Instant::now());
        let config = self.config.clone();
        let events = self.events_tx.clone();
        let shutdown = Arc::clone(&self.shutdown);
        let status = Arc::clone(&self.status);
        let timeout = config.connect_timeout;
        let _ = thread::Builder::new()
            .name(format!("obs-p2p-dial-{}", addr))
            .spawn(move || {
                let stream = match TcpStream::connect_timeout(&addr, timeout) {
                    Ok(stream) => stream,
                    Err(error) => {
                        let _ = events.send(PeerEvent::Rejected {
                            addr,
                            dialed: Some(addr),
                            inbound: false,
                            reason: DisconnectReason::Io(error.to_string()),
                            protocol_violation: false,
                        });
                        return;
                    }
                };
                let (head, height) = match status.lock() {
                    Ok(status) => (status.head, status.height),
                    Err(_) => (Hash32::ZERO, 0),
                };
                peer::run_connection(
                    stream,
                    config,
                    Role::Initiator,
                    events,
                    shutdown,
                    head,
                    height,
                    Some(addr),
                );
            });
    }

    /// Queues a message for one peer.
    pub fn send(&mut self, node_key: &[u8; 32], message: NetMessage) -> bool {
        let payload_len = message.encoded().len() as u64 + 4;
        let sent = match self.handles.get(node_key) {
            Some(handle) => handle.send(message),
            None => false,
        };
        if sent {
            let stats = self.stats.entry(*node_key).or_default();
            stats.messages_out += 1;
            stats.bytes_out += payload_len;
        }
        sent
    }

    /// Queues a message for every peer.
    pub fn broadcast(&mut self, message: NetMessage, except: Option<[u8; 32]>) {
        let targets: Vec<[u8; 32]> = self
            .handles
            .keys()
            .copied()
            .filter(|key| Some(*key) != except)
            .collect();
        for key in targets {
            self.send(&key, message.clone());
        }
    }

    /// Disconnects a peer politely.
    pub fn disconnect(&mut self, node_key: &[u8; 32], code: u8) {
        if let Some(handle) = self.handles.get(node_key) {
            let _ = handle.send(NetMessage::Bye(code));
            handle.close();
        }
    }

    /// Addresses of peers that accept inbound connections.
    pub fn known_peers(&self) -> Vec<SocketAddr> {
        let mut addresses: Vec<SocketAddr> = self.known_addrs.values().copied().collect();
        addresses.sort();
        addresses
    }

    /// Everything an operator can see about the current peers.
    pub fn peers(&self) -> Vec<PeerStatus> {
        let now = Instant::now();
        self.handles
            .iter()
            .map(|(node_key, handle)| {
                let stats = self.stats.get(node_key);
                PeerStatus {
                    node_key: *node_key,
                    addr: handle.info.addr,
                    inbound: handle.info.inbound,
                    listen_port: handle.info.listen_port,
                    head: stats
                        .and_then(|stats| stats.head)
                        .unwrap_or(handle.info.head),
                    height: stats
                        .map(|stats| stats.height)
                        .filter(|height| *height > 0)
                        .unwrap_or(handle.info.height),
                    genesis_timestamp: handle.info.genesis_timestamp,
                    registration_authority: handle.info.registration_authority,
                    connected_secs: now.duration_since(handle.connected_at).as_secs(),
                    idle_secs: stats
                        .and_then(|stats| stats.last_seen)
                        .map(|seen| now.duration_since(seen).as_secs())
                        .unwrap_or_else(|| now.duration_since(handle.connected_at).as_secs()),
                    messages_in: stats.map(|stats| stats.messages_in).unwrap_or(0),
                    messages_out: stats.map(|stats| stats.messages_out).unwrap_or(0),
                    bytes_in: stats.map(|stats| stats.bytes_in).unwrap_or(0),
                    bytes_out: stats.map(|stats| stats.bytes_out).unwrap_or(0),
                    last_message: stats.and_then(|stats| stats.last_message.clone()),
                }
            })
            .collect()
    }

    /// Accepts new connections, drains peer events, and runs the heartbeat.
    ///
    /// Returns everything that happened, in order.  The node is expected to
    /// call this in a loop; `timeout` bounds how long it blocks when the node
    /// has nothing else to do.
    pub fn poll(&mut self, timeout: Duration) -> Vec<PeerEvent> {
        self.accept_pending();
        let mut events: Vec<PeerEvent> = Vec::new();
        match self.events_rx.recv_timeout(timeout) {
            Ok(event) => events.push(event),
            Err(RecvTimeoutError::Timeout) => {}
            Err(RecvTimeoutError::Disconnected) => return events,
        }
        while let Ok(event) = self.events_rx.try_recv() {
            events.push(event);
        }
        // Handle a copy of every event, and return the originals: the node
        // needs to see exactly what happened, including the events the manager
        // acted on itself.
        let mut returned: Vec<PeerEvent> = Vec::with_capacity(events.len() + 1);
        for event in events.drain(..) {
            self.handle_event(&event);
            returned.push(event);
        }
        // The heartbeat can end a connection without the peer sending anything,
        // and the node still has to hear about it.
        returned.extend(self.heartbeat());
        returned
    }

    /// Drains events without blocking.
    pub fn poll_now(&mut self) -> Vec<PeerEvent> {
        self.poll(Duration::from_millis(0))
    }

    fn accept_pending(&mut self) {
        loop {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    let now = Instant::now();
                    if self
                        .ip_bans
                        .get(&addr.ip())
                        .map(|until| *until > now)
                        .unwrap_or(false)
                    {
                        refuse_and_close(stream, RejectCode::Banned, "this address is banned");
                        continue;
                    }
                    let from_ip = self.inbound_by_ip.get(&addr.ip()).copied().unwrap_or(0);
                    if self.handles.len() >= self.config.max_peers {
                        refuse_and_close(stream, RejectCode::TooManyPeers, "at the peer limit");
                        continue;
                    }
                    if from_ip >= self.config.max_inbound_per_ip {
                        refuse_and_close(
                            stream,
                            RejectCode::TooManyPeers,
                            "too many connections from this address",
                        );
                        continue;
                    }
                    *self.inbound_by_ip.entry(addr.ip()).or_insert(0) += 1;
                    let config = self.config.clone();
                    let events = self.events_tx.clone();
                    let shutdown = Arc::clone(&self.shutdown);
                    let status = Arc::clone(&self.status);
                    let spawned = thread::Builder::new()
                        .name(format!("obs-p2p-in-{}", addr))
                        .spawn(move || {
                            let (head, height) = match status.lock() {
                                Ok(status) => (status.head, status.height),
                                Err(_) => (Hash32::ZERO, 0),
                            };
                            peer::run_connection(
                                stream,
                                config,
                                Role::Responder,
                                events,
                                shutdown,
                                head,
                                height,
                                None,
                            );
                        });
                    if spawned.is_err() {
                        let count = self.inbound_by_ip.entry(addr.ip()).or_insert(1);
                        *count = count.saturating_sub(1);
                    }
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                Err(_) => break,
            }
        }
    }

    fn handle_event(&mut self, event: &PeerEvent) {
        match event {
            PeerEvent::Connected {
                node_key,
                addr,
                dialed,
                handle,
                ..
            } => {
                // `addr` is where the peer turned out to be; `dialed` is what
                // this node dialled.  They differ whenever the configured
                // address was a wildcard or a name (0.0.0.0:port resolves to
                // 127.0.0.1:port), and removing only the first left the second
                // in the dial set for ever: the peer was connected, and the
                // node would never dial it again if it went away.
                self.dialing.remove(&addr);
                if let Some(dialed) = dialed {
                    self.dialing.remove(dialed);
                }
                if self.is_banned(&node_key) {
                    handle.close();
                    return;
                }
                if self.handles.contains_key(node_key) {
                    // Duplicate connection to the same identity: keep the
                    // established one.
                    handle.close();
                    return;
                }
                if handle.info.listen_port != 0 {
                    let candidate = SocketAddr::new(handle.info.addr.ip(), handle.info.listen_port);
                    self.known_addrs.insert(*node_key, candidate);
                }
                self.stats.insert(
                    *node_key,
                    PeerStats {
                        last_seen: Some(Instant::now()),
                        head: Some(handle.info.head),
                        height: handle.info.height,
                        ..PeerStats::default()
                    },
                );
                if let Some(cloned) = handle.try_clone() {
                    self.handles.insert(*node_key, cloned);
                }
            }
            PeerEvent::Message { node_key, message } => {
                let size = message.encoded().len() as u64 + 4;
                if let Some(stats) = self.stats.get_mut(node_key) {
                    stats.messages_in += 1;
                    stats.bytes_in += size;
                    stats.last_seen = Some(Instant::now());
                    stats.last_message = Some(message_name(&message).to_string());
                    match &**message {
                        NetMessage::Pong(_) => stats.ping_sent = None,
                        NetMessage::Status(status) => {
                            stats.head = Some(status.head);
                            stats.height = status.height;
                        }
                        _ => {}
                    }
                }
                // Liveness is answered here, not by the node: a ping carries no
                // protocol meaning and must never be able to stall block
                // processing.
                if let NetMessage::Ping(nonce) = **message {
                    self.send(node_key, NetMessage::Pong(nonce));
                }
            }
            PeerEvent::Disconnected {
                node_key, addr, ..
            } => {
                // Only remove the connection that actually ended.  Two
                // connections can carry the same node identity, and the one the
                // manager discarded must not take the live one's place in the
                // table with it.
                let is_current = self
                    .handles
                    .get(node_key)
                    .map(|handle| handle.info.addr == *addr)
                    .unwrap_or(false);
                if is_current {
                    self.handles.remove(node_key);
                    self.stats.remove(node_key);
                }
                self.release_ip(addr.ip());
            }
            PeerEvent::Rejected {
                addr,
                dialed,
                inbound,
                protocol_violation,
                ..
            } => {
                self.dialing.remove(addr);
                if let Some(dialed) = dialed {
                    self.dialing.remove(dialed);
                }
                if *inbound {
                    self.release_ip(addr.ip());
                }
                if *protocol_violation {
                    // A peer that cannot complete a handshake is not
                    // necessarily hostile, but it is not useful either, and the
                    // ban is what stops it from keeping the node busy trying.
                    // Note what this costs: an address ban takes every peer on
                    // that address with it, so only genuine violations reach
                    // here.  A self-connect is deliberately *not* one — an
                    // ordinary configuration mistake must never ban a host's
                    // other nodes.
                    self.ip_bans.insert(
                        addr.ip(),
                        Instant::now() + Duration::from_secs(self.config.handshake_ban_secs),
                    );
                }
            }
        }
    }

    fn release_ip(&mut self, ip: IpAddr) {
        let mut remove = false;
        if let Some(count) = self.inbound_by_ip.get_mut(&ip) {
            *count = count.saturating_sub(1);
            remove = *count == 0;
        }
        if remove {
            self.inbound_by_ip.remove(&ip);
        }
    }

    fn heartbeat(&mut self) -> Vec<PeerEvent> {
        let mut reported: Vec<PeerEvent> = Vec::new();
        let now = Instant::now();
        let idle_timeout = self.config.idle_timeout;
        let ping_interval = self.config.ping_interval;
        let mut timeouts: Vec<[u8; 32]> = Vec::new();
        let mut pings: Vec<([u8; 32], u64)> = Vec::new();
        for (node_key, handle) in &self.handles {
            let stats = self.stats.get(node_key);
            let last_seen = stats
                .and_then(|stats| stats.last_seen)
                .unwrap_or(handle.connected_at);
            let idle = now.duration_since(last_seen);
            let probed = stats.and_then(|stats| stats.ping_sent).is_some();
            // Probe first, then drop.  A peer is never removed before it has been
            // given the chance to answer a ping, even if this heartbeat loop was
            // delayed long enough for the idle timeout to have passed already:
            // the rule is "silent after a probe", not "idle for long enough".
            if idle >= ping_interval && !probed {
                self.ping_counter += 1;
                pings.push((*node_key, self.ping_counter));
            } else if idle >= idle_timeout {
                timeouts.push(*node_key);
            }
        }
        for (node_key, nonce) in pings {
            if self.send(&node_key, NetMessage::Ping(nonce)) {
                if let Some(stats) = self.stats.get_mut(&node_key) {
                    stats.ping_sent = Some(nonce);
                }
            }
        }
        for node_key in timeouts {
            if let Some(handle) = self.handles.remove(&node_key) {
                reported.push(PeerEvent::Disconnected {
                    node_key,
                    addr: handle.info.addr,
                    reason: DisconnectReason::Timeout,
                });
                handle.close();
            }
            self.stats.remove(&node_key);
        }
        self.node_bans.retain(|_, until| *until > now);
        self.ip_bans.retain(|_, until| *until > now);
        reported
    }

    /// Shuts every connection down.
    pub fn shutdown(&mut self) {
        self.shutdown.store(true, Ordering::Relaxed);
        for (_, handle) in std::mem::take(&mut self.handles) {
            let _ = handle.send(NetMessage::Bye(1));
            handle.close();
        }
        self.stats.clear();
    }
}

impl Drop for PeerManager {
    fn drop(&mut self) {
        if !self.handles.is_empty() {
            self.shutdown();
        }
    }
}

fn refuse_and_close(mut stream: TcpStream, code: RejectCode, detail: &str) {
    let _ = send_message(
        &mut stream,
        &NetMessage::Reject(Reject {
            code,
            detail: detail.to_string(),
        }),
    );
    let _ = stream.shutdown(Shutdown::Both);
}

fn message_name(message: &NetMessage) -> &'static str {
    match message {
        NetMessage::Hello(_) => "hello",
        NetMessage::Auth(_) => "auth",
        NetMessage::Status(_) => "status",
        NetMessage::GetBlocks(_) => "get_blocks",
        NetMessage::Blocks(_) => "blocks",
        NetMessage::Transactions(_) => "transactions",
        NetMessage::Attestations(_) => "attestations",
        NetMessage::Ping(_) => "ping",
        NetMessage::Pong(_) => "pong",
        NetMessage::Reject(_) => "reject",
        NetMessage::Bye(_) => "bye",
    }
}
