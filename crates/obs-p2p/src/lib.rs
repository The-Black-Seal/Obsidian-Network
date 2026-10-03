//! # obs-p2p — the Obsidian Network peer transport
//!
//! The network layer moves bytes between nodes; it never decides anything about
//! the chain.  Blocks and transactions that arrive from a peer are handed to
//! the node, which validates them exactly as if it had produced them itself.  A
//! peer that lies is disconnected; it is never believed.
//!
//! ```text
//!   node thread                     peer threads
//!       |                                |
//!       |  poll()  <-- PeerEvent ---    |  handshake (Initiator/Responder)
//!       |                                |  read frame -> decode -> event
//!       +--> validate, apply, store      |  <- queue of outbound messages
//!       +--> broadcast what the chain says
//! ```
//!
//! ## What the transport guarantees
//!
//! * **Peer authentication.** Every connection is authenticated in both
//!   directions by the handshake in [`handshake`]: the peer must hold the
//!   private key for the node identity it claims.
//! * **Chain isolation.** The handshake pins the chain id and genesis hash, so
//!   a testnet peer is refused by a mainnet node, and nothing an attacker
//!   records on one network can be replayed on another.
//! * **Replay resistance.** Each side contributes a fresh 32-byte nonce, and
//!   the initiator's second signature covers both, so a recorded handshake
//!   cannot be replayed against a new connection.
//! * **Bounded peer behaviour.** Frame size, message counts and peer counts are
//!   capped, and a peer that breaks framing or the message grammar is banned
//!   for a while, by node identity and by IP address.
//!
//! ## What the transport does *not* do
//!
//! It does not order blocks, choose forks, validate signatures on chain data,
//! or decide when to ask for anything: those are [`obs_consensus`] and
//! [`obs_node`] concerns, and keeping them out of the transport is what makes
//! the same event sequence produce the same chain on every node.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod handshake;
pub mod manager;
pub mod peer;
pub mod protocol;

use std::time::Duration;

use obs_crypto::ed25519::Keypair;
use obs_primitives::hash::Hash32;
use obs_primitives::network::Network;

pub use handshake::{HandshakeError, HandshakeOutcome, Role};
pub use manager::{LocalStatus, PeerManager, PeerStatus};
pub use peer::{ConnectionHandle, DisconnectReason, PeerEvent, PeerInfo};
pub use protocol::{
    Auth, GetBlocks, Hello, MessageError, NetMessage, Reject, RejectCode, Status, Tag,
    MAX_BLOCKS_PER_MESSAGE, MAX_FRAME_BYTES, PROTOCOL_VERSION,
};

/// Default inbound port per network.
pub const DEFAULT_PORT: u16 = 9_200;

/// Everything a peer connection needs to know.
///
/// The node identity key is deliberately *not* printable: `Debug` shows only
/// its public half, so a log line can never leak the private key.
#[derive(Clone)]
pub struct PeerConfig {
    /// Chain id this node speaks.
    pub chain_id: u32,
    /// Genesis hash this node requires.
    pub genesis_hash: Hash32,
    /// Genesis protocol timestamp this node requires.  Zero means "not
    /// known", which is only possible for a node that has not joined a chain
    /// yet; every other value is enforced against a peer's handshake.
    pub genesis_timestamp: u64,
    /// Registration authority of this node's chain, or all-zero bytes when the
    /// node has not learned it yet.  A node that knows it refuses a peer that
    /// reports a different one.
    pub registration_authority: [u8; 32],
    /// This node's identity key.  Distinct from any wallet key: a validator's
    /// node identity signs consensus traffic and nothing else.
    pub node_key: Keypair,
    /// Port to listen on (0 lets the operating system choose).
    pub listen_port: u16,
    /// Protocol version.
    pub protocol_version: u32,
    /// Largest frame accepted.
    pub max_frame_bytes: usize,
    /// How long a handshake may take.
    pub handshake_timeout: Duration,
    /// How long a peer may be silent before it is dropped.
    pub idle_timeout: Duration,
    /// How long a peer may be idle before it is pinged.
    pub ping_interval: Duration,
    /// How long a dial may take.
    pub connect_timeout: Duration,
    /// Maximum established peers.
    pub max_peers: usize,
    /// Maximum simultaneous inbound connections from one IP.
    pub max_inbound_per_ip: usize,
    /// How long a protocol violation keeps a node key out.
    pub ban_secs: u64,
    /// How long a failed handshake keeps an IP address out.
    pub handshake_ban_secs: u64,
    /// What this node calls itself in operator logs.
    pub user_agent: String,
}

impl core::fmt::Debug for PeerConfig {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("PeerConfig")
            .field("chain_id", &self.chain_id)
            .field("genesis_hash", &self.genesis_hash)
            .field("node_key", &obs_crypto::encoding::hex_encode(&self.node_key.public_key()))
            .field("listen_port", &self.listen_port)
            .field("protocol_version", &self.protocol_version)
            .field("max_peers", &self.max_peers)
            .field("user_agent", &self.user_agent)
            .finish_non_exhaustive()
    }
}

impl PeerConfig {
    /// Sensible defaults for a public node.
    pub fn new(network: Network, genesis_hash: Hash32, node_key: Keypair, listen_port: u16) -> PeerConfig {
        PeerConfig {
            chain_id: network.chain_id,
            genesis_hash,
            genesis_timestamp: 0,
            registration_authority: [0u8; 32],
            node_key,
            listen_port,
            protocol_version: PROTOCOL_VERSION,
            max_frame_bytes: MAX_FRAME_BYTES,
            handshake_timeout: Duration::from_secs(10),
            idle_timeout: Duration::from_secs(90),
            ping_interval: Duration::from_secs(30),
            connect_timeout: Duration::from_secs(5),
            max_peers: 32,
            max_inbound_per_ip: 4,
            ban_secs: 600,
            handshake_ban_secs: 60,
            user_agent: format!("obsidian-node/{}", PROTOCOL_VERSION),
        }
    }

    /// Overrides the maximum number of peers.
    pub fn with_max_peers(mut self, max_peers: usize) -> PeerConfig {
        self.max_peers = max_peers;
        self
    }

    /// Overrides the heartbeat timings (used by tests).
    pub fn with_timings(mut self, idle_timeout: Duration, ping_interval: Duration) -> PeerConfig {
        self.idle_timeout = idle_timeout;
        self.ping_interval = ping_interval;
        self
    }

    /// Overrides the handshake timeout.
    pub fn with_handshake_timeout(mut self, timeout: Duration) -> PeerConfig {
        self.handshake_timeout = timeout;
        self
    }

    /// Carries a chain's genesis parameters in the handshake.
    ///
    /// The anchor the handshake compares is derived from the network, the
    /// protocol version and the epoch, so passing the record completes the
    /// handshake's identity check without adding a secret to it: the
    /// registration authority is a public parameter of the network.
    pub fn with_genesis(mut self, genesis: &obs_chain::state::GenesisConfig) -> PeerConfig {
        self.genesis_timestamp = genesis.timestamp;
        self.registration_authority = genesis.registration_authority;
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::MAINNET;

    #[test]
    fn default_config_is_sane() {
        let config = PeerConfig::new(
            MAINNET,
            Hash32::from_bytes([1u8; 32]),
            Keypair::from_seed(&[2u8; 32]),
            0,
        );
        assert_eq!(config.chain_id, MAINNET.chain_id);
        assert_eq!(config.protocol_version, PROTOCOL_VERSION);
        assert!(config.max_peers >= 8);
        assert!(config.idle_timeout > config.ping_interval);
        assert!(config.max_frame_bytes <= MAX_FRAME_BYTES);
    }
}
