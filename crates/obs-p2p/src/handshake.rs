//! The authenticated peer handshake.
//!
//! Three messages, two signatures, two fresh nonces:
//!
//! ```text
//! initiator                                          responder
//!    |-- Hello(nonce_a, remote_nonce = 0, sig_a) ------->|
//!    |<-- Hello(nonce_b, remote_nonce = nonce_a, sig_b) -|
//!    |-- Auth(sig over nonce_a || nonce_b) ------------->|
//! ```
//!
//! * The responder verifies that the initiator holds the private key for the
//!   node identity it claims, and that its chain id, genesis hash and protocol
//!   version match.
//! * The initiator verifies the same about the responder, and that the
//!   responder echoed *its* nonce.
//! * The `Auth` signature covers both nonces, so a recording of an earlier
//!   handshake cannot be replayed: the responder picks a new nonce every time,
//!   and a stale `Auth` will not verify against it.
//!
//! A node refuses to talk to itself, to a peer on another chain, and to a peer
//! running a protocol version it does not implement.  Failures are answered
//! with a [`Reject`] code where possible, so an operator can see *why*.

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use obs_crypto::ed25519;
use obs_primitives::hash::Hash32;

pub use crate::protocol::{auth_preimage, hello_preimage};
use crate::protocol::{
    NetMessage, Reject, RejectCode, Status, Hello, MAX_FRAME_BYTES, MAGIC, PROTOCOL_VERSION,
};
use crate::PeerConfig;

/// Which end of the connection this process is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Role {
    /// The side that dialled.
    Initiator,
    /// The side that accepted.
    Responder,
}

/// What the handshake proved about a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeOutcome {
    /// The peer's node identity public key.
    pub node_key: [u8; 32],
    /// The port the peer listens on, or 0 when it does not accept inbound.
    pub listen_port: u16,
    /// The peer's head hash.
    pub head: Hash32,
    /// The peer's head height.
    pub height: u64,
    /// The nonce this side contributed.
    pub nonce: [u8; 32],
    /// The nonce the peer contributed.
    pub remote_nonce: [u8; 32],
}

/// Why a handshake failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HandshakeError {
    /// The socket failed.
    Io(String),
    /// The peer stopped talking mid-handshake.
    Incomplete,
    /// The peer sent something other than the expected handshake message.
    UnexpectedMessage(u8),
    /// The peer's chain id does not match this node's.
    WrongChain,
    /// The peer's genesis hash does not match this node's.
    WrongGenesis,
    /// The peer speaks a different protocol version.
    UnsupportedVersion(u32),
    /// A handshake signature did not verify.
    BadSignature,
    /// Both ends are the same node identity.
    SelfConnect,
    /// The peer responded to our nonce with a different nonce.
    NonceMismatch,
    /// The peer sent nothing for too long.
    Timeout,
    /// The peer promised a frame larger than the protocol allows.
    TooLarge,
    /// The peer refused, with a reason.
    Refused {
        /// Code the peer sent.
        code: RejectCode,
        /// Detail the peer sent.
        detail: String,
    },
}

impl HandshakeError {
    /// True when the failure means "this peer is not trustworthy", as opposed
    /// to "this peer is on another network" or "the socket broke".
    pub fn is_protocol_violation(&self) -> bool {
        matches!(
            self,
            HandshakeError::BadSignature
                | HandshakeError::NonceMismatch
                | HandshakeError::UnexpectedMessage(_)
                | HandshakeError::SelfConnect
                | HandshakeError::Incomplete
                | HandshakeError::TooLarge
        )
    }
}

impl core::fmt::Display for HandshakeError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            HandshakeError::Io(detail) => write!(f, "socket error: {}", detail),
            HandshakeError::Incomplete => write!(f, "the peer closed the connection mid-handshake"),
            HandshakeError::UnexpectedMessage(tag) => {
                write!(f, "unexpected handshake message tag {}", tag)
            }
            HandshakeError::WrongChain => write!(f, "the peer is on a different chain"),
            HandshakeError::WrongGenesis => write!(f, "the peer has a different genesis block"),
            HandshakeError::UnsupportedVersion(version) => {
                write!(f, "the peer speaks protocol version {}", version)
            }
            HandshakeError::BadSignature => write!(f, "a handshake signature did not verify"),
            HandshakeError::SelfConnect => write!(f, "the peer is this node"),
            HandshakeError::NonceMismatch => write!(f, "the peer did not echo our nonce"),
            HandshakeError::Timeout => write!(f, "the peer sent nothing for too long"),
            HandshakeError::TooLarge => write!(f, "the peer promised an oversized frame"),
            HandshakeError::Refused { code, detail } => {
                write!(f, "the peer refused the connection ({:?}): {}", code, detail)
            }
        }
    }
}

impl std::error::Error for HandshakeError {}

impl From<io::Error> for HandshakeError {
    fn from(error: io::Error) -> Self {
        HandshakeError::Io(error.to_string())
    }
}

/// Why a frame could not be read.
///
/// The distinction matters: a read timeout is *not* a broken socket, and a peer
/// that is merely quiet must not be treated as hostile.
#[derive(Debug)]
pub enum FrameError {
    /// The socket failed.
    Io(String),
    /// The peer closed the connection mid-frame.
    Truncated,
    /// The frame header promised more bytes than the protocol allows.
    TooLarge {
        /// Length the peer promised.
        length: usize,
        /// Largest frame this node accepts.
        limit: usize,
    },
    /// Nothing arrived before the read timeout.
    Timeout,
}

impl core::fmt::Display for FrameError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            FrameError::Io(detail) => write!(f, "socket error: {}", detail),
            FrameError::Truncated => write!(f, "the connection ended mid-frame"),
            FrameError::TooLarge { length, limit } => {
                write!(f, "frame of {} bytes exceeds the {} byte limit", length, limit)
            }
            FrameError::Timeout => write!(f, "no data arrived before the read timeout"),
        }
    }
}

/// Reads one frame, or `None` at a clean end of stream.
pub fn read_frame(stream: &mut TcpStream, max_bytes: usize) -> Result<Option<Vec<u8>>, FrameError> {
    let mut header = [0u8; 4];
    match read_exact_or_eof(stream, &mut header)? {
        false => return Ok(None),
        true => {}
    }
    let length = u32::from_le_bytes(header) as usize;
    let limit = max_bytes.min(MAX_FRAME_BYTES);
    if length > limit {
        return Err(FrameError::TooLarge { length, limit });
    }
    let mut payload = vec![0u8; length];
    if !read_exact_or_eof(stream, &mut payload)? {
        return Err(FrameError::Truncated);
    }
    Ok(Some(payload))
}

/// Reads exactly `buffer.len()` bytes, reporting a clean EOF before any byte.
fn read_exact_or_eof(stream: &mut TcpStream, buffer: &mut [u8]) -> Result<bool, FrameError> {
    let mut filled = 0;
    while filled < buffer.len() {
        match stream.read(&mut buffer[filled..]) {
            Ok(0) => {
                if filled == 0 {
                    return Ok(false);
                }
                return Err(FrameError::Truncated);
            }
            Ok(read) => filled += read,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error)
                if error.kind() == io::ErrorKind::WouldBlock
                    || error.kind() == io::ErrorKind::TimedOut =>
            {
                if filled == 0 {
                    return Err(FrameError::Timeout);
                }
                // A partial frame that then timed out: keep waiting, the peer is
                // simply slow.
                continue;
            }
            Err(error) => return Err(FrameError::Io(error.to_string())),
        }
    }
    Ok(true)
}

/// Writes a frame.
pub fn write_frame(stream: &mut TcpStream, payload: &[u8]) -> Result<(), HandshakeError> {
    if payload.len() > MAX_FRAME_BYTES {
        return Err(HandshakeError::Io("frame too large to send".to_string()));
    }
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(payload);
    stream.write_all(&frame)?;
    stream.flush()?;
    Ok(())
}

/// Sends a message.
pub fn send_message(stream: &mut TcpStream, message: &NetMessage) -> Result<(), HandshakeError> {
    write_frame(stream, &message.encoded())
}

/// Sends a refusal, ignoring failure (the connection is going away anyway).
pub fn send_reject(stream: &mut TcpStream, code: RejectCode, detail: &str) {
    let detail: String = detail.chars().take(200).collect();
    let _ = send_message(stream, &NetMessage::Reject(Reject { code, detail }));
}

/// Generates a 32-byte nonce, refusing to continue without real entropy.
fn fresh_nonce() -> Result<[u8; 32], HandshakeError> {
    let mut nonce = [0u8; 32];
    obs_crypto::rand::os_random(&mut nonce)
        .map_err(|error| HandshakeError::Io(format!("no entropy available: {}", error)))?;
    Ok(nonce)
}

/// Builds this node's `Hello`.
pub fn build_hello(
    config: &PeerConfig,
    nonce: [u8; 32],
    remote_nonce: [u8; 32],
    head: Hash32,
    height: u64,
) -> Hello {
    let mut hello = Hello {
        chain_id: config.chain_id,
        protocol_version: config.protocol_version,
        genesis_hash: config.genesis_hash,
        node_key: config.node_key.public_key(),
        listen_port: config.listen_port,
        nonce,
        remote_nonce,
        head,
        height,
        signature: [0u8; 64],
    };
    let preimage = hello_preimage(
        hello.chain_id,
        hello.protocol_version,
        &hello.genesis_hash,
        &hello.node_key,
        &hello.nonce,
        &hello.remote_nonce,
    );
    hello.signature = config.node_key.sign(&preimage);
    hello
}

/// Verifies a peer's `Hello`.
pub fn verify_hello(config: &PeerConfig, hello: &Hello) -> Result<(), HandshakeError> {
    if hello.chain_id != config.chain_id {
        return Err(HandshakeError::WrongChain);
    }
    if hello.protocol_version != config.protocol_version {
        return Err(HandshakeError::UnsupportedVersion(hello.protocol_version));
    }
    if hello.genesis_hash != config.genesis_hash {
        return Err(HandshakeError::WrongGenesis);
    }
    if hello.node_key == config.node_key.public_key() {
        return Err(HandshakeError::SelfConnect);
    }
    let preimage = hello_preimage(
        hello.chain_id,
        hello.protocol_version,
        &hello.genesis_hash,
        &hello.node_key,
        &hello.nonce,
        &hello.remote_nonce,
    );
    if !ed25519::verify(&hello.node_key, &preimage, &hello.signature) {
        return Err(HandshakeError::BadSignature);
    }
    Ok(())
}

/// Runs the handshake as the side that dialled.
pub fn initiator(
    stream: &mut TcpStream,
    config: &PeerConfig,
    head: Hash32,
    height: u64,
) -> Result<HandshakeOutcome, HandshakeError> {
    stream.set_read_timeout(Some(config.handshake_timeout))?;
    stream.set_write_timeout(Some(config.handshake_timeout))?;

    let nonce = fresh_nonce()?;
    let hello = build_hello(config, nonce, [0u8; 32], head, height);
    send_message(stream, &NetMessage::Hello(hello))?;

    let remote = match read_message(stream, config)? {
        NetMessage::Hello(hello) => hello,
        NetMessage::Reject(reject) => {
            return Err(HandshakeError::Refused {
                code: reject.code,
                detail: reject.detail,
            })
        }
        other => return Err(HandshakeError::UnexpectedMessage(other.tag() as u8)),
    };
    verify_hello(config, &remote)?;
    if remote.remote_nonce != nonce {
        return Err(HandshakeError::NonceMismatch);
    }

    let preimage = auth_preimage(
        config.chain_id,
        &config.genesis_hash,
        &config.node_key.public_key(),
        &nonce,
        &remote.nonce,
    );
    let auth = NetMessage::Auth(crate::protocol::Auth {
        node_key: config.node_key.public_key(),
        nonce,
        remote_nonce: remote.nonce,
        signature: config.node_key.sign(&preimage),
    });
    send_message(stream, &auth)?;

    Ok(HandshakeOutcome {
        node_key: remote.node_key,
        listen_port: remote.listen_port,
        head: remote.head,
        height: remote.height,
        nonce,
        remote_nonce: remote.nonce,
    })
}

/// Runs the handshake as the side that accepted the connection.
pub fn responder(
    stream: &mut TcpStream,
    config: &PeerConfig,
    head: Hash32,
    height: u64,
) -> Result<HandshakeOutcome, HandshakeError> {
    stream.set_read_timeout(Some(config.handshake_timeout))?;
    stream.set_write_timeout(Some(config.handshake_timeout))?;

    let remote = match read_message(stream, config)? {
        NetMessage::Hello(hello) => hello,
        other => {
            send_reject(stream, RejectCode::Malformed, "expected a handshake");
            return Err(HandshakeError::UnexpectedMessage(other.tag() as u8));
        }
    };
    if let Err(error) = verify_hello(config, &remote) {
        let (code, detail) = match &error {
            HandshakeError::WrongChain => (RejectCode::WrongChain, "different chain id"),
            HandshakeError::WrongGenesis => (RejectCode::WrongChain, "different genesis block"),
            HandshakeError::UnsupportedVersion(_) => {
                (RejectCode::WrongVersion, "unsupported protocol version")
            }
            HandshakeError::SelfConnect => (RejectCode::DuplicatePeer, "peer is our own node key"),
            _ => (RejectCode::BadSignature, "handshake signature did not verify"),
        };
        send_reject(stream, code, detail);
        return Err(error);
    }
    if remote.remote_nonce != [0u8; 32] {
        send_reject(stream, RejectCode::Malformed, "the first handshake must not echo a nonce");
        return Err(HandshakeError::NonceMismatch);
    }

    let nonce = fresh_nonce()?;
    let hello = build_hello(config, nonce, remote.nonce, head, height);
    send_message(stream, &NetMessage::Hello(hello))?;

    let auth = match read_message(stream, config)? {
        NetMessage::Auth(auth) => auth,
        other => {
            send_reject(stream, RejectCode::Malformed, "expected authentication");
            return Err(HandshakeError::UnexpectedMessage(other.tag() as u8));
        }
    };
    if auth.node_key != remote.node_key {
        send_reject(stream, RejectCode::BadSignature, "the authenticated key is not the announced key");
        return Err(HandshakeError::BadSignature);
    }
    if auth.nonce != remote.nonce || auth.remote_nonce != nonce {
        send_reject(stream, RejectCode::BadSignature, "the authentication does not bind both nonces");
        return Err(HandshakeError::NonceMismatch);
    }
    let preimage = auth_preimage(
        config.chain_id,
        &config.genesis_hash,
        &auth.node_key,
        &auth.nonce,
        &auth.remote_nonce,
    );
    if !ed25519::verify(&auth.node_key, &preimage, &auth.signature) {
        send_reject(stream, RejectCode::BadSignature, "the authentication signature did not verify");
        return Err(HandshakeError::BadSignature);
    }

    Ok(HandshakeOutcome {
        node_key: remote.node_key,
        listen_port: remote.listen_port,
        head: remote.head,
        height: remote.height,
        nonce,
        remote_nonce: remote.nonce,
    })
}

/// Reads and decodes one message, enforcing the frame limit.
pub fn read_message(stream: &mut TcpStream, config: &PeerConfig) -> Result<NetMessage, HandshakeError> {
    let payload = match read_frame(stream, config.max_frame_bytes).map_err(|error| match error {
        FrameError::Timeout => HandshakeError::Timeout,
        FrameError::TooLarge { .. } => HandshakeError::TooLarge,
        other => HandshakeError::Io(other.to_string()),
    })? {
        Some(payload) => payload,
        None => return Err(HandshakeError::Incomplete),
    };
    if !payload.starts_with(MAGIC.as_slice()) && !matches!(payload.first(), Some(1..=11)) {
        // Every payload starts with its tag; the magic only appears inside the
        // handshake preimages, where it separates Obsidian messages from any
        // other protocol that might one day share a port.
        return Err(HandshakeError::Io("not an Obsidian message".to_string()));
    }
    NetMessage::decode_bytes(&payload).map_err(|error| HandshakeError::Io(error.to_string()))
}

/// The status this node advertises.
pub fn status(head: Hash32, height: u64, weight_atoms: u128, finalized_height: u64, mempool_len: usize) -> Status {
    Status {
        head,
        height,
        weight_atoms,
        finalized_height,
        mempool_len: mempool_len.min(u32::MAX as usize) as u32,
    }
}

/// Default connection timeout used by the tests.
pub const TEST_TIMEOUT: Duration = Duration::from_secs(5);

/// Version string reported by [`PeerConfig::user_agent`].
pub fn user_agent() -> String {
    format!("obsidian-node/{}", PROTOCOL_VERSION)
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_crypto::ed25519::Keypair;
    use obs_primitives::network::MAINNET;

    fn config(seed: u8) -> PeerConfig {
        PeerConfig::new(
            MAINNET,
            Hash32::from_bytes([0xAB; 32]),
            Keypair::from_seed(&[seed; 32]),
            0,
        )
    }

    #[test]
    fn hellos_verify_only_for_the_right_chain_and_key() {
        let ours = config(1);
        let theirs = config(2);
        let head = Hash32::from_bytes([3u8; 32]);
        let hello = build_hello(&theirs, [7u8; 32], [0u8; 32], head, 10);
        assert!(verify_hello(&ours, &hello).is_ok());

        // Wrong chain id.
        let mut wrong_chain = hello.clone();
        wrong_chain.chain_id = MAINNET.chain_id + 1;
        assert_eq!(verify_hello(&ours, &wrong_chain), Err(HandshakeError::WrongChain));

        // Wrong genesis.
        let mut wrong_genesis = hello.clone();
        wrong_genesis.genesis_hash = Hash32::from_bytes([0xCD; 32]);
        assert_eq!(
            verify_hello(&ours, &wrong_genesis),
            Err(HandshakeError::WrongGenesis)
        );

        // Wrong protocol version.
        let mut wrong_version = hello.clone();
        wrong_version.protocol_version = PROTOCOL_VERSION + 1;
        assert_eq!(
            verify_hello(&ours, &wrong_version),
            Err(HandshakeError::UnsupportedVersion(PROTOCOL_VERSION + 1))
        );

        // A tampered nonce invalidates the signature.
        let mut tampered = hello.clone();
        tampered.nonce = [9u8; 32];
        assert_eq!(verify_hello(&ours, &tampered), Err(HandshakeError::BadSignature));

        // And talking to ourselves is refused.
        let ours_hello = build_hello(&ours, [1u8; 32], [0u8; 32], head, 1);
        assert_eq!(verify_hello(&ours, &ours_hello), Err(HandshakeError::SelfConnect));
    }

    #[test]
    fn a_handshake_replay_cannot_authenticate_a_new_connection() {
        let alice = config(1);
        let mallory = config(2);
        // Mallory records Alice's first handshake message.
        let recorded = build_hello(&alice, [5u8; 32], [0u8; 32], Hash32::ZERO, 0);

        // It is a perfectly valid Hello for Mallory's node to receive...
        assert!(verify_hello(&mallory, &recorded).is_ok());

        // ... but Mallory still cannot produce the Auth that binds the
        // responder's *fresh* nonce, because that requires Alice's key.
        let responder_nonce = [0x77u8; 32];
        let mut forged_auth = crate::protocol::Auth {
            node_key: alice.node_key.public_key(),
            nonce: recorded.nonce,
            remote_nonce: responder_nonce,
            signature: [0u8; 64],
        };
        let preimage = auth_preimage(
            mallory.chain_id,
            &mallory.genesis_hash,
            &forged_auth.node_key,
            &forged_auth.nonce,
            &forged_auth.remote_nonce,
        );
        assert!(!ed25519::verify(
            &forged_auth.node_key,
            &preimage,
            &forged_auth.signature
        ));
        forged_auth.signature = mallory.node_key.sign(&preimage);
        assert!(
            !ed25519::verify(&forged_auth.node_key, &preimage, &forged_auth.signature),
            "a signature by another key must not authenticate as Alice"
        );
    }
}
