//! One peer connection: handshake, reader thread, writer thread.
//!
//! Ownership is deliberately simple.  A connection is one OS thread reading and
//! one OS thread writing, plus the node's event loop thread.  The reader never
//! touches node state: it decodes a message and hands it to the node as an
//! event.  The writer never inspects what it is sending beyond the frame limit.
//! Everything that decides anything happens on the node's own thread, which is
//! what makes "the same events produce the same chain" true.

use std::io::{self, Write};
use std::net::{Shutdown, SocketAddr, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{channel, Receiver, RecvTimeoutError, Sender};
use std::sync::Arc;
use std::thread;
use std::time::{Duration, Instant};

use obs_primitives::hash::Hash32;

use crate::handshake::{self, FrameError, HandshakeError, Role};
use crate::protocol::{NetMessage, Reject, RejectCode};
use crate::PeerConfig;

/// Why a connection ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DisconnectReason {
    /// The peer closed the connection.
    PeerClosed,
    /// The peer said goodbye.
    Bye(u8),
    /// The peer refused us, or we refused the peer.
    Refused {
        /// Machine-readable code.
        code: RejectCode,
        /// Human-readable detail.
        detail: String,
    },
    /// The peer was silent for too long.
    Timeout,
    /// The socket failed.
    Io(String),
    /// The peer broke the protocol.
    ProtocolViolation(String),
    /// This node is shutting down.
    Shutdown,
    /// The peer was banned by local policy.
    Banned,
}

impl core::fmt::Display for DisconnectReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            DisconnectReason::PeerClosed => write!(f, "the peer closed the connection"),
            DisconnectReason::Bye(code) => write!(f, "the peer said goodbye ({})", code),
            DisconnectReason::Refused { code, detail } => {
                write!(f, "refused ({:?}): {}", code, detail)
            }
            DisconnectReason::Timeout => write!(f, "the peer went quiet"),
            DisconnectReason::Io(detail) => write!(f, "socket error: {}", detail),
            DisconnectReason::ProtocolViolation(detail) => {
                write!(f, "protocol violation: {}", detail)
            }
            DisconnectReason::Shutdown => write!(f, "this node is shutting down"),
            DisconnectReason::Banned => write!(f, "the peer is banned"),
        }
    }
}

/// What a connection tells the node about itself at handshake time.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PeerInfo {
    /// Peer's node identity.
    pub node_key: [u8; 32],
    /// Peer's address as we see it.
    pub addr: SocketAddr,
    /// True when the peer dialled us.
    pub inbound: bool,
    /// Port the peer listens on (0 when it does not accept inbound).
    pub listen_port: u16,
    /// Peer's head hash at handshake time.
    pub head: Hash32,
    /// Peer's head height at handshake time.
    pub height: u64,
}

/// The handle a node keeps for an established peer.
#[derive(Debug)]
pub struct ConnectionHandle {
    /// What the handshake proved.
    pub info: PeerInfo,
    /// Channel to the writer thread.
    pub outbound: Sender<NetMessage>,
    /// A clone of the socket, used to force the connection closed.
    pub socket: TcpStream,
    /// When the connection was established.
    pub connected_at: Instant,
}

impl ConnectionHandle {
    /// Duplicates this handle.  The clone shares the socket and the writer
    /// queue, which is what lets the manager keep its own copy while the
    /// connection thread keeps running.
    pub fn try_clone(&self) -> Option<ConnectionHandle> {
        Some(ConnectionHandle {
            info: self.info.clone(),
            outbound: self.outbound.clone(),
            socket: self.socket.try_clone().ok()?,
            connected_at: self.connected_at,
        })
    }

    /// Queues a message.  Returns false when the writer has gone away.
    pub fn send(&self, message: NetMessage) -> bool {
        self.outbound.send(message).is_ok()
    }

    /// Closes the connection immediately.
    pub fn close(&self) {
        let _ = self.socket.shutdown(Shutdown::Both);
    }
}

/// Events a connection reports to the node.
pub enum PeerEvent {
    /// A peer finished its handshake and is ready.
    Connected {
        /// Node key of the peer.
        node_key: [u8; 32],
        /// Address of the peer.
        addr: SocketAddr,
        /// Handle for sending messages.
        handle: Box<ConnectionHandle>,
        /// Bytes received during the handshake.
        handshake_bytes_in: u64,
        /// Bytes sent during the handshake.
        handshake_bytes_out: u64,
    },
    /// A peer sent a message.
    Message {
        /// Node key of the peer.
        node_key: [u8; 32],
        /// The message.
        message: Box<NetMessage>,
    },
    /// A peer disconnected.
    Disconnected {
        /// Node key of the peer.
        node_key: [u8; 32],
        /// Address of the peer.
        addr: SocketAddr,
        /// Why.
        reason: DisconnectReason,
    },
    /// A connection attempt or handshake failed before a peer existed.
    Rejected {
        /// Address that failed.
        addr: SocketAddr,
        /// True when the peer dialled us.
        inbound: bool,
        /// Why.
        reason: DisconnectReason,
        /// True when this looks like a hostile or broken peer.
        protocol_violation: bool,
    },
}

/// Runs a connection to completion on the calling thread.
///
/// The caller is expected to be a dedicated thread: this function blocks for the
/// lifetime of the connection.
pub fn run_connection(
    mut stream: TcpStream,
    config: PeerConfig,
    role: Role,
    events: Sender<PeerEvent>,
    shutdown: Arc<AtomicBool>,
    head: Hash32,
    height: u64,
) {
    let peer_addr = match stream.peer_addr() {
        Ok(addr) => addr,
        Err(error) => {
            let _ = events.send(PeerEvent::Rejected {
                addr: "0.0.0.0:0".parse().expect("valid address"),
                inbound: role == Role::Responder,
                reason: DisconnectReason::Io(error.to_string()),
                protocol_violation: false,
            });
            return;
        }
    };
    let _ = stream.set_nodelay(true);

    let outcome = match role {
        Role::Initiator => handshake::initiator(&mut stream, &config, head, height),
        Role::Responder => handshake::responder(&mut stream, &config, head, height),
    };
    let outcome = match outcome {
        Ok(outcome) => outcome,
        Err(error) => {
            let reason = match &error {
                HandshakeError::Refused { code, detail } => DisconnectReason::Refused {
                    code: *code,
                    detail: detail.clone(),
                },
                HandshakeError::Io(detail) => DisconnectReason::Io(detail.clone()),
                HandshakeError::Incomplete => DisconnectReason::PeerClosed,
                HandshakeError::Timeout => DisconnectReason::Timeout,
                HandshakeError::TooLarge => DisconnectReason::ProtocolViolation(error.to_string()),
                other => DisconnectReason::ProtocolViolation(other.to_string()),
            };
            let _ = events.send(PeerEvent::Rejected {
                addr: peer_addr,
                inbound: role == Role::Responder,
                reason,
                protocol_violation: error.is_protocol_violation(),
            });
            let _ = stream.shutdown(Shutdown::Both);
            return;
        }
    };

    let info = PeerInfo {
        node_key: outcome.node_key,
        addr: peer_addr,
        inbound: role == Role::Responder,
        listen_port: outcome.listen_port,
        head: outcome.head,
        height: outcome.height,
    };

    // The writer owns a clone; the reader keeps the original.
    let writer_stream = match stream.try_clone() {
        Ok(clone) => clone,
        Err(error) => {
            let _ = events.send(PeerEvent::Rejected {
                addr: peer_addr,
                inbound: role == Role::Responder,
                reason: DisconnectReason::Io(error.to_string()),
                protocol_violation: false,
            });
            return;
        }
    };
    let socket = match stream.try_clone() {
        Ok(clone) => clone,
        Err(error) => {
            let _ = events.send(PeerEvent::Rejected {
                addr: peer_addr,
                inbound: role == Role::Responder,
                reason: DisconnectReason::Io(error.to_string()),
                protocol_violation: false,
            });
            return;
        }
    };
    let (outbound, inbound_queue) = channel::<NetMessage>();
    let node_key = info.node_key;
    if events
        .send(PeerEvent::Connected {
            node_key,
            addr: peer_addr,
            handle: Box::new(ConnectionHandle {
                info: info.clone(),
                outbound,
                socket,
                connected_at: Instant::now(),
            }),
            handshake_bytes_in: 0,
            handshake_bytes_out: 0,
        })
        .is_err()
    {
        return;
    }

    let writer_shutdown = Arc::clone(&shutdown);
    let writer = thread::Builder::new()
        .name(format!("obs-p2p-write-{}", peer_addr))
        .spawn(move || write_loop(writer_stream, inbound_queue, writer_shutdown, config.max_frame_bytes));
    if writer.is_err() {
        return;
    }
    // The writer is *not* joined.  It exits on its own as soon as the socket
    // fails or the node drops this connection's handle (which closes the
    // channel).  Waiting for it here would let a peer that simply stops talking
    // keep the reader thread — and therefore the disconnect event the node
    // needs — parked indefinitely.

    // The reader owns the connection from here.
    let idle_timeout = config.idle_timeout;
    let max_frame = config.max_frame_bytes;
    let mut last_read = Instant::now();
    let reason = loop {
        if shutdown.load(Ordering::Relaxed) {
            break DisconnectReason::Shutdown;
        }
        let remaining = idle_timeout.saturating_sub(last_read.elapsed());
        let _ = stream.set_read_timeout(Some(remaining.max(Duration::from_millis(50))));
        match handshake::read_frame(&mut stream, max_frame) {
            Ok(None) => break DisconnectReason::PeerClosed,
            Ok(Some(payload)) => {
                last_read = Instant::now();
                match NetMessage::decode_bytes(&payload) {
                    Ok(message) => {
                        let terminate = matches!(
                            message,
                            NetMessage::Bye(_) | NetMessage::Hello(_) | NetMessage::Auth(_)
                        );
                        let bye_code = match message {
                            NetMessage::Bye(code) => Some(code),
                            _ => None,
                        };
                        if events
                            .send(PeerEvent::Message {
                                node_key,
                                message: Box::new(message),
                            })
                            .is_err()
                        {
                            break DisconnectReason::Shutdown;
                        }
                        if terminate {
                            break match bye_code {
                                Some(code) => DisconnectReason::Bye(code),
                                None => DisconnectReason::ProtocolViolation(
                                    "a handshake message arrived after the handshake".to_string(),
                                ),
                            };
                        }
                    }
                    Err(error) => {
                        break DisconnectReason::ProtocolViolation(error.to_string());
                    }
                }
            }
            Err(FrameError::Timeout) => {
                if last_read.elapsed() >= idle_timeout {
                    break DisconnectReason::Timeout;
                }
                continue;
            }
            Err(FrameError::Io(detail)) => break DisconnectReason::Io(detail),
            Err(FrameError::TooLarge { length, limit }) => {
                break DisconnectReason::ProtocolViolation(format!(
                    "frame of {} bytes exceeds the {} byte limit",
                    length, limit
                ))
            }
            Err(FrameError::Truncated) => break DisconnectReason::PeerClosed,
        }
    };

    let _ = stream.shutdown(Shutdown::Both);
    drop(stream);
    let _ = events.send(PeerEvent::Disconnected {
        node_key,
        addr: peer_addr,
        reason,
    });
}

fn write_loop(
    mut stream: TcpStream,
    queue: Receiver<NetMessage>,
    shutdown: Arc<AtomicBool>,
    max_frame_bytes: usize,
) {
    loop {
        if shutdown.load(Ordering::Relaxed) {
            break;
        }
        match queue.recv_timeout(Duration::from_millis(100)) {
            Ok(message) => {
                let payload = message.encoded();
                if payload.len() > max_frame_bytes {
                    // Never send something the peer would refuse to read.
                    continue;
                }
                let mut frame = Vec::with_capacity(payload.len() + 4);
                frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
                frame.extend_from_slice(&payload);
                if stream.write_all(&frame).is_err() || stream.flush().is_err() {
                    break;
                }
                if matches!(message, NetMessage::Bye(_)) {
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => continue,
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let _ = stream.shutdown(Shutdown::Both);
}

/// Sends a refusal on a raw stream, ignoring failure.
pub fn refuse(stream: &mut TcpStream, code: RejectCode, detail: &str) {
    let payload = NetMessage::Reject(Reject {
        code,
        detail: detail.chars().take(200).collect(),
    })
    .encoded();
    let mut frame = Vec::with_capacity(payload.len() + 4);
    frame.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    frame.extend_from_slice(&payload);
    let _ = stream.write_all(&frame);
    let _ = stream.flush();
    let _ = stream.shutdown(Shutdown::Both);
}

/// Convenience used by tests: the io error for a closed socket.
pub fn is_disconnect_error(error: &io::Error) -> bool {
    matches!(
        error.kind(),
        io::ErrorKind::BrokenPipe
            | io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionAborted
            | io::ErrorKind::UnexpectedEof
            | io::ErrorKind::NotConnected
    )
}
