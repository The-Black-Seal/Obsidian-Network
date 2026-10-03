//! The Obsidian peer wire protocol.
//!
//! Framing is deliberately boring: a little-endian `u32` length followed by a
//! single tagged message.  There is no compression, no chunking and no
//! extension mechanism in version 1 — every byte a peer can send is described
//! by [`NetMessage`], every message has a strict decoder, and anything that
//! does not decode is a protocol violation rather than something to guess at.
//!
//! Two properties matter for the network's safety:
//!
//! * **Chain separation.**  Every handshake carries the chain id and the
//!   genesis hash, and both must match exactly.  A testnet peer cannot talk to
//!   a mainnet node, and a replayed message cannot cross networks because the
//!   handshake transcript is bound to the peer's fresh nonce.
//! * **Bounded work.**  Frame size and message counts are capped before
//!   allocation, so a hostile peer can waste a bounded amount of a node's
//!   memory and no more.

use obs_chain::{Block, Transaction};
use obs_chain::block::Attestation;
use obs_primitives::codec::{decode_exact, Decode, Decoder, Encode, Seq};
use obs_primitives::hash::Hash32;

/// Magic bytes at the start of every handshake frame.
pub const MAGIC: [u8; 8] = *b"OBSNET1\0";
/// Protocol version implemented by this crate.
pub const PROTOCOL_VERSION: u32 = 1;
/// Largest frame accepted on the wire.
pub const MAX_FRAME_BYTES: usize = 8 * 1024 * 1024;
/// Largest number of blocks in one `Blocks` message.
pub const MAX_BLOCKS_PER_MESSAGE: usize = 128;
/// Largest number of transactions in one `Transactions` message.
pub const MAX_TRANSACTIONS_PER_MESSAGE: usize = 512;
/// Largest number of attestations in one `Attestations` message.
pub const MAX_ATTESTATIONS_PER_MESSAGE: usize = 512;
/// Largest `Reject` detail string.
pub const MAX_REJECT_DETAIL: usize = 256;

/// Message tags on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum Tag {
    /// First message of a connection, carrying the sender's identity.
    Hello = 1,
    /// Second message from the initiator, proving possession of its key.
    Auth = 2,
    /// Chain position of the sender.
    Status = 3,
    /// Request for a range of blocks by height.
    GetBlocks = 4,
    /// A batch of blocks.
    Blocks = 5,
    /// A batch of transactions.
    Transactions = 6,
    /// A batch of attestations.
    Attestations = 7,
    /// Liveness probe.
    Ping = 8,
    /// Liveness reply.
    Pong = 9,
    /// A refusal, with a machine-readable code.
    Reject = 10,
    /// An orderly goodbye.
    Bye = 11,
}

impl Tag {
    /// Parses a tag byte.
    pub fn from_byte(byte: u8) -> Option<Tag> {
        Some(match byte {
            1 => Tag::Hello,
            2 => Tag::Auth,
            3 => Tag::Status,
            4 => Tag::GetBlocks,
            5 => Tag::Blocks,
            6 => Tag::Transactions,
            7 => Tag::Attestations,
            8 => Tag::Ping,
            9 => Tag::Pong,
            10 => Tag::Reject,
            11 => Tag::Bye,
            _ => return None,
        })
    }
}

/// Machine-readable rejection codes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RejectCode {
    /// The peer sent something this implementation does not understand.
    Malformed = 1,
    /// The peer's chain id or genesis hash does not match.
    WrongChain = 2,
    /// The peer is running an incompatible protocol version.
    WrongVersion = 3,
    /// The peer's handshake signature did not verify.
    BadSignature = 4,
    /// The peer is banned.
    Banned = 5,
    /// The node is at its peer limit.
    TooManyPeers = 6,
    /// A block was rejected by consensus.
    BadBlock = 7,
    /// A transaction was rejected by consensus or by pool policy.
    BadTransaction = 8,
    /// The peer sent too much.
    TooMuch = 9,
    /// The peer is already connected.
    DuplicatePeer = 10,
}

impl RejectCode {
    /// Parses a code byte.
    pub fn from_byte(byte: u8) -> Option<RejectCode> {
        Some(match byte {
            1 => RejectCode::Malformed,
            2 => RejectCode::WrongChain,
            3 => RejectCode::WrongVersion,
            4 => RejectCode::BadSignature,
            5 => RejectCode::Banned,
            6 => RejectCode::TooManyPeers,
            7 => RejectCode::BadBlock,
            8 => RejectCode::BadTransaction,
            9 => RejectCode::TooMuch,
            10 => RejectCode::DuplicatePeer,
            _ => return None,
        })
    }
}

/// The first message of a connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hello {
    /// Chain id of the sender.
    pub chain_id: u32,
    /// Protocol version of the sender.
    pub protocol_version: u32,
    /// Genesis hash the sender's chain descends from.
    pub genesis_hash: Hash32,
    /// Sender's node identity public key.
    pub node_key: [u8; 32],
    /// Sender's listening port (0 when the sender does not accept inbound).
    pub listen_port: u16,
    /// Fresh nonce chosen by the sender.
    pub nonce: [u8; 32],
    /// Nonce the sender saw from the peer, or zero on the first message.
    pub remote_nonce: [u8; 32],
    /// Head block hash.
    pub head: Hash32,
    /// Head height.
    pub height: u64,
    /// Signature over [`hello_preimage`].
    pub signature: [u8; 64],
}

/// Second message of a connection: the initiator proves it holds its key.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Auth {
    /// Node key of the sender.
    pub node_key: [u8; 32],
    /// The sender's own nonce.
    pub nonce: [u8; 32],
    /// The responder's nonce.
    pub remote_nonce: [u8; 32],
    /// Signature over [`auth_preimage`].
    pub signature: [u8; 64],
}

/// Chain position of a peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Status {
    /// Head block hash.
    pub head: Hash32,
    /// Head height.
    pub height: u64,
    /// Accumulated PoT weight at the head.
    pub weight_atoms: u128,
    /// Last finalised height.
    pub finalized_height: u64,
    /// How many transactions the sender has pooled.
    pub mempool_len: u32,
}

/// Request for a contiguous run of blocks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GetBlocks {
    /// First height requested.
    pub from_height: u64,
    /// Maximum number of blocks to return.
    pub max_blocks: u32,
}

/// A refusal.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reject {
    /// Machine-readable code.
    pub code: RejectCode,
    /// Short, human-readable explanation (never internal detail).
    pub detail: String,
}

/// Every message a peer may send.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NetMessage {
    /// Handshake, step one.
    Hello(Hello),
    /// Handshake, step two (initiator only).
    Auth(Auth),
    /// Chain position.
    Status(Status),
    /// Request blocks.
    GetBlocks(GetBlocks),
    /// Blocks.
    Blocks(Vec<Block>),
    /// Transactions.
    Transactions(Vec<Transaction>),
    /// Attestations.
    Attestations(Vec<Attestation>),
    /// Liveness probe carrying a caller-chosen value.
    Ping(u64),
    /// Liveness reply echoing the probe value.
    Pong(u64),
    /// Refusal.
    Reject(Reject),
    /// Orderly goodbye.
    Bye(u8),
}

impl NetMessage {
    /// The wire tag for this message.
    pub fn tag(&self) -> Tag {
        match self {
            NetMessage::Hello(_) => Tag::Hello,
            NetMessage::Auth(_) => Tag::Auth,
            NetMessage::Status(_) => Tag::Status,
            NetMessage::GetBlocks(_) => Tag::GetBlocks,
            NetMessage::Blocks(_) => Tag::Blocks,
            NetMessage::Transactions(_) => Tag::Transactions,
            NetMessage::Attestations(_) => Tag::Attestations,
            NetMessage::Ping(_) => Tag::Ping,
            NetMessage::Pong(_) => Tag::Pong,
            NetMessage::Reject(_) => Tag::Reject,
            NetMessage::Bye(_) => Tag::Bye,
        }
    }

    /// Encodes the message, tag first.
    pub fn encoded(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(1024);
        out.push(self.tag() as u8);
        match self {
            NetMessage::Hello(hello) => hello.encode(&mut out),
            NetMessage::Auth(auth) => auth.encode(&mut out),
            NetMessage::Status(status) => status.encode(&mut out),
            NetMessage::GetBlocks(get) => get.encode(&mut out),
            NetMessage::Blocks(blocks) => Seq(blocks.clone()).encode(&mut out),
            NetMessage::Transactions(transactions) => Seq(transactions.clone()).encode(&mut out),
            NetMessage::Attestations(attestations) => Seq(attestations.clone()).encode(&mut out),
            NetMessage::Ping(nonce) => nonce.encode(&mut out),
            NetMessage::Pong(nonce) => nonce.encode(&mut out),
            NetMessage::Reject(reject) => reject.encode(&mut out),
            NetMessage::Bye(code) => code.encode(&mut out),
        }
        out
    }

    /// Decodes a message from its payload (tag included).
    pub fn decode_bytes(input: &[u8]) -> Result<NetMessage, MessageError> {
        let tag = *input.first().ok_or(MessageError::Empty)?;
        let tag = Tag::from_byte(tag).ok_or(MessageError::UnknownTag(tag))?;
        let mut decoder = Decoder::new(&input[1..]);
        let message = match tag {
            Tag::Hello => NetMessage::Hello(Hello::decode(&mut decoder).map_err(MessageError::Codec)?),
            Tag::Auth => NetMessage::Auth(Auth::decode(&mut decoder).map_err(MessageError::Codec)?),
            Tag::Status => NetMessage::Status(Status::decode(&mut decoder).map_err(MessageError::Codec)?),
            Tag::GetBlocks => {
                NetMessage::GetBlocks(GetBlocks::decode(&mut decoder).map_err(MessageError::Codec)?)
            }
            Tag::Blocks => {
                let blocks: Vec<Block> =
                    Seq::<Block>::decode(&mut decoder).map_err(MessageError::Codec)?.0;
                if blocks.len() > MAX_BLOCKS_PER_MESSAGE {
                    return Err(MessageError::TooMany);
                }
                NetMessage::Blocks(blocks)
            }
            Tag::Transactions => {
                let transactions: Vec<Transaction> =
                    Seq::<Transaction>::decode(&mut decoder).map_err(MessageError::Codec)?.0;
                if transactions.len() > MAX_TRANSACTIONS_PER_MESSAGE {
                    return Err(MessageError::TooMany);
                }
                NetMessage::Transactions(transactions)
            }
            Tag::Attestations => {
                let attestations: Vec<Attestation> =
                    Seq::<Attestation>::decode(&mut decoder).map_err(MessageError::Codec)?.0;
                if attestations.len() > MAX_ATTESTATIONS_PER_MESSAGE {
                    return Err(MessageError::TooMany);
                }
                NetMessage::Attestations(attestations)
            }
            Tag::Ping => NetMessage::Ping(u64::decode(&mut decoder).map_err(MessageError::Codec)?),
            Tag::Pong => NetMessage::Pong(u64::decode(&mut decoder).map_err(MessageError::Codec)?),
            Tag::Reject => {
                let reject = Reject::decode(&mut decoder).map_err(MessageError::Codec)?;
                if reject.detail.len() > MAX_REJECT_DETAIL {
                    return Err(MessageError::TooMany);
                }
                NetMessage::Reject(reject)
            }
            Tag::Bye => NetMessage::Bye(u8::decode(&mut decoder).map_err(MessageError::Codec)?),
        };
        if !decoder.is_finished() {
            return Err(MessageError::Trailing(decoder.remaining()));
        }
        Ok(message)
    }
}

/// Why a message could not be decoded.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum MessageError {
    /// The payload was empty.
    Empty,
    /// The tag byte is not defined by this protocol version.
    UnknownTag(u8),
    /// The body did not decode.
    Codec(obs_primitives::codec::CodecError),
    /// Something in the message exceeded a protocol limit.
    TooMany,
    /// Bytes remained after the message.
    Trailing(usize),
}

impl core::fmt::Display for MessageError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            MessageError::Empty => write!(f, "empty message"),
            MessageError::UnknownTag(tag) => write!(f, "unknown message tag {}", tag),
            MessageError::Codec(error) => write!(f, "malformed message body: {}", error),
            MessageError::TooMany => write!(f, "message exceeds a protocol limit"),
            MessageError::Trailing(count) => write!(f, "{} trailing bytes after the message", count),
        }
    }
}

impl std::error::Error for MessageError {}

/// Domain separator for the first handshake signature.
pub const HELLO_DOMAIN: &[u8] = b"OBSIDIAN/P2P/HELLO/v1";
/// Domain separator for the second handshake signature.
pub const AUTH_DOMAIN: &[u8] = b"OBSIDIAN/P2P/AUTH/v1";

/// Bytes signed by [`Hello`].
pub fn hello_preimage(
    chain_id: u32,
    protocol_version: u32,
    genesis_hash: &Hash32,
    node_key: &[u8; 32],
    nonce: &[u8; 32],
    remote_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(HELLO_DOMAIN.len() + 8 + 96 + 64 + 64);
    out.extend_from_slice(HELLO_DOMAIN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&protocol_version.to_le_bytes());
    out.extend_from_slice(&genesis_hash.0);
    out.extend_from_slice(node_key);
    out.extend_from_slice(nonce);
    out.extend_from_slice(remote_nonce);
    out
}

/// Bytes signed by [`Auth`].
///
/// The initiator signs both nonces, so its proof of key possession is bound to
/// the responder's fresh challenge.  A recording of an earlier handshake cannot
/// be replayed against a different connection.
pub fn auth_preimage(
    chain_id: u32,
    genesis_hash: &Hash32,
    node_key: &[u8; 32],
    nonce: &[u8; 32],
    remote_nonce: &[u8; 32],
) -> Vec<u8> {
    let mut out = Vec::with_capacity(AUTH_DOMAIN.len() + 8 + 32 + 32 + 64 + 64);
    out.extend_from_slice(AUTH_DOMAIN);
    out.extend_from_slice(&MAGIC);
    out.extend_from_slice(&chain_id.to_le_bytes());
    out.extend_from_slice(&genesis_hash.0);
    out.extend_from_slice(node_key);
    out.extend_from_slice(nonce);
    out.extend_from_slice(remote_nonce);
    out
}

impl Encode for Hello {
    fn encode(&self, out: &mut Vec<u8>) {
        self.chain_id.encode(out);
        self.protocol_version.encode(out);
        self.genesis_hash.encode(out);
        out.extend_from_slice(&self.node_key);
        self.listen_port.encode(out);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.remote_nonce);
        self.head.encode(out);
        self.height.encode(out);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for Hello {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Hello {
            chain_id: u32::decode(decoder)?,
            protocol_version: u32::decode(decoder)?,
            genesis_hash: Hash32::decode(decoder)?,
            node_key: <[u8; 32]>::decode(decoder)?,
            listen_port: u16::decode(decoder)?,
            nonce: <[u8; 32]>::decode(decoder)?,
            remote_nonce: <[u8; 32]>::decode(decoder)?,
            head: Hash32::decode(decoder)?,
            height: u64::decode(decoder)?,
            signature: <[u8; 64]>::decode(decoder)?,
        })
    }
}

impl Encode for Auth {
    fn encode(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.node_key);
        out.extend_from_slice(&self.nonce);
        out.extend_from_slice(&self.remote_nonce);
        out.extend_from_slice(&self.signature);
    }
}

impl Decode for Auth {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Auth {
            node_key: <[u8; 32]>::decode(decoder)?,
            nonce: <[u8; 32]>::decode(decoder)?,
            remote_nonce: <[u8; 32]>::decode(decoder)?,
            signature: <[u8; 64]>::decode(decoder)?,
        })
    }
}

impl Encode for Status {
    fn encode(&self, out: &mut Vec<u8>) {
        self.head.encode(out);
        self.height.encode(out);
        self.weight_atoms.encode(out);
        self.finalized_height.encode(out);
        self.mempool_len.encode(out);
    }
}

impl Decode for Status {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(Status {
            head: Hash32::decode(decoder)?,
            height: u64::decode(decoder)?,
            weight_atoms: u128::decode(decoder)?,
            finalized_height: u64::decode(decoder)?,
            mempool_len: u32::decode(decoder)?,
        })
    }
}

impl Encode for GetBlocks {
    fn encode(&self, out: &mut Vec<u8>) {
        self.from_height.encode(out);
        self.max_blocks.encode(out);
    }
}

impl Decode for GetBlocks {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        Ok(GetBlocks {
            from_height: u64::decode(decoder)?,
            max_blocks: u32::decode(decoder)?,
        })
    }
}

impl Encode for Reject {
    fn encode(&self, out: &mut Vec<u8>) {
        out.push(self.code as u8);
        self.detail.encode(out);
    }
}

impl Decode for Reject {
    fn decode(decoder: &mut Decoder<'_>) -> Result<Self, obs_primitives::codec::CodecError> {
        let code = u8::decode(decoder)?;
        let code = RejectCode::from_byte(code).ok_or(
            obs_primitives::codec::CodecError::InvalidValue("reject code"),
        )?;
        Ok(Reject {
            code,
            detail: String::decode(decoder)?,
        })
    }
}

/// Convenience for tests and callers that want a decode with an exact shape.
pub fn decode_message(bytes: &[u8]) -> Result<NetMessage, MessageError> {
    NetMessage::decode_bytes(bytes)
}

/// Decodes a message that must be exactly one message.
pub fn decode_message_exact(bytes: &[u8]) -> Result<NetMessage, MessageError> {
    let message = decode_message(bytes)?;
    // `decode_bytes` already rejects trailing bytes; this helper exists so that
    // call sites read the same either way.
    Ok(message)
}

/// A single message decoded from a frame, kept for symmetry with `encode_frame`.
pub fn encode_frame(message: &NetMessage) -> Vec<u8> {
    let payload = message.encoded();
    let mut out = Vec::with_capacity(payload.len() + 4);
    out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
    out.extend_from_slice(&payload);
    out
}

/// Decodes a frame, returning the message and the number of bytes consumed.
pub fn decode_frame(input: &[u8]) -> Result<Option<(NetMessage, usize)>, MessageError> {
    if input.len() < 4 {
        return Ok(None);
    }
    let length = u32::from_le_bytes([input[0], input[1], input[2], input[3]]) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(MessageError::TooMany);
    }
    if input.len() < 4 + length {
        return Ok(None);
    }
    let message = NetMessage::decode_bytes(&input[4..4 + length])?;
    Ok(Some((message, 4 + length)))
}

/// Decodes a value that must consume its entire input.
pub fn decode_body<T: Decode>(bytes: &[u8]) -> Result<T, MessageError> {
    decode_exact(bytes).map_err(MessageError::Codec)
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::MAINNET;

    fn sample_status() -> Status {
        Status {
            head: Hash32::from_bytes([7u8; 32]),
            height: 42,
            weight_atoms: 123_456_789,
            finalized_height: 40,
            mempool_len: 3,
        }
    }

    #[test]
    fn every_message_round_trips() {
        let messages = vec![
            NetMessage::Hello(Hello {
                chain_id: MAINNET.chain_id,
                protocol_version: PROTOCOL_VERSION,
                genesis_hash: Hash32::from_bytes([1u8; 32]),
                node_key: [2u8; 32],
                listen_port: 9_200,
                nonce: [3u8; 32],
                remote_nonce: [4u8; 32],
                head: Hash32::from_bytes([5u8; 32]),
                height: 99,
                signature: [6u8; 64],
            }),
            NetMessage::Auth(Auth {
                node_key: [8u8; 32],
                nonce: [9u8; 32],
                remote_nonce: [10u8; 32],
                signature: [11u8; 64],
            }),
            NetMessage::Status(sample_status()),
            NetMessage::GetBlocks(GetBlocks {
                from_height: 1,
                max_blocks: 64,
            }),
            NetMessage::Blocks(Vec::new()),
            NetMessage::Transactions(Vec::new()),
            NetMessage::Attestations(Vec::new()),
            NetMessage::Ping(1_700_000_000),
            NetMessage::Pong(1_700_000_000),
            NetMessage::Reject(Reject {
                code: RejectCode::BadBlock,
                detail: "the state root does not match".to_string(),
            }),
            NetMessage::Bye(0),
        ];
        for message in messages {
            let bytes = message.encoded();
            let decoded = NetMessage::decode_bytes(&bytes).expect("round trip");
            assert_eq!(decoded, message);
            assert_eq!(decoded.tag(), message.tag());

            // And through the frame codec, which adds the length prefix.
            let frame = encode_frame(&message);
            let (framed, consumed) = decode_frame(&frame).unwrap().unwrap();
            assert_eq!(framed, message);
            assert_eq!(consumed, frame.len());
        }
    }

    #[test]
    fn incomplete_frames_ask_for_more_bytes() {
        let frame = encode_frame(&NetMessage::Status(sample_status()));
        for cut in 0..frame.len() {
            match decode_frame(&frame[..cut]) {
                Ok(None) => {}
                other => panic!("a truncated frame must be incomplete, got {:?}", other.is_ok()),
            }
        }
        assert!(decode_frame(&frame).unwrap().is_some());
    }

    #[test]
    fn malformed_and_hostile_messages_are_refused() {
        assert_eq!(decode_message(&[]), Err(MessageError::Empty));
        assert_eq!(decode_message(&[99]), Err(MessageError::UnknownTag(99)));

        // A valid tag with a truncated body.
        let mut bytes = NetMessage::Status(sample_status()).encoded();
        bytes.truncate(bytes.len() - 1);
        assert!(matches!(
            decode_message(&bytes),
            Err(MessageError::Codec(_))
        ));

        // Trailing bytes after an otherwise valid message.
        let mut bytes = NetMessage::Ping(1).encoded();
        bytes.push(0);
        assert_eq!(decode_message(&bytes), Err(MessageError::Trailing(1)));

        // A frame that claims to be larger than the protocol allows.
        let mut frame = vec![0xff, 0xff, 0xff, 0xff];
        frame.extend_from_slice(&[0u8; 8]);
        assert_eq!(decode_frame(&frame), Err(MessageError::TooMany));

        // A reject with an absurd detail string.
        let reject = NetMessage::Reject(Reject {
            code: RejectCode::Malformed,
            detail: "x".repeat(MAX_REJECT_DETAIL + 1),
        });
        assert_eq!(
            NetMessage::decode_bytes(&reject.encoded()),
            Err(MessageError::TooMany)
        );
    }

    #[test]
    fn handshake_preimages_are_domain_separated_and_bind_both_nonces() {
        let chain_id = MAINNET.chain_id;
        let genesis = Hash32::from_bytes([1u8; 32]);
        let key = [2u8; 32];
        let nonce = [3u8; 32];
        let remote = [4u8; 32];

        let hello = hello_preimage(chain_id, PROTOCOL_VERSION, &genesis, &key, &nonce, &remote);
        let auth = auth_preimage(chain_id, &genesis, &key, &nonce, &remote);
        assert_ne!(hello, auth, "the two signatures must not be interchangeable");
        assert!(hello.starts_with(HELLO_DOMAIN));
        assert!(auth.starts_with(AUTH_DOMAIN));

        for changed in [
            hello_preimage(chain_id + 1, PROTOCOL_VERSION, &genesis, &key, &nonce, &remote),
            hello_preimage(chain_id, PROTOCOL_VERSION + 1, &genesis, &key, &nonce, &remote),
            hello_preimage(
                chain_id,
                PROTOCOL_VERSION,
                &Hash32::from_bytes([9u8; 32]),
                &key,
                &nonce,
                &remote,
            ),
            hello_preimage(chain_id, PROTOCOL_VERSION, &genesis, &[9u8; 32], &nonce, &remote),
            hello_preimage(chain_id, PROTOCOL_VERSION, &genesis, &key, &[9u8; 32], &remote),
            hello_preimage(chain_id, PROTOCOL_VERSION, &genesis, &key, &nonce, &[9u8; 32]),
        ] {
            assert_ne!(changed, hello);
        }
        assert_ne!(
            auth_preimage(chain_id, &genesis, &key, &nonce, &[9u8; 32]),
            auth_preimage(chain_id, &genesis, &key, &[9u8; 32], &remote)
        );
    }
}
