//! Durable block storage.
//!
//! The block log is a single append-only file with a small, versioned,
//! self-describing record format:
//!
//! ```text
//! file  := magic:8 "OBSBLK1\0" record*
//! record := len:u32_le | crc32:u32_le | payload[len]
//! payload := canonical encoding of one Block
//! ```
//!
//! Properties the storage layer guarantees, and the tests prove:
//!
//! * **Atomic records.**  A record is either fully present and correct, or it
//!   is ignored.  A partially written trailing record (a power failure during
//!   `append`) is detected by length and dropped on load; the log is truncated
//!   back to the last complete record so the next append starts clean.
//! * **Fail closed on corruption.**  A complete record whose checksum does not
//!   match is an error: the node refuses to start rather than silently building
//!   a chain on damaged data.
//! * **Durability.**  Every accepted block is written to the log.  With
//!   `fsync` set, every append is also flushed to the disk (`sync_data`) before
//!   it is reported as stored, so an acknowledged block survives a crash; set
//!   or not, it survives the process.
//! * **One chain per directory.**  The genesis a directory was founded with is
//!   written beside the log and is authoritative afterwards: restarting a node
//!   resumes the chain it has, it does not refound it.  Starting a node against
//!   a directory that holds a different chain is an error, not a silent reset.
//!
//! The log is not the source of truth for the *chain*: it is a set of candidate
//! blocks.  Which of them form the canonical chain is decided by the fork
//! choice in [`crate::ChainStore`], exactly as it is on the wire.

use std::fs::{File, OpenOptions};
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

use obs_chain::state::GenesisConfig;
use obs_chain::Block;
use obs_primitives::codec::Encode;
use obs_primitives::hash::Hash32;
use obs_primitives::network::Network;

/// File magic, including a format version.
pub const LOG_MAGIC: &[u8; 8] = b"OBSBLK1\0";

/// First line of a data directory's genesis record.
pub const GENESIS_HEADER: &str = "obsidian-genesis 1";

/// Maximum size of a single block record payload (8 MiB, matching the codec).
pub const MAX_RECORD_LEN: usize = 8 * 1024 * 1024;

/// Size of a record header: `len` + `crc32`.
pub const RECORD_HEADER_LEN: usize = 8;

/// Storage errors.  Every variant is terminal for the operation that produced
/// it; the caller decides whether to retry, and a node never continues on a
/// corrupted log.
#[derive(Debug)]
pub enum StoreError {
    /// Underlying I/O failure.
    Io(io::Error),
    /// The file does not start with the expected magic and version.
    BadMagic,
    /// A complete record failed its checksum: the log is corrupt.
    ChecksumMismatch {
        /// Byte offset of the offending record.
        offset: u64,
    },
    /// A record declared a length that the format does not allow.
    RecordTooLarge {
        /// Declared length.
        len: u32,
    },
    /// A stored payload could not be decoded as a block.
    Decode(obs_primitives::codec::CodecError),
    /// The genesis record in the data directory is malformed.
    BadGenesis,
    /// A data directory holds blocks but no record of the chain they belong to,
    /// so the genesis they descend from cannot be reconstructed.
    GenesisUnrecorded {
        /// How many blocks the log holds.
        blocks: u64,
    },
    /// The configuration a node was started with does not describe the chain
    /// already stored in its data directory.
    GenesisMismatch {
        /// What the data directory holds.
        stored: String,
        /// What this process was started with.
        started: String,
    },
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreError::Io(error) => write!(f, "storage I/O error: {}", error),
            StoreError::BadMagic => write!(f, "not an Obsidian block log"),
            StoreError::ChecksumMismatch { offset } => {
                write!(f, "block log checksum mismatch at offset {}", offset)
            }
            StoreError::RecordTooLarge { len } => {
                write!(f, "block log record of {} bytes exceeds the limit", len)
            }
            StoreError::BadGenesis => {
                write!(f, "this data directory's genesis record is malformed")
            }
            StoreError::GenesisUnrecorded { blocks } => write!(
                f,
                "this data directory holds {} blocks but no genesis record, so the chain they \
                 belong to cannot be reconstructed: restore the missing genesis record, or \
                 start from a new data directory",
                blocks
            ),
            StoreError::GenesisMismatch { stored, started } => write!(
                f,
                "this data directory holds the chain {}; this process was started for {}",
                stored, started
            ),
            StoreError::Decode(error) => write!(f, "block log record failed to decode: {}", error),
        }
    }
}

impl std::error::Error for StoreError {}

impl From<io::Error> for StoreError {
    fn from(error: io::Error) -> Self {
        StoreError::Io(error)
    }
}

impl From<obs_primitives::codec::CodecError> for StoreError {
    fn from(error: obs_primitives::codec::CodecError) -> Self {
        StoreError::Decode(error)
    }
}

/// The result of scanning a log file.
#[derive(Debug)]
pub struct ScanResult {
    /// Every complete, checksum-valid block found, in file order.
    pub blocks: Vec<Block>,
    /// Number of bytes of complete records (the truncation point).
    pub valid_len: u64,
    /// Bytes dropped because they formed an incomplete trailing record.
    pub truncated_tail: u64,
}

/// Appends blocks to a file, durably.
#[derive(Debug)]
pub struct BlockLog {
    path: PathBuf,
    file: File,
    fsync: bool,
}

impl BlockLog {
    /// Opens (creating if needed) a block log, returning it together with
    /// everything already stored.
    ///
    /// A partial trailing record is dropped and the file is truncated back to
    /// the last complete record, so the log is always in a state where the next
    /// append is at a record boundary.
    pub fn open(path: impl AsRef<Path>, fsync: bool) -> Result<(BlockLog, ScanResult), StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let mut file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open(&path)?;

        let size = file.metadata()?.len();
        if size == 0 {
            file.write_all(LOG_MAGIC)?;
            file.sync_data()?;
        }

        let scan = scan_log(&mut file)?;
        if scan.truncated_tail > 0 {
            // Rewrite the file without the partial tail so the next append lands
            // on a record boundary.
            file.set_len(scan.valid_len)?;
            file.sync_data()?;
        }
        file.seek(SeekFrom::End(0))?;
        Ok((
            BlockLog {
                path,
                file,
                fsync,
            },
            scan,
        ))
    }

    /// Path of the log file.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Appends one block.  The block is only reported as stored once it is in
    /// the operating system's or the disk's hands, depending on `fsync`.
    pub fn append(&mut self, block: &Block) -> Result<u64, StoreError> {
        let payload = block.encoded();
        if payload.len() > MAX_RECORD_LEN {
            return Err(StoreError::RecordTooLarge {
                len: payload.len() as u32,
            });
        }
        let mut record = Vec::with_capacity(RECORD_HEADER_LEN + payload.len());
        record.extend_from_slice(&(payload.len() as u32).to_le_bytes());
        record.extend_from_slice(&crc32(&payload).to_le_bytes());
        record.extend_from_slice(&payload);

        self.file.write_all(&record)?;
        if self.fsync {
            self.file.sync_data()?;
        }
        Ok(self.file.seek(SeekFrom::End(0))?)
    }

    /// Current length of the log in bytes.
    pub fn len(&self) -> io::Result<u64> {
        Ok(self.file.metadata()?.len())
    }

    /// Is the log empty (no blocks stored)?
    pub fn is_empty(&self) -> bool {
        self.len().map(|len| len <= LOG_MAGIC.len() as u64).unwrap_or(true)
    }

    /// Forces buffered data to disk.
    pub fn flush(&mut self) -> Result<(), StoreError> {
        self.file.sync_data()?;
        Ok(())
    }
}

/// Scans a log from the beginning.
fn scan_log(file: &mut File) -> Result<ScanResult, StoreError> {
    file.seek(SeekFrom::Start(0))?;
    let mut data = Vec::new();
    file.read_to_end(&mut data)?;

    if data.len() < LOG_MAGIC.len() || &data[..LOG_MAGIC.len()] != LOG_MAGIC {
        return Err(StoreError::BadMagic);
    }

    let mut blocks = Vec::new();
    let mut offset = LOG_MAGIC.len();
    let mut valid_len = LOG_MAGIC.len() as u64;
    let mut truncated_tail = 0u64;

    while offset < data.len() {
        if data.len() - offset < RECORD_HEADER_LEN {
            // A partial header: an interrupted append.  Drop it.
            truncated_tail = (data.len() - offset) as u64;
            break;
        }
        let len = u32::from_le_bytes(
            data[offset..offset + 4]
                .try_into()
                .expect("four bytes are present"),
        ) as usize;
        let crc = u32::from_le_bytes(
            data[offset + 4..offset + 8]
                .try_into()
                .expect("four bytes are present"),
        );
        if len > MAX_RECORD_LEN {
            return Err(StoreError::RecordTooLarge { len: len as u32 });
        }
        let payload_start = offset + RECORD_HEADER_LEN;
        if data.len() - payload_start < len {
            // A partial payload: an interrupted append.  Drop it.
            truncated_tail = (data.len() - offset) as u64;
            break;
        }
        let payload = &data[payload_start..payload_start + len];
        if crc32(payload) != crc {
            return Err(StoreError::ChecksumMismatch {
                offset: offset as u64,
            });
        }
        let block: Block = obs_primitives::codec::decode_exact(payload)?;
        blocks.push(block);
        offset = payload_start + len;
        valid_len = offset as u64;
    }

    Ok(ScanResult {
        blocks,
        valid_len,
        truncated_tail,
    })
}

/// CRC-32 (IEEE 802.3, the same polynomial as zip and gzip).
///
/// A checksum is used here rather than a hash because its only job is to detect
/// accidental write corruption, and it is computed over the exact stored bytes
/// — content integrity is already guaranteed by the block hash.
pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for byte in data {
        crc ^= *byte as u32;
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Convenience: the file name used for a network's block log.
pub fn log_file_name(network: obs_primitives::network::Network) -> PathBuf {
    PathBuf::from(format!("{}-blocks.log", network.name))
}

/// Convenience: the path of the head pointer file for a network.
pub fn head_file_name(network: obs_primitives::network::Network) -> PathBuf {
    PathBuf::from(format!("{}-head", network.name))
}

/// Convenience: the path of the genesis record for a network.
pub fn genesis_file_name(network: Network) -> PathBuf {
    PathBuf::from(format!("{}-genesis", network.name))
}

/// Reads the genesis record a data directory was founded with, if it has one.
///
/// The format is one `key value` per line with a version tag, so an operator can
/// read it with `cat` and diff two directories without a tool.  Anything not
/// exactly of this shape is an error: a data directory's genesis is not a hint.
pub fn read_genesis(path: impl AsRef<Path>) -> Result<Option<GenesisConfig>, StoreError> {
    let path = path.as_ref();
    let text = match std::fs::read_to_string(path) {
        Ok(text) => text,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(StoreError::Io(error)),
    };
    let mut network: Option<Network> = None;
    let mut chain_id: Option<u64> = None;
    let mut authority: Option<Hash32> = None;
    let mut timestamp: Option<u64> = None;
    let mut lines = text.lines();
    if lines.next() != Some(GENESIS_HEADER) {
        return Err(StoreError::BadGenesis);
    }
    // The record is machine-written, so a missing final newline is a sign the
    // file was truncated rather than written: refuse it instead of accepting a
    // record whose tail may be missing.
    if !text.ends_with('\n') {
        return Err(StoreError::BadGenesis);
    }
    for line in lines {
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line.split_once(' ').ok_or(StoreError::BadGenesis)?;
        match key {
            "network" => {
                network = Some(Network::by_name(value).ok_or(StoreError::BadGenesis)?)
            }
            "chain_id" => chain_id = Some(value.parse().map_err(|_| StoreError::BadGenesis)?),
            "authority" => {
                authority = Some(Hash32::from_hex(value.trim()).ok_or(StoreError::BadGenesis)?)
            }
            "timestamp" => timestamp = Some(value.parse().map_err(|_| StoreError::BadGenesis)?),
            _ => return Err(StoreError::BadGenesis),
        }
    }
    let network = network.ok_or(StoreError::BadGenesis)?;
    if chain_id != Some(network.chain_id as u64) {
        return Err(StoreError::BadGenesis);
    }
    Ok(Some(GenesisConfig {
        network,
        registration_authority: authority.ok_or(StoreError::BadGenesis)?.0,
        timestamp: timestamp.ok_or(StoreError::BadGenesis)?,
    }))
}

/// Writes a genesis record atomically (temporary file, then rename), so a
/// half-written record can never be read back as a chain's identity.
pub fn write_genesis(path: impl AsRef<Path>, genesis: &GenesisConfig) -> Result<(), StoreError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let body = format!(
        "{}\nnetwork {}\nchain_id {}\nauthority {}\ntimestamp {}\n",
        GENESIS_HEADER,
        genesis.network.name,
        genesis.network.chain_id,
        Hash32(genesis.registration_authority).to_hex(),
        genesis.timestamp
    );
    let temporary = path.with_extension("genesis.tmp");
    {
        let mut file = File::create(&temporary)?;
        file.write_all(body.as_bytes())?;
        file.sync_data()?;
    }
    std::fs::rename(&temporary, path)?;
    Ok(())
}

/// Reads a persisted head pointer (best block hash), if present.
pub fn read_head(path: impl AsRef<Path>) -> Result<Option<Hash32>, StoreError> {
    let path = path.as_ref();
    match std::fs::read(path) {
        Ok(bytes) => {
            if bytes.len() != 32 {
                return Err(StoreError::ChecksumMismatch { offset: 0 });
            }
            let mut raw = [0u8; 32];
            raw.copy_from_slice(&bytes);
            Ok(Some(Hash32::from_bytes(raw)))
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(StoreError::Io(error)),
    }
}

/// Writes a head pointer atomically (write to a temporary file, then rename).
///
/// The rename is atomic on every supported platform, so a crash can never leave
/// a half-written head pointer: readers see either the previous head or the new
/// one, never a mix.
pub fn write_head(path: impl AsRef<Path>, head: &Hash32) -> Result<(), StoreError> {
    let path = path.as_ref();
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let temporary = path.with_extension("tmp");
    {
        let mut file = File::create(&temporary)?;
        file.write_all(&head.0)?;
        file.sync_data()?;
    }
    std::fs::rename(&temporary, path)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_chain::params::{GENESIS_TIMESTAMP, PROTOCOL_VERSION};
    use obs_primitives::network::MAINNET;

    fn genesis_block() -> Block {
        Block::genesis(MAINNET, PROTOCOL_VERSION, GENESIS_TIMESTAMP)
    }

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obs-consensus-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn crc32_matches_known_values() {
        // Standard CRC-32 test vectors.
        assert_eq!(crc32(b""), 0x0000_0000);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
        assert_eq!(crc32(b"The quick brown fox jumps over the lazy dog"), 0x414F_A339);
    }

    #[test]
    fn blocks_round_trip_through_the_log() {
        let dir = temp_dir("roundtrip");
        let path = dir.join("test.log");
        let block = genesis_block();
        {
            let (mut log, scan) = BlockLog::open(&path, true).unwrap();
            assert!(log.is_empty());
            assert_eq!(scan.blocks.len(), 0);
            log.append(&block).unwrap();
            log.append(&block).unwrap();
            log.flush().unwrap();
        }
        let (_log, scan) = BlockLog::open(&path, false).unwrap();
        assert_eq!(scan.blocks.len(), 2);
        assert_eq!(scan.blocks[0], block);
        assert_eq!(scan.truncated_tail, 0);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_partial_trailing_record_is_dropped_and_the_log_repaired() {
        let dir = temp_dir("partial");
        let path = dir.join("test.log");
        {
            let (mut log, _) = BlockLog::open(&path, true).unwrap();
            log.append(&genesis_block()).unwrap();
            log.flush().unwrap();
        }
        let complete_len = std::fs::metadata(&path).unwrap().len();
        // Simulate a crash mid-append: write a header without its payload.
        {
            let mut file = OpenOptions::new().append(true).open(&path).unwrap();
            file.write_all(&1_000u32.to_le_bytes()).unwrap();
            file.write_all(&0xDEAD_BEEFu32.to_le_bytes()).unwrap();
            file.write_all(b"partial").unwrap();
        }

        let (log, scan) = BlockLog::open(&path, true).unwrap();
        assert_eq!(scan.blocks.len(), 1, "the complete record survives");
        assert!(scan.truncated_tail > 0);
        assert_eq!(log.len().unwrap(), complete_len, "the tail is truncated away");

        // The repaired log accepts a new append and reloads cleanly.
        drop(log);
        let (mut log, _) = BlockLog::open(&path, true).unwrap();
        log.append(&genesis_block()).unwrap();
        log.flush().unwrap();
        drop(log);
        let (_log, scan) = BlockLog::open(&path, false).unwrap();
        assert_eq!(scan.blocks.len(), 2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_corrupt_record_is_rejected() {
        let dir = temp_dir("corrupt");
        let path = dir.join("test.log");
        {
            let (mut log, _) = BlockLog::open(&path, true).unwrap();
            log.append(&genesis_block()).unwrap();
            log.flush().unwrap();
        }
        // Flip one bit inside the payload, leaving the length intact: this is
        // corruption, not truncation, and it must be an error.
        let mut bytes = std::fs::read(&path).unwrap();
        let last = bytes.len() - 1;
        bytes[last] ^= 0x01;
        std::fs::write(&path, &bytes).unwrap();

        match BlockLog::open(&path, false) {
            Err(StoreError::ChecksumMismatch { .. }) => {}
            other => panic!("corruption must be detected, got {:?}", other.is_ok()),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_foreign_file_is_not_a_block_log() {
        let dir = temp_dir("foreign");
        let path = dir.join("test.log");
        std::fs::write(&path, b"not an obsidian block log at all").unwrap();
        match BlockLog::open(&path, false) {
            Err(StoreError::BadMagic) => {}
            other => panic!("expected BadMagic, got ok={}", other.is_ok()),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_genesis_record_round_trips() {
        let dir = temp_dir("genesis");
        let path = dir.join(genesis_file_name(MAINNET));
        assert_eq!(read_genesis(&path).unwrap(), None, "an empty directory has none");
        let genesis = GenesisConfig {
            network: MAINNET,
            registration_authority: [9u8; 32],
            timestamp: GENESIS_TIMESTAMP,
        };
        write_genesis(&path, &genesis).unwrap();
        assert_eq!(read_genesis(&path).unwrap(), Some(genesis));
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_log_with_blocks_but_no_genesis_record_is_refused() {
        // The directory cannot be resumed: the anchor is a hash, so the epoch it
        // was founded with is not recoverable from the blocks, and guessing one
        // would silently orphan every block in the log.
        let dir = temp_dir("genesis-unrecorded");
        let block = genesis_block();
        {
            let (mut log, _) = BlockLog::open(dir.join(log_file_name(MAINNET)), false).unwrap();
            log.append(&block).unwrap();
        }
        let reopened = crate::ChainStore::open(
            &dir,
            MAINNET,
            GenesisConfig {
                network: MAINNET,
                registration_authority: [1u8; 32],
                timestamp: GENESIS_TIMESTAMP,
            },
            false,
        );
        match reopened {
            Ok(_) => panic!("a chain that cannot be identified must not be resumed"),
            Err(error) => assert_eq!(
                error.to_string(),
                StoreError::GenesisUnrecorded { blocks: 1 }.to_string()
            ),
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_genesis_record_that_is_not_exactly_right_is_an_error() {
        let dir = temp_dir("genesis-bad");
        let path = dir.join("devnet-genesis");
        let good_authority = "0000000000000000000000000000000000000000000000000000000000000000";
        for text in [
            "",
            "obsidian-genesis 1\n",
            "obsidian-genesis 2\nnetwork devnet\nchain_id 3\nauthority 00\ntimestamp 1\n",
            &format!("obsidian-genesis 1\nnetwork devnet\nchain_id 4\nauthority {}\ntimestamp 1\n", good_authority),
            &format!("obsidian-genesis 1\nnetwork devnet\nchain_id 3\nauthority nothex\ntimestamp 1\n"),
            &format!("obsidian-genesis 1\nnetwork devnet\nchain_id 3\nauthority {}\ntimestamp soon\n", good_authority),
            &format!("obsidian-genesis 1\nnetwork devnet\nchain_id 3\nauthority {}\ntimestamp 1\nextra 2\n", good_authority),
            &format!("obsidian-genesis 1\nnetwork devnet\nchain_id 3\nauthority {}\ntimestamp 1", good_authority),
        ] {
            std::fs::write(&path, text).unwrap();
            assert_eq!(
                read_genesis(&path).unwrap_err().to_string(),
                StoreError::BadGenesis.to_string(),
                "a genesis record that is not exact must not be guessed at: {:?}",
                text
            );
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn the_head_pointer_is_written_atomically_and_read_back() {
        let dir = temp_dir("head");
        let path = dir.join("head");
        assert_eq!(read_head(&path).unwrap(), None);
        let head = Hash32::from_bytes([7u8; 32]);
        write_head(&path, &head).unwrap();
        assert_eq!(read_head(&path).unwrap(), Some(head));
        // A truncated head pointer is an error rather than a silent default.
        std::fs::write(&path, [1u8, 2, 3]).unwrap();
        assert!(read_head(&path).is_err());
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
