//! Durable storage for the gateway's own state.
//!
//! The gateway stores exactly one thing: its *own* records (accounts, invitations,
//! API keys, sessions).  Everything about the chain — balances, blocks, claims,
//! validators — is read from a node and never stored here, because a gateway
//! that kept its own copy of chain state would eventually disagree with the
//! chain.  The authority hierarchy is: consensus decides, a node reports, the
//! gateway indexes, the UI displays.
//!
//! Writes are atomic: the new document is written to a temporary file, flushed,
//! and then renamed over the old one, so a crash leaves either the previous
//! document or the new one, never half of either.  A reader that finds a
//! truncated or unparsable document refuses to start rather than silently
//! beginning with an empty account list — losing the registry quietly would be
//! far worse than failing loudly.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

/// A failure reading or writing the store.
#[derive(Debug)]
pub enum StoreError {
    /// The filesystem refused an operation.
    Io(String),
    /// The document could not be understood.
    Corrupt(String),
}

impl core::fmt::Display for StoreError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            StoreError::Io(detail) => write!(f, "storage I/O: {}", detail),
            StoreError::Corrupt(detail) => write!(f, "storage document is not usable: {}", detail),
        }
    }
}

impl std::error::Error for StoreError {}

/// An atomically rewritten document.
#[derive(Debug, Clone)]
pub struct AtomicStore {
    path: PathBuf,
    /// Flush to disk before reporting success.
    fsync: bool,
}

impl AtomicStore {
    /// Opens (or prepares to create) a store at `path`.
    pub fn open(path: impl AsRef<Path>, fsync: bool) -> Result<AtomicStore, StoreError> {
        let path = path.as_ref().to_path_buf();
        if let Some(parent) = path.parent() {
            if !parent.as_os_str().is_empty() {
                fs::create_dir_all(parent).map_err(|error| StoreError::Io(error.to_string()))?;
            }
        }
        Ok(AtomicStore { path, fsync })
    }

    /// The path of the document.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Reads the document, or `None` when the store is new.
    ///
    /// A document that exists but cannot be read is an error: starting from an
    /// empty registry because a file was damaged would silently reset every
    /// account, invitation and API key.
    pub fn load(&self) -> Result<Option<String>, StoreError> {
        match fs::read_to_string(&self.path) {
            Ok(text) => Ok(Some(text)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(StoreError::Io(error.to_string())),
        }
    }

    /// Writes the document atomically.
    pub fn save(&self, document: &str) -> Result<(), StoreError> {
        let temporary = self.path.with_extension("tmp");
        {
            let mut file = fs::File::create(&temporary)
                .map_err(|error| StoreError::Io(error.to_string()))?;
            file.write_all(document.as_bytes())
                .map_err(|error| StoreError::Io(error.to_string()))?;
            if self.fsync {
                file.sync_all().map_err(|error| StoreError::Io(error.to_string()))?;
            }
        }
        fs::rename(&temporary, &self.path).map_err(|error| StoreError::Io(error.to_string()))?;
        if self.fsync {
            if let Some(parent) = self.path.parent() {
                if let Ok(directory) = fs::File::open(parent) {
                    let _ = directory.sync_all();
                }
            }
        }
        Ok(())
    }

    /// Parses the document, or returns `None` for a new store.
    pub fn load_json(&self) -> Result<Option<obs_primitives::json::Json>, StoreError> {
        match self.load()? {
            Some(text) => {
                let parsed = obs_primitives::json::parse(&text)
                    .map_err(|error| StoreError::Corrupt(error.to_string()))?;
                Ok(Some(parsed))
            }
            None => Ok(None),
        }
    }

    /// Writes a document from a JSON value.
    pub fn save_json(&self, value: &obs_primitives::json::Json) -> Result<(), StoreError> {
        self.save(&value.to_canonical_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::json::Json;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obs-gateway-store-{}-{}",
            std::process::id(),
            name
        ));
        let _ = fs::remove_dir_all(&dir);
        dir.join("registry.json")
    }

    #[test]
    fn a_new_store_is_empty_and_a_written_one_reads_back() {
        let path = temp_path("roundtrip");
        let store = AtomicStore::open(&path, false).unwrap();
        assert!(store.load().unwrap().is_none());
        let value = Json::obj([("version", Json::Int(1))]);
        store.save_json(&value).unwrap();
        let read = store.load_json().unwrap().unwrap();
        assert_eq!(read.get("version").unwrap().as_i128(), Some(1));
        // The temporary file is gone: the rename replaced it.
        assert!(!path.with_extension("tmp").exists());
    }

    #[test]
    fn a_damaged_document_is_an_error_not_an_empty_store() {
        let path = temp_path("damaged");
        let store = AtomicStore::open(&path, false).unwrap();
        store.save("{not json at all").unwrap();
        match store.load_json() {
            Err(StoreError::Corrupt(_)) => {}
            other => panic!("a damaged document must be reported: {:?}", other),
        }
    }

    #[test]
    fn a_rewrite_leaves_only_the_new_document() {
        let path = temp_path("rewrite");
        let store = AtomicStore::open(&path, false).unwrap();
        for version in 1..=5 {
            store
                .save_json(&Json::obj([("version", Json::Int(version))]))
                .unwrap();
            assert_eq!(
                store.load_json().unwrap().unwrap().get("version").unwrap().as_i128(),
                Some(version)
            );
        }
    }
}
