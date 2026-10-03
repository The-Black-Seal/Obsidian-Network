//! The registration authority.
//!
//! The chain lets an account register only if the transaction carries an
//! [`InviteAuthorization`] signed by a registration authority key.  That key is
//! what stops an invitation from being spent by somebody other than the identity
//! it was issued for: the authorisation commits to *both* the invitation code and
//! the canonical Gmail, and a registration transaction must present a matching
//! one, so a leaked code is useless without passing the enrolment flow.
//!
//! ## The key file
//!
//! The authority key is the one secret this service holds that carries protocol
//! weight, so it lives in its own file, created with `0600` permissions, outside
//! the account store.  If the file is missing, the gateway *refuses to start*
//! rather than quietly generating a new authority — a new authority would be
//! unable to authorise anything for the network whose genesis bound the real
//! one, so silently replacing it would just break registration in a confusing
//! way.
//!
//! An operator can generate one with `obs-gateway --generate-authority`.

use std::path::{Path, PathBuf};

use obs_chain::chain::{invite_commitment, InviteAuthorization};
use obs_crypto::ed25519::Keypair;
use obs_crypto::encoding::{hex_decode, hex_encode};
use obs_primitives::address::Address;
use obs_primitives::hash::Hash32;
use obs_primitives::network::Network;

/// A failure loading or creating the authority key.
#[derive(Debug)]
pub enum AuthorityError {
    /// The file could not be read or written.
    Io(String),
    /// The file exists but is not a usable key.
    BadKey(String),
}

impl core::fmt::Display for AuthorityError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            AuthorityError::Io(detail) => write!(f, "authority key I/O: {}", detail),
            AuthorityError::BadKey(detail) => write!(f, "authority key is not usable: {}", detail),
        }
    }
}

impl std::error::Error for AuthorityError {}

/// The registration authority's signing key.
pub struct Authority {
    network: Network,
    keypair: Keypair,
    path: PathBuf,
}

impl Authority {
    /// Loads the authority key from `path`.
    pub fn load(path: impl AsRef<Path>, network: Network) -> Result<Authority, AuthorityError> {
        let path = path.as_ref().to_path_buf();
        let text = std::fs::read_to_string(&path).map_err(|error| {
            AuthorityError::Io(format!(
                "{}: {} (generate one with --generate-authority)",
                path.display(),
                error
            ))
        })?;
        let seed = parse_key_file(&text)?;
        Ok(Authority {
            network,
            keypair: Keypair::from_seed(&seed),
            path,
        })
    }

    /// Generates a new authority key and writes it with `0600` permissions.
    ///
    /// This is an operator action, run once per network: the resulting public key
    /// is what the network's genesis records.
    pub fn generate(path: impl AsRef<Path>, network: Network) -> Result<Authority, AuthorityError> {
        let path = path.as_ref().to_path_buf();
        let mut seed = [0u8; 32];
        obs_crypto::rand::os_random(&mut seed).map_err(|error| AuthorityError::Io(error.to_string()))?;
        let keypair = Keypair::from_seed(&seed);
        let seed_hex = hex_encode(&seed);
        let public_hex = hex_encode(&keypair.public_key());
        seed.fill(0);
        let document = format!(
            "# Obsidian Network registration authority key.\n\
             # Network: {} (chain id {}).\n\
             # This file is the authority for invitation authorisations. Keep it secret,\n\
             # keep it out of source control, and back it up: losing it means no new\n\
             # account can be registered on this network.\n\
             seed {}\n\
             public {}\n",
            network.name,
            network.chain_id,
            seed_hex,
            public_hex
        );
        write_private(&path, &document)?;
        Ok(Authority {
            network,
            keypair,
            path,
        })
    }

    /// Loads the key, or generates one when the file does not exist.
    ///
    /// Only for local development networks: on a real network, a missing
    /// authority key must stop the service, not create a new identity.
    pub fn load_or_generate(
        path: impl AsRef<Path>,
        network: Network,
    ) -> Result<Authority, AuthorityError> {
        let path = path.as_ref();
        if path.exists() {
            Authority::load(path, network)
        } else {
            Authority::generate(path, network)
        }
    }

    /// Where the key lives.
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// The authority's public key, which genesis records.
    pub fn public_key(&self) -> [u8; 32] {
        self.keypair.public_key()
    }

    /// The authority's public key as hex, for pasting into a genesis file.
    pub fn public_key_hex(&self) -> String {
        hex_encode(&self.keypair.public_key())
    }

    /// Issues an invitation authorisation.
    ///
    /// The invitation's commitment is computed here from the code, so the code
    /// itself is never stored: the authorisation carries only the commitment, and
    /// the chain checks the same computation.
    pub fn authorize(
        &self,
        code: &str,
        gmail_commitment: Hash32,
        issued_at: u64,
        expires_at: u64,
        issuer: Option<Address>,
    ) -> InviteAuthorization {
        InviteAuthorization::issue(
            self.network.chain_id,
            &self.keypair,
            invite_commitment(self.network.chain_id, code),
            gmail_commitment,
            issued_at,
            expires_at,
            issuer,
        )
    }
}

fn parse_key_file(text: &str) -> Result<[u8; 32], AuthorityError> {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.split_whitespace();
        let tag = parts.next().unwrap_or_default();
        let value = parts.next().unwrap_or_default();
        if tag == "seed" {
            let bytes = hex_decode(value)
                .ok_or_else(|| AuthorityError::BadKey("the seed is not hex".to_string()))?;
            if bytes.len() != 32 {
                return Err(AuthorityError::BadKey("the seed must be 32 bytes".to_string()));
            }
            let mut seed = [0u8; 32];
            seed.copy_from_slice(&bytes);
            return Ok(seed);
        }
    }
    Err(AuthorityError::BadKey("no seed line".to_string()))
}

fn write_private(path: &Path, document: &str) -> Result<(), AuthorityError> {
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent).map_err(|error| AuthorityError::Io(error.to_string()))?;
        }
    }
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
        .map_err(|error| AuthorityError::Io(error.to_string()))?;
    file.write_all(document.as_bytes())
        .map_err(|error| AuthorityError::Io(error.to_string()))?;
    file.sync_all().map_err(|error| AuthorityError::Io(error.to_string()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::DEVNET;

    fn temp_path(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obs-authority-{}-{}",
            std::process::id(),
            name
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir.join("authority.key")
    }

    #[test]
    fn a_generated_key_round_trips_and_its_file_is_owner_only() {
        let path = temp_path("roundtrip");
        let authority = Authority::generate(&path, DEVNET).unwrap();
        let public = authority.public_key();
        let loaded = Authority::load(&path, DEVNET).unwrap();
        assert_eq!(loaded.public_key(), public);
        let text = std::fs::read_to_string(&path).unwrap();
        assert!(text.contains("public"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600, "the authority key must not be world-readable");
        }
    }

    #[test]
    fn a_broken_key_file_is_refused_rather_than_replaced() {
        let path = temp_path("broken");
        std::fs::write(&path, "seed not-hex\n").unwrap();
        assert!(matches!(Authority::load(&path, DEVNET), Err(AuthorityError::BadKey(_))));
        // Loading must not overwrite the file it could not read.
        assert!(std::fs::read_to_string(&path).unwrap().contains("not-hex"));
    }

    #[test]
    fn an_authorisation_commits_to_the_code_and_the_identity() {
        let path = temp_path("authorize");
        let authority = Authority::generate(&path, DEVNET).unwrap();
        let commitment = obs_chain::chain::gmail_commitment(DEVNET.chain_id, "miner@gmail.com");
        let authorisation = authority.authorize(
            "OBS-ABCD-EFGH-JKMP-QRST",
            commitment,
            1_700_000_000,
            1_800_000_000,
            None,
        );
        assert!(authorisation.verify_signature(DEVNET.chain_id));
        assert_eq!(authorisation.gmail_commitment, commitment);
        // The same code on another network is a different commitment, so an
        // authorisation can never be replayed across networks.
        let other = Authority::generate(temp_path("authorize-2"), obs_primitives::network::TESTNET)
            .unwrap();
        let cross = other.authorize("OBS-ABCD-EFGH-JKMP-QRST", commitment, 0, 1, None);
        assert!(!cross.verify_signature(DEVNET.chain_id));
    }
}
