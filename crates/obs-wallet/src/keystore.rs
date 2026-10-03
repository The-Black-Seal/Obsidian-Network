//! The encrypted wallet file.
//!
//! A keystore is the wallet's secret material — never the recovery phrase, and
//! never a server-side copy — encrypted with a password the user knows:
//!
//! ```text
//!   OBSK1 | header (version, kdf params, salt, nonce, label) | ciphertext||tag
//!            └── authenticated as additional data ──────────────┘
//! ```
//!
//! * **Argon2id**, 64 MiB and three passes, turns the password into a 32-byte
//!   encryption key.  Those are the protocol's [`Argon2Params::PASSWORD`]
//!   parameters: memory-hard, so a GPU farm gains little over a laptop, and
//!   deliberately expensive enough that online guessing is hopeless.
//! * **ChaCha20-Poly1305** encrypts the seed and authenticates the header, so
//!   changing a cost parameter, a salt or a nonce is a *decryption failure*
//!   rather than a silently weakened file.
//! * Only the 64-byte BIP-39 seed is stored, not the derived private keys: the
//!   phrase can be re-derived from it, and the format stays stable if the
//!   derivation roles ever gain a sibling.
//!
//! The file carries a *label* (usually a partially masked account identifier) so
//! a user with several wallets can tell them apart without opening either.  The
//! label is authenticated, and it is never a secret.

use obs_crypto::argon2::{argon2id, Argon2Params, Argon2Type};
use obs_crypto::chacha::ChaCha20Poly1305;
use obs_crypto::ct::{Zeroize, Zeroizing};
use obs_crypto::encoding::{base64url_decode, base64url_encode};
use obs_primitives::network::Network;

use crate::{Wallet, WalletError};

/// Keystore format version.
pub const FORMAT_VERSION: u8 = 1;
/// Magic bytes at the start of every keystore.
pub const MAGIC: &[u8; 5] = b"OBSK1";
/// Salt length for Argon2id.
pub const SALT_LEN: usize = 16;
/// Nonce length for ChaCha20-Poly1305.
pub const NONCE_LEN: usize = 12;
/// Largest label accepted.
pub const MAX_LABEL_LEN: usize = 96;

/// A sealed wallet file.
pub struct Keystore {
    version: u8,
    params: Argon2Params,
    salt: [u8; SALT_LEN],
    nonce: [u8; NONCE_LEN],
    label: String,
    network: Network,
    account: u32,
    sealed: Vec<u8>,
}

impl core::fmt::Debug for Keystore {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Keystore")
            .field("version", &self.version)
            .field("label", &self.label)
            .field("network", &self.network.name)
            .field("account", &self.account)
            .field("memory_kib", &self.params.memory_kib)
            .field("iterations", &self.params.iterations)
            .field("sealed_bytes", &self.sealed.len())
            .finish()
    }
}

impl Keystore {
    /// Seals a wallet under a password.
    pub fn seal(wallet: &Wallet, password: &str, label: &str) -> Result<Keystore, WalletError> {
        if password.is_empty() {
            return Err(WalletError::Unsupported(
                "a keystore password may not be empty".to_string(),
            ));
        }
        if label.len() > MAX_LABEL_LEN {
            return Err(WalletError::Unsupported(format!(
                "a keystore label must be at most {} bytes",
                MAX_LABEL_LEN
            )));
        }
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        obs_crypto::rand::os_random(&mut salt)?;
        obs_crypto::rand::os_random(&mut nonce)?;

        let params = Argon2Params::PASSWORD;
        let mut secret = Zeroizing(Vec::from(wallet.seed_bytes()));
        let mut key = Zeroizing(derive_key(&params, password, &salt)?);
        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&key);

        let header = header_bytes(
            FORMAT_VERSION,
            &params,
            &salt,
            &nonce,
            label,
            wallet.network(),
            wallet.account(),
        );
        let sealed = ChaCha20Poly1305::encrypt(&cipher_key, &nonce, &header, &secret);
        secret.zeroize();
        cipher_key.zeroize();
        key.zeroize();
        Ok(Keystore {
            version: FORMAT_VERSION,
            params,
            salt,
            nonce,
            label: label.to_string(),
            network: wallet.network(),
            account: wallet.account(),
            sealed,
        })
    }

    /// Opens a keystore with a password.
    ///
    /// A wrong password and a damaged file are reported identically: the caller
    /// learns that the wallet did not open, and nothing else.
    pub fn open(&self, password: &str) -> Result<Wallet, WalletError> {
        let key = Zeroizing(derive_key(&self.params, password, &self.salt).map_err(|_| {
            WalletError::BadKeystore("the key-derivation parameters are not usable".to_string())
        })?);
        let mut cipher_key = [0u8; 32];
        cipher_key.copy_from_slice(&key);
        let header = header_bytes(
            self.version,
            &self.params,
            &self.salt,
            &self.nonce,
            &self.label,
            self.network,
            self.account,
        );
        let mut seed = Zeroizing(
            ChaCha20Poly1305::decrypt(&cipher_key, &self.nonce, &header, &self.sealed)
                .ok_or(WalletError::BadPasswordOrCorrupt)?,
        );
        if seed.len() != 64 {
            return Err(WalletError::BadPasswordOrCorrupt);
        }
        let mut seed64 = [0u8; 64];
        seed64.copy_from_slice(&seed);
        let wallet = Wallet::from_seed(self.network, &seed64, self.account)?;
        seed64.zeroize();
        seed.zeroize();
        Ok(wallet)
    }

    /// The file, as bytes to write.
    ///
    /// The header (which begins with [`MAGIC`]) is length-prefixed, so a reader
    /// never has to guess where the header ends and the ciphertext starts.
    pub fn to_bytes(&self) -> Vec<u8> {
        let header = header_bytes(
            self.version,
            &self.params,
            &self.salt,
            &self.nonce,
            &self.label,
            self.network,
            self.account,
        );
        let mut framed = Vec::with_capacity(4 + header.len() + self.sealed.len());
        framed.extend_from_slice(&(header.len() as u32).to_le_bytes());
        framed.extend_from_slice(&header);
        framed.extend_from_slice(&self.sealed);
        framed
    }

    /// Reads a keystore file.  Does not authenticate anything: that happens on
    /// [`Keystore::open`], where a wrong password must fail.
    pub fn from_bytes(bytes: &[u8]) -> Result<Keystore, WalletError> {
        if bytes.len() < 4 + MAGIC.len() {
            return Err(WalletError::BadKeystore("the file is too short".to_string()));
        }
        let header_len = u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]) as usize;
        let body = &bytes[4..];
        if body.len() < header_len {
            return Err(WalletError::BadKeystore("the header is truncated".to_string()));
        }
        let (header, sealed) = body.split_at(header_len);
        if !header.starts_with(MAGIC) {
            return Err(WalletError::BadKeystore("not an Obsidian keystore".to_string()));
        }
        let mut cursor = MAGIC.len();
        let version = *header
            .get(cursor)
            .ok_or_else(|| WalletError::BadKeystore("truncated version".to_string()))?;
        if version != FORMAT_VERSION {
            return Err(WalletError::BadKeystore(format!(
                "keystore version {} is not supported by this build",
                version
            )));
        }
        cursor += 1;
        let variant = *header
            .get(cursor)
            .ok_or_else(|| WalletError::BadKeystore("truncated KDF tag".to_string()))?;
        let variant = match variant {
            0 => Argon2Type::D,
            1 => Argon2Type::I,
            2 => Argon2Type::Id,
            _ => return Err(WalletError::BadKeystore("unknown KDF".to_string())),
        };
        cursor += 1;
        let params = Argon2Params {
            memory_kib: read_u32(header, &mut cursor)?,
            iterations: read_u32(header, &mut cursor)?,
            lanes: read_u32(header, &mut cursor)?,
            output_len: read_u32(header, &mut cursor)?,
            variant,
        };
        params
            .validate()
            .map_err(|detail| WalletError::BadKeystore(detail.to_string()))?;
        let mut salt = [0u8; SALT_LEN];
        let mut nonce = [0u8; NONCE_LEN];
        read_exact(header, &mut cursor, &mut salt)?;
        read_exact(header, &mut cursor, &mut nonce)?;
        let chain_id = read_u32(header, &mut cursor)?;
        let network =
            Network::by_chain_id(chain_id).ok_or_else(|| WalletError::BadKeystore("unknown network".to_string()))?;
        let account = read_u32(header, &mut cursor)?;
        let label_len = read_u32(header, &mut cursor)? as usize;
        if label_len > MAX_LABEL_LEN {
            return Err(WalletError::BadKeystore("label is too long".to_string()));
        }
        let mut label_bytes = vec![0u8; label_len];
        read_exact(header, &mut cursor, &mut label_bytes)?;
        let label = String::from_utf8(label_bytes)
            .map_err(|_| WalletError::BadKeystore("label is not UTF-8".to_string()))?;
        if cursor != header.len() {
            return Err(WalletError::BadKeystore(
                "the header has trailing bytes".to_string(),
            ));
        }
        if sealed.len() < 16 + 64 {
            return Err(WalletError::BadKeystore("the payload is too short".to_string()));
        }
        Ok(Keystore {
            version,
            params,
            salt,
            nonce,
            label,
            network,
            account,
            sealed: sealed.to_vec(),
        })
    }

    /// The label shown in a wallet list.
    pub fn label(&self) -> &str {
        &self.label
    }

    /// The network this keystore belongs to.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The account index this keystore belongs to.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The KDF parameters, for display and for support tooling.
    pub fn kdf(&self) -> (u32, u32, u32) {
        (
            self.params.memory_kib,
            self.params.iterations,
            self.params.lanes,
        )
    }

    /// A printable form: the header as base64url, for a QR code or a clipboard
    /// transfer.
    pub fn to_text(&self) -> String {
        base64url_encode(&self.to_bytes())
    }

    /// Reads the printable form.
    pub fn from_text(text: &str) -> Result<Keystore, WalletError> {
        let bytes = base64url_decode(text.trim())
            .ok_or_else(|| WalletError::BadKeystore("not valid base64url".to_string()))?;
        Keystore::from_bytes(&bytes)
    }
}

/// The canonical header, which is both written to the file and used as the
/// AEAD's additional data.
fn header_bytes(
    version: u8,
    params: &Argon2Params,
    salt: &[u8; SALT_LEN],
    nonce: &[u8; NONCE_LEN],
    label: &str,
    network: Network,
    account: u32,
) -> Vec<u8> {
    let mut out = Vec::with_capacity(80 + label.len());
    out.extend_from_slice(MAGIC);
    out.push(version);
    out.push(match params.variant {
        Argon2Type::D => 0,
        Argon2Type::I => 1,
        Argon2Type::Id => 2,
    });
    out.extend_from_slice(&params.memory_kib.to_le_bytes());
    out.extend_from_slice(&params.iterations.to_le_bytes());
    out.extend_from_slice(&params.lanes.to_le_bytes());
    out.extend_from_slice(&params.output_len.to_le_bytes());
    out.extend_from_slice(salt);
    out.extend_from_slice(nonce);
    out.extend_from_slice(&network.chain_id.to_le_bytes());
    out.extend_from_slice(&account.to_le_bytes());
    out.extend_from_slice(&(label.len() as u32).to_le_bytes());
    out.extend_from_slice(label.as_bytes());
    out
}

fn derive_key(params: &Argon2Params, password: &str, salt: &[u8]) -> Result<Vec<u8>, WalletError> {
    argon2id(params, password.as_bytes(), salt)
        .map_err(|detail| WalletError::BadKeystore(detail.to_string()))
}

fn read_u32(bytes: &[u8], cursor: &mut usize) -> Result<u32, WalletError> {
    if *cursor + 4 > bytes.len() {
        return Err(WalletError::BadKeystore("truncated field".to_string()));
    }
    let value = u32::from_le_bytes([
        bytes[*cursor],
        bytes[*cursor + 1],
        bytes[*cursor + 2],
        bytes[*cursor + 3],
    ]);
    *cursor += 4;
    Ok(value)
}

fn read_exact(bytes: &[u8], cursor: &mut usize, out: &mut [u8]) -> Result<(), WalletError> {
    if *cursor + out.len() > bytes.len() {
        return Err(WalletError::BadKeystore("truncated field".to_string()));
    }
    out.copy_from_slice(&bytes[*cursor..*cursor + out.len()]);
    *cursor += out.len();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::MAINNET;

    #[test]
    fn a_wallet_survives_a_round_trip_through_a_file() {
        let (wallet, _phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let keystore = wallet.to_keystore("correct horse battery staple", "obs1ab…cd").unwrap();
        let bytes = keystore.to_bytes();
        let reloaded = Keystore::from_bytes(&bytes).unwrap();
        assert_eq!(reloaded.label(), "obs1ab…cd");
        assert_eq!(reloaded.network().chain_id, MAINNET.chain_id);
        assert_eq!(reloaded.kdf(), (65_536, 3, 1));
        let opened = reloaded.open("correct horse battery staple").unwrap();
        assert_eq!(opened.public_keys(), wallet.public_keys());

        // The printable form is the same file.
        let from_text = Keystore::from_text(&keystore.to_text()).unwrap();
        assert_eq!(
            from_text.open("correct horse battery staple").unwrap().public_keys(),
            wallet.public_keys()
        );
    }

    #[test]
    fn a_wrong_password_opens_nothing_and_says_nothing() {
        let (wallet, phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let keystore = wallet.to_keystore("right password", "wallet").unwrap();
        let error = keystore.open("wrong password").unwrap_err();
        assert_eq!(error, WalletError::BadPasswordOrCorrupt);
        assert!(!format!("{}", error).contains("password is"));
        assert!(!format!("{:?}", error).contains(&phrase));
        // An empty password is refused at seal time, not silently accepted.
        assert!(wallet.to_keystore("", "wallet").is_err());
    }

    #[test]
    fn the_header_is_authenticated_so_tampering_is_a_failure_not_a_weakening() {
        let (wallet, _phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let keystore = wallet.to_keystore("password", "wallet").unwrap();
        let bytes = keystore.to_bytes();

        // Lowering the Argon2 memory cost is the classic downgrade attack: the
        // file must not open afterwards.
        let mut weakened = bytes.clone();
        let memory_offset = 4 + MAGIC.len() + 2;
        weakened[memory_offset..memory_offset + 4].copy_from_slice(&8u32.to_le_bytes());
        let weakened = Keystore::from_bytes(&weakened).unwrap();
        assert_eq!(weakened.open("password").unwrap_err(), WalletError::BadPasswordOrCorrupt);

        // Flipping one ciphertext bit fails the tag.
        let mut flipped = bytes.clone();
        let last = flipped.len() - 1;
        flipped[last] ^= 1;
        assert_eq!(
            Keystore::from_bytes(&flipped).unwrap().open("password").unwrap_err(),
            WalletError::BadPasswordOrCorrupt
        );

        // Changing the label changes the authenticated header.  The label is
        // stored verbatim in the header, so it can be located by its bytes.
        let mut relabelled = bytes.clone();
        let offset = relabelled
            .windows(6)
            .position(|window| window == b"wallet")
            .expect("the label is in the header");
        relabelled[offset] = b'x';
        assert_eq!(
            Keystore::from_bytes(&relabelled).unwrap().open("password").unwrap_err(),
            WalletError::BadPasswordOrCorrupt
        );
    }

    #[test]
    fn a_file_from_nowhere_is_refused_with_a_format_error() {
        assert!(Keystore::from_bytes(b"").is_err());
        assert!(Keystore::from_bytes(b"not a keystore at all").is_err());
        let mut wrong_magic = vec![0u8; 100];
        wrong_magic[4..9].copy_from_slice(b"XXXXX");
        assert!(Keystore::from_bytes(&wrong_magic).is_err());
        assert!(Keystore::from_text("!!! not base64 !!!").is_err());
    }

    #[test]
    fn debug_output_describes_the_file_without_revealing_it() {
        let (wallet, _) = Wallet::generate(MAINNET, 3).unwrap();
        let keystore = wallet.to_keystore("password", "obs1test…key").unwrap();
        let rendered = format!("{:?}", keystore);
        assert!(rendered.contains("sealed_bytes"));
        assert!(!rendered.contains(&keystore.to_text()));
    }
}
