//! # obs-wallet — the non-custodial Obsidian wallet
//!
//! A wallet is a *keystore and a signer*, never a custodian.  Everything in this
//! crate runs where the keys are: a desktop process, a phone, or the browser
//! through the WebAssembly build.  Nothing in it sends a key anywhere, and no
//! server in this workspace is ever given one.
//!
//! ## The key hierarchy
//!
//! ```text
//!   256-bit CSPRNG entropy
//!        │  BIP-39 words (24)                    ← the wallet recovery phrase
//!        ▼
//!   BIP-39 seed (PBKDF2-HMAC-SHA512, optional passphrase)
//!        │  SLIP-0010 hardened derivation
//!        ├── m/8504'/0'/0'   wallet key      (Ed25519) — signs transactions, owns the account
//!        ├── m/8504'/0'/1'   node key        (Ed25519) — validator identity, always distinct
//!        └── m/8504'/0'/2'   recovery key    (Ed25519) — authorised to rotate the wallet key
//! ```
//!
//! The three keys are derived on different paths and never from one another's
//! private key.  The protocol requires the validator node key to differ from the
//! wallet key, and the recovery key to be a third, independent key: a compromised
//! machine that holds the validator key can attest, but it cannot move funds, and
//! a recovery key that is used to rotate the wallet key cannot spend by itself.
//!
//! ## Recovery, twice over
//!
//! * **Wallet recovery** restores *keys*: the 24-word phrase (plus the optional
//!   passphrase) reconstructs every key above, on any machine, without asking
//!   anybody's permission.  Nothing about it involves the registration service.
//! * **Account recovery** restores *access to the account record*: the
//!   registration service's single-use, server-side recovery code lets the owner
//!   re-enrol MFA and reset a password.  That code cannot sign a transaction, and
//!   the service has no key material, so account recovery can never move value.
//! * **Key rotation**, for when the phrase itself may have leaked, is the one
//!   operation that changes custody, and it is a signed transaction authorised by
//!   the recovery key.
//!
//! They are three different problems with three different secrets, and the
//! documentation and the API keep them apart.
//!
//! ## At rest
//!
//! [`Keystore`] encrypts the derived secret material with Argon2id (64 MiB, three
//! passes) and ChaCha20-Poly1305, with the header authenticated as additional
//! data, so a modified cost parameter, salt or nonce is a decryption failure
//! rather than a weakened file.  A wrong password is indistinguishable from a
//! corrupt file: both are reported as [`WalletError::BadPasswordOrCorrupt`].
//!
//! ## What a wallet will not do
//!
//! * It will not invent a nonce, a claim sequence or a protocol timestamp.  Those
//!   come from chain state; a wallet that made them up would simply produce
//!   transactions the network refuses.
//! * It will not sign something it cannot decode.  Every builder in
//!   [`sign`] takes the fields it signs as typed arguments, and the pre-image is
//!   constructed by `obs-chain`, the same code every node verifies against.
//! * It will not log, print, serialise or transmit key material.  The types that
//!   hold secrets have hand-written `Debug` implementations that print a
//!   placeholder.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

pub mod keystore;
pub mod recovery;
pub mod seed;
pub mod sign;

use obs_crypto::ct::Zeroizing;
use obs_crypto::ed25519::Keypair;
use obs_primitives::address::Address;
use obs_primitives::network::Network;

/// Derivation purpose for this chain's keys.
pub const PURPOSE: u32 = 8504;
/// Wallet key path role.
pub const ROLE_WALLET: u32 = 0;
/// Validator node identity path role.
pub const ROLE_NODE: u32 = 1;
/// Recovery key path role.
pub const ROLE_RECOVERY: u32 = 2;

/// Why a wallet operation failed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WalletError {
    /// The recovery phrase is not a valid phrase.
    BadPhrase(String),
    /// The keystore could not be decrypted: wrong password, or a damaged file.
    BadPasswordOrCorrupt,
    /// The keystore file is not in a format this build understands.
    BadKeystore(String),
    /// The seed material is unusable.
    BadSeed(String),
    /// The caller asked for something the wallet does not do.
    Unsupported(String),
    /// The operating system's CSPRNG refused.
    Entropy(String),
}

impl core::fmt::Display for WalletError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            WalletError::BadPhrase(detail) => write!(f, "invalid recovery phrase: {}", detail),
            WalletError::BadPasswordOrCorrupt => {
                write!(f, "the wallet could not be opened: wrong password or damaged file")
            }
            WalletError::BadKeystore(detail) => write!(f, "unreadable keystore: {}", detail),
            WalletError::BadSeed(detail) => write!(f, "unusable seed: {}", detail),
            WalletError::Unsupported(detail) => write!(f, "unsupported operation: {}", detail),
            WalletError::Entropy(detail) => write!(f, "no secure randomness available: {}", detail),
        }
    }
}

impl std::error::Error for WalletError {}

impl From<obs_crypto::rand::EntropyError> for WalletError {
    fn from(error: obs_crypto::rand::EntropyError) -> WalletError {
        WalletError::Entropy(error.to_string())
    }
}

/// A wallet, unlocked: the three keys above, derived and held in memory.
///
/// The struct has no `Clone` and no `Serialize`: a wallet cannot be copied into
/// a log line or a JSON body by accident.  Its `Debug` implementation prints
/// addresses, never keys.
pub struct Wallet {
    network: Network,
    account: u32,
    /// The BIP-39 seed.  Held while the wallet is unlocked so that the keystore
    /// can be re-sealed (password change) and so that every key is derived from
    /// one place.  It is zeroized on drop, and it never leaves this crate.
    seed: Zeroizing<[u8; 64]>,
    wallet_key: Keypair,
    node_key: Keypair,
    recovery_key: Keypair,
}

impl core::fmt::Debug for Wallet {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("Wallet")
            .field("network", &self.network.name)
            .field("account", &self.account)
            .field("address", &self.address().to_string())
            .field("wallet_key", &"<redacted>")
            .field("node_key", &"<redacted>")
            .field("recovery_key", &"<redacted>")
            .finish()
    }
}

impl Wallet {
    /// Creates a wallet from a recovery phrase and an optional passphrase.
    ///
    /// The passphrase is the BIP-39 "25th word": wallets created with one are
    /// mathematically distinct wallets, which is why the wallet UI asks for it
    /// explicitly and never silently defaults it.
    pub fn from_phrase(
        network: Network,
        phrase: &str,
        passphrase: &str,
        account: u32,
    ) -> Result<Wallet, WalletError> {
        let seed = seed::seed_from_phrase(phrase, passphrase)?;
        Wallet::from_seed(network, &seed, account)
    }

    /// Creates a wallet from a 64-byte BIP-39 seed (the output of
    /// [`seed::seed_from_phrase`], and what a keystore holds).
    pub fn from_seed(network: Network, seed: &[u8; 64], account: u32) -> Result<Wallet, WalletError> {
        Ok(Wallet {
            network,
            account,
            seed: Zeroizing(*seed),
            wallet_key: seed::derive_key(seed, account, ROLE_WALLET)?,
            node_key: seed::derive_key(seed, account, ROLE_NODE)?,
            recovery_key: seed::derive_key(seed, account, ROLE_RECOVERY)?,
        })
    }

    /// Creates a wallet from 32 bytes of entropy, the way a phrase is built:
    /// entropy → 24 words → seed.  Used when a caller already has CSPRNG output
    /// (an air-gapped generator, for instance) rather than a phrase.
    pub fn from_entropy(network: Network, entropy: &[u8], account: u32) -> Result<Wallet, WalletError> {
        let phrase = obs_crypto::mnemonic::entropy_to_mnemonic(entropy)
            .map_err(|error| WalletError::BadPhrase(error.to_string()))?;
        Wallet::from_phrase(network, &phrase, "", account)
    }

    /// The seed's bytes, for sealing and re-deriving.  Crate-private on purpose:
    /// no caller outside the wallet has any use for it.
    pub(crate) fn seed_bytes(&self) -> [u8; 64] {
        *self.seed
    }

    /// Derives the keys for another account index from the same seed.
    pub fn account_wallet(&self, account: u32) -> Result<Wallet, WalletError> {
        Wallet::from_seed(self.network, &self.seed, account)
    }

    /// Creates a brand-new wallet from the operating system's CSPRNG.
    ///
    /// Returns the wallet and its recovery phrase.  The phrase is the *only* way
    /// to restore the wallet: it is shown once, by the caller, and never stored
    /// by this crate.
    pub fn generate(network: Network, account: u32) -> Result<(Wallet, String), WalletError> {
        let phrase = seed::generate_phrase()?;
        let wallet = Wallet::from_phrase(network, &phrase, "", account)?;
        Ok((wallet, phrase))
    }

    /// The network this wallet signs for.
    pub fn network(&self) -> Network {
        self.network
    }

    /// The account index this wallet is derived at.
    pub fn account(&self) -> u32 {
        self.account
    }

    /// The account address: the wallet key's public key, in this network's
    /// namespace.
    pub fn address(&self) -> Address {
        Address::from_public_key(self.network, &self.wallet_key.public_key())
    }

    /// The validator node identity address (distinct from the account address).
    pub fn node_address(&self) -> Address {
        Address::from_public_key(self.network, &self.node_key.public_key())
    }

    /// The recovery key's address: the key a `RotateWalletKey` transaction must
    /// be authorised by.
    pub fn recovery_address(&self) -> Address {
        Address::from_public_key(self.network, &self.recovery_key.public_key())
    }

    /// The public keys an operator or a registration service may need, and
    /// nothing else.
    ///
    /// A public key is public data: this is the only accessor that exposes key
    /// material, and it never exposes a private key.
    pub fn public_keys(&self) -> PublicKeys {
        PublicKeys {
            wallet_key: self.wallet_key.public_key(),
            node_key: self.node_key.public_key(),
            recovery_key: self.recovery_key.public_key(),
        }
    }

    /// The wallet keypair: what signs this account's transactions.
    ///
    /// Handed out because a wallet that cannot reach its own key cannot sign.
    /// The reference belongs to the wallet, which zeroizes the key on drop, so
    /// callers should use it and not copy it anywhere durable.
    pub fn wallet_keypair(&self) -> &Keypair {
        &self.wallet_key
    }

    /// The validator node identity keypair: what signs attestations.
    pub fn node_keypair(&self) -> &Keypair {
        &self.node_key
    }

    /// The recovery keypair.
    ///
    /// Used by [`sign::recovery_intent`] and for nothing else: the recovery key
    /// never signs a transaction, because protocol version 1 defines no
    /// transaction it could sign.  See [`recovery`] for what that means today.
    pub fn recovery_keypair(&self) -> &Keypair {
        &self.recovery_key
    }

    /// Signs an arbitrary domain-separated pre-image with the wallet key.
    ///
    /// This is the primitive behind the account-proof endpoint and every
    /// transaction builder; callers should prefer the typed helpers in
    /// [`sign`], which construct the pre-image for them.
    pub fn sign_preimage(&self, preimage: &[u8]) -> [u8; 64] {
        self.wallet_key.sign(preimage)
    }

    /// The keystore this wallet is stored as, encrypted with `password`.
    pub fn to_keystore(&self, password: &str, label: &str) -> Result<keystore::Keystore, WalletError> {
        keystore::Keystore::seal(self, password, label)
    }
}

/// A wallet's public keys.  Safe to publish, log and send to a server.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PublicKeys {
    /// Wallet key: owns the account and signs transactions.
    pub wallet_key: [u8; 32],
    /// Validator node identity.
    pub node_key: [u8; 32],
    /// Recovery key: may rotate the wallet key, never spend.
    pub recovery_key: [u8; 32],
}

impl PublicKeys {
    /// Hex encodings, for display and for API payloads.
    pub fn to_hex(&self) -> (String, String, String) {
        (
            obs_crypto::encoding::hex_encode(&self.wallet_key),
            obs_crypto::encoding::hex_encode(&self.node_key),
            obs_crypto::encoding::hex_encode(&self.recovery_key),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use obs_primitives::network::{MAINNET, TESTNET};

    #[test]
    fn the_three_keys_are_distinct_and_stable() {
        let (wallet, phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let restored = Wallet::from_phrase(MAINNET, &phrase, "", 0).unwrap();
        assert_eq!(wallet.public_keys(), restored.public_keys());
        assert_eq!(wallet.address(), restored.address());

        let keys = wallet.public_keys();
        assert_ne!(keys.wallet_key, keys.node_key, "the node key is not the wallet key");
        assert_ne!(keys.wallet_key, keys.recovery_key);
        assert_ne!(keys.node_key, keys.recovery_key);
        assert_ne!(wallet.address(), wallet.node_address());
        assert_ne!(wallet.address(), wallet.recovery_address());
    }

    #[test]
    fn a_different_account_index_is_a_different_wallet() {
        let (first, phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let second = Wallet::from_phrase(MAINNET, &phrase, "", 1).unwrap();
        assert_ne!(first.public_keys(), second.public_keys());
        assert_ne!(first.address(), second.address());
    }

    #[test]
    fn the_passphrase_changes_the_wallet_entirely() {
        let (_, phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let plain = Wallet::from_phrase(MAINNET, &phrase, "", 0).unwrap();
        let with_passphrase = Wallet::from_phrase(MAINNET, &phrase, "a long passphrase", 0).unwrap();
        assert_ne!(plain.public_keys(), with_passphrase.public_keys());
        // A wrong passphrase is not an error, it is a different wallet — which is
        // why the UI has to be explicit about it.
        let wrong = Wallet::from_phrase(MAINNET, &phrase, "another passphrase", 0).unwrap();
        assert_ne!(wrong.public_keys(), with_passphrase.public_keys());
    }

    #[test]
    fn the_same_phrase_on_another_network_is_another_account() {
        let (_, phrase) = Wallet::generate(MAINNET, 0).unwrap();
        let mainnet = Wallet::from_phrase(MAINNET, &phrase, "", 0).unwrap();
        let testnet = Wallet::from_phrase(TESTNET, &phrase, "", 0).unwrap();
        // The keys are the same (they come from the seed), but the account
        // address and every signature are bound to the network.
        assert_eq!(mainnet.public_keys(), testnet.public_keys());
        assert_ne!(mainnet.address().to_string(), testnet.address().to_string());
        assert!(mainnet.address().to_string().starts_with("obs1"));
        assert!(testnet.address().to_string().starts_with("tobs1"));
    }

    #[test]
    fn a_bad_phrase_is_refused_rather_than_guessed_at() {
        for bad in [
            "",
            "not a phrase",
            "abandon abandon abandon",
            "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon",
        ] {
            let result = Wallet::from_phrase(MAINNET, bad, "", 0);
            assert!(result.is_err(), "{:?} must not be accepted", bad);
        }
    }

    #[test]
    fn debug_output_never_contains_a_private_key() {
        // The canonical BIP-39 vector phrase, plus a freshly generated wallet, so
        // that both the fixed and the random path are covered.
        let canonical = "abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon abandon abandon \
                         abandon abandon abandon abandon abandon abandon abandon art";
        let fixed = Wallet::from_phrase(MAINNET, canonical, "", 0).unwrap();
        let (generated, phrase) = Wallet::generate(MAINNET, 7).unwrap();

        for (wallet, secret) in [(&fixed, canonical), (&generated, phrase.as_str())] {
            let rendered = format!("{:?}", wallet);

            // Exact, not a substring hunt: the debug form is the public fields and
            // three redactions, and nothing else.  The previous version of this
            // test asserted that no phrase *word* appeared anywhere in the output,
            // which is a coin flip rather than a property: "main" is inside
            // "mainnet", "over" is inside "recovery_key", and an address is bech32
            // text that can contain a word by chance.  It failed about once in
            // forty runs and would have gone on leaking nothing while it did.
            let expected = format!(
                "Wallet {{ network: {:?}, account: {}, address: {:?}, wallet_key: \"<redacted>\", \
                 node_key: \"<redacted>\", recovery_key: \"<redacted>\" }}",
                wallet.network.name,
                wallet.account,
                wallet.address().to_string()
            );
            assert_eq!(rendered, expected, "the debug form must be the public fields only");

            // And the secret itself is nowhere in it.  A phrase is a wide string
            // with spaces: this one cannot be a coincidence.
            assert!(!rendered.contains(secret), "the debug output contains the phrase");
            let (wallet_key, node_key, recovery_key) = wallet.public_keys().to_hex();
            for key in [wallet_key, node_key, recovery_key] {
                assert!(!rendered.contains(&key), "the debug output contains a key");
            }
        }
    }
}
