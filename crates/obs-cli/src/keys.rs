//! Local key handling: keystores, passwords, and the recovery phrase.
//!
//! Everything in this module happens on the user's machine.  The password never
//! leaves it, the phrase is never written anywhere unless the user names a file,
//! and the wallet's private keys exist only inside this process while a command
//! runs.
//!
//! Password sources, in order of preference:
//!
//! 1. `--password-file <path>` — a file only the user can read.  Best for
//!    scripts and services.
//! 2. `OBS_WALLET_PASSWORD` — an environment variable.  Visible to the process
//!    list on some systems; acceptable for a workstation.
//! 3. `--password <value>` — refused, because shell history and process
//!    arguments are readable by other users on the machine.
//!
//! A phrase is written to a file with owner-only permissions when the user asks
//! for that with `--phrase-out`, and never otherwise.  It is never printed by
//! default: a phrase in a terminal is a phrase in the scrollback buffer, the log
//! file and the screen share.

use std::path::{Path, PathBuf};

use obs_primitives::network::Network;
use obs_rpc::cli::Args;
use obs_wallet::keystore::Keystore;
use obs_wallet::Wallet;

use crate::CliError;

/// Where a wallet's password comes from.
pub const PASSWORD_ENV: &str = "OBS_WALLET_PASSWORD";

/// Options every wallet command accepts.
pub const WALLET_OPTIONS: &[&'static str] = &["keystore", "password-file"];

/// Reads the password for a keystore.
pub fn password(args: &Args) -> Result<String, CliError> {
    if args.get("password").is_some() {
        return Err(CliError::Usage(
            "--password is not accepted: arguments are visible to other processes and are kept \
             in shell history.  Use --password-file <path>, or set OBS_WALLET_PASSWORD."
                .to_string(),
        ));
    }
    if let Some(path) = args.get("password-file") {
        let text = std::fs::read_to_string(path).map_err(|error| {
            CliError::Failed(format!("--password-file {}: {}", path, error))
        })?;
        let password = text.trim_end_matches(['\n', '\r']).to_string();
        if password.is_empty() {
            return Err(CliError::Failed(format!(
                "--password-file {} is empty; the password would be empty",
                path
            )));
        }
        return Ok(password);
    }
    match std::env::var(PASSWORD_ENV) {
        Ok(password) if !password.is_empty() => Ok(password),
        _ => Err(CliError::Usage(format!(
            "a password is needed: pass --password-file <path> or set {} in the environment",
            PASSWORD_ENV
        ))),
    }
}

/// The keystore path a command was given; there is no implicit default, so a
/// command can never operate on the wrong wallet by accident.
pub fn keystore_path(args: &Args) -> Result<PathBuf, CliError> {
    match args.get("keystore") {
        Some(path) => Ok(PathBuf::from(path)),
        None => Err(CliError::Usage(
            "--keystore <path> is required: name the wallet this command should use".to_string(),
        )),
    }
}

/// Opens a keystore and returns the wallet.
///
/// The password is checked by the keystore's own authenticated encryption: a
/// wrong password fails here, and the wallet is never partially opened.
pub fn open_wallet(args: &Args, network: Network) -> Result<Wallet, CliError> {
    let path = keystore_path(args)?;
    let password = password(args)?;
    open_wallet_with(&path, &password, network)
}

/// Opens a named keystore with an already-obtained password.
pub fn open_wallet_with(path: &Path, password: &str, network: Network) -> Result<Wallet, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::Failed(format!("{}: {}", path.display(), error)))?;
    let keystore = Keystore::from_text(&text)
        .map_err(|error| CliError::Failed(format!("{}: {}", path.display(), error)))?;
    if keystore.network() != network {
        return Err(CliError::Failed(format!(
            "{} holds a {} wallet but this command is talking to {}; \
             the address prefix and the chain id differ, so a signature from it would be refused",
            path.display(),
            keystore.network().name,
            network.name
        )));
    }
    keystore
        .open(password)
        .map_err(|error| CliError::Failed(format!("{}: {}", path.display(), error)))
}

/// Creates a wallet and writes it, sealed with the password, to `path`.
///
/// The phrase is written only if the caller asked for a file, and that file is
/// created with owner-only permissions.  If the phrase has nowhere to go, the
/// wallet is still created — and the caller is told plainly that the phrase is
/// gone, because a recovery phrase shown nowhere is a wallet that can never be
/// recovered.
pub fn create_wallet(
    network: Network,
    path: &Path,
    password: &str,
    label: &str,
    phrase_out: Option<&Path>,
) -> Result<Wallet, CliError> {
    let (wallet, phrase) = Wallet::generate(network, 0)
        .map_err(|error| CliError::Failed(format!("the wallet could not be created: {}", error)))?;
    seal_wallet(&wallet, path, password, label)?;
    if let Some(phrase_path) = phrase_out {
        write_private(phrase_path, &format!("{}\n", phrase))?;
    }
    Ok(wallet)
}

/// Creates a wallet from a phrase the operator already holds, and seals it.
///
/// The reason this exists is ownership, not convenience.  A wallet generated by
/// a tool is a wallet whose recovery phrase exists because that tool wrote it,
/// and on a chain the wallet that can claim the genesis allocation is the one
/// whose claim is in the first block.  An operator who wants to be that person
/// on their own terms brings words they created — in the browser wallet, on
/// paper, wherever they keep them — and this derives the same wallet from them.
///
/// The phrase is validated by BIP-39 (words and checksum) before anything is
/// written, so a mistyped word is a refusal rather than a wallet nobody can
/// recover.  It is *not* copied anywhere: the operator already has it.
pub fn create_wallet_from_phrase(
    network: Network,
    phrase: &str,
    path: &Path,
    password: &str,
    label: &str,
) -> Result<Wallet, CliError> {
    if path.exists() {
        return Err(CliError::Failed(format!(
            "{} already exists; refusing to overwrite a wallet",
            path.display()
        )));
    }
    let wallet = Wallet::from_phrase(network, phrase, "", 0)
        .map_err(|error| CliError::Failed(format!("--phrase-file: {}", error)))?;
    seal_wallet(&wallet, path, password, label)?;
    Ok(wallet)
}

/// Reads a recovery phrase from a file, normalising the whitespace.
///
/// A phrase is often written with a newline, as several lines, or with more
/// spaces than BIP-39 uses; all of those are the same phrase.  What is *not*
/// normalised away is a mistake: the wallet's own checksum is what decides, in
/// [`create_wallet_from_phrase`].
pub fn read_phrase_file(path: &Path) -> Result<String, CliError> {
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::Failed(format!("--phrase-file {}: {}", path.display(), error)))?;
    let phrase = text
        .split_whitespace()
        .map(str::to_lowercase)
        .collect::<Vec<_>>()
        .join(" ");
    if phrase.is_empty() {
        return Err(CliError::Failed(format!(
            "--phrase-file {} is empty; it must hold a 24-word recovery phrase",
            path.display()
        )));
    }
    Ok(phrase)
}

/// Seals a wallet into a keystore file only its owner can read.
fn seal_wallet(
    wallet: &Wallet,
    path: &Path,
    password: &str,
    label: &str,
) -> Result<(), CliError> {
    if path.exists() {
        return Err(CliError::Failed(format!(
            "{} already exists; refusing to overwrite a wallet",
            path.display()
        )));
    }
    let keystore = wallet
        .to_keystore(password, label)
        .map_err(|error| CliError::Failed(format!("the keystore could not be sealed: {}", error)))?;
    if let Some(parent) = path.parent() {
        if !parent.as_os_str().is_empty() {
            std::fs::create_dir_all(parent)
                .map_err(|error| CliError::Failed(format!("{}: {}", parent.display(), error)))?;
        }
    }
    write_private(path, &keystore.to_text())
}

/// Writes a file only the owner can read.
///
/// The permissions are set when the file is created, not afterwards: creating a
/// secret world-readable and then narrowing it leaves a window in which another
/// process could have opened it.
pub fn write_private(path: &Path, contents: &str) -> Result<(), CliError> {
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
        .map_err(|error| CliError::Failed(format!("{}: {}", path.display(), error)))?;
    file.write_all(contents.as_bytes())
        .map_err(|error| CliError::Failed(format!("{}: {}", path.display(), error)))
}

/// Reads 32 bytes of hex from a flag, with a message naming the flag.
pub fn hex32_flag(args: &Args, name: &str) -> Result<Option<[u8; 32]>, CliError> {
    let Some(value) = args.get(name) else {
        return Ok(None);
    };
    let bytes = obs_crypto::encoding::hex_decode(value)
        .ok_or_else(|| CliError::Usage(format!("--{} must be hex", name)))?;
    if bytes.len() != 32 {
        return Err(CliError::Usage(format!("--{} must be 32 bytes of hex", name)));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Ok(Some(out))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    #[test]
    fn a_password_on_the_command_line_is_refused_with_the_reason() {
        let args = Args::parse(
            "obs-cli",
            &argv(&["--keystore", "w.json", "--password", "hunter2"]),
            &["keystore", "password-file", "password"],
        )
        .unwrap();
        match password(&args) {
            Err(CliError::Usage(detail)) => assert!(detail.contains("shell history"), "{}", detail),
            other => panic!("expected a usage error, got {:?}", other.map(|_| ())),
        }
    }

    #[test]
    fn a_wallet_can_be_derived_from_a_phrase_the_operator_supplies() {
        let dir = std::env::temp_dir().join(format!("obs-cli-phrase-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let phrase_path = dir.join("phrase.txt");
        // Newlines and extra spaces are the same phrase; the words are not.
        std::fs::write(&phrase_path, "legal winner thank year wave sausage\n  worth useful legal winner thank year\nwave sausage worth useful legal winner thank year\nwave sausage worth title\n").unwrap();
        let phrase = read_phrase_file(&phrase_path).unwrap();
        assert_eq!(phrase.split(' ').count(), 24);

        let keystore = dir.join("founder.keystore.json");
        let wallet =
            create_wallet_from_phrase(obs_primitives::network::DEVNET, &phrase, &keystore, "a password", "test")
                .unwrap();
        let expected = Wallet::from_phrase(obs_primitives::network::DEVNET, &phrase, "", 0).unwrap();
        assert_eq!(
            wallet.address().to_string(),
            expected.address().to_string(),
            "the supplied phrase must decide the address"
        );
        assert!(keystore.is_file(), "the wallet is sealed to disk");
        // The phrase is the operator's: it is not copied next to the keystore.
        assert!(!dir.join("founder.phrase.txt").exists());

        // A wallet is never overwritten, and a phrase with a mistake in it is
        // refused rather than turned into a wallet nobody can recover.
        assert!(create_wallet_from_phrase(obs_primitives::network::DEVNET, &phrase, &keystore, "x", "y").is_err());
        let wrong = phrase.replace("title", "abandon");
        assert!(create_wallet_from_phrase(
            obs_primitives::network::DEVNET,
            &wrong,
            &dir.join("other.json"),
            "a password",
            "test"
        )
        .is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_password_file_is_read_without_its_trailing_newline() {
        let dir = std::env::temp_dir().join(format!("obs-cli-keys-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("password");
        std::fs::write(&path, "correct horse battery staple\n").unwrap();
        let args = Args::parse(
            "obs-cli",
            &argv(&["--password-file", path.to_str().unwrap()]),
            &["password-file"],
        )
        .unwrap();
        assert_eq!(password(&args).unwrap(), "correct horse battery staple");
        std::fs::remove_dir_all(&dir).ok();
    }

    #[test]
    fn a_written_secret_is_owner_readable_only() {
        let dir = std::env::temp_dir().join(format!("obs-cli-perm-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("secret");
        write_private(&path, "seed\n").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode();
            assert_eq!(mode & 0o077, 0, "the file is readable by others: {:o}", mode);
        }
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "seed\n");
        std::fs::remove_dir_all(&dir).ok();
    }
}
