//! The browser wallet: Obsidian's own wallet code, compiled to WebAssembly.
//!
//! The web interface is the one place in this project where code that is not
//! Rust runs in front of a user, so the boundary is drawn where it matters.  The
//! interface may render anything it likes; it may *not* derive a key, seal a
//! keystore, build a signature or decide what a transaction says.  All of that
//! happens in this module, which is the same [`obs_wallet`] and [`obs_crypto`]
//! code the command-line client runs, compiled for `wasm32-unknown-unknown`.
//!
//! ## The ABI, and why it is shaped this way
//!
//! JavaScript calls [`obs_call`] with an operation name and a JSON request, and
//! gets JSON back.  Every value that crosses the boundary is therefore either
//! public or a value the caller is about to publish anyway:
//!
//! * A wallet **unlocked** here stays here.  [`obs_call`] returns a numeric
//!   handle, not a key; signing operations take the handle.  A private key, a
//!   seed or a phrase never appears in a JavaScript value, so a bug in the
//!   interface cannot leak one and a script injected into the page has nothing
//!   to read.  [`lock`] drops the wallet and zeroizes it.
//! * A phrase crosses *in*, once, when a person types or pastes one, and crosses
//!   *out* once, when a wallet is created — because a recovery phrase whose owner
//!   never saw it is a wallet nobody can recover.  That is the whole of it.
//! * Keystores cross as text, sealed with the user's password by the same Argon2id
//!   and ChaCha20-Poly1305 code as everywhere else.  The interface stores that
//!   text if the user asks it to; the password is never sent anywhere, and the
//!   module has no way to send anything at all — it has no sockets, no clock and
//!   no filesystem.
//!
//! Randomness comes from the host's `crypto.getRandomValues`, through the
//! [`obs_wasm_random`] import that [`obs_crypto::rand`] already uses on wasm.
//! That is the browser's CSPRNG — seeded by the operating system, the same source
//! the page itself would use — and it is the only thing this module asks the host
//! for.

use core::sync::atomic::{AtomicU64, Ordering};
use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};

use obs_primitives::json::Json;
use obs_primitives::network::{Network, DEVNET, MAINNET, STAGING, TESTNET};
use obs_wallet::Wallet;

// ---------------------------------------------------------------------------
// The wallet table
// ---------------------------------------------------------------------------

/// Unlocked wallets, kept inside the module.
///
/// The handle is an opaque counter: a page can hold several wallets (a person
/// may have more than one account) and can drop each one when it is done.
fn wallets() -> &'static Mutex<HashMap<u64, Wallet>> {
    static WALLETS: OnceLock<Mutex<HashMap<u64, Wallet>>> = OnceLock::new();
    WALLETS.get_or_init(|| Mutex::new(HashMap::new()))
}

fn next_handle() -> u64 {
    static NEXT: AtomicU64 = AtomicU64::new(1);
    NEXT.fetch_add(1, Ordering::Relaxed)
}

fn insert(wallet: Wallet) -> u64 {
    let handle = next_handle();
    if let Ok(mut table) = wallets().lock() {
        table.insert(handle, wallet);
    }
    handle
}

/// Runs `f` against an unlocked wallet, without ever handing the wallet out.
fn with<T>(handle: u64, f: impl FnOnce(&Wallet) -> Result<T, String>) -> Result<T, String> {
    let table = wallets().lock().map_err(|_| "the wallet table is unavailable")?;
    let wallet = table.get(&handle).ok_or("no such wallet handle")?;
    f(wallet)
}

/// Everything the interface is allowed to know about a wallet.
fn public_view(wallet: &Wallet, handle: u64, phrase: Option<&str>) -> Json {
    let keys = wallet.public_keys();
    let mut fields = vec![
        ("handle", Json::Int(handle as i128)),
        ("network", Json::Str(wallet.network().name.to_string())),
        ("chain_id", Json::Int(wallet.network().chain_id as i128)),
        ("account", Json::Int(wallet.account() as i128)),
        ("address", Json::Str(wallet.address().to_string())),
        ("node_address", Json::Str(wallet.node_address().to_string())),
        (
            "recovery_address",
            Json::Str(wallet.recovery_address().to_string()),
        ),
        ("wallet_key", Json::Str(hex(&keys.wallet_key))),
        ("node_key", Json::Str(hex(&keys.node_key))),
        ("recovery_key", Json::Str(hex(&keys.recovery_key))),
        ("derivation_path", Json::Str(format!("m/44'/0'/{}'/0", wallet.account()))),
    ];
    if let Some(phrase) = phrase {
        fields.push((
            "phrase_notice",
            Json::Str(
                "this is the only time the recovery phrase is produced: write it down and keep \
                 it offline"
                    .to_string(),
            ),
        ));
        fields.push(("phrase", Json::Str(phrase.to_string())));
    }
    Json::obj(fields)
}

// ---------------------------------------------------------------------------
// Operations
// ---------------------------------------------------------------------------

/// Performs one wallet operation.
///
/// Every operation returns either `{"ok": true, ...}` or
/// `{"ok": false, "error": "..."}`, so the interface never has to interpret a
/// thrown exception as an outcome.
pub fn call(operation: &str, request: &Json) -> Json {
    match dispatch(operation, request) {
        Ok(value) => value,
        Err(message) => Json::obj([
            ("ok", Json::Bool(false)),
            ("error", Json::Str(message)),
            ("operation", Json::Str(operation.to_string())),
        ]),
    }
}

fn dispatch(operation: &str, request: &Json) -> Result<Json, String> {
    match operation {
        "phrase_new" => {
            let phrase = obs_wallet::seed::generate_phrase().map_err(|error| error.to_string())?;
            Ok(Json::obj([
                ("ok", Json::Bool(true)),
                ("phrase", Json::Str(phrase)),
                (
                    "entropy_bits",
                    Json::Int(obs_crypto::WALLET_ENTROPY_BITS as i128),
                ),
            ]))
        }
        "phrase_validate" => {
            let phrase = string(request, "phrase")?;
            match obs_wallet::seed::validate_phrase(&phrase) {
                Ok(()) => Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("valid", Json::Bool(true)),
                    ("words", Json::Int(phrase.split_whitespace().count() as i128)),
                ])),
                Err(error) => Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("valid", Json::Bool(false)),
                    ("error", Json::Str(error.to_string())),
                ])),
            }
        }
        "wallet_generate" => {
            let network = network(request)?;
            let account = number(request, "account").unwrap_or(0) as u32;
            let (wallet, phrase) =
                Wallet::generate(network, account).map_err(|error| error.to_string())?;
            let handle = insert(wallet);
            let mut view = public_view(
                wallets()
                    .lock()
                    .map_err(|_| "the wallet table is unavailable")?
                    .get(&handle)
                    .ok_or("the wallet vanished")?,
                handle,
                Some(&phrase),
            );
            if let Json::Object(fields) = &mut view {
                fields.insert(
                    0,
                    ("ok".to_string(), Json::Bool(true)),
                );
            }
            Ok(view)
        }
        "wallet_from_phrase" => {
            let network = network(request)?;
            let phrase = string(request, "phrase")?;
            let passphrase = optional_string(request, "passphrase").unwrap_or_default();
            let account = number(request, "account").unwrap_or(0) as u32;
            let wallet = Wallet::from_phrase(network, &phrase, &passphrase, account)
                .map_err(|error| error.to_string())?;
            let handle = insert(wallet);
            let table = wallets().lock().map_err(|_| "the wallet table is unavailable")?;
            let wallet = table.get(&handle).ok_or("the wallet vanished")?;
            let mut view = public_view(wallet, handle, None);
            if let Json::Object(fields) = &mut view {
                fields.insert(0, ("ok".to_string(), Json::Bool(true)));
            }
            Ok(view)
        }
        "keystore_seal" => {
            let handle = number(request, "handle")?;
            let password = string(request, "password")?;
            let label = optional_string(request, "label").unwrap_or_else(|| "Obsidian wallet".to_string());
            with(handle, |wallet| {
                let keystore = wallet
                    .to_keystore(&password, &label)
                    .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("keystore", Json::Str(keystore.to_text())),
                    (
                        "kdf",
                        Json::Str("Argon2id (64 MiB, 3 passes) then ChaCha20-Poly1305".to_string()),
                    ),
                ]))
            })
        }
        "keystore_open" => {
            let network = network(request)?;
            let text = string(request, "keystore")?;
            let password = string(request, "password")?;
            let keystore = obs_wallet::keystore::Keystore::from_text(&text)
                .map_err(|error| error.to_string())?;
            if keystore.network() != network {
                return Err(format!(
                    "that keystore holds a {} wallet, but this interface is connected to {}",
                    keystore.network().name,
                    network.name
                ));
            }
            let wallet = keystore.open(&password).map_err(|error| error.to_string())?;
            let handle = insert(wallet);
            let table = wallets().lock().map_err(|_| "the wallet table is unavailable")?;
            let wallet = table.get(&handle).ok_or("the wallet vanished")?;
            let mut view = public_view(wallet, handle, None);
            if let Json::Object(fields) = &mut view {
                fields.insert(0, ("ok".to_string(), Json::Bool(true)));
            }
            Ok(view)
        }
        "wallet_lock" => {
            let handle = number(request, "handle")?;
            let removed = wallets()
                .lock()
                .map_err(|_| "the wallet table is unavailable")?
                .remove(&handle)
                .is_some();
            // `Wallet` zeroizes its seed when it is dropped, which is why it is
            // dropped here rather than kept around for a later "reopen".
            Ok(Json::obj([
                ("ok", Json::Bool(true)),
                ("locked", Json::Bool(removed)),
            ]))
        }
        "wallet_list" => {
            let table = wallets().lock().map_err(|_| "the wallet table is unavailable")?;
            let mut items: Vec<Json> = table
                .iter()
                .map(|(handle, wallet)| {
                    Json::obj([
                        ("handle", Json::Int(*handle as i128)),
                        ("network", Json::Str(wallet.network().name.to_string())),
                        ("address", Json::Str(wallet.address().to_string())),
                    ])
                })
                .collect();
            items.sort_by_key(|item| item.get("handle").and_then(Json::as_u64).unwrap_or(0));
            Ok(Json::obj([
                ("ok", Json::Bool(true)),
                ("wallets", Json::Array(items)),
            ]))
        }
        "account_proof" => {
            let handle = number(request, "handle")?;
            let nonce = string(request, "nonce")?;
            with(handle, |wallet| {
                let signature = obs_wallet::sign::account_proof(wallet, &nonce);
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("address", Json::Str(wallet.address().to_string())),
                    ("nonce", Json::Str(nonce)),
                    ("signature", Json::Str(hex(&signature))),
                ]))
            })
        }
        "sign_transfer" => {
            let handle = number(request, "handle")?;
            let to = string(request, "to")?;
            let amount_text = string(request, "amount")?;
            let nonce = number(request, "nonce")?;
            with(handle, |wallet| {
                let recipient = obs_primitives::address::Address::parse(wallet.network(), &to)
                    .map_err(|error| error.to_string())?;
                let amount = obs_primitives::money::Amount::parse(&amount_text)
                    .map_err(|error| error.to_string())?;
                if amount.is_zero() {
                    return Err("a transfer of nothing is not a transfer".to_string());
                }
                let fee = obs_chain::params::gas_fee_for(amount);
                let tx = obs_wallet::sign::transfer(wallet, recipient, amount, nonce)
                    .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("transaction", Json::Str(hex(&tx.to_bytes()))),
                    ("id", Json::Str(tx.id().0.to_hex())),
                    ("fee", Json::Str(fee.to_decimal_string())),
                    ("fee_rule", Json::Str("0.02% of the amount, capped at 0.01 OBS".to_string())),
                    ("to", Json::Str(recipient.to_string())),
                    ("amount", Json::Str(amount.to_decimal_string())),
                ]))
            })
        }
        "sign_claim" => {
            let handle = number(request, "handle")?;
            let protocol_time = number(request, "protocol_time")?;
            let sequence = number(request, "sequence")?;
            let nonce = number(request, "nonce")?;
            with(handle, |wallet| {
                let tx = obs_wallet::sign::claim(wallet, protocol_time, sequence, nonce)
                    .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("transaction", Json::Str(hex(&tx.to_bytes()))),
                    ("id", Json::Str(tx.id().0.to_hex())),
                    ("protocol_time", Json::Int(protocol_time as i128)),
                ]))
            })
        }
        "sign_registration" => {
            let handle = number(request, "handle")?;
            let authorization = request
                .get("invite_authorization")
                .ok_or("an invitation authorisation is required")?;
            let nonce = number(request, "nonce").unwrap_or(1);
            with(handle, |wallet| {
                let authorization = read_authorization(authorization, wallet.network())?;
                let gmail_commitment = authorization.gmail_commitment;
                let tx = obs_wallet::sign::register(
                    wallet,
                    obs_wallet::sign::Registration {
                        invite: authorization,
                        gmail_commitment,
                        nonce,
                    },
                )
                .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("transaction", Json::Str(hex(&tx.to_bytes()))),
                    ("id", Json::Str(tx.id().0.to_hex())),
                    (
                        "gmail_commitment",
                        Json::Str(hex(&gmail_commitment.0)),
                    ),
                ]))
            })
        }
        "sign_validator_register" => {
            let handle = number(request, "handle")?;
            let endpoint = optional_string(request, "endpoint").unwrap_or_default();
            let nonce = number(request, "nonce")?;
            with(handle, |wallet| {
                let tx = obs_wallet::sign::register_validator(wallet, &endpoint, nonce)
                    .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("transaction", Json::Str(hex(&tx.to_bytes()))),
                    ("id", Json::Str(tx.id().0.to_hex())),
                    (
                        "bond",
                        Json::Str(obs_primitives::money::VALIDATOR_BOND.to_decimal_string()),
                    ),
                    ("node_key", Json::Str(hex(&wallet.public_keys().node_key))),
                ]))
            })
        }
        "sign_validator_deregister" => {
            let handle = number(request, "handle")?;
            let nonce = number(request, "nonce")?;
            with(handle, |wallet| {
                let tx = obs_wallet::sign::deregister_validator(wallet, nonce)
                    .map_err(|error| error.to_string())?;
                Ok(Json::obj([
                    ("ok", Json::Bool(true)),
                    ("transaction", Json::Str(hex(&tx.to_bytes()))),
                    ("id", Json::Str(tx.id().0.to_hex())),
                    (
                        "unbonding",
                        Json::Str("48 hours, enforced by the chain".to_string()),
                    ),
                ]))
            })
        }
        "protocol_facts" => Ok(Json::obj([
            ("ok", Json::Bool(true)),
            (
                "unit",
                Json::Str("1 OBS = 1,000,000,000,000 grains".to_string()),
            ),
            (
                "max_supply",
                Json::Str(obs_primitives::money::MAX_SUPPLY.to_decimal_string()),
            ),
            (
                "genesis_allocation",
                Json::Str(obs_primitives::money::GENESIS_ALLOCATION.to_decimal_string()),
            ),
            (
                "validator_bond",
                Json::Str(obs_primitives::money::VALIDATOR_BOND.to_decimal_string()),
            ),
            ("claim_interval_secs", Json::Int(obs_chain::params::CLAIM_INTERVAL_SECS as i128)),
            ("max_claims_per_day", Json::Int(obs_chain::params::MAX_CLAIMS_PER_DAY as i128)),
            ("max_invites", Json::Int(obs_chain::params::MAX_INVITES_PER_ACCOUNT as i128)),
            (
                "gas_rule",
                Json::Str("0.02% of the amount, capped at 0.01 OBS, split 40/60".to_string()),
            ),
        ])),
        other => Err(format!("no such operation: {}", other)),
    }
}

/// Reads an invitation authorisation from the JSON the registration service
/// returned.  This is the only structure the interface passes through untouched,
/// and it is verified before it is signed over — a wallet that signed a
/// mismatched authorisation would produce a transaction the chain refuses.
fn read_authorization(
    value: &Json,
    network: Network,
) -> Result<obs_chain::chain::InviteAuthorization, String> {
    let hash = |name: &str| -> Result<obs_primitives::hash::Hash32, String> {
        let text = value
            .get(name)
            .and_then(Json::as_str)
            .ok_or_else(|| format!("the authorisation is missing {}", name))?;
        let bytes = obs_crypto::encoding::hex_decode(text)
            .ok_or_else(|| format!("the authorisation's {} is not hex", name))?;
        if bytes.len() != 32 {
            return Err(format!("the authorisation's {} is not 32 bytes", name));
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Ok(obs_primitives::hash::Hash32(out))
    };
    let signature_text = value
        .get("signature")
        .and_then(Json::as_str)
        .ok_or("the authorisation has no signature")?;
    let signature_bytes =
        obs_crypto::encoding::hex_decode(signature_text).ok_or("the signature is not hex")?;
    if signature_bytes.len() != 64 {
        return Err("the signature is not 64 bytes".to_string());
    }
    let mut signature = [0u8; 64];
    signature.copy_from_slice(&signature_bytes);
    let authorization = obs_chain::chain::InviteAuthorization {
        commitment: hash("commitment")?,
        gmail_commitment: hash("gmail_commitment")?,
        issued_at: number(value, "issued_at")?,
        expires_at: number(value, "expires_at")?,
        issuer: match value.get("issuer").and_then(Json::as_str) {
            Some(text) => Some(
                obs_primitives::address::Address::parse(network, text)
                    .map_err(|error| error.to_string())?,
            ),
            None => None,
        },
        authority_key: hash("authority_key")?.0,
        signature,
    };
    // The chain checks this signature again when the transaction is validated;
    // checking it here means a mismatched authorisation is refused at the moment
    // a person is looking at the screen, with a sentence that says what is wrong,
    // rather than as a rejected transaction later.
    if !authorization.verify_signature(network.chain_id) {
        return Err(
            "the invitation authorisation is not valid for this network: it was issued by a              different authority, or for a different chain, or it has been altered"
                .to_string(),
        );
    }
    Ok(authorization)
}

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

fn string(request: &Json, name: &str) -> Result<String, String> {
    request
        .get(name)
        .and_then(Json::as_str)
        .map(|value| value.to_string())
        .ok_or_else(|| format!("{} is required", name))
}

fn optional_string(request: &Json, name: &str) -> Option<String> {
    request
        .get(name)
        .and_then(Json::as_str)
        .filter(|value| !value.is_empty())
        .map(|value| value.to_string())
}

fn number(request: &Json, name: &str) -> Result<u64, String> {
    request
        .get(name)
        .and_then(Json::as_u64)
        .ok_or_else(|| format!("{} is required and must be a whole number", name))
}

fn network(request: &Json) -> Result<Network, String> {
    match optional_string(request, "network").as_deref() {
        None | Some("devnet") => Ok(DEVNET),
        Some("testnet") => Ok(TESTNET),
        Some("staging") => Ok(STAGING),
        Some("mainnet") => Ok(MAINNET),
        Some(other) => Err(format!("{} is not a network", other)),
    }
}

fn hex(bytes: &[u8]) -> String {
    obs_crypto::encoding::hex_encode(bytes)
}

// ---------------------------------------------------------------------------
// The C ABI
// ---------------------------------------------------------------------------

/// Allocates a buffer the host can write into.
///
/// # Safety
/// The returned pointer must be passed back to [`obs_free`] with the same length.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub extern "C" fn obs_alloc(len: usize) -> *mut u8 {
    let mut buffer = vec![0u8; len.max(1)];
    let pointer = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    pointer
}

/// Frees a buffer from [`obs_alloc`].
///
/// # Safety
/// `pointer` must come from [`obs_alloc`] with the same `len`.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn obs_free(pointer: *mut u8, len: usize) {
    if pointer.is_null() {
        return;
    }
    drop(unsafe { Vec::from_raw_parts(pointer, len.max(1), len.max(1)) });
}

/// Runs one operation and returns a length-prefixed JSON result.
///
/// The result is laid out as four little-endian bytes of length followed by that
/// many bytes of UTF-8 JSON.  A length prefix rather than a NUL terminator means
/// the interface never has to scan for a terminator it cannot see the end of, and
/// the length is known before the bytes are read.
///
/// **The caller must release the result with that whole size — four bytes plus
/// the length it read.**  The allocator is given back the same layout it was
/// asked for; releasing a buffer with a different size corrupts the heap, and in
/// a wasm build the failure is an abort rather than anything a person could
/// diagnose.  Input buffers are allocated as exactly their length (or one byte
/// when the length is zero) and are released the same way.
///
/// # Safety
/// `operation` and `request` must be valid for their stated lengths; the caller
/// owns the returned buffer and must release it with [`obs_free`], using the
/// length it read from the prefix.
#[cfg(target_arch = "wasm32")]
#[no_mangle]
pub unsafe extern "C" fn obs_call(
    operation: *const u8,
    operation_len: usize,
    request: *const u8,
    request_len: usize,
) -> *mut u8 {
    let name = match unsafe { str_from(operation, operation_len) } {
        Ok(name) => name,
        Err(message) => return leak(&envelope(&message).to_string()),
    };
    let request_json = match request_len {
        0 => Json::obj(Vec::<(String, Json)>::new()),
        _ => match unsafe { str_from(request, request_len) } {
            Ok(text) => match obs_primitives::json::parse(&text) {
                Ok(json) => json,
                Err(error) => {
                    return leak(&envelope(&format!("the request is not JSON: {}", error)).to_string())
                }
            },
            Err(message) => return leak(&envelope(&message).to_string()),
        },
    };
    let result = call(&name, &request_json);
    leak(&result.to_string())
}

#[cfg(target_arch = "wasm32")]
unsafe fn str_from(pointer: *const u8, len: usize) -> Result<String, String> {
    if len == 0 {
        return Ok(String::new());
    }
    if pointer.is_null() {
        return Err("a null pointer with a non-zero length".to_string());
    }
    let slice = unsafe { core::slice::from_raw_parts(pointer, len) };
    core::str::from_utf8(slice)
        .map(|text| text.to_string())
        .map_err(|_| "the input is not valid UTF-8".to_string())
}

/// Wraps an error in the same envelope every other failure uses.
#[cfg(target_arch = "wasm32")]
fn envelope(message: &str) -> Json {
    Json::obj([
        ("ok", Json::Bool(false)),
        ("error", Json::Str(message.to_string())),
    ])
}

/// Length-prefixes a payload and leaks it for the host to free.
#[cfg(target_arch = "wasm32")]
fn leak(payload: &str) -> *mut u8 {
    let bytes = payload.as_bytes();
    let mut buffer = Vec::with_capacity(bytes.len() + 4);
    buffer.extend_from_slice(&(bytes.len() as u32).to_le_bytes());
    buffer.extend_from_slice(bytes);
    let pointer = buffer.as_mut_ptr();
    core::mem::forget(buffer);
    pointer
}

#[cfg(test)]
mod tests {
    use super::*;

    fn request(pairs: Vec<(&str, Json)>) -> Json {
        Json::obj(pairs.into_iter().map(|(key, value)| (key.to_string(), value)))
    }

    #[test]
    fn a_generated_wallet_returns_its_phrase_once_and_keeps_its_keys_inside() {
        let answer = call("wallet_generate", &request(vec![("network", Json::Str("devnet".to_string()))]));
        assert_eq!(answer.get("ok").and_then(Json::as_bool), Some(true));
        let phrase = answer.get("phrase").and_then(Json::as_str).expect("a phrase");
        assert_eq!(phrase.split_whitespace().count(), 24);
        let handle = answer.get("handle").and_then(Json::as_u64).expect("a handle");
        let address = answer.get("address").and_then(Json::as_str).expect("an address");
        assert!(address.starts_with("dobs1"), "{}", address);

        // The phrase is in this answer because the owner asked for a wallet; no
        // other operation returns it, and none returns a private key at all.
        for operation in ["account_proof", "sign_claim"] {
            let answer = call(
                operation,
                &request(vec![
                    ("handle", Json::Int(handle as i128)),
                    ("nonce", Json::Str("n".to_string())),
                    ("protocol_time", Json::Int(1)),
                    ("sequence", Json::Int(1)),
                ]),
            );
            let rendered = answer.to_string();
            assert!(!rendered.contains("phrase"), "{} leaked a phrase", operation);
            assert!(!rendered.contains(&hex(&[0u8; 32])[..8]), "{} leaked a seed", operation);
        }
    }

    #[test]
    fn a_wallet_is_rebuilt_from_its_phrase_and_signs_the_same_address() {
        let first = call("wallet_generate", &request(vec![("network", Json::Str("devnet".to_string()))]));
        let phrase = first.get("phrase").and_then(Json::as_str).unwrap().to_string();
        let address = first.get("address").and_then(Json::as_str).unwrap().to_string();
        let rebuilt = call(
            "wallet_from_phrase",
            &request(vec![
                ("network", Json::Str("devnet".to_string())),
                ("phrase", Json::Str(phrase)),
            ]),
        );
        assert_eq!(rebuilt.get("address").and_then(Json::as_str), Some(address.as_str()));

        // A typo is not a new wallet: an invalid phrase is refused.
        let broken = call(
            "wallet_from_phrase",
            &request(vec![
                ("network", Json::Str("devnet".to_string())),
                ("phrase", Json::Str("not a recovery phrase".to_string())),
            ]),
        );
        assert_eq!(broken.get("ok").and_then(Json::as_bool), Some(false));
    }

    #[test]
    fn a_sealed_keystore_reopens_only_with_its_password() {
        let generated = call("wallet_generate", &request(vec![("network", Json::Str("devnet".to_string()))]));
        let handle = generated.get("handle").and_then(Json::as_u64).unwrap();
        let address = generated.get("address").and_then(Json::as_str).unwrap().to_string();
        let sealed = call(
            "keystore_seal",
            &request(vec![
                ("handle", Json::Int(handle as i128)),
                ("password", Json::Str("correct horse battery staple".to_string())),
                ("label", Json::Str("test".to_string())),
            ]),
        );
        let keystore = sealed.get("keystore").and_then(Json::as_str).unwrap().to_string();
        assert!(!keystore.contains("phrase"));

        let reopened = call(
            "keystore_open",
            &request(vec![
                ("network", Json::Str("devnet".to_string())),
                ("keystore", Json::Str(keystore.clone())),
                ("password", Json::Str("correct horse battery staple".to_string())),
            ]),
        );
        assert_eq!(reopened.get("address").and_then(Json::as_str), Some(address.as_str()));

        let wrong = call(
            "keystore_open",
            &request(vec![
                ("network", Json::Str("devnet".to_string())),
                ("keystore", Json::Str(keystore)),
                ("password", Json::Str("wrong password".to_string())),
            ]),
        );
        assert_eq!(wrong.get("ok").and_then(Json::as_bool), Some(false));

        // Locking drops the wallet: the handle stops working.
        let locked = call("wallet_lock", &request(vec![("handle", Json::Int(handle as i128))]));
        assert_eq!(locked.get("locked").and_then(Json::as_bool), Some(true));
        let proof = call(
            "account_proof",
            &request(vec![
                ("handle", Json::Int(handle as i128)),
                ("nonce", Json::Str("n".to_string())),
            ]),
        );
        assert_eq!(proof.get("ok").and_then(Json::as_bool), Some(false));
    }

    #[test]
    fn a_transfer_carries_the_protocols_own_fee() {
        let generated = call("wallet_generate", &request(vec![("network", Json::Str("devnet".to_string()))]));
        let handle = generated.get("handle").and_then(Json::as_u64).unwrap();
        let recipient = obs_primitives::address::Address::from_public_key(
            DEVNET,
            &obs_crypto::ed25519::Keypair::from_seed(&[9u8; 32]).public_key(),
        );
        let signed = call(
            "sign_transfer",
            &request(vec![
                ("handle", Json::Int(handle as i128)),
                ("to", Json::Str(recipient.to_string())),
                ("amount", Json::Str("1".to_string())),
                ("nonce", Json::Int(1)),
            ]),
        );
        assert_eq!(signed.get("ok").and_then(Json::as_bool), Some(true));
        // 0.02% of 1 OBS is 0.0002 OBS, and the interface did not choose it.
        assert_eq!(signed.get("fee").and_then(Json::as_str), Some("0.0002"));

        // The signed bytes are a real transaction, decodable by the chain code.
        let bytes = obs_crypto::encoding::hex_decode(
            signed.get("transaction").and_then(Json::as_str).unwrap(),
        )
        .unwrap();
        let tx = obs_chain::Transaction::from_bytes(&bytes).expect("a decodable transaction");
        assert_eq!(tx.chain_id, DEVNET.chain_id);
        assert!(tx.verify_signature());
    }

    #[test]
    fn unknown_operations_and_bad_input_are_refused_rather_than_guessed() {
        let answer = call("teleport", &Json::obj(Vec::<(String, Json)>::new()));
        assert_eq!(answer.get("ok").and_then(Json::as_bool), Some(false));
        assert!(answer.get("error").and_then(Json::as_str).unwrap().contains("teleport"));

        let missing = call("sign_claim", &Json::obj(Vec::<(String, Json)>::new()));
        assert_eq!(missing.get("ok").and_then(Json::as_bool), Some(false));
        assert!(missing.get("error").and_then(Json::as_str).unwrap().contains("handle"));

        let wrong_network = call(
            "wallet_generate",
            &request(vec![("network", Json::Str("moonnet".to_string()))]),
        );
        assert_eq!(wrong_network.get("ok").and_then(Json::as_bool), Some(false));
    }
}
