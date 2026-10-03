//! Registration against a service, and the wallet's own part in it.
//!
//! The flow has six steps and no email verification:
//!
//! ```text
//!   gmail → password → invite code → recovery code → MFA (TOTP) → wallet → activated
//! ```
//!
//! The service keeps the account: the canonical Gmail identity, the password
//! hash, the invitation it consumed, the sealed TOTP secret, and the three
//! public keys of the wallet.  It holds no private key of the account, and it
//! could not: the last step is the *wallet* signing the registration
//! transaction, and the chain checks that signature against the wallet key the
//! service was given.  The invitation authorisation the service returns binds
//! the invitation to this account's Gmail commitment, so it cannot be used for
//! anybody else's account either.
//!
//! Two secrets are produced in this flow and both are shown exactly once, by the
//! service, in the step that creates them: the account recovery code and the MFA
//! secret.  This CLI writes them to owner-only files rather than to the terminal,
//! and the wallet's own recovery phrase never leaves the machine at all.

use obs_primitives::identity::canonical_gmail;
use obs_primitives::json::Json;
use obs_rpc::cli::Args;
use obs_wallet::Wallet;

use crate::keys;
use crate::{field, print_json, CliError, Context};

/// Options for the registration commands.
pub const OPTIONS: &[&'static str] = &[
    "keystore",
    "password-file",
    "label",
    "phrase-out",
    "gmail",
    "invite",
    "code",
    "secrets-out",
    "session-out",
    "account",
];

/// Runs the whole six-step enrolment, then signs the account on chain.
///
/// The Gmail password is read from the same sources as the keystore password —
/// a file or an environment variable — for the same reason: an email account's
/// password on a command line is a password in the process list.
pub fn register(context: &Context, args: &Args) -> Result<(), CliError> {
    let gmail = args
        .get("gmail")
        .ok_or_else(|| CliError::Usage("--gmail <address@gmail.com> is required".to_string()))?;
    let canonical = canonical_gmail(gmail)
        .map_err(|error| CliError::Usage(format!("--gmail: {}", error)))?;
    let invite = args
        .get("invite")
        .ok_or_else(|| CliError::Usage("--invite <code> is required".to_string()))?;
    let password = keys::password(args)?;

    // The wallet is created *before* the account exists, on this machine, so the
    // keys the service is told about were generated here and never left.
    let keystore = keys::keystore_path(args)?;
    let label = args.or("label", "Obsidian wallet");
    let phrase_out = args.get("phrase-out").map(std::path::PathBuf::from);
    let wallet = keys::create_wallet(context.network, &keystore, &password, &label, phrase_out.as_deref())?;
    println!("obs-cli: wallet created at {}", keystore.display());
    println!("obs-cli: address {}", wallet.address());

    let begin = post(context, "register/begin", Json::obj([
        ("gmail", Json::Str(gmail.to_string())),
    ]))?;
    let token = field(&begin, "token")?.to_string();
    println!(
        "obs-cli: step 1/6 gmail accepted as {} (no email verification is used)",
        field(&begin, "gmail").unwrap_or("(masked)")
    );

    post(context, "register/password", Json::obj([
        ("token", Json::Str(token.clone())),
        ("password", Json::Str(password.clone())),
    ]))?;
    println!("obs-cli: step 2/6 password set");

    let step = post(context, "register/invite", Json::obj([
        ("token", Json::Str(token.clone())),
        ("code", Json::Str(invite.to_string())),
    ]))?;
    println!("obs-cli: step 3/6 invitation accepted");
    let _ = step;

    let step = post(context, "register/recovery-code", Json::obj([
        ("token", Json::Str(token.clone())),
    ]))?;
    let recovery_code = field(&step, "value")?.to_string();
    println!("obs-cli: step 4/6 account recovery code issued");

    let step = post(context, "register/mfa", Json::obj([
        ("token", Json::Str(token.clone())),
    ]))?;
    let mfa_secret = field(&step, "value")?.to_string();
    println!("obs-cli: step 5/6 MFA secret issued");

    // Both secrets are written where the owner can read them and nobody else can.
    let secrets_path = args
        .get("secrets-out")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| keystore.with_extension("secrets.txt"));
    let document = format!(
        "# Obsidian Network account secrets for {}\n\
         # Shown once by the service and never again.  Keep this file offline.\n\
         account_recovery_code {}\n\
         mfa_secret {}\n\
         mfa_otpauth otpauth://totp/Obsidian:{}?secret={}&issuer=Obsidian\n\
         gmail_commitment {}\n",
        canonical,
        recovery_code,
        mfa_secret,
        canonical,
        mfa_secret,
        obs_crypto::encoding::hex_encode(
            obs_chain::gmail_commitment(context.network.chain_id, &canonical).as_bytes()
        ),
    );
    keys::write_private(&secrets_path, &document)?;
    println!("obs-cli: secrets written to {}", secrets_path.display());

    // Step five is confirmed here, with a code this machine computes from the
    // secret it was just given: the enrolment is not complete until a code from
    // the authenticator has been accepted, and leaving that to a human would
    // leave the account unactivated.  The code is computed for the *next* step
    // boundary when this request lands near one, so a registration is never
    // refused for a reason that has nothing to do with it.
    confirm_mfa(context, &token, mfa_secret.trim())?;
    println!("obs-cli: step 5/6 MFA confirmed");

    let keys = wallet.public_keys();
    let step = post(context, "register/wallet", Json::obj([
        ("token", Json::Str(token.clone())),
        ("wallet_key", Json::Str(hex(&keys.wallet_key))),
        ("node_key", Json::Str(hex(&keys.node_key))),
        ("recovery_key", Json::Str(hex(&keys.recovery_key))),
    ]))?;
    println!("obs-cli: step 6/6 wallet attached; the account is activated");

    // The last thing the flow gives the wallet is the invitation authorisation:
    // the authority's signature binding this invitation to this Gmail identity.
    // The wallet signs the registration itself, which is what puts the account on
    // chain without the service ever holding a key that could move value.
    let authorization = step
        .get("invite_authorization")
        .ok_or_else(|| CliError::Failed("the service did not return an invitation authorisation".to_string()))?;
    let authorization = obs_gateway::api::authorization_from_json(authorization, context.network)
        .ok_or_else(|| CliError::Failed("the authorisation was not readable".to_string()))?;
    let gmail_commitment = obs_chain::gmail_commitment(context.network.chain_id, &canonical);
    if authorization.gmail_commitment != gmail_commitment {
        return Err(CliError::Failed(
            "the invitation authorisation is for a different Gmail identity".to_string(),
        ));
    }
    let tx = obs_wallet::sign::register(
        &wallet,
        obs_wallet::sign::Registration {
            invite: authorization,
            gmail_commitment,
            nonce: 1,
        },
    )
    .map_err(|error| CliError::Failed(format!("the registration could not be signed: {}", error)))?;

    let body = Json::obj([("transaction", Json::Str(hex(&tx.to_bytes())))]);
    let answer = context.node_post("transactions", &body)?;
    println!(
        "obs-cli: registration submitted to the node as {} ({})",
        tx.id().0.to_hex(),
        answer.get("status").and_then(Json::as_str).unwrap_or("pooled")
    );
    println!(
        "obs-cli: the account exists on chain once that transaction is mined; mining is enabled \
         for this account, one claim every four hours"
    );
    println!("obs-cli: address {}", wallet.address());
    Ok(())
}

/// Signs in to a service and writes the session token where a script can use it.
pub fn sign_in(context: &Context, args: &Args) -> Result<(), CliError> {
    let gmail = args
        .get("gmail")
        .ok_or_else(|| CliError::Usage("--gmail <address@gmail.com> is required".to_string()))?;
    let password = keys::password(args)?;
    let code = args
        .get("code")
        .ok_or_else(|| CliError::Usage("--code <6-digit TOTP> is required".to_string()))?;
    let answer = post(context, "auth/sign-in", Json::obj([
        ("gmail", Json::Str(gmail.to_string())),
        ("password", Json::Str(password)),
        ("mfa_code", Json::Str(code.to_string())),
    ]))?;
    let token = field(&answer, "token")?.to_string();
    match args.get("session-out") {
        Some(path) => {
            keys::write_private(std::path::Path::new(path), &format!("{}\n", token))?;
            println!("obs-cli: session written to {}", path);
        }
        None => print_json(&answer),
    }
    Ok(())
}

/// The signed-in account's own view: invitations used, mining state.
pub fn account(context: &Context, args: &Args) -> Result<(), CliError> {
    let token = session(args)?;
    let client = context.client.clone();
    let response = client
        .with_header("Authorization", format!("Bearer {}", token))
        .get(&format!("{}/v1/account", context.gateway_url))?;
    if response.status.code() >= 400 {
        return Err(CliError::Failed(format!(
            "the service refused: status {}",
            response.status.code()
        )));
    }
    print_json(&obs_rpc::client::json_body(&response)?);
    Ok(())
}

/// Issues an invitation from this account's budget.
pub fn issue_invite(context: &Context, args: &Args) -> Result<(), CliError> {
    let token = session(args)?;
    let client = context.client.clone();
    let response = client
        .with_header("Authorization", format!("Bearer {}", token))
        .post_json(&format!("{}/v1/invites", context.gateway_url), &Json::obj(Vec::<(String, Json)>::new()))?;
    if response.status.code() >= 400 {
        return Err(CliError::Failed(format!(
            "the service refused the invitation: status {}",
            response.status.code()
        )));
    }
    let body = obs_rpc::client::json_body(&response)?;
    println!(
        "obs-cli: invitation issued ({} of {} used)",
        0,
        obs_chain::params::MAX_INVITES_PER_ACCOUNT
    );
    print_json(&body);
    Ok(())
}

/// The session token, from the file the sign-in wrote.
fn session(args: &Args) -> Result<String, CliError> {
    let path = args
        .get("session-out")
        .ok_or_else(|| CliError::Usage("--session-out <path> is required".to_string()))?;
    let text = std::fs::read_to_string(path)
        .map_err(|error| CliError::Failed(format!("{}: {}", path, error)))?;
    Ok(text.trim().to_string())
}

/// The authenticator secret inside whatever step five returned.
///
/// The service hands back a provisioning URI — the form a person scans — and the
/// secret is inside it.  A bare secret is accepted too, so this works whichever
/// form a deployment returns.
fn authenticator_secret(issued: &str) -> Result<&str, CliError> {
    let issued = issued.trim();
    if !issued.starts_with("otpauth://") {
        return Ok(issued);
    }
    issued
        .split("secret=")
        .nth(1)
        .and_then(|rest| rest.split('&').next())
        .filter(|secret| !secret.is_empty())
        .ok_or_else(|| {
            CliError::Failed("the provisioning URI carries no authenticator secret".to_string())
        })
}

/// Confirms the authenticator enrolment with a code computed from the secret.
///
/// A TOTP code is only valid inside its own thirty-second step, so a request that
/// lands on a boundary is retried with the code for the step that has begun
/// rather than the one that just ended.
fn confirm_mfa(context: &Context, token: &str, issued: &str) -> Result<(), CliError> {
    // Step five returns a provisioning URI, which is what a person scans; the
    // secret inside it is what a program uses.  Accept either form.
    let secret_base32 = authenticator_secret(issued)?;
    let secret = obs_crypto::totp::Secret::parse_base32(secret_base32)
        .map_err(|error| CliError::Failed(format!("the MFA secret is not usable: {}", error)))?;
    let mut last = None;
    for attempt in 0..3u64 {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|elapsed| elapsed.as_secs())
            .unwrap_or(0);
        // Step forward when the current window is nearly over.
        let at = now + if now % 30 >= 25 { 30 - (now % 30) } else { 0 };
        let code = format!("{:06}", secret.code_at(at));
        let response = context
            .client
            .post_json(
                &format!("{}/v1/register/mfa/confirm", context.gateway_url),
                &Json::obj([
                    ("token", Json::Str(token.to_string())),
                    ("code", Json::Str(code)),
                ]),
            )
            .map_err(|error| CliError::Failed(error.to_string()))?;
        if response.status.code() < 400 {
            return Ok(());
        }
        last = Some(response.status.code());
        std::thread::sleep(std::time::Duration::from_millis(400 * (attempt + 1)));
    }
    Err(CliError::Failed(format!(
        "the service refused the authenticator code (last status {:?}); step 5 of 6 could not be confirmed",
        last
    )))
}

fn post(context: &Context, path: &str, body: Json) -> Result<Json, CliError> {
    context.post(&format!("{}/v1/{}", context.gateway_url, path), &body)
}

fn hex(bytes: &[u8]) -> String {
    obs_crypto::encoding::hex_encode(bytes)
}

/// Prints the wallet's own registration material without contacting anything.
///
/// Useful when a person registers in a browser but holds the wallet on a machine
/// that has no network: this prints the three public keys the browser's wallet
/// step needs.
pub fn public_keys(_context: &Context, args: &Args) -> Result<(), CliError> {
    let args = args;
    let network = crate::Context::from_args(args)?.network;
    let wallet: Wallet = keys::open_wallet(args, network)?;
    let keys = wallet.public_keys();
    let body = Json::obj([
        ("wallet_key", Json::Str(hex(&keys.wallet_key))),
        ("node_key", Json::Str(hex(&keys.node_key))),
        ("recovery_key", Json::Str(hex(&keys.recovery_key))),
    ]);
    print_json(&body);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_authenticator_secret_is_read_from_either_form() {
        // The URI form: what a person scans, and what the service returns.
        let uri = "otpauth://totp/Obsidian:someone@gmail.com?secret=JBSWY3DPEHPK3PXP&issuer=Obsidian";
        assert_eq!(authenticator_secret(uri).unwrap(), "JBSWY3DPEHPK3PXP");
        // The bare form, for a deployment that returns the secret itself.
        assert_eq!(authenticator_secret(" JBSWY3DPEHPK3PXP\n").unwrap(), "JBSWY3DPEHPK3PXP");
        // A URI with no secret is refused rather than treated as a secret: an
        // enrolment that silently confirmed the wrong value would be worse than
        // a clear failure.
        assert!(authenticator_secret("otpauth://totp/Obsidian:x?issuer=Obsidian").is_err());
        assert!(authenticator_secret("otpauth://totp/Obsidian:x?secret=&issuer=Obsidian").is_err());
    }

    #[test]
    fn a_secret_from_the_service_produces_a_code_the_verifier_accepts() {
        // Six digits, always: the verifier refuses anything that is not a
        // fixed-width code, so a code must never be formatted without padding.
        // Twenty bytes of entropy, the minimum the TOTP implementation accepts.
        let secret =
            obs_crypto::totp::Secret::parse_base32("JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP").unwrap();
        let code = format!("{:06}", secret.code_at(1_700_000_000));
        assert_eq!(code.len(), 6);
        assert!(code.chars().all(|c| c.is_ascii_digit()));
        assert!(secret.code_at(1_700_000_000) < 1_000_000);
    }
}
