//! The HTTP API of the registration gateway.
//!
//! Everything an API can do here is *account administrative*: create an account
//! record, sign in, issue an invitation, recover access, hand back an invitation
//! authorisation.  Nothing on this surface can move value, mint a coin, approve
//! a claim or change a balance, because those are consensus operations and the
//! gateway has no key or endpoint that could influence them.  The registration
//! transaction is built and signed by the **client's own wallet**; the gateway
//! only says "this identity presented a valid invitation".
//!
//! Two rules are enforced on every route:
//!
//! 1. **State-changing requests must come from the service's own origin.**  A
//!    browser session cookie cannot be leveraged by another site, because a
//!    cross-origin request is refused before it is read.
//! 2. **Secrets are returned exactly once and never logged.**  A recovery code,
//!    a provisioning URI, an invitation code and a session token appear in the
//!    single response that creates them and nowhere else — not in a listing, not
//!    in a store, not in a log line.

use std::sync::{Arc, Mutex};

use obs_primitives::json::Json;
use obs_primitives::network::Network;
use obs_rpc::http::{Method, Request, Response, Status};
use obs_rpc::server::{Handler, Peer};

use crate::accounts::{AccountError, Registry, Stage, Step};

/// Longest body any route accepts.
pub const MAX_BODY: usize = 8 * 1024;
/// Where the gateway's own pages are served from, by default.
pub const GATEWAY_PORT: u16 = 8080;
/// The domain the gateway is published under.
pub const GATEWAY_DOMAIN: &str = "https://obsidian.network";
/// The node API the gateway points clients at.
pub const NODE_API: &str = "http://127.0.0.1:7200";

/// The gateway's shared state.
pub struct Gateway {
    registry: Arc<Mutex<Registry>>,
    network: Network,
    /// Clock, injectable for tests.  A service's clock is administrative
    /// bookkeeping — never a consensus input.
    now: Box<dyn Fn() -> u64 + Send + Sync>,
    allowed_origins: Vec<String>,
}

impl Gateway {
    /// Wraps a registry that is shared with the rest of the deployment.
    ///
    /// A service that hosts the account flow *and* anything else that needs to
    /// read accounts (the developer portal, for instance) keeps one registry
    /// behind one lock, so there is exactly one writer and no second copy that
    /// could drift.
    pub fn from_shared(registry: Arc<Mutex<Registry>>, network: Network) -> Gateway {
        let allowed_origins = vec![
            format!("localhost:{GATEWAY_PORT}"),
            format!("127.0.0.1:{GATEWAY_PORT}"),
            GATEWAY_DOMAIN.to_string(),
        ];
        Gateway {
            registry,
            network,
            now: Box::new(|| {
                u64::try_from(
                    std::time::SystemTime::now()
                        .duration_since(std::time::UNIX_EPOCH)
                        .map(|duration| duration.as_secs())
                        .unwrap_or(0),
                )
                .unwrap_or(0)
            }),
            allowed_origins,
        }
    }

    /// Wraps a registry.
    pub fn new(registry: Registry, network: Network) -> Gateway {
        Gateway::from_shared(Arc::new(Mutex::new(registry)), network)
    }

    /// Replaces the clock (test hook).
    pub fn with_clock(mut self, clock: Box<dyn Fn() -> u64 + Send + Sync>) -> Gateway {
        self.now = clock;
        self
    }

    /// Adds an origin allowed to make state-changing requests.
    pub fn allow_origin(mut self, origin: impl Into<String>) -> Gateway {
        self.allowed_origins.push(origin.into());
        self
    }

    fn now(&self) -> u64 {
        (self.now)()
    }

    /// Confirms the gateway is bound to a network, for callers that build one.
    pub fn origins(&self) -> Vec<String> {
        self.allowed_origins.clone()
    }

    /// The network this gateway serves.
    pub fn network(&self) -> Network {
        self.network
    }
}

fn ok(value: Json) -> Response {
    Response::json(Status::OK, &value).no_store().hardened()
}

fn created(value: Json) -> Response {
    Response::json(Status::CREATED, &value).no_store().hardened()
}

fn error(status: Status, code: &str, message: &str) -> Response {
    Response::error(status, code, message).no_store().hardened()
}

fn account_error(failure: AccountError) -> Response {
    let (status, code) = match &failure {
        AccountError::BadGmail => (Status::BAD_REQUEST, "bad_gmail"),
        AccountError::GmailTaken => (Status::CONFLICT, "gmail_taken"),
        AccountError::BadPassword(_) => (Status::BAD_REQUEST, "bad_password"),
        AccountError::BadInvite => (Status::BAD_REQUEST, "bad_invite"),
        AccountError::InviteBudget => (Status::FORBIDDEN, "invite_budget"),
        AccountError::BadMfaCode => (Status::FORBIDDEN, "bad_mfa_code"),
        AccountError::Locked { .. } => (Status::TOO_MANY_REQUESTS, "locked"),
        AccountError::BadEnrolment => (Status::BAD_REQUEST, "bad_enrolment"),
        AccountError::OutOfOrder { .. } => (Status::CONFLICT, "out_of_order"),
        AccountError::BadCredentials => (Status::FORBIDDEN, "bad_credentials"),
        AccountError::BadSession => (Status::FORBIDDEN, "bad_session"),
        AccountError::MfaNotEnrolled => (Status::CONFLICT, "mfa_not_enrolled"),
        AccountError::RecoveryUsed => (Status::CONFLICT, "recovery_used"),
        AccountError::Store(_) => (Status::INTERNAL, "storage_error"),
    };
    error(status, code, &failure.to_string())
}

fn field<'a>(body: &'a Json, name: &str) -> Option<&'a Json> {
    body.get(name)
}

fn string(body: &Json, name: &str) -> Option<String> {
    field(body, name).and_then(Json::as_str).map(|text| text.to_string())
}

fn key32(body: &Json, name: &str) -> Option<[u8; 32]> {
    let text = string(body, name)?;
    let bytes = obs_crypto::encoding::hex_decode(&text)?;
    if bytes.len() != 32 {
        return None;
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&bytes);
    Some(out)
}

fn stage_json(stage: Stage) -> Json {
    Json::obj([
        ("stage", Json::Str(stage.name().to_string())),
        (
            "next",
            match stage.next() {
                Some(next) => Json::Str(next.name().to_string()),
                None => Json::Null,
            },
        ),
    ])
}

fn step_json(step: Step) -> Json {
    match step {
        Step::Continue { stage } => stage_json(stage),
        Step::Show { stage, value } => {Json::obj([
            ("stage", Json::Str(stage.name().to_string())),
            ("next", match stage.next() {
                Some(next) => Json::Str(next.name().to_string()),
                None => Json::Null,
            }),
            ("value", Json::Str(value)),
            (
                "notice",
                Json::Str("shown once; store it somewhere safe, it will not be displayed again".to_string()),
            ),
        ])
        }
        Step::Activated(activation) => Json::obj([
            ("stage", Json::Str("activated".to_string())),
            ("next", Json::Null),
            ("gmail_commitment", Json::Str(obs_crypto::encoding::hex_encode(&activation.gmail_commitment))),
            ("wallet_key", Json::Str(obs_crypto::encoding::hex_encode(&activation.wallet_key))),
            ("node_key", Json::Str(obs_crypto::encoding::hex_encode(&activation.node_key))),
            ("chain_id", Json::Int(activation.chain_id as i128)),
            (
                "mining_enabled",
                Json::Bool(true),
            ),
            (
                "invite_authorization",
                match &activation.authorization {
                    Some(authorization) => authorization_json(authorization),
                    None => Json::Null,
                },
            ),
        ]),
    }
}

/// The invitation authorisation as JSON: the wire form between this service and a
/// client wallet.
///
/// A client receives one of these once, in the activation response, and puts it
/// verbatim into its own registration transaction.  Field names and the exact
/// byte encodings matter: the chain verifies the authority's signature over the
/// commitment, the identity commitment and the validity window, so a client that
/// re-encodes any of them differently simply produces a transaction the network
/// refuses.
pub fn authorization_json(authorization: &obs_chain::chain::InviteAuthorization) -> Json {
    Json::obj([
        (
            "commitment",
            Json::Str(obs_crypto::encoding::hex_encode(&authorization.commitment.0)),
        ),
        (
            "gmail_commitment",
            Json::Str(obs_crypto::encoding::hex_encode(&authorization.gmail_commitment.0)),
        ),
        ("issued_at", Json::Int(authorization.issued_at as i128)),
        ("expires_at", Json::Int(authorization.expires_at as i128)),
        (
            "issuer",
            match authorization.issuer {
                Some(address) => Json::Str(address.to_string()),
                None => Json::Null,
            },
        ),
        (
            "authority_key",
            Json::Str(obs_crypto::encoding::hex_encode(&authorization.authority_key)),
        ),
        (
            "signature",
            Json::Str(obs_crypto::encoding::hex_encode(&authorization.signature)),
        ),
    ])
}

/// Reads an invitation authorisation back from its JSON form.
pub fn authorization_from_json(
    value: &Json,
    network: Network,
) -> Option<obs_chain::chain::InviteAuthorization> {
    use obs_primitives::hash::Hash32;
    let hash = |name: &str| -> Option<Hash32> {
        let bytes = obs_crypto::encoding::hex_decode(value.get(name)?.as_str()?)?;
        if bytes.len() != 32 {
            return None;
        }
        let mut out = [0u8; 32];
        out.copy_from_slice(&bytes);
        Some(Hash32(out))
    };
    let signature = obs_crypto::encoding::hex_decode(value.get("signature")?.as_str()?)?;
    if signature.len() != 64 {
        return None;
    }
    let mut sig = [0u8; 64];
    sig.copy_from_slice(&signature);
    let authority_key = hash("authority_key")?;
    let issuer = match value.get("issuer").and_then(Json::as_str) {
        Some(text) => Some(obs_primitives::address::Address::parse(network, text).ok()?),
        None => None,
    };
    Some(obs_chain::chain::InviteAuthorization {
        commitment: hash("commitment")?,
        gmail_commitment: hash("gmail_commitment")?,
        issued_at: value.get("issued_at")?.as_i128()? as u64,
        expires_at: value.get("expires_at")?.as_i128()? as u64,
        issuer,
        authority_key: authority_key.0,
        signature: sig,
    })
}

impl Handler for Gateway {
    fn handle(&self, request: &Request, _peer: &Peer) -> Response {
        let state_changing = matches!(request.method, Method::Post | Method::Put | Method::Delete);
        if state_changing
            && !request.same_origin(&self.origins())
            && !request.same_origin_as_host()
        {
            return error(
                Status::FORBIDDEN,
                "cross_origin",
                "state-changing requests must come from the service's own origin",
            );
        }
        let now = self.now();
        match (request.method, request.path.as_str()) {
            (Method::Get, "/healthz") => ok(Json::obj([
                ("status", Json::Str("ok".to_string())),
                ("chain_id", Json::Int(self.network.chain_id as i128)),
            ])),
            (Method::Get, "/v1/network") => ok(Json::obj([
                ("name", Json::Str(self.network.name.to_string())),
                ("chain_id", Json::Int(self.network.chain_id as i128)),
                ("address_prefix", Json::Str(self.network.address_prefix.to_string())),
                ("node_api", Json::Str(NODE_API.to_string())),
            ])),
            (Method::Post, "/v1/register/begin") => self.begin(request, now),
            (Method::Post, "/v1/register/password") => self.password(request, now),
            (Method::Post, "/v1/register/invite") => self.invite(request, now),
            (Method::Post, "/v1/register/recovery-code") => self.recovery_code(request, now),
            (Method::Post, "/v1/register/mfa") => self.mfa(request, now),
            (Method::Post, "/v1/register/mfa/confirm") => self.mfa_confirm(request, now),
            (Method::Post, "/v1/register/wallet") => self.wallet(request, now),
            (Method::Post, "/v1/auth/sign-in") => self.sign_in(request, now),
            (Method::Post, "/v1/auth/sign-out") => self.sign_out(request, now),
            (Method::Get, "/v1/account") => self.account(request, now),
            (Method::Post, "/v1/invites") => self.issue_invite(request, now),
            (Method::Get, "/v1/invites") => self.list_invites(request, now),
            (Method::Post, "/v1/recovery/verify") => self.recovery_verify(request, now),
            (Method::Post, "/v1/recovery/mfa") => self.recovery_mfa(request, now),
            (Method::Get, "/v1/authority") => ok(Json::obj([(
                "authority_key",
                match self.state().authority_public_key() {
                    Some(key) => Json::Str(obs_crypto::encoding::hex_encode(&key)),
                    None => Json::Null,
                },
            )])),
            _ => error(Status::NOT_FOUND, "not_found", "no such endpoint"),
        }
    }
}

impl Gateway {
    /// The shared registry, for operator tooling (minting a network invitation,
    /// auditing accounts) and for tests.
    pub fn registry(&self) -> Arc<Mutex<Registry>> {
        Arc::clone(&self.registry)
    }

    fn state(&self) -> std::sync::MutexGuard<'_, Registry> {
        self.registry
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn body(&self, request: &Request) -> Result<Json, Response> {
        if request.body.len() > MAX_BODY {
            return Err(error(Status::PAYLOAD_TOO_LARGE, "too_large", "the request body is too large"));
        }
        request.json().map_err(|_| {
            error(Status::BAD_REQUEST, "bad_json", "the request body is not a JSON object")
        })
    }

    fn begin(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(gmail) = string(&body, "gmail") else {
            return error(Status::BAD_REQUEST, "bad_json", "a gmail field is required");
        };
        match self.state().begin(&gmail, now) {
            Ok((token, canonical)) => created(Json::obj([
                ("token", Json::Str(token)),
                ("stage", Json::Str(Stage::Gmail.name().to_string())),
                ("next", Json::Str(Stage::Password.name().to_string())),
                ("gmail", Json::Str(crate::accounts::mask_gmail(&canonical))),
                (
                    "notice",
                    Json::Str("no email verification step is used; continue with your password".to_string()),
                ),
            ])),
            Err(error) => account_error(error),
        }
    }

    fn password(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(token), Some(password)) = (string(&body, "token"), string(&body, "password")) else {
            return error(Status::BAD_REQUEST, "bad_json", "token and password are required");
        };
        match self.state().set_password(&token, &password, now) {
            Ok(stage) => ok(stage_json(stage)),
            Err(error) => account_error(error),
        }
    }

    fn invite(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(token), Some(code)) = (string(&body, "token"), string(&body, "code")) else {
            return error(Status::BAD_REQUEST, "bad_json", "token and code are required");
        };
        match self.state().redeem_invite(&token, &code, now) {
            Ok(stage) => ok(stage_json(stage)),
            Err(error) => account_error(error),
        }
    }

    fn recovery_code(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(token) = string(&body, "token") else {
            return error(Status::BAD_REQUEST, "bad_json", "a token is required");
        };
        match self.state().issue_recovery_code(&token, now) {
            Ok(step) => ok(step_json(step)),
            Err(error) => account_error(error),
        }
    }

    fn mfa(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(token) = string(&body, "token") else {
            return error(Status::BAD_REQUEST, "bad_json", "a token is required");
        };
        match self.state().enrol_mfa(&token, now) {
            Ok(step) => ok(step_json(step)),
            Err(error) => account_error(error),
        }
    }

    fn mfa_confirm(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(token), Some(code)) = (string(&body, "token"), string(&body, "code")) else {
            return error(Status::BAD_REQUEST, "bad_json", "token and code are required");
        };
        match self.state().confirm_mfa(&token, &code, now) {
            Ok(stage) => ok(stage_json(stage)),
            Err(error) => account_error(error),
        }
    }

    fn wallet(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let Some(token) = string(&body, "token") else {
            return error(Status::BAD_REQUEST, "bad_json", "a token is required");
        };
        let (Some(wallet_key), Some(node_key), Some(recovery_key)) = (
            key32(&body, "wallet_key"),
            key32(&body, "node_key"),
            key32(&body, "recovery_key"),
        ) else {
            return error(
                Status::BAD_REQUEST,
                "bad_json",
                "wallet_key, node_key and recovery_key are required, each 32 bytes of hex",
            );
        };
        match self
            .state()
            .attach_wallet(&token, wallet_key, node_key, recovery_key, now)
        {
            Ok(step) => ok(step_json(step)),
            Err(error) => account_error(error),
        }
    }

    fn sign_in(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(gmail), Some(password), Some(mfa_code)) = (
            string(&body, "gmail"),
            string(&body, "password"),
            string(&body, "mfa_code"),
        ) else {
            return error(
                Status::BAD_REQUEST,
                "bad_json",
                "gmail, password and mfa_code are required",
            );
        };
        match self.state().sign_in(&gmail, &password, &mfa_code, now) {
            Ok((token, session)) => ok(Json::obj([
                ("token", Json::Str(token)),
                ("expires_at", Json::Int(session.expires_at as i128)),
            ])),
            Err(error) => account_error(error),
        }
    }

    fn bearer<'a>(&self, request: &'a Request) -> Option<String> {
        request
            .header("authorization")
            .and_then(|value| value.strip_prefix("Bearer "))
            .map(|token| token.to_string())
    }

    fn sign_out(&self, request: &Request, _now: u64) -> Response {
        let Some(token) = self.bearer(request) else {
            return error(Status::FORBIDDEN, "bad_session", "a bearer token is required");
        };
        match self.state().sign_out(&token) {
            Ok(()) => ok(Json::obj([("signed_out", Json::Bool(true))])),
            Err(error) => account_error(error),
        }
    }

    fn account(&self, request: &Request, now: u64) -> Response {
        let Some(token) = self.bearer(request) else {
            return error(Status::FORBIDDEN, "bad_session", "a bearer token is required");
        };
        let registry = self.state();
        let session = match registry.session(&token, now) {
            Ok(session) => session.canonical_gmail.clone(),
            Err(error) => return account_error(error),
        };
        match registry.account(&session) {
            Some(account) => ok(account.owner_view()),
            None => error(Status::FORBIDDEN, "bad_session", "the session is not valid"),
        }
    }

    fn issue_invite(&self, request: &Request, now: u64) -> Response {
        let Some(token) = self.bearer(request) else {
            return error(Status::FORBIDDEN, "bad_session", "a bearer token is required");
        };
        let mut registry = self.state();
        let session = match registry.session(&token, now) {
            Ok(session) => session.canonical_gmail.clone(),
            Err(error) => return account_error(error),
        };
        match registry.issue_invite(&session, now) {
            Ok(code) => created(Json::obj([
                ("code", Json::Str(code)),
                (
                    "notice",
                    Json::Str("shown once; the code is stored only as a hash and cannot be recovered".to_string()),
                ),
            ])),
            Err(error) => account_error(error),
        }
    }

    fn list_invites(&self, request: &Request, now: u64) -> Response {
        let Some(token) = self.bearer(request) else {
            return error(Status::FORBIDDEN, "bad_session", "a bearer token is required");
        };
        let registry = self.state();
        let session = match registry.session(&token, now) {
            Ok(session) => session.canonical_gmail.clone(),
            Err(error) => return account_error(error),
        };
        let invites: Vec<Json> = registry
            .invites_of(&session)
            .into_iter()
            .map(|(label, spent, expires_at)| {
                Json::obj([
                    ("redeemed_by", Json::Str(label)),
                    ("spent", Json::Bool(spent)),
                    ("expires_at", Json::Int(expires_at as i128)),
                ])
            })
            .collect();
        ok(Json::obj([("invites", Json::Array(invites))]))
    }

    fn recovery_verify(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(gmail), Some(code)) = (string(&body, "gmail"), string(&body, "recovery_code")) else {
            return error(Status::BAD_REQUEST, "bad_json", "gmail and recovery_code are required");
        };
        match self.state().recover(&gmail, &code, now) {
            Ok(stage) => ok(stage_json(stage)),
            Err(error) => account_error(error),
        }
    }

    fn recovery_mfa(&self, request: &Request, now: u64) -> Response {
        let body = match self.body(request) {
            Ok(body) => body,
            Err(response) => return response,
        };
        let (Some(gmail), Some(password)) = (string(&body, "gmail"), string(&body, "password")) else {
            return error(Status::BAD_REQUEST, "bad_json", "gmail and password are required");
        };
        match self.state().reenrol_mfa(&gmail, &password, now) {
            Ok(uri) => ok(Json::obj([
                ("provisioning_uri", Json::Str(uri)),
                (
                    "notice",
                    Json::Str("shown once; your previous authenticator is no longer valid".to_string()),
                ),
            ])),
            Err(error) => account_error(error),
        }
    }
}

