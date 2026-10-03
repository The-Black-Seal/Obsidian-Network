//! Minimal, strict HTTP/1.1 for Obsidian services.
//!
//! The Obsidian Network ships with **zero third-party dependencies**, so the
//! node RPC endpoint, the public gateway and the static web application are all
//! served by the implementation in this module.  It is deliberately small, and
//! its defaults are deliberately strict:
//!
//! * **Bounded.** Request line, header count, header size and body size are all
//!   capped before anything is allocated for them.
//! * **Explicit.** The only transfer encoding accepted is `Content-Length`;
//!   `Transfer-Encoding: chunked` is refused rather than half-supported.
//! * **Fail closed.** Malformed framing, control characters, invalid
//!   percent-escapes, `%00` and `..` path segments are rejected with a real
//!   status code, never repaired or guessed at.
//!
//! Nothing in this module makes an authority decision: it moves bytes, and the
//! protocol layer decides what they mean.

use core::fmt;
use std::io::{self, Read, Write};
use std::net::TcpStream;

use obs_primitives::json::Json;

/// Maximum size of the request line, including CRLF.
pub const MAX_REQUEST_LINE: usize = 8 * 1024;
/// Maximum number of headers accepted in one request.
pub const MAX_HEADERS: usize = 100;
/// Maximum size of the header block, including CRLF.
pub const MAX_HEADER_BYTES: usize = 32 * 1024;
/// Default maximum body size.
pub const DEFAULT_MAX_BODY: usize = 1024 * 1024;

/// An HTTP method this server understands.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Method {
    /// `GET`
    Get,
    /// `HEAD`
    Head,
    /// `POST`
    Post,
    /// `PUT`
    Put,
    /// `DELETE`
    Delete,
    /// `OPTIONS`
    Options,
}

impl Method {
    /// Parses a method token.
    pub fn parse(token: &str) -> Option<Method> {
        match token {
            "GET" => Some(Method::Get),
            "HEAD" => Some(Method::Head),
            "POST" => Some(Method::Post),
            "PUT" => Some(Method::Put),
            "DELETE" => Some(Method::Delete),
            "OPTIONS" => Some(Method::Options),
            _ => None,
        }
    }

    /// The canonical spelling of the method.
    pub fn as_str(self) -> &'static str {
        match self {
            Method::Get => "GET",
            Method::Head => "HEAD",
            Method::Post => "POST",
            Method::Put => "PUT",
            Method::Delete => "DELETE",
            Method::Options => "OPTIONS",
        }
    }
}

impl fmt::Display for Method {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// A parsed HTTP request.
#[derive(Debug, Clone)]
pub struct Request {
    /// Request method.
    pub method: Method,
    /// Decoded path, always starting with `/`.
    pub path: String,
    /// Raw query string (without the leading `?`).
    pub query: String,
    /// Request headers, lower-cased names.
    pub headers: Vec<(String, String)>,
    /// Request body.
    pub body: Vec<u8>,
    /// Whether the peer asked to keep the connection open.
    pub keep_alive: bool,
    /// The `Host` header, when present.
    pub host: Option<String>,
}

impl Request {
    /// Returns the first value for a header, matched case-insensitively.
    pub fn header(&self, name: &str) -> Option<&str> {
        let name = name.to_ascii_lowercase();
        self.headers
            .iter()
            .find(|(key, _)| *key == name)
            .map(|(_, value)| value.as_str())
    }

    /// Parses the body as JSON.
    pub fn json(&self) -> Result<Json, JsonError> {
        let text = core::str::from_utf8(&self.body).map_err(|_| JsonError::NotUtf8)?;
        obs_primitives::json::parse(text).map_err(|_| JsonError::Malformed)
    }

    /// Decoded query parameters, in order of appearance.
    pub fn query_params(&self) -> Vec<(String, String)> {
        let mut out = Vec::new();
        for pair in self.query.split('&') {
            if pair.is_empty() {
                continue;
            }
            let (key, value) = match pair.split_once('=') {
                Some((key, value)) => (key, value),
                None => (pair, ""),
            };
            if let (Some(key), Some(value)) = (percent_decode(key, false), percent_decode(value, true)) {
                out.push((key, value));
            }
        }
        out
    }

    /// First value of a query parameter.
    pub fn param(&self, name: &str) -> Option<String> {
        self.query_params()
            .into_iter()
            .find(|(key, _)| key == name)
            .map(|(_, value)| value)
    }

    /// True when the request came from the same origin as the service itself.
    ///
    /// Browser cross-site requests carry a different `Origin`, and this is what
    /// lets state-changing endpoints refuse to be driven by another page.
    pub fn same_origin(&self, expected_hosts: &[String]) -> bool {
        match self.header("origin") {
            None => true,
            Some(origin) => {
                let host = match origin.split_once("://") {
                    Some((_, rest)) => rest,
                    None => return false,
                };
                let host = host.trim_end_matches('/');
                expected_hosts.iter().any(|expected| expected == host)
            }
        }
    }

    /// True when the request's `Origin` matches the host this request was
    /// addressed to.
    ///
    /// This is the general form of the same-origin rule, and the one a service
    /// that serves its own pages should use: a browser loading the page from
    /// `http://host:port` sends `Origin: http://host:port` with its fetches, so
    /// comparing the origin against the `Host` header accepts exactly the pages
    /// this service serves — whatever address the operator published it on —
    /// and refuses every other site.  A request with no `Origin` is not a
    /// browser making a cross-site call, and is left to the caller's other
    /// checks.
    pub fn same_origin_as_host(&self) -> bool {
        let Some(origin) = self.header("origin") else {
            return true;
        };
        let Some((_scheme, origin_host)) = origin.split_once("://") else {
            return false;
        };
        let Some(host) = self.host.as_deref() else {
            return false;
        };
        origin_host.trim_end_matches('/').eq_ignore_ascii_case(host)
    }
}

/// Why a body could not be read as JSON.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum JsonError {
    /// The body was not valid UTF-8.
    NotUtf8,
    /// The body was not valid JSON, or exceeded the JSON limits.
    Malformed,
}

/// An HTTP status code with a canonical reason phrase.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
    /// `200 OK`
    pub const OK: Status = Status(200);
    /// `201 Created`
    pub const CREATED: Status = Status(201);
    /// `204 No Content`
    pub const NO_CONTENT: Status = Status(204);
    /// `400 Bad Request`
    pub const BAD_REQUEST: Status = Status(400);
    /// `403 Forbidden`
    pub const FORBIDDEN: Status = Status(403);
    /// `404 Not Found`
    pub const NOT_FOUND: Status = Status(404);
    /// `405 Method Not Allowed`
    pub const METHOD_NOT_ALLOWED: Status = Status(405);
    /// `408 Request Timeout`
    pub const REQUEST_TIMEOUT: Status = Status(408);
    /// `409 Conflict`
    pub const CONFLICT: Status = Status(409);
    /// `413 Payload Too Large`
    pub const PAYLOAD_TOO_LARGE: Status = Status(413);
    /// `415 Unsupported Media Type`
    pub const UNSUPPORTED_MEDIA_TYPE: Status = Status(415);
    /// `422 Unprocessable Entity`
    pub const UNPROCESSABLE_ENTITY: Status = Status(422);
    /// `429 Too Many Requests`
    pub const TOO_MANY_REQUESTS: Status = Status(429);
    /// `500 Internal Server Error`
    pub const INTERNAL: Status = Status(500);
    /// `501 Not Implemented`
    pub const NOT_IMPLEMENTED: Status = Status(501);
    /// `503 Service Unavailable`
    pub const UNAVAILABLE: Status = Status(503);

    /// The three-digit code.
    pub fn code(self) -> u16 {
        self.0
    }

    /// The canonical reason phrase.
    pub fn reason(self) -> &'static str {
        match self.0 {
            200 => "OK",
            201 => "Created",
            204 => "No Content",
            304 => "Not Modified",
            400 => "Bad Request",
            401 => "Unauthorized",
            403 => "Forbidden",
            404 => "Not Found",
            405 => "Method Not Allowed",
            408 => "Request Timeout",
            409 => "Conflict",
            413 => "Payload Too Large",
            415 => "Unsupported Media Type",
            422 => "Unprocessable Entity",
            429 => "Too Many Requests",
            500 => "Internal Server Error",
            501 => "Not Implemented",
            503 => "Service Unavailable",
            _ => "Unknown",
        }
    }
}

/// An HTTP response.
#[derive(Debug, Clone)]
pub struct Response {
    /// Status code.
    pub status: Status,
    /// Response headers, in the order they will be written.
    pub headers: Vec<(String, String)>,
    /// Response body.
    pub body: Vec<u8>,
}

impl Response {
    /// An empty response with the given status.
    pub fn new(status: Status) -> Response {
        Response {
            status,
            headers: Vec::new(),
            body: Vec::new(),
        }
    }

    /// A `text/plain` response.
    pub fn text(status: Status, body: impl Into<String>) -> Response {
        let body = body.into().into_bytes();
        let mut response = Response::new(status);
        response
            .headers
            .push(("Content-Type".to_string(), "text/plain; charset=utf-8".to_string()));
        response.body = body;
        response
    }

    /// A JSON response.
    pub fn json(status: Status, value: &Json) -> Response {
        let body = value.to_string().into_bytes();
        let mut response = Response::new(status);
        response.headers.push((
            "Content-Type".to_string(),
            "application/json; charset=utf-8".to_string(),
        ));
        response.body = body;
        response
    }

    /// A JSON error body of the shape `{"error": {...}}`.
    ///
    /// Every API error carries a machine-readable `code` and a human `message`;
    /// no internal detail is ever echoed back to the caller.
    pub fn error(status: Status, code: &str, message: &str) -> Response {
        let value = Json::obj([
            (
                "error",
                Json::obj([
                    ("code", Json::Str(code.to_string())),
                    ("message", Json::Str(message.to_string())),
                    ("status", Json::Int(status.code() as i128)),
                ]),
            ),
            ("ok", Json::Bool(false)),
        ]);
        Response::json(status, &value).no_store()
    }

    /// Returns the first value for a header, matched case-insensitively.
    pub fn header_value(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    /// Adds a header.
    pub fn header(mut self, name: &str, value: impl Into<String>) -> Response {
        self.headers.push((name.to_string(), value.into()));
        self
    }

    /// Marks the response as uncacheable, as every authenticated API response
    /// must be.
    pub fn no_store(mut self) -> Response {
        self.headers
            .push(("Cache-Control".to_string(), "no-store".to_string()));
        self
    }

    /// Adds the hardening headers used by the browser-facing responses.
    pub fn hardened(mut self) -> Response {
        for (name, value) in [
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer"),
            ("X-Frame-Options", "DENY"),
        ] {
            self.headers.push((name.to_string(), value.to_string()));
        }
        self
    }

    /// Serialises the response head.
    pub fn head_bytes(&self, keep_alive: bool, include_body: bool) -> Vec<u8> {
        let mut out = Vec::with_capacity(256 + self.body.len());
        out.extend_from_slice(
            format!("HTTP/1.1 {} {}\r\n", self.status.code(), self.status.reason()).as_bytes(),
        );
        let mut has_length = false;
        for (name, value) in &self.headers {
            if name.eq_ignore_ascii_case("content-length") {
                has_length = true;
            }
            out.extend_from_slice(name.as_bytes());
            out.extend_from_slice(b": ");
            out.extend_from_slice(value.as_bytes());
            out.extend_from_slice(b"\r\n");
        }
        if !has_length {
            // A HEAD response advertises the length the equivalent GET would
            // have sent; only the body bytes are omitted.
            out.extend_from_slice(format!("Content-Length: {}\r\n", self.body.len()).as_bytes());
        }
        out.extend_from_slice(
            format!(
                "Connection: {}\r\n",
                if keep_alive { "keep-alive" } else { "close" }
            )
            .as_bytes(),
        );
        out.extend_from_slice(b"\r\n");
        if include_body {
            out.extend_from_slice(&self.body);
        }
        out
    }
}

/// A request that could not be parsed, with the status that should be returned.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpError {
    /// Status to return to the caller.
    pub status: Status,
    /// Machine-readable reason.
    pub code: &'static str,
}

impl HttpError {
    /// Builds an error.
    pub const fn new(status: Status, code: &'static str) -> HttpError {
        HttpError { status, code }
    }

    /// Converts the error into a response.
    pub fn into_response(self) -> Response {
        Response::error(self.status, self.code, self.code.replace('_', " ").as_str()).hardened()
    }
}

/// The result of trying to parse one request from a buffer.
#[derive(Debug)]
pub enum Parsed {
    /// More bytes are needed.
    Incomplete,
    /// A complete request and the number of bytes it consumed.
    Complete(Request, usize),
    /// The request was rejected.
    Invalid(HttpError),
}

/// Incremental request parser.
#[derive(Debug, Default)]
pub struct Parser {
    max_body: Option<usize>,
}

impl Parser {
    /// Creates a parser with the default body limit.
    pub fn new() -> Parser {
        Parser { max_body: None }
    }

    /// Overrides the maximum body size.
    pub fn with_max_body(mut self, max_body: usize) -> Parser {
        self.max_body = Some(max_body);
        self
    }

    /// The maximum body size this parser accepts.
    pub fn max_body(&self) -> usize {
        self.max_body.unwrap_or(DEFAULT_MAX_BODY)
    }

    /// Attempts to parse a request from `input`.
    pub fn parse(&self, input: &[u8]) -> Parsed {
        let max_body = self.max_body.unwrap_or(DEFAULT_MAX_BODY);
        let head_end = match find_head_end(input) {
            Some(index) => index,
            None => {
                if input.len() > MAX_HEADER_BYTES + MAX_REQUEST_LINE {
                    return Parsed::Invalid(HttpError::new(Status::PAYLOAD_TOO_LARGE, "headers_too_large"));
                }
                return Parsed::Incomplete;
            }
        };
        let head = &input[..head_end];
        let text = match core::str::from_utf8(head) {
            Ok(text) => text,
            Err(_) => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "invalid_utf8")),
        };
        let mut lines = text.split("\r\n");
        let request_line = match lines.next() {
            Some(line) => line,
            None => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "empty_request")),
        };
        if request_line.len() > MAX_REQUEST_LINE {
            return Parsed::Invalid(HttpError::new(Status::PAYLOAD_TOO_LARGE, "request_line_too_long"));
        }
        let mut parts = request_line.split(' ');
        let (method_token, target, version) = match (parts.next(), parts.next(), parts.next()) {
            (Some(m), Some(t), Some(v)) => (m, t, v),
            _ => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "malformed_request_line")),
        };
        if parts.next().is_some() {
            return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "malformed_request_line"));
        }
        let method = match Method::parse(method_token) {
            Some(method) => method,
            None => {
                return Parsed::Invalid(HttpError::new(Status::METHOD_NOT_ALLOWED, "unknown_method"))
            }
        };
        let keep_alive = match version {
            "HTTP/1.1" => true,
            "HTTP/1.0" => false,
            _ => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "unsupported_version")),
        };

        // Origin-form or absolute-form only; anything else is a proxy request
        // this server is not allowed to make on the caller's behalf.
        let (path_and_query, absolute_host) = if let Some(rest) = target.strip_prefix("http://") {
            match rest.split_once('/') {
                Some((host, path)) => (format!("/{}", path), Some(host.to_string())),
                None => (String::from("/"), Some(rest.to_string())),
            }
        } else if let Some(rest) = target.strip_prefix("https://") {
            match rest.split_once('/') {
                Some((host, path)) => (format!("/{}", path), Some(host.to_string())),
                None => (String::from("/"), Some(rest.to_string())),
            }
        } else if target.starts_with('/') {
            (target.to_string(), None)
        } else {
            return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_target"));
        };
        let (raw_path, query) = match path_and_query.split_once('?') {
            Some((path, query)) => (path.to_string(), query.to_string()),
            None => (path_and_query.clone(), String::new()),
        };
        let path = match percent_decode(&raw_path, false) {
            Some(path) => path,
            None => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_path_encoding")),
        };
        if path.contains('\0') || path.contains("..") || !path.starts_with('/') {
            return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_path"));
        }
        if query.len() > MAX_REQUEST_LINE {
            return Parsed::Invalid(HttpError::new(Status::PAYLOAD_TOO_LARGE, "query_too_long"));
        }

        let mut headers: Vec<(String, String)> = Vec::new();
        for line in lines {
            if line.is_empty() {
                continue;
            }
            if line.starts_with(' ') || line.starts_with('\t') {
                // Obsolete line folding: refused, because different
                // intermediaries disagree about what it means.
                return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "folded_header"));
            }
            let (raw_name, value) = match line.split_once(':') {
                Some((name, value)) => (name, value.trim()),
                None => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "malformed_header")),
            };
            // RFC 9110: no whitespace is permitted between the field name and
            // the colon.  Accepting it would mean two parsers could disagree
            // about the same request, so it is refused.
            let name = raw_name;
            if name.is_empty() || name.trim_end() != name || !name.bytes().all(is_token_byte) {
                return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_header_name"));
            }
            if value.bytes().any(|b| b == 0 || b == b'\r' || b == b'\n') {
                return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_header_value"));
            }
            if headers.len() >= MAX_HEADERS {
                return Parsed::Invalid(HttpError::new(Status::PAYLOAD_TOO_LARGE, "too_many_headers"));
            }
            headers.push((name.to_ascii_lowercase(), value.to_string()));
        }

        let host = headers
            .iter()
            .find(|(name, _)| name == "host")
            .map(|(_, value)| value.clone())
            .or(absolute_host);
        if version == "HTTP/1.1" && host.is_none() {
            return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "missing_host"));
        }
        if headers
            .iter()
            .any(|(name, _)| name == "transfer-encoding")
        {
            return Parsed::Invalid(HttpError::new(Status::NOT_IMPLEMENTED, "chunked_unsupported"));
        }
        let content_length = match headers
            .iter()
            .find(|(name, _)| name == "content-length")
            .map(|(_, value)| value.as_str())
        {
            Some(value) => match value.parse::<usize>() {
                Ok(length) => length,
                Err(_) => return Parsed::Invalid(HttpError::new(Status::BAD_REQUEST, "bad_content_length")),
            },
            None => 0,
        };
        if content_length > max_body {
            return Parsed::Invalid(HttpError::new(Status::PAYLOAD_TOO_LARGE, "body_too_large"));
        }
        let total = head_end + 4 + content_length;
        if input.len() < total {
            return Parsed::Incomplete;
        }
        let body = input[head_end + 4..total].to_vec();
        let keep_alive = keep_alive
            && !headers
                .iter()
                .any(|(name, value)| name == "connection" && value.eq_ignore_ascii_case("close"));
        Parsed::Complete(
            Request {
                method,
                path,
                query,
                headers,
                body,
                keep_alive,
                host,
            },
            total,
        )
    }
}

fn find_head_end(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

fn is_token_byte(byte: u8) -> bool {
    byte.is_ascii_alphanumeric()
        || matches!(
            byte,
            b'!' | b'#'
                | b'$'
                | b'%'
                | b'&'
                | b'\''
                | b'*'
                | b'+'
                | b'-'
                | b'.'
                | b'^'
                | b'_'
                | b'`'
                | b'|'
                | b'~'
        )
}

/// Percent-decodes a URL component.
///
/// `plus_as_space` is only true for query values, where `+` traditionally means
/// a space.  Invalid escapes, `%00` and bytes that decode to control characters
/// are refused.
pub fn percent_decode(input: &str, plus_as_space: bool) -> Option<String> {
    let bytes = input.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'%' => {
                if index + 2 >= bytes.len() {
                    return None;
                }
                let high = hex_value(bytes[index + 1])?;
                let low = hex_value(bytes[index + 2])?;
                let byte = (high << 4) | low;
                if byte == 0 || byte < 0x20 || byte == 0x7f {
                    return None;
                }
                out.push(byte);
                index += 3;
            }
            b'+' if plus_as_space => {
                out.push(b' ');
                index += 1;
            }
            byte if byte < 0x20 || byte == 0x7f => return None,
            byte => {
                out.push(byte);
                index += 1;
            }
        }
    }
    String::from_utf8(out).ok()
}

fn hex_value(byte: u8) -> Option<u8> {
    match byte {
        b'0'..=b'9' => Some(byte - b'0'),
        b'a'..=b'f' => Some(byte - b'a' + 10),
        b'A'..=b'F' => Some(byte - b'A' + 10),
        _ => None,
    }
}

/// Percent-encodes a path segment.
pub fn percent_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        let keep = byte.is_ascii_alphanumeric()
            || matches!(byte, b'-' | b'_' | b'.' | b'~' | b'/' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')' | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@');
        if keep {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{:02X}", byte));
        }
    }
    out
}

/// Reads one request, keeping any pipelined bytes in `buffer`.
///
/// `buffer` must be preserved between calls on the same connection: HTTP/1.1
/// clients are allowed to pipeline, and silently dropping the bytes that follow
/// the first request would corrupt the connection.
pub fn read_request(
    reader: &mut impl Read,
    buffer: &mut Vec<u8>,
    parser: &Parser,
) -> io::Result<Result<Request, HttpError>> {
    loop {
        match parser.parse(buffer) {
            Parsed::Complete(request, consumed) => {
                buffer.drain(..consumed);
                return Ok(Ok(request));
            }
            Parsed::Invalid(error) => {
                buffer.clear();
                return Ok(Err(error));
            }
            Parsed::Incomplete => {
                let ceiling = MAX_HEADER_BYTES + MAX_REQUEST_LINE + parser.max_body();
                if buffer.len() > ceiling {
                    buffer.clear();
                    return Ok(Err(HttpError::new(
                        Status::PAYLOAD_TOO_LARGE,
                        "request_too_large",
                    )));
                }
                let mut chunk = [0u8; 4096];
                let read = reader.read(&mut chunk)?;
                if read == 0 {
                    if buffer.is_empty() {
                        return Err(io::Error::new(
                            io::ErrorKind::UnexpectedEof,
                            "peer closed the connection",
                        ));
                    }
                    buffer.clear();
                    return Ok(Err(HttpError::new(Status::BAD_REQUEST, "truncated_request")));
                }
                buffer.extend_from_slice(&chunk[..read]);
            }
        }
    }
}

/// Writes a response to a stream.
pub fn write_response(
    stream: &mut TcpStream,
    response: &Response,
    keep_alive: bool,
    include_body: bool,
) -> io::Result<()> {
    let bytes = response.head_bytes(keep_alive, include_body);
    stream.write_all(&bytes)?;
    stream.flush()
}

/// Formats a Unix timestamp as an IMF-fixdate, the only format HTTP permits.
pub fn http_date(unix_secs: u64) -> String {
    let days = (unix_secs / 86_400) as i64;
    let seconds_of_day = unix_secs % 86_400;
    let (year, month, day) = civil_from_days(days);
    let weekday = weekday_from_days(days);
    format!(
        "{}, {:02} {} {} {:02}:{:02}:{:02} GMT",
        weekday,
        day,
        MONTHS[month as usize - 1],
        year,
        seconds_of_day / 3_600,
        (seconds_of_day % 3_600) / 60,
        seconds_of_day % 60
    )
}

const MONTHS: [&str; 12] = [
    "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
];

/// Howard Hinnant's civil-from-days algorithm (proleptic Gregorian).
fn civil_from_days(days: i64) -> (i64, u32, u32) {
    let z = days + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let year = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let month = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if month <= 2 { year + 1 } else { year }, month, day)
}

fn weekday_from_days(days: i64) -> &'static str {
    const NAMES: [&str; 7] = ["Thu", "Fri", "Sat", "Sun", "Mon", "Tue", "Wed"];
    NAMES[(days.rem_euclid(7)) as usize]
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(input: &str) -> Parsed {
        Parser::new().parse(input.as_bytes())
    }

    #[test]
    fn a_simple_request_is_parsed() {
        let request = "GET /api/v1/status?verbose=1 HTTP/1.1\r\nHost: node.local:8080\r\nAccept: */*\r\n\r\n";
        match parse(request) {
            Parsed::Complete(request, consumed) => {
                assert_eq!(consumed, request_bytes_len());
                assert_eq!(request.method, Method::Get);
                assert_eq!(request.path, "/api/v1/status");
                assert_eq!(request.param("verbose").as_deref(), Some("1"));
                assert_eq!(request.host.as_deref(), Some("node.local:8080"));
                assert!(request.keep_alive);
                assert!(request.body.is_empty());
            }
            other => panic!("expected a parsed request, got {:?}", other),
        }
        fn request_bytes_len() -> usize {
            "GET /api/v1/status?verbose=1 HTTP/1.1\r\nHost: node.local:8080\r\nAccept: */*\r\n\r\n".len()
        }
    }

    #[test]
    fn a_request_with_a_body_is_parsed_and_trailing_bytes_are_left_alone() {
        let raw = "POST /tx HTTP/1.1\r\nHost: node\r\nContent-Length: 5\r\n\r\nhelloGET /x HTTP/1.1\r\nHost: node\r\n\r\n";
        match Parser::new().parse(raw.as_bytes()) {
            Parsed::Complete(request, consumed) => {
                assert_eq!(request.body, b"hello");
                assert_eq!(consumed, raw.len() - "GET /x HTTP/1.1\r\nHost: node\r\n\r\n".len());
                match Parser::new().parse(&raw.as_bytes()[consumed..]) {
                    Parsed::Complete(next, _) => assert_eq!(next.path, "/x"),
                    other => panic!("expected the pipelined request, got {:?}", other),
                }
            }
            other => panic!("expected a parsed request, got {:?}", other),
        }
    }

    #[test]
    fn the_same_origin_rule_compares_the_origin_with_the_host() {
        let sent = |origin: &str| {
            let raw = format!(
                "POST /v1/portal/keys HTTP/1.1\r\nHost: explorer.obsidian.network\r\nOrigin: {}\r\n\r\n",
                origin
            );
            match parse(&raw) {
                Parsed::Complete(request, _) => request,
                other => panic!("expected a parsed request, got {:?}", other),
            }
        };
        // The service's own page: accepted, whatever address it was published on.
        assert!(sent("http://explorer.obsidian.network").same_origin_as_host());
        assert!(sent("https://explorer.obsidian.network").same_origin_as_host());
        // A different site, a look-alike host, a missing scheme and an empty
        // host are all refused.
        assert!(!sent("https://evil.example").same_origin_as_host());
        assert!(!sent("https://explorer.obsidian.network.evil.example").same_origin_as_host());
        assert!(!sent("explorer.obsidian.network").same_origin_as_host());
        assert!(!sent("").same_origin_as_host());
        // A request without an Origin is not a browser cross-site call.
        let raw = "GET /v1/explorer/status HTTP/1.1\r\nHost: explorer.obsidian.network\r\n\r\n";
        match parse(raw) {
            Parsed::Complete(request, _) => assert!(request.same_origin_as_host()),
            other => panic!("expected a parsed request, got {:?}", other),
        }
        // And the explicit-list form still works for deployments behind a proxy.
        assert!(sent("https://explorer.obsidian.network")
            .same_origin(&["explorer.obsidian.network".to_string()]));
    }

    #[test]
    fn incomplete_input_asks_for_more_bytes() {
        assert!(matches!(parse("GET / HTTP/1.1\r\nHost: n\r\n"), Parsed::Incomplete));
        assert!(matches!(
            parse("POST / HTTP/1.1\r\nHost: n\r\nContent-Length: 10\r\n\r\nabc"),
            Parsed::Incomplete
        ));
    }

    #[test]
    fn malformed_requests_are_rejected() {
        for (raw, code) in [
            ("GET / HTTP/2.0\r\nHost: n\r\n\r\n", "unsupported_version"),
            ("GET / HTTP/1.1\r\n\r\n", "missing_host"),
            ("BREW / HTTP/1.1\r\nHost: n\r\n\r\n", "unknown_method"),
            ("GET /a/../b HTTP/1.1\r\nHost: n\r\n\r\n", "bad_path"),
            ("GET /a%00b HTTP/1.1\r\nHost: n\r\n\r\n", "bad_path_encoding"),
            ("GET /\r\nHost: n\r\n\r\n", "malformed_request_line"),
            (
                "POST / HTTP/1.1\r\nHost: n\r\nTransfer-Encoding: chunked\r\n\r\n",
                "chunked_unsupported",
            ),
            (
                "POST / HTTP/1.1\r\nHost: n\r\nContent-Length: nope\r\n\r\n",
                "bad_content_length",
            ),
            (
                "GET / HTTP/1.1\r\nHost: n\r\nContent-Length: 99999999\r\n\r\n",
                "body_too_large",
            ),
            ("GET / HTTP/1.1\r\nHost : n\r\n\r\n", "bad_header_name"),
            ("GET / HTTP/1.1\r\nHost:n\r\nBad Name: x\r\n\r\n", "bad_header_name"),
            ("GET / HTTP/1.1\r\nHost: n\r\nBad Header: x\r\n\r\n", "bad_header_name"),
        ] {
            match parse(raw) {
                Parsed::Invalid(error) => {
                    assert_eq!(error.code, code, "for input {:?}", raw);
                    assert!(error.status.code() >= 400);
                }
                other => panic!("expected a rejection for {:?}, got {:?}", raw, other),
            }
        }
    }

    #[test]
    fn response_framing_is_exact() {
        let response = Response::json(Status::OK, &Json::obj([("ok", Json::Bool(true))]));
        let bytes = response.head_bytes(true, true);
        let text = String::from_utf8(bytes).unwrap();
        assert!(text.starts_with("HTTP/1.1 200 OK\r\n"));
        assert!(text.contains("Content-Type: application/json; charset=utf-8\r\n"));
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.contains("Connection: keep-alive\r\n"));
        assert!(text.ends_with("\r\n\r\n{\"ok\":true}"));

        // A HEAD response advertises the length it would have sent.
        let head = response.head_bytes(false, false);
        let text = String::from_utf8(head).unwrap();
        assert!(text.contains("Content-Length: 11\r\n"));
        assert!(text.ends_with("\r\n\r\n"));
    }

    #[test]
    fn errors_are_machine_readable_and_do_not_leak_internals() {
        let response = HttpError::new(Status::BAD_REQUEST, "bad_request").into_response();
        let body = String::from_utf8(response.body.clone()).unwrap();
        assert!(body.contains("\"code\":\"bad_request\""));
        assert!(body.contains("\"status\":400"));
        assert!(response
            .headers
            .iter()
            .any(|(name, value)| name == "Cache-Control" && value == "no-store"));
    }

    #[test]
    fn percent_decoding_is_strict() {
        assert_eq!(percent_decode("a%20b", false).as_deref(), Some("a b"));
        assert_eq!(percent_decode("a+b", true).as_deref(), Some("a b"));
        assert_eq!(percent_decode("a+b", false).as_deref(), Some("a+b"));
        assert!(percent_decode("a%2", false).is_none());
        assert!(percent_decode("a%zz", false).is_none());
        assert!(percent_decode("a%00", false).is_none());
        assert!(percent_decode("a%0A", false).is_none());
        assert_eq!(percent_encode("/a b"), "/a%20b");
        assert_eq!(percent_encode("obs1abc"), "obs1abc");
    }

    #[test]
    fn http_dates_match_the_specification() {
        assert_eq!(http_date(0), "Thu, 01 Jan 1970 00:00:00 GMT");
        assert_eq!(http_date(1_700_000_000), "Tue, 14 Nov 2023 22:13:20 GMT");
        assert_eq!(http_date(1_718_000_000), "Mon, 10 Jun 2024 06:13:20 GMT");
        assert_eq!(http_date(951_782_400), "Tue, 29 Feb 2000 00:00:00 GMT");
    }

    #[test]
    fn same_origin_only_accepts_the_service_host() {
        let request = "POST /x HTTP/1.1\r\nHost: node.local\r\nOrigin: https://evil.example\r\n\r\n";
        match parse(request) {
            Parsed::Complete(request, _) => {
                assert!(!request.same_origin(&["node.local".to_string()]));
                assert!(request.same_origin(&["evil.example".to_string()]));
            }
            other => panic!("expected a parsed request, got {:?}", other),
        }
        let request = "POST /x HTTP/1.1\r\nHost: node.local\r\n\r\n";
        match parse(request) {
            Parsed::Complete(request, _) => assert!(request.same_origin(&[])),
            other => panic!("expected a parsed request, got {:?}", other),
        }
    }
}
