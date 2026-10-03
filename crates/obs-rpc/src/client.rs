//! A small blocking HTTP client.
//!
//! Used by the operator CLI, by the acceptance tests and by the node when it
//! talks to a peer's RPC port.  It speaks exactly the subset of HTTP/1.1 the
//! server in this crate produces: `Content-Length` framing, no chunking.

use std::io::{BufReader, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use obs_primitives::json::Json;

use crate::http::{Method, Response, Status};

/// Client-side failures.
#[derive(Debug)]
pub enum ClientError {
    /// The URL could not be understood.
    BadUrl(String),
    /// The connection failed.
    Io(String),
    /// The response was malformed.
    Protocol(String),
}

impl core::fmt::Display for ClientError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            ClientError::BadUrl(url) => write!(f, "unsupported url: {}", url),
            ClientError::Io(detail) => write!(f, "connection failed: {}", detail),
            ClientError::Protocol(detail) => write!(f, "malformed response: {}", detail),
        }
    }
}

impl std::error::Error for ClientError {}

/// A blocking HTTP client with a fixed timeout.
#[derive(Debug, Clone)]
pub struct Client {
    timeout: Duration,
    /// Extra headers sent with every request (for example `Authorization`).
    pub default_headers: Vec<(String, String)>,
}

impl Default for Client {
    fn default() -> Self {
        Client {
            timeout: Duration::from_secs(15),
            default_headers: Vec::new(),
        }
    }
}

impl Client {
    /// A client with the given timeout.
    pub fn with_timeout(timeout: Duration) -> Client {
        Client {
            timeout,
            default_headers: Vec::new(),
        }
    }

    /// Adds a header sent with every request.
    pub fn with_header(mut self, name: &str, value: impl Into<String>) -> Client {
        self.default_headers.push((name.to_string(), value.into()));
        self
    }

    /// Sends a GET request.
    pub fn get(&self, url: &str) -> Result<Response, ClientError> {
        self.send(Method::Get, url, None, None)
    }

    /// Sends a POST request with a JSON body.
    pub fn post_json(&self, url: &str, body: &Json) -> Result<Response, ClientError> {
        self.send(Method::Post, url, Some(body), None)
    }

    /// Sends a POST request with a raw body.
    pub fn post_raw(
        &self,
        url: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<Response, ClientError> {
        self.send_raw(Method::Post, url, body, content_type)
    }

    /// Sends a DELETE request.
    pub fn delete(&self, url: &str) -> Result<Response, ClientError> {
        self.send(Method::Delete, url, None, None)
    }

    /// Sends a request and returns the parsed response.
    pub fn send(
        &self,
        method: Method,
        url: &str,
        body: Option<&Json>,
        bearer: Option<&str>,
    ) -> Result<Response, ClientError> {
        let (raw, content_type) = match body {
            Some(value) => (value.to_string().into_bytes(), "application/json"),
            None => (Vec::new(), "application/octet-stream"),
        };
        let mut client = self.clone();
        if let Some(token) = bearer {
            client
                .default_headers
                .push(("Authorization".to_string(), format!("Bearer {}", token)));
        }
        client.send_raw(method, url, raw, content_type)
    }

    /// Sends a request with a raw body.
    pub fn send_raw(
        &self,
        method: Method,
        url: &str,
        body: Vec<u8>,
        content_type: &str,
    ) -> Result<Response, ClientError> {
        let rest = match url.strip_prefix("http://") {
            Some(rest) => rest,
            None => return Err(ClientError::BadUrl(url.to_string())),
        };
        let (authority, path_and_query) = match rest.split_once('/') {
            Some((authority, path)) => (authority, format!("/{}", path)),
            None => (rest, String::from("/")),
        };
        let address = if authority.contains(':') {
            authority.to_string()
        } else {
            format!("{}:80", authority)
        };
        let mut addresses = address
            .to_socket_addrs()
            .map_err(|error| ClientError::BadUrl(format!("{}: {}", url, error)))?;
        let socket = addresses
            .next()
            .ok_or_else(|| ClientError::BadUrl(format!("{}: no address", url)))?;

        let mut stream = TcpStream::connect_timeout(&socket, self.timeout)
            .map_err(|error| ClientError::Io(error.to_string()))?;
        stream.set_read_timeout(Some(self.timeout)).ok();
        stream.set_write_timeout(Some(self.timeout)).ok();

        let mut head = format!(
            "{} {} HTTP/1.1\r\nHost: {}\r\nUser-Agent: obsidian-client/1.0\r\nAccept: application/json\r\nConnection: close\r\nContent-Length: {}\r\n",
            method.as_str(),
            path_and_query,
            authority,
            body.len()
        );
        if !body.is_empty() {
            head.push_str(&format!("Content-Type: {}\r\n", content_type));
        }
        for (name, value) in &self.default_headers {
            head.push_str(&format!("{}: {}\r\n", name, value));
        }
        head.push_str("\r\n");
        stream
            .write_all(head.as_bytes())
            .and_then(|_| stream.write_all(&body))
            .map_err(|error| ClientError::Io(error.to_string()))?;
        stream.flush().ok();

        let mut raw = Vec::new();
        let mut reader = BufReader::new(stream);
        reader
            .read_to_end(&mut raw)
            .map_err(|error| ClientError::Io(error.to_string()))?;
        parse_response(&raw)
    }
}

/// Parses a complete HTTP response from bytes.
pub fn parse_response(raw: &[u8]) -> Result<Response, ClientError> {
    let head_end = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or_else(|| ClientError::Protocol("no header terminator".to_string()))?;
    let head = core::str::from_utf8(&raw[..head_end])
        .map_err(|_| ClientError::Protocol("non-utf8 header".to_string()))?;
    let mut lines = head.split("\r\n");
    let status_line = lines
        .next()
        .ok_or_else(|| ClientError::Protocol("empty response".to_string()))?;
    let mut parts = status_line.split(' ');
    let version = parts.next().unwrap_or_default();
    if !version.starts_with("HTTP/1.") {
        return Err(ClientError::Protocol(format!("bad status line {:?}", status_line)));
    }
    let code = parts
        .next()
        .and_then(|code| code.parse::<u16>().ok())
        .ok_or_else(|| ClientError::Protocol(format!("bad status line {:?}", status_line)))?;
    let mut headers = Vec::new();
    for line in lines {
        let (name, value) = line
            .split_once(':')
            .ok_or_else(|| ClientError::Protocol(format!("bad header {:?}", line)))?;
        headers.push((name.trim().to_string(), value.trim().to_string()));
    }
    let body = raw[head_end + 4..].to_vec();
    Ok(Response {
        status: Status(code),
        headers,
        body,
    })
}

/// Parses a JSON body, mapping failures to a client error.
pub fn json_body(response: &Response) -> Result<Json, ClientError> {
    let text = core::str::from_utf8(&response.body)
        .map_err(|_| ClientError::Protocol("non-utf8 body".to_string()))?;
    obs_primitives::json::parse(text).map_err(|error| ClientError::Protocol(format!("{:?}", error)))
}

/// Parses a URL into `(host, port, path)`.
pub fn split_url(url: &str) -> Result<(String, u16, String), ClientError> {
    let rest = url
        .strip_prefix("http://")
        .ok_or_else(|| ClientError::BadUrl(url.to_string()))?;
    let (authority, path) = match rest.split_once('/') {
        Some((authority, path)) => (authority, format!("/{}", path)),
        None => (rest, String::from("/")),
    };
    match authority.rsplit_once(':') {
        Some((host, port)) => {
            let port = port
                .parse::<u16>()
                .map_err(|_| ClientError::BadUrl(url.to_string()))?;
            Ok((host.to_string(), port, path))
        }
        None => Ok((authority.to_string(), 80, path)),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Request;
    use crate::server::{Handler, Server, ServerConfig};
    use std::sync::atomic::AtomicBool;
    use std::sync::Arc;

    #[test]
    fn urls_are_split_into_host_port_and_path() {
        assert_eq!(
            split_url("http://node.local:8080/api/v1/status").unwrap(),
            ("node.local".to_string(), 8080, "/api/v1/status".to_string())
        );
        assert_eq!(
            split_url("http://node.local").unwrap(),
            ("node.local".to_string(), 80, "/".to_string())
        );
        assert!(split_url("https://node.local").is_err());
    }

    #[test]
    fn responses_are_parsed_and_errors_are_reported() {
        let raw = b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n\r\n{}";
        let response = parse_response(raw).unwrap();
        assert_eq!(response.status, Status::OK);
        assert_eq!(response.header_value("content-type"), Some("application/json"));
        assert_eq!(response.body, b"{}");
        assert!(parse_response(b"nonsense").is_err());
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nbroken\r\n\r\n").is_err());
    }

    #[test]
    fn a_real_request_round_trips() {
        struct Echo;
        impl Handler for Echo {
            fn handle(&self, request: &Request, _peer: &Peer) -> Response {
                let value = Json::obj([
                    ("method", Json::Str(request.method.to_string())),
                    ("path", Json::Str(request.path.clone())),
                    (
                        "id",
                        Json::Str(request.param("id").unwrap_or_else(|| "none".to_string())),
                    ),
                    ("echo", request.json().unwrap_or(Json::Null)),
                ]);
                Response::json(Status::OK, &value).no_store()
            }
        }
        use crate::server::Peer;

        let server = Server::bind("127.0.0.1:0", ServerConfig::default()).unwrap();
        let addr = server.local_addr();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = server.spawn(Arc::new(Echo), Arc::clone(&shutdown));
        let url = format!("http://{}/api/v1/echo?id=7", addr);

        let client = Client::default();
        let response = client
            .post_json(&url, &Json::obj([("hello", Json::Str("world".to_string()))]))
            .unwrap();
        assert_eq!(response.status, Status::OK);
        let body = json_body(&response).unwrap();
        assert_eq!(body.get("method").and_then(Json::as_str), Some("POST"));
        assert_eq!(body.get("id").and_then(Json::as_str), Some("7"));
        assert_eq!(
            body.get("echo")
                .and_then(|echo| echo.get("hello"))
                .and_then(Json::as_str),
            Some("world")
        );

        shutdown.store(true, std::sync::atomic::Ordering::Relaxed);
        handle.join().unwrap().unwrap();
    }
}
