//! The Obsidian HTTP server: bounded connections, strict parsing, static files.
//!
//! ```no_run
//! use std::sync::Arc;
//! use std::sync::atomic::AtomicBool;
//! use obs_rpc::server::{Handler, Peer, Server, ServerConfig};
//! use obs_rpc::http::{Request, Response, Status};
//!
//! struct Status200;
//! impl Handler for Status200 {
//!     fn handle(&self, _request: &Request, _peer: &Peer) -> Response {
//!         Response::text(Status::OK, "ok")
//!     }
//! }
//!
//! let server = Server::bind("127.0.0.1:0", ServerConfig::default()).unwrap();
//! let shutdown = Arc::new(AtomicBool::new(false));
//! server.spawn(Arc::new(Status200), shutdown);
//! ```

use std::collections::HashMap;
use std::io::{self, BufReader};
use std::net::{SocketAddr, TcpListener, TcpStream, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Arc;
use std::thread::{self, JoinHandle};
use std::time::Duration;

use crate::http::{read_request, write_response, Parser, Request, Response, Status};

/// Connection and request limits.
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// Largest number of simultaneous connections.
    pub max_connections: usize,
    /// How long a client may stay silent between requests.
    pub idle_timeout: Duration,
    /// Largest request body accepted.
    pub max_body: usize,
    /// Maximum requests served on one keep-alive connection.
    pub max_requests_per_connection: usize,
    /// Requests larger than this are refused before parsing.
    pub max_request_bytes: usize,
}

impl Default for ServerConfig {
    fn default() -> Self {
        ServerConfig {
            max_connections: 128,
            idle_timeout: Duration::from_secs(20),
            max_body: 1024 * 1024,
            max_requests_per_connection: 128,
            max_request_bytes: 2 * 1024 * 1024,
        }
    }
}

/// Information about the client a request came from.
#[derive(Debug, Clone)]
pub struct Peer {
    /// Remote address.
    pub addr: SocketAddr,
    /// Local address the request was accepted on.
    pub local: SocketAddr,
}

/// The application behind the HTTP server.
pub trait Handler: Send + Sync + 'static {
    /// Produces a response for a request.  Implementations must be pure with
    /// respect to concurrency: several threads call this at the same time.
    fn handle(&self, request: &Request, peer: &Peer) -> Response;
}

/// An HTTP/1.1 server.
pub struct Server {
    listener: TcpListener,
    local: SocketAddr,
    config: ServerConfig,
}

impl Server {
    /// Binds a listening socket.
    pub fn bind(addr: impl ToSocketAddrs, config: ServerConfig) -> io::Result<Server> {
        let listener = TcpListener::bind(addr)?;
        let local = listener.local_addr()?;
        Ok(Server {
            listener,
            local,
            config,
        })
    }

    /// The address the server is listening on.
    pub fn local_addr(&self) -> SocketAddr {
        self.local
    }

    /// Serves until `shutdown` is set, then returns.
    pub fn serve(
        self,
        handler: Arc<dyn Handler>,
        shutdown: Arc<AtomicBool>,
    ) -> io::Result<()> {
        let live = Arc::new(AtomicUsize::new(0));
        self.listener.set_nonblocking(true)?;
        let mut workers: Vec<JoinHandle<()>> = Vec::new();
        while !shutdown.load(Ordering::Relaxed) {
            match self.listener.accept() {
                Ok((stream, addr)) => {
                    if live.load(Ordering::Relaxed) >= self.config.max_connections {
                        // Over the limit: refuse politely instead of queueing
                        // unbounded work.
                        let mut stream = stream;
                        let _ = write_response(
                            &mut stream,
                            &Response::error(Status::UNAVAILABLE, "too_many_connections", "server is at its connection limit"),
                            false,
                            true,
                        );
                        continue;
                    }
                    live.fetch_add(1, Ordering::Relaxed);
                    let handler = Arc::clone(&handler);
                    let config = self.config.clone();
                    let live = Arc::clone(&live);
                    let local = self.local;
                    workers.push(thread::spawn(move || {
                        serve_connection(stream, addr, local, handler, config);
                        live.fetch_sub(1, Ordering::Relaxed);
                    }));
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                    thread::sleep(Duration::from_millis(2));
                }
                Err(error) => {
                    if shutdown.load(Ordering::Relaxed) {
                        break;
                    }
                    return Err(error);
                }
            }
        }
        for worker in workers {
            let _ = worker.join();
        }
        Ok(())
    }

    /// Serves on a background thread.
    pub fn spawn(
        self,
        handler: Arc<dyn Handler>,
        shutdown: Arc<AtomicBool>,
    ) -> JoinHandle<io::Result<()>> {
        thread::spawn(move || self.serve(handler, shutdown))
    }
}

fn serve_connection(
    stream: TcpStream,
    addr: SocketAddr,
    local: SocketAddr,
    handler: Arc<dyn Handler>,
    config: ServerConfig,
) {
    let _ = stream.set_read_timeout(Some(config.idle_timeout));
    let _ = stream.set_write_timeout(Some(config.idle_timeout));
    let _ = stream.set_nodelay(true);
    let peer = Peer { addr, local };
    let mut reader = BufReader::new(match stream.try_clone() {
        Ok(clone) => clone,
        Err(_) => return,
    });
    let mut writer = stream;
    let parser = Parser::new().with_max_body(config.max_body);
    // Pipelined bytes that arrived with the previous request.
    let mut buffer: Vec<u8> = Vec::with_capacity(2048);

    for _ in 0..config.max_requests_per_connection {
        let request = match read_request(&mut reader, &mut buffer, &parser) {
            Ok(Ok(request)) => request,
            Ok(Err(error)) => {
                let _ = write_response(&mut writer, &error.into_response(), false, true);
                return;
            }
            Err(error) if error.kind() == io::ErrorKind::TimedOut
                || error.kind() == io::ErrorKind::WouldBlock =>
            {
                return;
            }
            Err(_) => return,
        };
        let keep_alive = request.keep_alive;
        let include_body = request.method != crate::http::Method::Head;
        let response = match std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            handler.handle(&request, &peer)
        })) {
            Ok(response) => response,
            Err(_) => Response::error(
                Status::INTERNAL,
                "internal_error",
                "the request could not be completed",
            )
            .hardened(),
        };
        if write_response(&mut writer, &response, keep_alive, include_body).is_err() {
            return;
        }
        if !keep_alive {
            return;
        }
    }
}

/// A file system tree served as static content.
pub struct StaticFiles {
    root: PathBuf,
    spa_fallback: Option<PathBuf>,
    cache_secs: u64,
    types: HashMap<&'static str, &'static str>,
}

impl StaticFiles {
    /// Roots a static file tree.
    ///
    /// The root is canonicalised once, at construction, so every later request
    /// is checked against the real directory on disk (symlink escapes included).
    pub fn new(root: impl AsRef<Path>) -> io::Result<StaticFiles> {
        let root = root.as_ref().canonicalize()?;
        let mut types = HashMap::new();
        for (extension, content_type) in [
            ("html", "text/html; charset=utf-8"),
            ("css", "text/css; charset=utf-8"),
            ("js", "text/javascript; charset=utf-8"),
            ("mjs", "text/javascript; charset=utf-8"),
            ("json", "application/json; charset=utf-8"),
            ("svg", "image/svg+xml"),
            ("png", "image/png"),
            ("jpg", "image/jpeg"),
            ("jpeg", "image/jpeg"),
            ("webp", "image/webp"),
            ("ico", "image/x-icon"),
            ("woff2", "font/woff2"),
            ("wasm", "application/wasm"),
            ("txt", "text/plain; charset=utf-8"),
            ("map", "application/json; charset=utf-8"),
        ] {
            types.insert(extension, content_type);
        }
        Ok(StaticFiles {
            root,
            spa_fallback: None,
            cache_secs: 60,
            types,
        })
    }

    /// Serves `index.html` for unknown, extension-less paths (single-page app
    /// routing).  API routes must never fall through to this.
    pub fn with_spa_fallback(mut self, file: &str) -> StaticFiles {
        let candidate = self.root.join(file);
        if candidate.is_file() {
            self.spa_fallback = Some(candidate);
        }
        self
    }

    /// Sets the `Cache-Control: max-age` value used for immutable assets.
    pub fn with_cache_secs(mut self, seconds: u64) -> StaticFiles {
        self.cache_secs = seconds;
        self
    }

    /// The configured root.
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// Serves a request, or returns `None` when the method is not a read.
    pub fn serve(&self, request: &Request) -> Option<Response> {
        if !matches!(request.method, crate::http::Method::Get | crate::http::Method::Head) {
            return None;
        }
        if request.path.starts_with("/api/") {
            // API paths are the handler's business; never answer them from disk.
            return None;
        }
        let relative = request.path.trim_start_matches('/');
        let mut candidate = self.root.join(relative);
        if candidate.is_dir() {
            candidate = candidate.join("index.html");
        }
        if !candidate.is_file() {
            let has_extension = Path::new(relative)
                .extension()
                .is_some();
            match (&self.spa_fallback, has_extension) {
                (Some(fallback), false) => return Some(file_response(fallback, self, true, false)),
                _ => {
                    return Some(
                        Response::text(Status::NOT_FOUND, "not found")
                            .hardened()
                            .no_store(),
                    )
                }
            }
        }
        Some(file_response(&candidate, self, false, false))
    }

    /// Serves a file by absolute path inside the root, if the path is safe.
    pub fn serve_file(&self, path: &Path, immutable: bool) -> Option<Response> {
        if !path.is_file() {
            return None;
        }
        Some(file_response(path, self, false, immutable))
    }

    fn content_type(&self, path: &Path) -> &'static str {
        path.extension()
            .and_then(|extension| extension.to_str())
            .and_then(|extension| self.types.get(extension).copied())
            .unwrap_or("application/octet-stream")
    }
}

fn file_response(path: &Path, files: &StaticFiles, no_cache: bool, immutable: bool) -> Response {
    // Refuse anything that escapes the root, following symlinks.
    let canonical = match path.canonicalize() {
        Ok(canonical) => canonical,
        Err(_) => {
            return Response::text(Status::NOT_FOUND, "not found")
                .hardened()
                .no_store()
        }
    };
    if !canonical.starts_with(files.root()) {
        return Response::error(Status::FORBIDDEN, "outside_root", "the path is outside the document root")
            .hardened();
    }
    let body = match std::fs::read(&canonical) {
        Ok(body) => body,
        Err(_) => {
            return Response::text(Status::NOT_FOUND, "not found")
                .hardened()
                .no_store()
        }
    };
    let modified = std::fs::metadata(&canonical)
        .and_then(|metadata| metadata.modified())
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
        .unwrap_or(0);
    let etag = format!("\"{:x}-{:x}\"", body.len(), modified);
    let mut response = Response::new(Status::OK);
    response
        .headers
        .push(("Content-Type".to_string(), files.content_type(&canonical).to_string()));
    response.headers.push(("ETag".to_string(), etag));
    if no_cache {
        response
            .headers
            .push(("Cache-Control".to_string(), "no-store".to_string()));
    } else if immutable {
        response.headers.push((
            "Cache-Control".to_string(),
            format!("public, max-age={}, immutable", files.cache_secs),
        ));
    } else {
        response.headers.push((
            "Cache-Control".to_string(),
            format!("public, max-age={}", files.cache_secs),
        ));
    }
    response.body = body;
    response.hardened()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::Method;
    use std::io::Write;

    fn request(method: Method, path: &str) -> Request {
        Request {
            method,
            path: path.to_string(),
            query: String::new(),
            headers: Vec::new(),
            body: Vec::new(),
            keep_alive: false,
            host: Some("localhost".to_string()),
        }
    }

    fn fixture_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "obs-rpc-static-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("index.html"), "<!doctype html><title>Obsidian</title>").unwrap();
        std::fs::write(dir.join("app.js"), "export const x = 1;").unwrap();
        std::fs::create_dir_all(dir.join("assets")).unwrap();
        std::fs::write(dir.join("assets/logo.svg"), "<svg></svg>").unwrap();
        dir
    }

    #[test]
    fn static_files_are_served_with_types_and_etags() {
        let dir = fixture_dir("serve");
        let files = StaticFiles::new(&dir).unwrap().with_spa_fallback("index.html");
        let response = files.serve(&request(Method::Get, "/app.js")).unwrap();
        assert_eq!(response.status, Status::OK);
        assert_eq!(
            response.header_value("Content-Type"),
            Some("text/javascript; charset=utf-8")
        );
        assert!(response.header_value("ETag").is_some());
        assert!(response.header_value("Cache-Control").unwrap().contains("max-age"));

        let index = files.serve(&request(Method::Get, "/")).unwrap();
        assert!(String::from_utf8_lossy(&index.body).contains("Obsidian"));

        // An unknown, extension-less path falls back to the single page app.
        let spa = files.serve(&request(Method::Get, "/wallet/receive")).unwrap();
        assert_eq!(spa.status, Status::OK);
        assert!(String::from_utf8_lossy(&spa.body).contains("Obsidian"));

        // A missing asset does not.
        let missing = files.serve(&request(Method::Get, "/nope.js")).unwrap();
        assert_eq!(missing.status, Status::NOT_FOUND);

        // API paths are never served from disk.
        assert!(files.serve(&request(Method::Get, "/api/v1/status")).is_none());

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn directory_traversal_and_symlink_escapes_are_refused() {
        let dir = fixture_dir("escape");
        let outside = std::env::temp_dir().join(format!("obs-rpc-outside-{}", std::process::id()));
        std::fs::write(&outside, "secret").unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(&outside, dir.join("link.txt")).unwrap();

        let files = StaticFiles::new(&dir).unwrap();
        // The parser rejects `..` already; the file layer rejects symlinks that
        // point outside the root even when the path itself looks innocent.
        #[cfg(unix)]
        {
            let response = files.serve(&request(Method::Get, "/link.txt")).unwrap();
            assert_ne!(response.status, Status::OK);
            assert_eq!(response.status, Status::FORBIDDEN);
        }
        let missing = files.serve(&request(Method::Get, "/../secret")).unwrap();
        assert_eq!(missing.status, Status::NOT_FOUND);

        std::fs::remove_dir_all(&dir).unwrap();
        let _ = std::fs::remove_file(&outside);
    }

    #[test]
    fn a_server_answers_over_tcp_and_keeps_the_connection_alive() {
        struct Echo;
        impl Handler for Echo {
            fn handle(&self, request: &Request, _peer: &Peer) -> Response {
                if request.path == "/boom" {
                    panic!("a handler must not be able to kill the server");
                }
                Response::text(Status::OK, format!("path={}", request.path))
            }
        }

        let server = Server::bind("127.0.0.1:0", ServerConfig::default()).unwrap();
        let addr = server.local_addr();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = server.spawn(Arc::new(Echo), Arc::clone(&shutdown));

        // Two requests on one connection, then a request that makes the handler
        // panic: the server must survive it and answer with a 500.
        let mut stream = TcpStream::connect(addr).unwrap();
        stream
            .write_all(b"GET /one HTTP/1.1\r\nHost: localhost\r\n\r\nGET /two HTTP/1.1\r\nHost: localhost\r\n\r\nGET /boom HTTP/1.1\r\nHost: localhost\r\n\r\nGET /three HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
            .unwrap();
        let mut raw = Vec::new();
        use std::io::Read;
        stream.read_to_end(&mut raw).unwrap();
        let text = String::from_utf8_lossy(&raw);
        assert_eq!(text.matches("HTTP/1.1 200 OK").count(), 3);
        assert_eq!(text.matches("HTTP/1.1 500 Internal Server Error").count(), 1);
        assert!(text.contains("path=/three"));

        shutdown.store(true, Ordering::Relaxed);
        handle.join().unwrap().unwrap();
    }

    #[test]
    fn oversized_and_malformed_requests_get_real_status_codes() {
        struct Ok200;
        impl Handler for Ok200 {
            fn handle(&self, _request: &Request, _peer: &Peer) -> Response {
                Response::text(Status::OK, "ok")
            }
        }
        let config = ServerConfig {
            max_body: 16,
            ..ServerConfig::default()
        };
        let server = Server::bind("127.0.0.1:0", config).unwrap();
        let addr = server.local_addr();
        let shutdown = Arc::new(AtomicBool::new(false));
        let handle = server.spawn(Arc::new(Ok200), Arc::clone(&shutdown));

        for (raw, expected) in [
            ("GET / HTTP/1.1\r\n\r\n", "400 Bad Request"),
            ("POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 100\r\n\r\n", "413 Payload Too Large"),
            ("GET / HTTP/1.1\r\nHost: h\r\nBad Header: x\r\n\r\n", "400 Bad Request"),
        ] {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(raw.as_bytes()).unwrap();
            let mut response = String::new();
            use std::io::Read;
            let _ = stream.read_to_string(&mut response);
            assert!(
                response.starts_with(&format!("HTTP/1.1 {}", expected)),
                "for {:?} expected {}, got {:?}",
                raw,
                expected,
                response
            );
        }

        shutdown.store(true, Ordering::Relaxed);
        handle.join().unwrap().unwrap();
    }
}
