//! The deployment's official logo.
//!
//! The logo is the project's own mark, and a deployment may keep it somewhere it
//! does not want published: a private host, a CDN URL with a token, a worker
//! behind an obscure hostname.  If a page referenced such a URL directly — the
//! obvious way to show a logo — the URL would appear in the page source for
//! anybody who looked, which is exactly what the operator asked to avoid.
//!
//! So this module fetches it **server-side** and serves it from the service's own
//! origin:
//!
//! * the browser never learns the URL, and never talks to the logo host;
//! * the repository never contains it — it is configuration, not source;
//! * [`LogoSource`]'s `Debug` implementation redacts it, so no log line, error
//!   message or panic can leak it by accident;
//! * a file named `logo-official.*` in the static directory wins over any
//!   configured source, so an operator who has the image needs no network at all;
//! * and if there is neither — or the source is unreachable, or answers with
//!   something that is not an image — the route returns `404` and the page falls
//!   back to its drawn mark.  A missing logo degrades *branding*, never the page.
//!
//! Only `image/*` responses are accepted (a logo host that answers HTML, or a
//! redirect to a login page, must not be served as if it were the mark), and only
//! up to [`MAX_LOGO_BYTES`].  SVG is allowed because logos are often SVG: it is
//! served as an image and referenced from `<img>`, where scripts inside it do not
//! run.

use std::sync::Mutex;
use std::time::{Duration, Instant};

use obs_rpc::client::Client;
use obs_rpc::http::{Response, Status};

/// Where the interface asks for the official logo.
pub const LOGO_PATH: &str = "/assets/logo-official.png";

/// Largest logo this service will accept from a source.
pub const MAX_LOGO_BYTES: usize = 2 * 1024 * 1024;

/// How long a fetch may take before it is abandoned.
const FETCH_TIMEOUT_SECS: u64 = 6;

/// How long to wait after a failed attempt before trying the source again.
const RETRY_AFTER_FAILURE: Duration = Duration::from_secs(60);

/// How long a successful fetch is reused before the source is consulted again.
const CACHE_TTL: Duration = Duration::from_secs(3_600);

/// How long a browser may cache the served image.
const BROWSER_CACHE_SECS: u64 = 300;

/// A URL this deployment fetches the official logo from.
///
/// The value is deliberately hard to print.  An operator gave this service a
/// link on the understanding that it would not be published, and the surest way
/// to keep that promise is for the type to refuse to say what it is: every log
/// line, error and `Debug` print shows only that a source is configured.
#[derive(Clone)]
pub struct LogoSource(String);

impl LogoSource {
    /// Wraps a URL the operator configured.
    pub fn new(url: impl Into<String>) -> LogoSource {
        LogoSource(url.into())
    }

    /// The URL itself.  Used only to make the request; never to describe it.
    fn url(&self) -> &str {
        &self.0
    }
}

impl core::fmt::Debug for LogoSource {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        // No length, no host, no scheme: nothing that could narrow a guess.
        f.write_str("LogoSource(<configured by the operator>)")
    }
}

/// What the service knows about the logo it serves.
#[derive(Debug, Default)]
enum State {
    /// Nothing asked for yet.
    #[default]
    Idle,
    /// A fetch is in flight; other requests are told to try again rather than
    /// queued behind it.
    Fetching,
    /// The bytes, their content type, and when they arrived.
    Ready {
        /// The image.
        bytes: Vec<u8>,
        /// Its media type, as the source declared it and as we verified it.
        content_type: String,
        /// When it was fetched, for [`CACHE_TTL`].
        fetched_at: Instant,
    },
    /// The last attempt failed; do not try again before this instant.
    Failed {
        /// The earliest time another attempt may be made.
        retry_at: Instant,
    },
}

/// Serves the deployment's official logo from its own origin.
#[derive(Debug, Default)]
pub struct Logo {
    source: Option<LogoSource>,
    state: Mutex<State>,
}

impl Logo {
    /// A logo served from the configured source, when there is one.
    pub fn new(source: Option<LogoSource>) -> Logo {
        Logo {
            source,
            state: Mutex::new(State::Idle),
        }
    }

    /// Whether a source is configured.  Says nothing about what it is.
    pub fn has_source(&self) -> bool {
        self.source.is_some()
    }

    /// Produces the response for [`LOGO_PATH`].
    pub fn serve(&self, static_dir: Option<&str>) -> Response {
        // 1. A file on disk.  An operator who has the image needs no network, and
        //    what they put in their own directory wins over anything fetched.
        if let Some(dir) = static_dir {
            for (name, content_type) in CANDIDATE_FILES {
                let path = std::path::Path::new(dir).join("assets").join(name);
                if let Ok(bytes) = std::fs::read(&path) {
                    return image(bytes, content_type);
                }
            }
        }

        // 2. The configured source.
        let Some(source) = self.source.as_ref() else {
            return missing("this deployment serves no official logo");
        };
        let mut state = match self.state.lock() {
            Ok(guard) => guard,
            Err(_) => return missing("the logo cache is unavailable"),
        };
        match &*state {
            State::Ready {
                bytes,
                content_type,
                fetched_at,
            } if fetched_at.elapsed() < CACHE_TTL => {
                return image(bytes.clone(), content_type);
            }
            State::Fetching => {
                return unavailable("the logo is being fetched; try again in a moment")
            }
            State::Failed { retry_at } if Instant::now() < *retry_at => {
                return missing("the configured logo source could not be reached")
            }
            _ => {}
        }
        *state = State::Fetching;
        // The network call happens with no lock held: a slow logo host must never
        // stall any other request this service is answering.
        drop(state);

        match self.fetch(source.url()) {
            Ok((bytes, content_type)) => {
                let mut state = match self.state.lock() {
                    Ok(guard) => guard,
                    Err(_) => return missing("the logo cache is unavailable"),
                };
                *state = State::Ready {
                    bytes: bytes.clone(),
                    content_type: content_type.clone(),
                    fetched_at: Instant::now(),
                };
                drop(state);
                image(bytes, &content_type)
            }
            Err(reason) => {
                if let Ok(mut state) = self.state.lock() {
                    *state = State::Failed {
                        retry_at: Instant::now() + RETRY_AFTER_FAILURE,
                    };
                }
                unavailable(&reason)
            }
        }
    }

    /// Fetches the image, and refuses anything that is not clearly one.
    fn fetch(&self, url: &str) -> Result<(Vec<u8>, String), String> {
        let client = Client::with_timeout(Duration::from_secs(FETCH_TIMEOUT_SECS));
        let response = client
            .get(url)
            .map_err(|_| "the configured logo source could not be reached".to_string())?;
        if response.status.code() != 200 {
            return Err(format!(
                "the configured logo source answered {}",
                response.status.code()
            ));
        }
        if response.body.len() > MAX_LOGO_BYTES {
            return Err(format!(
                "the configured logo source answered with {} bytes, above the {} this service will serve",
                response.body.len(),
                MAX_LOGO_BYTES
            ));
        }
        let declared = response
            .headers
            .iter()
            .find(|(name, _)| name.eq_ignore_ascii_case("content-type"))
            .map(|(_, value)| value.clone())
            .unwrap_or_default();
        let media_type = declared
            .split(';')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        if !ALLOWED_TYPES.contains(&media_type.as_str()) {
            return Err(format!(
                "the configured logo source answered {} rather than an image",
                if media_type.is_empty() {
                    "no content type".to_string()
                } else {
                    media_type
                }
            ));
        }
        if response.body.is_empty() {
            return Err("the configured logo source answered with an empty body".to_string());
        }
        Ok((response.body.clone(), media_type))
    }
}

/// Files an operator may drop into `web/assets/`, most specific first.
const CANDIDATE_FILES: &[(&str, &str)] = &[
    ("logo-official.png", "image/png"),
    ("logo-official.svg", "image/svg+xml"),
    ("logo-official.webp", "image/webp"),
    ("logo-official.jpg", "image/jpeg"),
    ("logo-official.jpeg", "image/jpeg"),
];

/// Media types this service will serve as the logo.
const ALLOWED_TYPES: &[&str] = &[
    "image/png",
    "image/jpeg",
    "image/svg+xml",
    "image/webp",
    "image/gif",
    "image/x-icon",
    "image/avif",
];

fn image(bytes: Vec<u8>, content_type: &str) -> Response {
    Response {
        status: Status::OK,
        headers: Vec::new(),
        body: bytes,
    }
    .header("content-type", content_type)
    .header("cache-control", &format!("public, max-age={}", BROWSER_CACHE_SECS))
    .hardened()
}

fn missing(reason: &str) -> Response {
    Response::error(Status::NOT_FOUND, "no_logo", reason)
        .no_store()
        .hardened()
}

fn unavailable(reason: &str) -> Response {
    Response::error(Status(502), "logo_unavailable", reason)
        .no_store()
        .hardened()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::sync::Arc;

    /// A stand-in for an operator's logo host: answers one image, counts hits.
    fn stand_in(body: Vec<u8>, content_type: &'static str, hits: Arc<AtomicU64>) -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        std::thread::spawn(move || {
            for stream in listener.incoming() {
                let Ok(mut stream) = stream else { break };
                let mut buffer = [0u8; 4096];
                let _ = stream.read(&mut buffer);
                hits.fetch_add(1, Ordering::Relaxed);
                let head = format!(
                    "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                    content_type,
                    body.len()
                );
                let _ = stream.write_all(head.as_bytes());
                let _ = stream.write_all(&body);
                let _ = stream.flush();
            }
        });
        port
    }

    const PNG: &[u8] = &[0x89, b'P', b'N', b'G', 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x01];

    #[test]
    fn a_configured_source_is_fetched_once_and_served_from_this_origin() {
        let hits = Arc::new(AtomicU64::new(0));
        let port = stand_in(PNG.to_vec(), "image/png", Arc::clone(&hits));
        let logo = Logo::new(Some(LogoSource::new(format!(
            "http://127.0.0.1:{}/logo.png",
            port
        ))));

        let first = logo.serve(None);
        assert_eq!(first.status, Status::OK);
        assert_eq!(first.body, PNG);
        assert_eq!(
            first
                .headers
                .iter()
                .find(|(name, _)| name == "content-type")
                .map(|(_, value)| value.as_str()),
            Some("image/png")
        );

        // The second request is served from memory: a logo host is asked once.
        let second = logo.serve(None);
        assert_eq!(second.body, PNG);
        assert_eq!(hits.load(Ordering::Relaxed), 1, "the source must be fetched once");
    }

    #[test]
    fn a_source_that_is_not_an_image_is_refused_rather_than_served() {
        let hits = Arc::new(AtomicU64::new(0));
        let port = stand_in(b"<html>not a logo</html>".to_vec(), "text/html", Arc::clone(&hits));
        let logo = Logo::new(Some(LogoSource::new(format!(
            "http://127.0.0.1:{}/logo.png",
            port
        ))));

        let response = logo.serve(None);
        assert_ne!(response.status, Status::OK);
        assert!(
            !String::from_utf8_lossy(&response.body).contains("not a logo"),
            "an HTML answer must never be served as the logo"
        );

        // And a failed attempt is not retried on every request.
        let before = hits.load(Ordering::Relaxed);
        let _ = logo.serve(None);
        assert_eq!(hits.load(Ordering::Relaxed), before, "a failure backs off");
    }

    #[test]
    fn without_a_source_or_a_file_the_route_is_simply_absent() {
        let response = Logo::default().serve(None);
        assert_eq!(response.status, Status::NOT_FOUND);
        // The page turns this into its drawn fallback; it is not an error a
        // person should ever be shown.
        assert!(String::from_utf8_lossy(&response.body).contains("no_logo"));
    }

    #[test]
    fn a_file_on_disk_wins_over_the_configured_source() {
        let dir = std::env::temp_dir().join(format!("obs-logo-{}", std::process::id()));
        let assets = dir.join("assets");
        std::fs::create_dir_all(&assets).unwrap();
        let file_bytes = [0x89, b'P', b'N', b'G', 9, 9, 9];
        std::fs::write(assets.join("logo-official.png"), file_bytes).unwrap();

        let hits = Arc::new(AtomicU64::new(0));
        let port = stand_in(PNG.to_vec(), "image/png", Arc::clone(&hits));
        let logo = Logo::new(Some(LogoSource::new(format!(
            "http://127.0.0.1:{}/logo.png",
            port
        ))));

        let response = logo.serve(Some(dir.to_str().unwrap()));
        assert_eq!(response.status, Status::OK);
        assert_eq!(response.body, file_bytes, "the local file is the logo");
        assert_eq!(hits.load(Ordering::Relaxed), 0, "no network is used at all");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_configured_source_never_describes_itself() {
        // The whole point of the type: it cannot be printed.
        let source = LogoSource::new("https://private.example/secret-logo.png");
        let printed = format!("{:?}", source);
        assert!(!printed.contains("private.example"));
        assert!(!printed.contains("secret-logo"));
        assert!(printed.contains("configured by the operator"));
    }
}
