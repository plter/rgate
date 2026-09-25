use anyhow::{anyhow, bail, Context, Result};
use http::{header, Request, Response, StatusCode, Uri, Version};
use http_body_util::BodyExt;
use hyper::body::Incoming;
use hyper::upgrade::OnUpgrade;
use hyper_util::rt::TokioIo;
use rustls::pki_types::ServerName;
use std::net::SocketAddr;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;

use crate::respond::{error, ResBody};

/// Upstream scheme
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scheme {
    Http,
    Https,
}

impl Scheme {
    fn as_str(self) -> &'static str {
        match self {
            Scheme::Http => "http",
            Scheme::Https => "https",
        }
    }
}

/// A parsed proxy target, e.g. "http://web:8080/web"
#[derive(Debug, Clone)]
pub struct ProxyTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// authority in host:port form
    pub authority: String,
    /// Upstream path prefix (e.g. /web), may be empty
    pub prefix: String,
}

impl ProxyTarget {
    pub fn parse(target: &str) -> Result<ProxyTarget> {
        let uri: Uri = target.parse().with_context(|| format!("invalid proxy target: {target}"))?;
        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            other => bail!("unsupported proxy scheme {other:?}, only http/https are supported"),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("proxy target missing host: {target}"))?
            .as_str()
            .to_string();
        let (host, port) = split_authority(&authority, scheme);
        let prefix = uri.path().trim_end_matches('/').to_string();
        Ok(ProxyTarget { scheme, host, port, authority, prefix })
    }
}

impl std::fmt::Display for ProxyTarget {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}://{}{}", self.scheme.as_str(), self.authority, self.prefix)
    }
}

/// Split into host and port; default ports are 80 for http and 443 for https
fn split_authority(authority: &str, scheme: Scheme) -> (String, u16) {
    let default_port = if scheme == Scheme::Https { 443 } else { 80 };
    if let Some((host, port)) = authority.rsplit_once(':') {
        // Skip bare IPv6 addresses (e.g. [::1] or ::1)
        if !host.is_empty() && !host.contains("]") {
            if let Ok(p) = port.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
    }
    (authority.to_string(), default_port)
}

/// A proxy rule: path prefix -> upstream
#[derive(Debug, Clone)]
pub struct ProxyRule {
    pub key: String,
    pub target: ProxyTarget,
}

impl ProxyRule {
    /// Prefix matching: /web matches /web and /web/**, but not /webfoo
    pub fn matches(&self, path: &str) -> bool {
        let key = self.key.trim_end_matches('/');
        if key.is_empty() {
            return true; // when key is "/", match all paths
        }
        path == key || path.starts_with(&format!("{key}/"))
    }
}

/// Forward a request to the upstream. Supports plain HTTP and WebSocket upgrades.
pub async fn forward(
    req: Request<Incoming>,
    rule: &ProxyRule,
    peer: SocketAddr,
    proto: &'static str,
    connector: &TlsConnector,
) -> Result<Response<ResBody>> {
    let target = rule.target.clone();
    let tcp = TcpStream::connect((target.host.as_str(), target.port))
        .await
        .with_context(|| format!("failed to connect to upstream {}", target.authority))?;
    match target.scheme {
        Scheme::Http => forward_io(req, rule, peer, proto, TokioIo::new(tcp)).await,
        Scheme::Https => {
            let name = ServerName::try_from(target.host.clone())
                .map_err(|e| anyhow!("invalid upstream host name: {e}"))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .context("upstream TLS handshake failed")?;
            forward_io(req, rule, peer, proto, TokioIo::new(tls)).await
        }
    }
}

async fn forward_io<IO>(
    mut req: Request<Incoming>,
    rule: &ProxyRule,
    peer: SocketAddr,
    proto: &'static str,
    io: TokioIo<IO>,
) -> Result<Response<ResBody>>
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let target = &rule.target;

    // WebSocket upgrade requests must keep the Connection / Upgrade headers as-is
    let is_ws = is_upgrade_request(&req);
    let client_upgrade = req.extensions_mut().remove::<OnUpgrade>();

    let (parts, body) = req.into_parts();

    // Build the upstream path: /web/foo (key=/web, upstream prefix=/web) -> /web/foo
    let suffix = path_suffix(&rule.key, parts.uri.path());
    let mut pq = join_path(&target.prefix, &suffix);
    if let Some(q) = parts.uri.query() {
        pq.push('?');
        pq.push_str(q);
    }
    // origin-form (path+query only); host info is conveyed via the Host header
    let uri = Uri::builder().path_and_query(pq).build()?;

    let mut headers = parts.headers;
    strip_hop_by_hop(&mut headers, is_ws);
    headers.insert(header::HOST, header::HeaderValue::from_str(&target.authority)?);
    headers.insert("x-forwarded-for", header::HeaderValue::from_str(&peer.ip().to_string())?);
    headers.insert("x-forwarded-proto", header::HeaderValue::from_static(proto));

    let mut upstream_req = Request::builder()
        .method(parts.method)
        .version(Version::HTTP_11)
        .uri(uri)
        .body(body)?;
    *upstream_req.headers_mut() = headers;

    // Each proxied request uses a dedicated upstream connection; with_upgrades allows 101 responses to upgrade
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            eprintln!("[proxy] upstream connection closed: {e}");
        }
    });

    let mut res = sender.send_request(upstream_req).await?;
    let status = res.status();
    let upstream_upgrade = res.extensions_mut().remove::<OnUpgrade>();

    // Strip hop-by-hop headers from the response too; 101 must keep Connection / Upgrade to trigger the client upgrade
    let mut out_headers = std::mem::take(res.headers_mut());
    strip_hop_by_hop(&mut out_headers, status == StatusCode::SWITCHING_PROTOCOLS);

    let out_body = res
        .into_body()
        .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))
        .boxed();
    let mut out = Response::builder()
        .status(status)
        .version(Version::HTTP_11)
        .body(out_body)?;
    *out.headers_mut() = out_headers;

    // Bidirectionally relay the WebSocket byte stream
    if status == StatusCode::SWITCHING_PROTOCOLS {
        let client_up = client_upgrade.ok_or_else(|| anyhow!("missing client upgrade handle"))?;
        let upstream_up = upstream_upgrade.ok_or_else(|| anyhow!("upstream did not return an upgrade handle"))?;
        tokio::spawn(async move {
            let client_up = match client_up.await {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("[ws] client upgrade failed: {e}");
                    return;
                }
            };
            let upstream_up = match upstream_up.await {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("[ws] upstream upgrade failed: {e}");
                    return;
                }
            };
            // Upgraded implements hyper's own IO trait; TokioIo adapts it to tokio
            let mut client_io = TokioIo::new(client_up);
            let mut upstream_io = TokioIo::new(upstream_up);
            if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                eprintln!("[ws] connection aborted: {e}");
            }
            eprintln!("[ws] connection closed");
        });
    }

    Ok(out)
}

/// Compute the path remaining after the matched key: /web/foo (key=/web) -> /foo
fn path_suffix(key: &str, path: &str) -> String {
    let key = key.trim_end_matches('/');
    if key.is_empty() {
        path.to_string()
    } else {
        path.strip_prefix(key).unwrap_or(path).to_string()
    }
}

/// Join the upstream prefix + remaining path into a full path
fn join_path(prefix: &str, suffix: &str) -> String {
    let p = prefix.trim_end_matches('/');
    if suffix.is_empty() {
        if p.is_empty() { "/".to_string() } else { p.to_string() }
    } else if p.is_empty() {
        suffix.to_string()
    } else {
        format!("{p}{suffix}")
    }
}

const HOP_BY_HOP: &[&str] = &[
    "connection",
    "keep-alive",
    "proxy-authenticate",
    "proxy-authorization",
    "te",
    "trailer",
    "transfer-encoding",
    "upgrade",
];

/// Strip hop-by-hop headers; keep Connection / Upgrade when keep_upgrade is true
fn strip_hop_by_hop(headers: &mut header::HeaderMap, keep_upgrade: bool) {
    for name in HOP_BY_HOP {
        if keep_upgrade && (*name == "connection" || *name == "upgrade") {
            continue;
        }
        headers.remove(*name);
    }
    headers.remove(header::HOST);
}

/// Check whether this is a WebSocket upgrade request
fn is_upgrade_request(req: &Request<Incoming>) -> bool {
    let conn_upgrade = req
        .headers()
        .get(header::CONNECTION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("upgrade"));
    let ws = req
        .headers()
        .get(header::UPGRADE)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.to_ascii_lowercase().contains("websocket"));
    conn_upgrade && ws
}

/// Client TLS connector for https upstreams (built-in root certificates, ALPN restricted to http/1.1)
pub fn build_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(std::sync::Arc::new(cfg))
}

/// 502 response used for upstream-unreachable and similar errors
pub fn bad_gateway() -> Response<ResBody> {
    error(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
}
