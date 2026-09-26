mod config;
mod proxy;
mod respond;
mod static_files;

use anyhow::{anyhow, Context, Result};
use config::{HostConfig, WebConfig};
use http::{header, Request, Response, StatusCode};
use hyper::body::Incoming;
use hyper::service::service_fn;
use hyper_util::rt::TokioIo;
use proxy::{bad_gateway, ProxyRule, ProxyTarget};
use std::net::SocketAddr;
use std::path::Path;
use std::sync::Arc;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;

use crate::respond::{error, text, ResBody};
use crate::static_files::serve as serve_static;

/// A virtual host with its name list, static root, and compiled proxy rules
pub struct HostState {
    /// Server names (lowercased) matched against the Host header / SNI
    pub names: Vec<String>,
    webroot: std::path::PathBuf,
    rules: Vec<ProxyRule>,
}

/// Globally shared state
pub struct State {
    /// Virtual hosts; the first one is the default when nothing matches
    hosts: Vec<HostState>,
    connector: tokio_rustls::TlsConnector,
    /// HTTPS port; when set, all plain-HTTP requests are redirected to it
    https_port: Option<u16>,
}

impl State {
    fn from_config(cfg: &WebConfig) -> Result<State> {
        let mut hosts = Vec::new();
        for host in &cfg.hosts {
            let mut rules = Vec::new();
            for (path, target) in &host.proxy {
                rules.push(ProxyRule { key: path.clone(), target: ProxyTarget::parse(target)? });
            }
            // Longest prefix matches first
            rules.sort_by(|a, b| b.key.len().cmp(&a.key.len()));
            hosts.push(HostState {
                names: host.names.iter().map(|n| n.to_ascii_lowercase()).collect(),
                webroot: host.webroot.clone(),
                rules,
            });
        }
        Ok(State {
            hosts,
            connector: proxy::build_connector(),
            https_port: cfg.https_port,
        })
    }

    /// Find the virtual host for a Host header; falls back to the default
    /// (first) host when no name matches. Note that on TLS connections the
    /// handshake has already restricted the client to a known SNI name.
    fn find_host(&self, host: &str) -> &HostState {
        let name = strip_port(host).to_ascii_lowercase();
        self.hosts
            .iter()
            .find(|h| h.names.iter().any(|n| n == &name))
            .unwrap_or(&self.hosts[0])
    }
}

/// Main entry for each request: when HTTPS is enabled, plain-HTTP requests are
/// redirected to it; otherwise, forward if a proxy rule of the matching
/// virtual host applies, or fall back to its static files
async fn handle_request(
    state: Arc<State>,
    peer: SocketAddr,
    proto: &'static str,
    req: Request<Incoming>,
) -> Result<Response<ResBody>, std::convert::Infallible> {
    if proto == "http" {
        if let Some(port) = state.https_port {
            return Ok(redirect_to_https(&req, port));
        }
    }

    let host_hdr = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| h.to_string())
        .unwrap_or_default();
    let host = state.find_host(&host_hdr);

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let res = match host.rules.iter().find(|r| r.matches(&path)) {
        Some(rule) => proxy::forward(req, rule, peer, proto, &state.connector).await,
        None => Ok(serve_static(&host.webroot, &path, &method).await),
    };
    let res = res.unwrap_or_else(|e| {
        eprintln!("[proxy] {method} {path} failed: {e:#}");
        bad_gateway()
    });

    println!("{proto} {peer} {} {path} -> {}", method, res.status());
    Ok(res)
}

/// Build a 301 redirect that moves a plain-HTTP request to the HTTPS listener
fn redirect_to_https(req: &Request<Incoming>, https_port: u16) -> Response<ResBody> {
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| strip_port(h).to_string());
    let Some(host) = host else {
        return error(StatusCode::BAD_REQUEST, "400 Bad Request\n");
    };
    let pq = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let port_suffix = if https_port == 443 { String::new() } else { format!(":{https_port}") };
    let location = format!("https://{host}{port_suffix}{pq}");
    let mut res = text(StatusCode::MOVED_PERMANENTLY, "301 Moved Permanently\n");
    if let Ok(v) = header::HeaderValue::from_str(&location) {
        res.headers_mut().insert(header::LOCATION, v);
    }
    res
}

/// Strip any port from a host value, keeping bracketed IPv6 literals intact
fn strip_port(host: &str) -> &str {
    if let Some(rest) = host.strip_prefix('[') {
        // [::1]:443 -> [::1]
        let end = rest.find(']').map(|i| i + 2).unwrap_or(host.len());
        host.get(..end).unwrap_or(host)
    } else {
        host.split(':').next().unwrap_or(host)
    }
}

/// Serve HTTP/1.1 over an established connection (plaintext or TLS), with WebSocket upgrade support
async fn serve_conn<IO>(state: Arc<State>, peer: SocketAddr, proto: &'static str, io: TokioIo<IO>)
where
    IO: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    let service = service_fn(move |req| {
        let state = state.clone();
        async move { handle_request(state, peer, proto, req).await }
    });
    if let Err(e) = hyper::server::conn::http1::Builder::new()
        .serve_connection(io, service)
        .with_upgrades()
        .await
    {
        eprintln!("[http] {peer} connection error: {e}");
    }
}

/// Build the server-side TLS acceptor: one certificate per host, selected by SNI
/// (ALPN restricted to http/1.1)
async fn build_acceptor(hosts: &[HostConfig]) -> Result<TlsAcceptor> {
    let mut resolver = rustls::server::ResolvesServerCertUsingSni::new();
    for host in hosts {
        let Some(ssl) = &host.ssl else {
            continue;
        };
        let certs = load_certs(&ssl.cert).await?;
        let key = load_key(&ssl.key).await?;
        let signing = rustls::crypto::ring::sign::any_supported_type(&key)
            .map_err(|e| anyhow!("unsupported key in {}: {e}", ssl.key.display()))?;
        for name in &host.names {
            resolver
                .add(name, rustls::sign::CertifiedKey { cert: certs.clone(), key: signing.clone(), ocsp: None })
                .with_context(|| format!("cannot use {} for name {name}", ssl.cert.display()))?;
        }
    }
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(resolver));
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(cfg)))
}

async fn load_certs(path: &Path) -> Result<Vec<rustls::pki_types::CertificateDer<'static>>> {
    let mut reader = tokio::fs::File::open(path).await?;
    let mut buf = Vec::new();
    use tokio::io::AsyncReadExt;
    reader.read_to_end(&mut buf).await?;
    let mut cursor = std::io::Cursor::new(&buf);
    let certs: Vec<_> = rustls_pemfile::certs(&mut cursor).collect::<std::io::Result<_>>()?;
    if certs.is_empty() {
        anyhow::bail!("no certificates found in cert file {path:?}");
    }
    Ok(certs)
}

async fn load_key(path: &Path) -> Result<rustls::pki_types::PrivateKeyDer<'static>> {
    let mut file = tokio::fs::File::open(path).await?;
    let mut buf = Vec::new();
    use tokio::io::AsyncReadExt;
    file.read_to_end(&mut buf).await?;
    let mut cursor = std::io::Cursor::new(&buf);
    rustls_pemfile::private_key(&mut cursor)?
        .ok_or_else(|| anyhow!("no private key found in key file {path:?}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.xml".to_string());
    let cfg = WebConfig::load(&config_path)?;
    let state = Arc::new(State::from_config(&cfg)?);

    let http_addr = SocketAddr::from(([0, 0, 0, 0], cfg.http_port));
    let http_listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("failed to listen on {http_addr}"))?;

    let https_addr = cfg.https_port.map(|port| SocketAddr::from(([0, 0, 0, 0], port)));
    let https_listener = match https_addr {
        Some(addr) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("failed to listen on {addr}"))?;
            Some(listener)
        }
        None => {
            if cfg.hosts.iter().any(|h| h.ssl.is_some()) {
                eprintln!("note: some hosts have ssl config but no https port; HTTPS is disabled");
            }
            None
        }
    };
    let acceptor = match https_listener {
        Some(_) => Some(build_acceptor(&cfg.hosts).await?),
        None => None,
    };

    println!("rgate started");
    println!("  http listening on http://{http_addr}");
    if let Some(addr) = https_addr {
        println!("  https listening on https://{addr}");
        println!("  plain-http requests are redirected to https");
    }
    for host in &state.hosts {
        println!(
            "  host {} (webroot {}, {} proxy rule(s))",
            host.names.join(", "),
            host.webroot.display(),
            host.rules.len()
        );
    }

    // Plain-HTTP accept loop
    let http_state = state.clone();
    tokio::spawn(async move {
        loop {
            match http_listener.accept().await {
                Ok((stream, peer)) => {
                    let state = http_state.clone();
                    tokio::spawn(async move {
                        serve_conn(state, peer, "http", TokioIo::new(stream)).await
                    });
                }
                Err(e) => eprintln!("[http] accept failed: {e}"),
            }
        }
    });

    // HTTPS accept loop
    if let (Some(listener), Some(acceptor)) = (https_listener, acceptor) {
        let https_state = state.clone();
        tokio::spawn(async move {
            loop {
                match listener.accept().await {
                    Ok((stream, peer)) => {
                        let state = https_state.clone();
                        let acceptor = acceptor.clone();
                        tokio::spawn(async move {
                            match acceptor.accept(stream).await {
                                Ok(s) => serve_conn(state, peer, "https", TokioIo::new(s)).await,
                                Err(e) => eprintln!("[tls] {peer} handshake failed: {e}"),
                            }
                        });
                    }
                    Err(e) => eprintln!("[https] accept failed: {e}"),
                }
            }
        });
    }

    // Keep the main task alive until interrupted
    tokio::signal::ctrl_c().await?;
    Ok(())
}
