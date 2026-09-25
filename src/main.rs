mod config;
mod proxy;
mod respond;
mod static_files;

use anyhow::{anyhow, Context, Result};
use config::{Config, SslConfig};
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

/// Globally shared state
pub struct State {
    webroot: std::path::PathBuf,
    rules: Vec<ProxyRule>,
    connector: tokio_rustls::TlsConnector,
    /// HTTPS port; when set, all plain-HTTP requests are redirected to it
    https_port: Option<u16>,
}

impl State {
    fn from_config(cfg: &Config) -> Result<State> {
        let mut rules = Vec::new();
        for (key, target) in &cfg.proxy {
            rules.push(ProxyRule { key: key.clone(), target: ProxyTarget::parse(target)? });
        }
        // Longest prefix matches first
        rules.sort_by(|a, b| b.key.len().cmp(&a.key.len()));
        Ok(State {
            webroot: cfg.webroot.clone(),
            rules,
            connector: proxy::build_connector(),
            https_port: cfg.https_port,
        })
    }

    fn find_rule(&self, path: &str) -> Option<ProxyRule> {
        self.rules.iter().find(|r| r.matches(path)).cloned()
    }
}

/// Main entry for each request: when HTTPS is enabled, plain-HTTP requests are
/// redirected to it; otherwise, forward if a proxy rule matches, or fall back
/// to static files
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

    let method = req.method().clone();
    let path = req.uri().path().to_string();

    let res = match state.find_rule(&path) {
        Some(rule) => proxy::forward(req, &rule, peer, proto, &state.connector).await,
        None => Ok(serve_static(&state.webroot, &path, &method).await),
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
    // Host without any port; bracketed IPv6 literals are kept intact
    let host = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            if let Some(rest) = h.strip_prefix('[') {
                rest.split(']').next().map(|ip| format!("[{ip}]")).unwrap_or_else(|| h.to_string())
            } else {
                h.split(':').next().unwrap_or(h).to_string()
            }
        });
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

/// Load the certificate and private key, and build the server-side TLS acceptor (ALPN restricted to http/1.1)
async fn build_acceptor(ssl: &SslConfig) -> Result<TlsAcceptor> {
    let certs = load_certs(&ssl.cert).await?;
    let key = load_key(&ssl.key).await?;
    let mut cfg = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("failed to load TLS certificate")?;
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
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.json".to_string());
    let cfg = Config::load(&config_path)?;
    let state = Arc::new(State::from_config(&cfg)?);

    let http_addr = SocketAddr::from(([0, 0, 0, 0], cfg.http_port));
    let http_listener = TcpListener::bind(http_addr)
        .await
        .with_context(|| format!("failed to listen on {http_addr}"))?;

    let https_addr = cfg.https_port.map(|port| SocketAddr::from(([0, 0, 0, 0], port)));
    let (https_listener, acceptor) = match (https_addr, &cfg.ssl) {
        (Some(addr), Some(ssl)) => {
            let listener = TcpListener::bind(addr)
                .await
                .with_context(|| format!("failed to listen on {addr}"))?;
            (Some(listener), Some(build_acceptor(ssl).await?))
        }
        (Some(_), None) => {
            return Err(anyhow!("httpsPort is configured but the ssl section is missing"))
        }
        (None, _) => {
            if cfg.ssl.is_some() {
                eprintln!("note: ssl config present but httpsPort is not; HTTPS is disabled");
            }
            (None, None)
        }
    };

    println!("rgate started");
    println!("  http listening on http://{http_addr}");
    if let Some(addr) = https_addr {
        println!("  https listening on https://{addr}");
        println!("  plain-http requests are redirected to https");
    }
    println!("  static file root: {}", state.webroot.display());
    for rule in &state.rules {
        println!("  proxy rule: {} -> {}", rule.key, rule.target);
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
