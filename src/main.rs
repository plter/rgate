mod config;
mod proxy;
mod respond;
mod static_files;

use anyhow::{Context, Result};
use config::{Config, SslConfig};
use http::{Request, Response};
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

use crate::respond::ResBody;
use crate::static_files::serve as serve_static;

/// Globally shared state
pub struct State {
    webroot: std::path::PathBuf,
    rules: Vec<ProxyRule>,
    connector: tokio_rustls::TlsConnector,
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
        })
    }

    fn find_rule(&self, path: &str) -> Option<ProxyRule> {
        self.rules.iter().find(|r| r.matches(path)).cloned()
    }
}

/// Main entry for each request: forward if a proxy rule matches, otherwise fall back to static files
async fn handle_request(
    state: Arc<State>,
    peer: SocketAddr,
    proto: &'static str,
    req: Request<Incoming>,
) -> Result<Response<ResBody>, std::convert::Infallible> {
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
        .ok_or_else(|| anyhow::anyhow!("no private key found in key file {path:?}"))
}

#[tokio::main]
async fn main() -> Result<()> {
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.json".to_string());
    let cfg = Config::load(&config_path)?;
    let state = Arc::new(State::from_config(&cfg)?);

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.port));
    let listener = TcpListener::bind(addr).await.with_context(|| format!("failed to listen on {addr}"))?;

    let acceptor = match &cfg.ssl {
        Some(ssl) => Some(build_acceptor(ssl).await?),
        None => None,
    };
    let proto: &'static str = if acceptor.is_some() { "https" } else { "http" };

    println!("rgate started, listening on {proto}://{addr}");
    println!("  static file root: {}", state.webroot.display());
    for rule in &state.rules {
        println!("  proxy rule: {} -> {}", rule.key, rule.target);
    }

    loop {
        let (stream, peer) = listener.accept().await?;
        let state = state.clone();
        let acceptor = acceptor.clone();
        tokio::spawn(async move {
            match acceptor {
                Some(acc) => match acc.accept(stream).await {
                    Ok(s) => serve_conn(state, peer, proto, TokioIo::new(s)).await,
                    Err(e) => eprintln!("[tls] {peer} handshake failed: {e}"),
                },
                None => serve_conn(state, peer, proto, TokioIo::new(stream)).await,
            }
        });
    }
}
