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

/// 上游协议
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

/// 解析后的代理目标，如 "http://web:8080/web"
#[derive(Debug, Clone)]
pub struct ProxyTarget {
    pub scheme: Scheme,
    pub host: String,
    pub port: u16,
    /// host:port 形式的 authority
    pub authority: String,
    /// 上游路径前缀（如 /web），可为空
    pub prefix: String,
}

impl ProxyTarget {
    pub fn parse(target: &str) -> Result<ProxyTarget> {
        let uri: Uri = target.parse().with_context(|| format!("非法代理目标: {target}"))?;
        let scheme = match uri.scheme_str() {
            Some("http") => Scheme::Http,
            Some("https") => Scheme::Https,
            other => bail!("代理协议不支持 {other:?}，仅支持 http/https"),
        };
        let authority = uri
            .authority()
            .ok_or_else(|| anyhow!("代理目标缺少主机: {target}"))?
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

/// 拆出 host 与 port，缺省端口 http 为 80、https 为 443
fn split_authority(authority: &str, scheme: Scheme) -> (String, u16) {
    let default_port = if scheme == Scheme::Https { 443 } else { 80 };
    if let Some((host, port)) = authority.rsplit_once(':') {
        // 跳过裸 IPv6 地址（形如 [::1] 或 ::1）
        if !host.is_empty() && !host.contains("]") {
            if let Ok(p) = port.parse::<u16>() {
                return (host.to_string(), p);
            }
        }
    }
    (authority.to_string(), default_port)
}

/// 一条代理规则：路径前缀 -> 上游
#[derive(Debug, Clone)]
pub struct ProxyRule {
    pub key: String,
    pub target: ProxyTarget,
}

impl ProxyRule {
    /// 前缀匹配：/web 命中 /web 与 /web/**，但不命中 /webfoo
    pub fn matches(&self, path: &str) -> bool {
        let key = self.key.trim_end_matches('/');
        if key.is_empty() {
            return true; // key 为 "/" 时匹配所有路径
        }
        path == key || path.starts_with(&format!("{key}/"))
    }
}

/// 转发一条请求到上游。支持普通 HTTP 与 WebSocket 升级。
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
        .with_context(|| format!("连接上游 {} 失败", target.authority))?;
    match target.scheme {
        Scheme::Http => forward_io(req, rule, peer, proto, TokioIo::new(tcp)).await,
        Scheme::Https => {
            let name = ServerName::try_from(target.host.clone())
                .map_err(|e| anyhow!("上游主机名非法: {e}"))?;
            let tls = connector
                .connect(name, tcp)
                .await
                .context("上游 TLS 握手失败")?;
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

    // WebSocket 升级请求需要原样保留 Connection / Upgrade 头
    let is_ws = is_upgrade_request(&req);
    let client_upgrade = req.extensions_mut().remove::<OnUpgrade>();

    let (parts, body) = req.into_parts();

    // 拼接上游路径：/web/foo（key=/web，上游前缀=/web）→ /web/foo
    let suffix = path_suffix(&rule.key, parts.uri.path());
    let mut pq = join_path(&target.prefix, &suffix);
    if let Some(q) = parts.uri.query() {
        pq.push('?');
        pq.push_str(q);
    }
    // origin-form（仅路径+查询），主机信息通过 Host 头传递
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

    // 每个代理请求使用独立上游连接；with_upgrades 使 101 响应可升级
    let (mut sender, conn) = hyper::client::conn::http1::handshake(io).await?;
    tokio::spawn(async move {
        if let Err(e) = conn.with_upgrades().await {
            eprintln!("[proxy] 上游连接关闭: {e}");
        }
    });

    let mut res = sender.send_request(upstream_req).await?;
    let status = res.status();
    let upstream_upgrade = res.extensions_mut().remove::<OnUpgrade>();

    // 响应同样剥掉逐跳头；101 需保留 Connection / Upgrade 以触发客户端升级
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

    // 双向透传 WebSocket 字节流
    if status == StatusCode::SWITCHING_PROTOCOLS {
        let client_up = client_upgrade.ok_or_else(|| anyhow!("缺少客户端升级句柄"))?;
        let upstream_up = upstream_upgrade.ok_or_else(|| anyhow!("上游未返回升级句柄"))?;
        tokio::spawn(async move {
            let client_up = match client_up.await {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("[ws] 客户端升级失败: {e}");
                    return;
                }
            };
            let upstream_up = match upstream_up.await {
                Ok(io) => io,
                Err(e) => {
                    eprintln!("[ws] 上游升级失败: {e}");
                    return;
                }
            };
            // Upgraded 实现 hyper 自身的 IO trait，用 TokioIo 适配到 tokio
            let mut client_io = TokioIo::new(client_up);
            let mut upstream_io = TokioIo::new(upstream_up);
            if let Err(e) = tokio::io::copy_bidirectional(&mut client_io, &mut upstream_io).await {
                eprintln!("[ws] 连接中断: {e}");
            }
            eprintln!("[ws] 连接结束");
        });
    }

    Ok(out)
}

/// 计算匹配 key 之后剩余的路径：/web/foo（key=/web）→ /foo
fn path_suffix(key: &str, path: &str) -> String {
    let key = key.trim_end_matches('/');
    if key.is_empty() {
        path.to_string()
    } else {
        path.strip_prefix(key).unwrap_or(path).to_string()
    }
}

/// 上游前缀 + 剩余路径 拼成完整路径
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

/// 剥离逐跳头；keep_upgrade 为 true 时保留 Connection / Upgrade
fn strip_hop_by_hop(headers: &mut header::HeaderMap, keep_upgrade: bool) {
    for name in HOP_BY_HOP {
        if keep_upgrade && (*name == "connection" || *name == "upgrade") {
            continue;
        }
        headers.remove(*name);
    }
    headers.remove(header::HOST);
}

/// 判断是否为 WebSocket 升级请求
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

/// 供访问 https 上游使用的客户端 TLS 连接器（内置根证书，ALPN 限定 http/1.1）
pub fn build_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let mut cfg = rustls::ClientConfig::builder()
        .with_root_certificates(roots)
        .with_no_client_auth();
    cfg.alpn_protocols = vec![b"http/1.1".to_vec()];
    TlsConnector::from(std::sync::Arc::new(cfg))
}

/// 上游不可达等错误时使用的 502 响应
pub fn bad_gateway() -> Response<ResBody> {
    error(StatusCode::BAD_GATEWAY, "502 Bad Gateway\n")
}
