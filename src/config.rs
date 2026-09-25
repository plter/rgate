use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration structure corresponding to config.json
///
/// ```json
/// {
///   "httpPort": 9001,
///   "httpsPort": 9002,
///   "webroot": "www",
///   "proxy": { "/web": "http://web:8080/web" },
///   "ssl": { "cert": "certs/cert.pem", "key": "certs/cert.key" }
/// }
/// ```
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Config {
    /// Port the plain-HTTP server listens on
    pub http_port: u16,
    /// When set, an HTTPS server listens on this port and all plain-HTTP
    /// requests are redirected to it; when absent, HTTPS stays disabled.
    pub https_port: Option<u16>,
    #[serde(default = "default_webroot")]
    pub webroot: PathBuf,
    /// Path prefix -> upstream address. Requests matching a prefix are reverse-proxied.
    #[serde(default)]
    pub proxy: HashMap<String, String>,
    /// Certificate and private key for the HTTPS server (required when httpsPort is set).
    pub ssl: Option<SslConfig>,
}

#[derive(Debug, Deserialize)]
pub struct SslConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn default_webroot() -> PathBuf {
    PathBuf::from("www")
}

impl Config {
    pub fn load(path: &str) -> Result<Config> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {path}"))?;
        let cfg: Config =
            serde_json::from_str(&raw).with_context(|| format!("failed to parse config file {path}"))?;
        Ok(cfg)
    }
}
