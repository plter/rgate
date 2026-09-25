use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// Configuration structure corresponding to config.json
///
/// ```json
/// {
///   "port": 9001,
///   "webroot": "www",
///   "proxy": { "/web": "http://web:8080/web" },
///   "ssl": { "cert": "certs/cert.pem", "key": "certs/cert.key" }
/// }
/// ```
#[derive(Debug, Deserialize)]
pub struct Config {
    pub port: u16,
    #[serde(default = "default_webroot")]
    pub webroot: PathBuf,
    /// Path prefix -> upstream address. Requests matching a prefix are reverse-proxied.
    #[serde(default)]
    pub proxy: HashMap<String, String>,
    /// When set, HTTPS is enabled (listening on port); otherwise plain HTTP is used.
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
