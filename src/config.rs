use anyhow::{Context, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::path::PathBuf;

/// config.json 对应的配置结构
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
    /// 路径前缀 -> 上游地址。命中前缀的请求将被反向代理。
    #[serde(default)]
    pub proxy: HashMap<String, String>,
    /// 配置后启用 HTTPS（监听 port），未配置则使用明文 HTTP。
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
            .with_context(|| format!("读取配置文件 {path} 失败"))?;
        let cfg: Config =
            serde_json::from_str(&raw).with_context(|| format!("解析配置文件 {path} 失败"))?;
        Ok(cfg)
    }
}
