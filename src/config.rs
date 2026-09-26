use anyhow::{anyhow, bail, Context, Result};
use quick_xml::events::{BytesStart, Event};
use quick_xml::Reader;
use std::path::PathBuf;

/// Configuration structure corresponding to config.xml
///
/// ```xml
/// <web>
///   <ports http="80" https="443"/>
///   <host>
///     <name value="test.yunp.top"/>
///     <ssl cert="certs/test.yunp.top.pem" key="certs/test.yunp.top.key"/>
///     <webroot value="www"/>
///     <proxy path="/web" target="http://127.0.0.1:9081/web"/>
///   </host>
///   <host>
///     <name value="yunp.top"/>
///     <name value="www.yunp.top"/>
///     <ssl cert="certs/yunp.top.pem" key="certs/yunp.top.key"/>
///     <webroot value="www"/>
///     <proxy path="/web" target="http://127.0.0.1:9082/web"/>
///   </host>
/// </web>
/// ```
#[derive(Debug)]
pub struct WebConfig {
    /// Port the plain-HTTP server listens on
    pub http_port: u16,
    /// When set, an HTTPS server listens on this port and all plain-HTTP
    /// requests are redirected to it; when absent, HTTPS stays disabled.
    pub https_port: Option<u16>,
    /// Virtual hosts, matched by Host header / SNI name; the first one is the default
    pub hosts: Vec<HostConfig>,
}

#[derive(Debug)]
pub struct HostConfig {
    /// Server names (lowercased) matched against the Host header and SNI
    pub names: Vec<String>,
    /// Certificate and private key for this host (required on every host when https is enabled)
    pub ssl: Option<SslConfig>,
    pub webroot: PathBuf,
    /// path prefix -> upstream address, in file order
    pub proxy: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct SslConfig {
    pub cert: PathBuf,
    pub key: PathBuf,
}

fn default_webroot() -> PathBuf {
    PathBuf::from("www")
}

impl WebConfig {
    pub fn load(path: &str) -> Result<WebConfig> {
        let raw = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read config file {path}"))?;
        let cfg = WebConfig::from_xml(&raw).with_context(|| format!("failed to parse config file {path}"))?;
        cfg.validate()?;
        Ok(cfg)
    }

    fn from_xml(xml: &str) -> Result<WebConfig> {
        let mut reader = Reader::from_str(xml);
        reader.config_mut().trim_text(true);

        let mut http_port: Option<u16> = None;
        let mut https_port: Option<u16> = None;
        let mut hosts: Vec<HostConfig> = Vec::new();
        // Host currently being built (between <host> and </host>)
        let mut host: Option<HostConfig> = None;

        let mut buf = Vec::new();
        loop {
            let (kind, event) = match reader.read_event_into(&mut buf) {
                Ok(Event::Start(e)) => (0, e),
                Ok(Event::Empty(e)) => (1, e),
                Ok(Event::End(e)) => {
                    if e.name().as_ref() == "host" {
                        if let Some(h) = host.take() {
                            hosts.push(h);
                        } else {
                            bail!("unexpected </host>");
                        }
                    }
                    buf.clear();
                    continue;
                }
                Ok(Event::Eof) => break,
                Ok(_) => {
                    buf.clear();
                    continue;
                }
                Err(e) => return Err(anyhow!(e.to_string())),
            };
            let e: BytesStart = event;

            match e.name().as_ref() {
                "ports" => {
                    if http_port.is_none() {
                        http_port = Some(
                            attr(&e, "http")
                                .and_then(|v| v.parse().ok())
                                .ok_or_else(|| anyhow!("<ports> is missing a valid http attribute"))?,
                        );
                    }
                    if https_port.is_none() {
                        https_port = attr(&e, "https").and_then(|v| v.parse().ok());
                    }
                }
                "host" if kind == 0 => {
                    if host.is_some() {
                        bail!("nested <host> elements are not allowed");
                    }
                    host = Some(HostConfig {
                        names: Vec::new(),
                        ssl: None,
                        webroot: default_webroot(),
                        proxy: Vec::new(),
                    });
                }
                "name" => {
                    let value = attr(&e, "value")
                        .ok_or_else(|| anyhow!("<name> is missing a value attribute"))?;
                    host.as_mut()
                        .ok_or_else(|| anyhow!("<name> outside of a <host> element"))?
                        .names
                        .push(value);
                }
                "ssl" => {
                    let cert = attr(&e, "cert")
                        .ok_or_else(|| anyhow!("<ssl> is missing a cert attribute"))?;
                    let key = attr(&e, "key")
                        .ok_or_else(|| anyhow!("<ssl> is missing a key attribute"))?;
                    let ssl = SslConfig { cert: cert.into(), key: key.into() };
                    host.as_mut()
                        .ok_or_else(|| anyhow!("<ssl> outside of a <host> element"))?
                        .ssl = Some(ssl);
                }
                "webroot" => {
                    let value = attr(&e, "value")
                        .ok_or_else(|| anyhow!("<webroot> is missing a value attribute"))?;
                    host.as_mut()
                        .ok_or_else(|| anyhow!("<webroot> outside of a <host> element"))?
                        .webroot = value.into();
                }
                "proxy" => {
                    let path = attr(&e, "path")
                        .ok_or_else(|| anyhow!("<proxy> is missing a path attribute"))?;
                    let target = attr(&e, "target")
                        .ok_or_else(|| anyhow!("<proxy> is missing a target attribute"))?;
                    host.as_mut()
                        .ok_or_else(|| anyhow!("<proxy> outside of a <host> element"))?
                        .proxy
                        .push((path, target));
                }
                _ => {}
            }
            buf.clear();
        }

        if host.take().is_some() {
            bail!("unclosed <host> element");
        }
        let http_port = http_port.ok_or_else(|| anyhow!("<ports> with a valid http attribute is required"))?;
        Ok(WebConfig { http_port, https_port, hosts })
    }

    fn validate(&self) -> Result<()> {
        if self.hosts.is_empty() {
            bail!("config contains no <host> elements");
        }
        for host in &self.hosts {
            if host.names.is_empty() {
                bail!("a <host> element has no <name> entries");
            }
            if self.https_port.is_some() && host.ssl.is_none() {
                bail!("https port is set but host {} has no <ssl> config", host.names[0]);
            }
        }
        Ok(())
    }
}

/// Extract an attribute value by key from a start/empty element
fn attr(e: &BytesStart, key: &str) -> Option<String> {
    e.attributes().find_map(|a| {
        a.ok().and_then(|a| (a.key.as_ref() == key).then(|| a.value.to_string()))
    })
}
