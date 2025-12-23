#![forbid(unsafe_code)]

use bytes::Bytes;
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum BootstrapSourceError {
    #[error("http error: {0}")]
    Http(String),
    #[error("invalid configuration: {0}")]
    Config(String),
    #[error("unsupported: {0}")]
    #[allow(dead_code)]
    Unsupported(String),
}

pub type Result<T> = std::result::Result<T, BootstrapSourceError>;

pub trait BootstrapSource: Send + Sync {
    fn fetch_index(&self) -> Result<Bytes>;
    fn fetch_artifact(&self, path: &str, range: Option<(u64, u64)>) -> Result<Bytes>;
    fn name(&self) -> &str;
}

#[derive(Clone)]
pub struct HttpSource {
    name: String,
    base_url: String,
    index_path: String,
    client: reqwest::blocking::Client,
}

impl HttpSource {
    pub fn new(
        name: impl Into<String>,
        base_url: impl Into<String>,
        index_path: impl Into<String>,
        connect_timeout: Duration,
        timeout: Duration,
    ) -> Result<Self> {
        let base_url = base_url.into();
        let index_path = index_path.into();
        if base_url.trim().is_empty() {
            return Err(BootstrapSourceError::Config(
                "base_url is empty".to_string(),
            ));
        }
        if index_path.trim().is_empty() {
            return Err(BootstrapSourceError::Config(
                "index_path is empty".to_string(),
            ));
        }
        let client = reqwest::blocking::Client::builder()
            .connect_timeout(connect_timeout)
            .timeout(timeout)
            .build()
            .map_err(|e| BootstrapSourceError::Http(e.to_string()))?;
        Ok(Self {
            name: name.into(),
            base_url: base_url.trim_end_matches('/').to_string(),
            index_path,
            client,
        })
    }

    pub fn base_url(&self) -> &str {
        &self.base_url
    }

    pub fn url_for(&self, rel_path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            rel_path.trim_start_matches('/')
        )
    }

    pub fn client(&self) -> &reqwest::blocking::Client {
        &self.client
    }
}

impl BootstrapSource for HttpSource {
    fn fetch_index(&self) -> Result<Bytes> {
        self.fetch_artifact(&self.index_path, None)
    }

    fn fetch_artifact(&self, path: &str, range: Option<(u64, u64)>) -> Result<Bytes> {
        let url = self.url_for(path);
        let mut req = self.client.get(&url);
        if let Some((start, end)) = range {
            req = req.header(reqwest::header::RANGE, format!("bytes={start}-{end}"));
        }
        let resp = req
            .send()
            .map_err(|e| BootstrapSourceError::Http(e.to_string()))?;
        let status = resp.status();
        if !status.is_success() {
            return Err(BootstrapSourceError::Http(format!(
                "GET {url} failed: http_status={status}"
            )));
        }
        resp.bytes()
            .map(|b| b.to_vec())
            .map(Bytes::from)
            .map_err(|e| BootstrapSourceError::Http(e.to_string()))
    }

    fn name(&self) -> &str {
        &self.name
    }
}

/// MVP peer-list mode uses HTTP gateways for peers.
#[derive(Clone)]
pub struct PeerSource {
    inner: HttpSource,
}

impl PeerSource {
    pub fn new(inner: HttpSource) -> Self {
        Self { inner }
    }

    pub fn base_url(&self) -> &str {
        self.inner.base_url()
    }

    pub fn url_for(&self, rel_path: &str) -> String {
        self.inner.url_for(rel_path)
    }

    pub fn client(&self) -> &reqwest::blocking::Client {
        self.inner.client()
    }
}

impl BootstrapSource for PeerSource {
    fn fetch_index(&self) -> Result<Bytes> {
        self.inner.fetch_index()
    }

    fn fetch_artifact(&self, path: &str, range: Option<(u64, u64)>) -> Result<Bytes> {
        self.inner.fetch_artifact(path, range)
    }

    fn name(&self) -> &str {
        self.inner.name()
    }
}

/// Optional future hook for true P2P/DHT transport.
///
/// MVP note: this type is only available when `fin-node` is built with
/// `--features bootstrap-ipndht`, and it always errors until a real transport
/// integration is added to this repository.
#[cfg(feature = "bootstrap-ipndht")]
#[allow(dead_code)]
pub struct IpndhtSource;

#[cfg(feature = "bootstrap-ipndht")]
impl BootstrapSource for IpndhtSource {
    fn fetch_index(&self) -> Result<Bytes> {
        Err(BootstrapSourceError::Unsupported(
            "IpndhtSource not built in this repo; enable in future integration".to_string(),
        ))
    }

    fn fetch_artifact(&self, _path: &str, _range: Option<(u64, u64)>) -> Result<Bytes> {
        Err(BootstrapSourceError::Unsupported(
            "IpndhtSource not built in this repo; enable in future integration".to_string(),
        ))
    }

    fn name(&self) -> &str {
        "ipndht"
    }
}
