//! Minimal Ollama client: status, tags, pull with progress, identity check,
//! raw generate and structured chat. Ollama must be on loopback.

use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use std::time::Duration;

#[derive(Debug, thiserror::Error)]
pub enum OllamaError {
    #[error("ollama not reachable at {0}")]
    Unreachable(String),
    #[error("ollama base URL must be loopback (127.0.0.1, ::1 or localhost)")]
    NotLoopback,
    #[error("ollama error: {0}")]
    Api(String),
    #[error("model identity mismatch: {0}")]
    Identity(String),
    #[error("timeout")]
    Timeout,
}

#[derive(Clone)]
pub struct Ollama {
    pub base: String,
    http: reqwest::Client,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TagModel {
    pub name: String,
    #[serde(default)]
    pub digest: String,
    #[serde(default)]
    pub size: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct PullProgress {
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub digest: Option<String>,
    #[serde(default)]
    pub total: Option<u64>,
    #[serde(default)]
    pub completed: Option<u64>,
    #[serde(default)]
    pub error: Option<String>,
}

pub fn is_loopback_url(u: &str) -> bool {
    match url_host(u) {
        Some(h) => h == "127.0.0.1" || h == "::1" || h == "[::1]" || h == "localhost",
        None => false,
    }
}

fn url_host(u: &str) -> Option<String> {
    let rest = u.split("://").nth(1)?;
    let hostport = rest.split('/').next()?;
    let hostport = hostport.rsplit('@').next()?;
    if let Some(stripped) = hostport.strip_prefix('[') {
        return Some(format!("[{}]", stripped.split(']').next()?));
    }
    Some(hostport.split(':').next()?.to_ascii_lowercase())
}

impl Ollama {
    pub fn new(base: &str) -> Result<Self, OllamaError> {
        if !is_loopback_url(base) {
            return Err(OllamaError::NotLoopback);
        }
        let http = reqwest::Client::builder().no_proxy().connect_timeout(Duration::from_secs(3)).build().expect("client");
        Ok(Ollama { base: base.trim_end_matches('/').to_string(), http })
    }

    pub async fn version(&self) -> Result<String, OllamaError> {
        let r = self
            .http
            .get(format!("{}/api/version", self.base))
            .timeout(Duration::from_secs(3))
            .send()
            .await
            .map_err(|_| OllamaError::Unreachable(self.base.clone()))?;
        let v: Value = r.json().await.map_err(|e| OllamaError::Api(e.to_string()))?;
        Ok(v["version"].as_str().unwrap_or("unknown").to_string())
    }

    pub async fn tags(&self) -> Result<Vec<TagModel>, OllamaError> {
        let r = self
            .http
            .get(format!("{}/api/tags", self.base))
            .timeout(Duration::from_secs(5))
            .send()
            .await
            .map_err(|_| OllamaError::Unreachable(self.base.clone()))?;
        let v: Value = r.json().await.map_err(|e| OllamaError::Api(e.to_string()))?;
        Ok(serde_json::from_value(v["models"].clone()).unwrap_or_default())
    }

    pub async fn has_model(&self, name: &str) -> Result<bool, OllamaError> {
        let want = if name.contains(':') { name.to_string() } else { format!("{name}:latest") };
        Ok(self.tags().await?.iter().any(|m| m.name == want || m.name == name))
    }

    /// Pull a model, invoking `progress` for each NDJSON status line.
    pub async fn pull(&self, name: &str, mut progress: impl FnMut(&PullProgress)) -> Result<(), OllamaError> {
        use futures::StreamExt;
        let r = self
            .http
            .post(format!("{}/api/pull", self.base))
            .json(&json!({ "model": name, "stream": true }))
            .send()
            .await
            .map_err(|_| OllamaError::Unreachable(self.base.clone()))?;
        if !r.status().is_success() {
            return Err(OllamaError::Api(format!("pull HTTP {}", r.status())));
        }
        let mut stream = r.bytes_stream();
        let mut buf = Vec::new();
        let mut ok = false;
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|e| OllamaError::Api(e.to_string()))?;
            buf.extend_from_slice(&chunk);
            while let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let line: Vec<u8> = buf.drain(..=pos).collect();
                if let Ok(p) = serde_json::from_slice::<PullProgress>(&line) {
                    if let Some(e) = &p.error {
                        return Err(OllamaError::Api(e.clone()));
                    }
                    if p.status == "success" {
                        ok = true;
                    }
                    progress(&p);
                }
            }
        }
        if ok {
            Ok(())
        } else {
            Err(OllamaError::Api("pull ended without success".into()))
        }
    }

    pub async fn show(&self, name: &str) -> Result<Value, OllamaError> {
        let r = self
            .http
            .post(format!("{}/api/show", self.base))
            .json(&json!({ "model": name }))
            .timeout(Duration::from_secs(10))
            .send()
            .await
            .map_err(|_| OllamaError::Unreachable(self.base.clone()))?;
        if !r.status().is_success() {
            return Err(OllamaError::Api(format!("show HTTP {}", r.status())));
        }
        r.json().await.map_err(|e| OllamaError::Api(e.to_string()))
    }

    /// The model weight layer digest, read from the modelfile's `FROM .../sha256-<hex>`.
    pub async fn weight_digest(&self, name: &str) -> Result<String, OllamaError> {
        let v = self.show(name).await?;
        let mf = v["modelfile"].as_str().unwrap_or_default();
        for line in mf.lines() {
            if let Some(path) = line.strip_prefix("FROM ") {
                if let Some(idx) = path.rfind("sha256-") {
                    return Ok(path[idx + 7..].trim().to_string());
                }
            }
        }
        Err(OllamaError::Identity("no weight blob in modelfile".into()))
    }

    /// Manifest digest reported by /api/tags for an installed model.
    pub async fn manifest_digest(&self, name: &str) -> Result<String, OllamaError> {
        let want = if name.contains(':') { name.to_string() } else { format!("{name}:latest") };
        self.tags().await?.into_iter().find(|t| t.name == want || t.name == name).map(|t| t.digest).ok_or_else(|| OllamaError::Identity(format!("{name} not installed")))
    }

    /// Verify identity: the GGUF weight blob sha256 or the platform manifest
    /// digest must match a value pinned in models.lock.json.
    pub async fn verify_identity(&self, name: &str, allowed_weights: &[String], allowed_manifests: &[String]) -> Result<String, OllamaError> {
        if let Ok(d) = self.weight_digest(name).await {
            if allowed_weights.iter().any(|a| a.eq_ignore_ascii_case(&d)) {
                return Ok(format!("weights:sha256:{d}"));
            }
        }
        let m = self.manifest_digest(name).await?;
        if allowed_manifests.iter().any(|a| a.eq_ignore_ascii_case(&m)) {
            return Ok(format!("manifest:sha256:{m}"));
        }
        Err(OllamaError::Identity(format!("{name} (manifest {m}) does not match any digest pinned in models.lock.json")))
    }

    pub async fn generate_raw(&self, model: &str, prompt: &str, num_predict: u32, timeout: Duration) -> Result<(String, GenStats), OllamaError> {
        let body = json!({
            "model": model, "prompt": prompt, "raw": true, "stream": false, "keep_alive": "30m",
            "options": { "temperature": 0, "num_predict": num_predict }
        });
        let v = self.post_json("/api/generate", &body, timeout).await?;
        Ok((v["response"].as_str().unwrap_or_default().to_string(), GenStats::from(&v)))
    }

    pub async fn chat_structured(&self, model: &str, messages: Value, schema: Value, timeout: Duration) -> Result<(String, GenStats), OllamaError> {
        let body = json!({
            "model": model, "messages": messages, "format": schema, "stream": false, "think": false, "keep_alive": "30m",
            "options": { "temperature": 0, "num_predict": 512 }
        });
        let v = self.post_json("/api/chat", &body, timeout).await?;
        Ok((v["message"]["content"].as_str().unwrap_or_default().to_string(), GenStats::from(&v)))
    }

    async fn post_json(&self, path: &str, body: &Value, timeout: Duration) -> Result<Value, OllamaError> {
        let fut = self.http.post(format!("{}{}", self.base, path)).json(body).send();
        let r = tokio::time::timeout(timeout, fut).await.map_err(|_| OllamaError::Timeout)?.map_err(|_| OllamaError::Unreachable(self.base.clone()))?;
        let status = r.status();
        let v: Value = tokio::time::timeout(timeout, r.json()).await.map_err(|_| OllamaError::Timeout)?.map_err(|e| OllamaError::Api(e.to_string()))?;
        if !status.is_success() {
            return Err(OllamaError::Api(v["error"].as_str().unwrap_or("request failed").to_string()));
        }
        Ok(v)
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct GenStats {
    pub eval_count: u64,
    pub eval_duration_ns: u64,
    pub total_duration_ns: u64,
}

impl GenStats {
    fn from(v: &Value) -> Self {
        GenStats {
            eval_count: v["eval_count"].as_u64().unwrap_or(0),
            eval_duration_ns: v["eval_duration"].as_u64().unwrap_or(0),
            total_duration_ns: v["total_duration"].as_u64().unwrap_or(0),
        }
    }
    pub fn tokens_per_sec(&self) -> f64 {
        if self.eval_duration_ns == 0 {
            0.0
        } else {
            self.eval_count as f64 / (self.eval_duration_ns as f64 / 1e9)
        }
    }
}

/// Official install guidance; Prompt VPN never installs Ollama itself.
pub fn install_instructions(os: &str) -> &'static str {
    match os {
        "macos" => "Install Ollama from the official site: https://ollama.com/download/mac (requires macOS 14+). Open the app once so the `ollama` CLI is linked, then re-run `promptvpn ollama status`.",
        "linux" => "Install Ollama from the official site: https://ollama.com/download/linux . Review the script before running it (curl -fsSL https://ollama.com/install.sh -o ollama-install.sh && less ollama-install.sh && sh ollama-install.sh), or use the manual tarball from https://docs.ollama.com/linux . Then start it with `ollama serve`.",
        _ => "See https://ollama.com/download for official installers.",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn loopback() {
        assert!(is_loopback_url("http://127.0.0.1:11434"));
        assert!(is_loopback_url("http://localhost:11434/"));
        assert!(is_loopback_url("http://[::1]:11434"));
        assert!(!is_loopback_url("http://10.0.0.2:11434"));
        assert!(!is_loopback_url("http://127.0.0.1.evil.com:11434"));
        assert!(!is_loopback_url("http://localhost@evil.com:11434"));
    }
}
