//! Local classifier lifecycle: Ollama detection, consented pulls with progress,
//! weight identity checks against models.lock.json, GLiNER provisioning.

use crate::state::Paths;
use pv_detectors::ollama::{install_instructions, Ollama};
use pv_detectors::semantic::{LfmClassifier, QwenGuardClassifier, SemanticClassifier};
use pv_detectors::Detector;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::Duration;

pub const MODELS_LOCK: &str = include_str!("../../../models.lock.json");

pub fn lock() -> Value {
    serde_json::from_str(MODELS_LOCK).expect("models.lock.json is valid")
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ClassifierKind {
    #[default]
    None,
    Qwen3guard,
    Lfm3,
}

impl ClassifierKind {
    pub fn lock_key(self) -> Option<&'static str> {
        match self {
            ClassifierKind::None => None,
            ClassifierKind::Qwen3guard => Some("qwen3guard"),
            ClassifierKind::Lfm3 => Some("lfm3"),
        }
    }
    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "none" | "off" => Some(ClassifierKind::None),
            "qwen3guard" | "qwen3guard-gen-0.6b" | "qwen" => Some(ClassifierKind::Qwen3guard),
            "lfm3" | "lfm3-1.7b" | "lfm" => Some(ClassifierKind::Lfm3),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ClassifierSelection {
    pub kind: ClassifierKind,
    pub ollama_url: String,
}

impl Default for ClassifierSelection {
    fn default() -> Self {
        ClassifierSelection { kind: ClassifierKind::None, ollama_url: "http://127.0.0.1:11434".into() }
    }
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct PullJob {
    pub id: String,
    pub model: String,
    pub status: String,
    pub completed: u64,
    pub total: u64,
    pub done: bool,
    pub error: Option<String>,
    pub verified_digest: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct ClassifierStatus {
    pub selected: ClassifierKind,
    pub active: bool,
    pub model: Option<String>,
    pub verified_digest: Option<String>,
    pub error: Option<String>,
}

#[derive(Debug, Clone, Serialize, Default)]
pub struct SpanStatus {
    pub compiled: bool,
    pub provisioned: bool,
    pub loaded: bool,
    pub revision: String,
    pub error: Option<String>,
}

pub struct ModelManager {
    paths: Paths,
    detector: Arc<Detector>,
    pub jobs: Mutex<HashMap<String, PullJob>>,
    pub classifier: Mutex<ClassifierStatus>,
    pub span: Mutex<SpanStatus>,
}

pub fn pull_name(kind: ClassifierKind) -> Option<String> {
    let l = lock();
    kind.lock_key().and_then(|k| l["generative"][k]["ollama_pull"].as_str().map(String::from))
}

pub fn allowed_digests(kind: ClassifierKind) -> Vec<String> {
    let l = lock();
    kind.lock_key()
        .and_then(|k| l["generative"][k]["weights_sha256"].as_array().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|v| v.as_str().map(String::from))
        .collect()
}

pub fn allowed_manifests(kind: ClassifierKind) -> Vec<String> {
    let l = lock();
    kind.lock_key()
        .and_then(|k| l["generative"][k]["manifest_digests"].as_object().cloned())
        .unwrap_or_default()
        .into_iter()
        .filter_map(|(_, v)| v.as_str().map(String::from))
        .collect()
}

pub fn os_name() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

impl ModelManager {
    pub fn new(paths: Paths, detector: Arc<Detector>) -> Self {
        ModelManager {
            paths,
            detector,
            jobs: Mutex::new(HashMap::new()),
            classifier: Mutex::new(ClassifierStatus::default()),
            span: Mutex::new(SpanStatus { compiled: cfg!(feature = "gliner"), revision: lock()["span"]["gliner-pii-edge"]["revision"].as_str().unwrap_or_default().into(), ..Default::default() }),
        }
    }

    pub async fn ollama_status(&self, url: &str) -> Value {
        match Ollama::new(url) {
            Err(e) => serde_json::json!({"url": url, "reachable": false, "error": e.to_string()}),
            Ok(o) => match o.version().await {
                Ok(v) => {
                    let tags = o.tags().await.unwrap_or_default();
                    let installed: HashMap<&str, bool> = [ClassifierKind::Qwen3guard, ClassifierKind::Lfm3]
                        .iter()
                        .map(|k| (k.lock_key().unwrap(), pull_name(*k).map(|n| tags.iter().any(|t| t.name == n || t.name == format!("{n}:latest"))).unwrap_or(false)))
                        .collect();
                    serde_json::json!({"url": url, "reachable": true, "version": v, "installed": installed, "models": tags.iter().map(|t| &t.name).collect::<Vec<_>>()})
                }
                Err(_) => serde_json::json!({"url": url, "reachable": false, "install": install_instructions(os_name())}),
            },
        }
    }

    /// Activate the selected classifier only after verifying weight identity.
    pub async fn apply_selection(&self, sel: &ClassifierSelection) -> ClassifierStatus {
        let mut st = ClassifierStatus { selected: sel.kind, ..Default::default() };
        if sel.kind == ClassifierKind::None {
            self.detector.set_semantic(None);
            *self.classifier.lock().unwrap() = st.clone();
            return st;
        }
        let name = pull_name(sel.kind).unwrap_or_default();
        st.model = Some(name.clone());
        let result: Result<(Arc<dyn SemanticClassifier>, String), String> = async {
            let o = Ollama::new(&sel.ollama_url).map_err(|e| e.to_string())?;
            o.version().await.map_err(|_| format!("Ollama not reachable at {}. {}", sel.ollama_url, install_instructions(os_name())))?;
            if !o.has_model(&name).await.map_err(|e| e.to_string())? {
                return Err(format!("{name} is not installed; run `promptvpn model install {}`", sel.kind.lock_key().unwrap()));
            }
            let digest = o.verify_identity(&name, &allowed_digests(sel.kind), &allowed_manifests(sel.kind)).await.map_err(|e| e.to_string())?;
            let timeout = Duration::from_secs(20);
            let c: Arc<dyn SemanticClassifier> = match sel.kind {
                ClassifierKind::Lfm3 => Arc::new(LfmClassifier { ollama: o, model: name.clone(), timeout }),
                ClassifierKind::Qwen3guard => Arc::new(QwenGuardClassifier { ollama: o, model: name.clone(), timeout }),
                ClassifierKind::None => unreachable!(),
            };
            Ok((c, digest))
        }
        .await;
        match result {
            Ok((c, d)) => {
                self.detector.set_semantic(Some(c));
                st.active = true;
                st.verified_digest = Some(d);
            }
            Err(e) => {
                // Selected but unusable: leave it unset so detection fails closed.
                self.detector.set_semantic(None);
                st.error = Some(e);
            }
        }
        *self.classifier.lock().unwrap() = st.clone();
        st
    }

    /// Start a consented pull. Returns the job id; progress via `jobs`.
    pub fn start_pull(self: &Arc<Self>, kind: ClassifierKind, url: &str) -> Result<String, String> {
        let name = pull_name(kind).ok_or("no model for this classifier")?;
        let o = Ollama::new(url).map_err(|e| e.to_string())?;
        let id = format!("pull_{}", uuid::Uuid::new_v4().simple());
        self.jobs.lock().unwrap().insert(id.clone(), PullJob { id: id.clone(), model: name.clone(), status: "starting".into(), ..Default::default() });
        let me = self.clone();
        let jid = id.clone();
        tokio::spawn(async move {
            let r = o
                .pull(&name, |p| {
                    let mut j = me.jobs.lock().unwrap();
                    if let Some(job) = j.get_mut(&jid) {
                        job.status = p.status.clone();
                        if let Some(t) = p.total {
                            job.total = t;
                        }
                        if let Some(c) = p.completed {
                            job.completed = c;
                        }
                    }
                })
                .await;
            let verified = match &r {
                Ok(()) => o.verify_identity(&name, &allowed_digests(kind), &allowed_manifests(kind)).await.map_err(|e| e.to_string()),
                Err(e) => Err(e.to_string()),
            };
            let mut j = me.jobs.lock().unwrap();
            if let Some(job) = j.get_mut(&jid) {
                job.done = true;
                match verified {
                    Ok(d) => {
                        job.status = "verified".into();
                        job.verified_digest = Some(d);
                    }
                    Err(e) => {
                        job.status = "failed".into();
                        job.error = Some(e);
                    }
                }
            }
        });
        Ok(id)
    }

    fn gliner_dir(&self) -> std::path::PathBuf {
        self.paths.models().join("gliner-pii-edge")
    }

    fn gliner_files() -> Vec<(String, String, String)> {
        let l = lock();
        let files = l["span"]["gliner-pii-edge"]["files"].as_object().cloned().unwrap_or_default();
        files
            .into_iter()
            .map(|(local, f)| (local, f["path"].as_str().unwrap_or_default().to_string(), f["sha256"].as_str().unwrap_or_default().to_string()))
            .collect()
    }

    pub fn gliner_provisioned(&self) -> Result<(), String> {
        for (local, _, sha) in Self::gliner_files() {
            let p = self.gliner_dir().join(&local);
            let b = std::fs::read(&p).map_err(|_| format!("missing {local}"))?;
            if hex::encode(Sha256::digest(&b)) != sha {
                return Err(format!("{local} hash mismatch"));
            }
        }
        Ok(())
    }

    /// Download pinned GLiNER files from Hugging Face and verify hashes.
    pub async fn provision_gliner(&self) -> Result<(), String> {
        let l = lock();
        let g = &l["span"]["gliner-pii-edge"];
        let repo = g["source"].as_str().unwrap_or_default().trim_start_matches("https://huggingface.co/").to_string();
        let rev = g["revision"].as_str().unwrap_or_default().to_string();
        let http = reqwest::Client::builder().timeout(Duration::from_secs(600)).build().map_err(|e| e.to_string())?;
        std::fs::create_dir_all(self.gliner_dir()).map_err(|e| e.to_string())?;
        for (local, remote, sha) in Self::gliner_files() {
            let dest = self.gliner_dir().join(&local);
            if let Ok(b) = std::fs::read(&dest) {
                if hex::encode(Sha256::digest(&b)) == sha {
                    continue;
                }
            }
            let url = format!("https://huggingface.co/{repo}/resolve/{rev}/{remote}");
            let r = http.get(&url).send().await.map_err(|e| format!("download {local}: {e}"))?;
            if !r.status().is_success() {
                return Err(format!("download {local}: HTTP {}", r.status()));
            }
            let b = r.bytes().await.map_err(|e| e.to_string())?;
            if hex::encode(Sha256::digest(&b)) != sha {
                return Err(format!("{local}: sha256 mismatch; refusing to install"));
            }
            let tmp = dest.with_extension("part");
            std::fs::write(&tmp, &b).map_err(|e| e.to_string())?;
            std::fs::rename(&tmp, &dest).map_err(|e| e.to_string())?;
        }
        self.span.lock().unwrap().provisioned = true;
        Ok(())
    }

    /// Load GLiNER if compiled in and provisioned with verified files.
    pub fn load_span_model(&self) {
        let mut st = self.span.lock().unwrap();
        st.provisioned = self.gliner_provisioned().is_ok();
        if !st.compiled {
            st.error = Some("built without the gliner feature".into());
            return;
        }
        if let Err(e) = self.gliner_provisioned() {
            st.error = Some(format!("not provisioned ({e}); run `promptvpn model install gliner`"));
            self.detector.set_span(None);
            return;
        }
        #[cfg(feature = "gliner")]
        {
            let dir = self.gliner_dir();
            let thr = lock()["span"]["gliner-pii-edge"]["threshold"].as_f64().unwrap_or(0.5) as f32;
            match pv_detectors::span::gliner_impl::GlinerModel::load(
                &dir.join("tokenizer.json").to_string_lossy(),
                &dir.join("model.onnx").to_string_lossy(),
                thr,
                &format!("gliner-pii-edge@{}", &st.revision[..7.min(st.revision.len())]),
            ) {
                Ok(m) => {
                    self.detector.set_span(Some(Arc::new(m)));
                    st.loaded = true;
                    st.error = None;
                }
                Err(e) => st.error = Some(e),
            }
        }
    }

    pub fn status(&self) -> Value {
        serde_json::json!({
            "classifier": *self.classifier.lock().unwrap(),
            "span": *self.span.lock().unwrap(),
            "jobs": self.jobs.lock().unwrap().values().cloned().collect::<Vec<_>>(),
            "lock": lock(),
        })
    }
}
