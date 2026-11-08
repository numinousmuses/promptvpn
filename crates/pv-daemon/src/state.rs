//! Daemon state: paths, bootstrap from SQLite + vault, live reconfiguration.

use crate::models::{ClassifierKind, ClassifierSelection, ModelManager};
use anyhow::{anyhow, Context, Result};
use pv_audit::{Db, JsonTable};
use pv_core::*;
use pv_detectors::semantic::Concept;
use pv_detectors::{Detector, DetectorSettings};
use pv_provider::{CredentialFn, Registry};
use pv_proxy::notify::{Desktop, NotificationSettings, Notifier, RateLimited, Recorder};
use pv_proxy::{Engine, Settings};
use pv_vault::keys::{FileBackend, KeyBackend, KeychainBackend, MemoryBackend};
use pv_vault::Vault;
use rand::RngCore;
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use std::sync::Arc;
use zeroize::Zeroizing;

pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const DEFAULT_PORT: u16 = 8787;

#[derive(Debug, Clone)]
pub struct Paths {
    pub data: PathBuf,
}

impl Paths {
    /// `PV_HOME` overrides; otherwise the OS data dir.
    pub fn resolve() -> Paths {
        if let Ok(h) = std::env::var("PV_HOME") {
            return Paths { data: PathBuf::from(h) };
        }
        let d = directories::ProjectDirs::from("dev", "promptvpn", "promptvpn").map(|p| p.data_dir().to_path_buf()).unwrap_or_else(|| PathBuf::from(".promptvpn"));
        Paths { data: d }
    }
    pub fn db(&self) -> PathBuf {
        self.data.join("promptvpn.db")
    }
    pub fn admin_token(&self) -> PathBuf {
        self.data.join("admin.token")
    }
    pub fn key_file(&self) -> PathBuf {
        self.data.join("keys.insecure.json")
    }
    pub fn pid(&self) -> PathBuf {
        self.data.join("daemon.pid")
    }
    pub fn port_file(&self) -> PathBuf {
        self.data.join("daemon.port")
    }
    pub fn log(&self) -> PathBuf {
        self.data.join("daemon.log")
    }
    pub fn models(&self) -> PathBuf {
        self.data.join("models")
    }
    pub fn app_key(&self, app: &str) -> PathBuf {
        self.data.join("apps").join(format!("{app}.key"))
    }
    pub fn backups(&self) -> PathBuf {
        self.data.join("client-backups")
    }
}

pub fn write_private(path: &Path, data: &[u8]) -> std::io::Result<()> {
    use std::io::Write;
    if let Some(d) = path.parent() {
        std::fs::create_dir_all(d)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let _ = std::fs::set_permissions(d, std::fs::Permissions::from_mode(0o700));
        }
    }
    let mut o = std::fs::OpenOptions::new();
    o.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        o.mode(0o600);
    }
    let mut f = o.open(path)?;
    f.write_all(data)?;
    f.sync_all()
}

pub fn random_hex(n: usize) -> String {
    let mut b = vec![0u8; n];
    rand::rngs::OsRng.fill_bytes(&mut b);
    hex::encode(b)
}

/// Which key backend to use: `keychain` (default), `file` (degraded), `memory` (tests).
pub fn key_backend(paths: &Paths) -> Result<Arc<dyn KeyBackend>> {
    match std::env::var("PV_KEY_BACKEND").as_deref() {
        Ok("file") => Ok(Arc::new(FileBackend { path: paths.key_file() })),
        Ok("memory") => Ok(Arc::new(MemoryBackend::default())),
        _ => {
            let account = format!("keyset:{}", &hex::encode(sha2_digest(paths.data.to_string_lossy().as_bytes()))[..16]);
            Ok(Arc::new(KeychainBackend::new("promptvpn", &account).map_err(|e| anyhow!(e))?))
        }
    }
}

fn sha2_digest(b: &[u8]) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(b).to_vec()
}

/// Concept stored in the vault (sealed) together with its policy action.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredConcept {
    pub concept: Concept,
    pub action: Action,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuidanceNote {
    pub id: String,
    pub text: String,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct OnboardingState {
    pub completed: bool,
    pub completed_at: Option<String>,
    pub version: u32,
    pub near_skipped: bool,
}

pub struct AppState {
    pub paths: Paths,
    pub engine: Arc<Engine>,
    pub models: Arc<ModelManager>,
    pub admin_token: Zeroizing<String>,
    pub sessions: crate::auth::Sessions,
    pub port: std::sync::atomic::AtomicU16,
    pub started: chrono::DateTime<chrono::Utc>,
    pub key_backend: Arc<dyn KeyBackend>,
    pub recorder: Arc<Recorder>,
    pub notify_settings: Arc<RateLimited<Arc<dyn Notifier>>>,
    pub shutdown: tokio::sync::Notify,
    pub creds: Arc<Credentials>,
}

/// Credential store: OS keychain, or the vault when running on the file backend.
pub struct Credentials {
    vault: Arc<Vault>,
    use_keychain: bool,
}

impl Credentials {
    pub fn new(vault: Arc<Vault>, use_keychain: bool) -> Self {
        Credentials { vault, use_keychain }
    }
    pub fn set(&self, r: &str, secret: &str) -> Result<()> {
        if self.use_keychain {
            keyring::Entry::new("promptvpn", &format!("cred:{r}"))?.set_password(secret)?;
        } else {
            self.vault.put_sealed("credential", r, secret.as_bytes())?;
        }
        Ok(())
    }
    pub fn get(&self, r: &str) -> Option<Zeroizing<String>> {
        if self.use_keychain {
            keyring::Entry::new("promptvpn", &format!("cred:{r}")).ok()?.get_password().ok().map(Zeroizing::new)
        } else {
            self.vault.get_sealed("credential", r).ok().flatten().map(|b| Zeroizing::new(String::from_utf8_lossy(&b).into_owned()))
        }
    }
    pub fn delete(&self, r: &str) {
        if self.use_keychain {
            if let Ok(e) = keyring::Entry::new("promptvpn", &format!("cred:{r}")) {
                let _ = e.delete_credential();
            }
        } else {
            let _ = self.vault.delete_sealed("credential", r);
        }
    }
}

pub struct Boot {
    pub state: Arc<AppState>,
}

pub fn load_or_create_admin_token(paths: &Paths) -> Result<Zeroizing<String>> {
    match std::fs::read_to_string(paths.admin_token()) {
        Ok(s) if s.trim().len() >= 32 => Ok(Zeroizing::new(s.trim().to_string())),
        _ => {
            let t = format!("pva_{}", random_hex(32));
            write_private(&paths.admin_token(), t.as_bytes()).context("write admin token")?;
            Ok(Zeroizing::new(t))
        }
    }
}

/// Open everything. `notifier` override is used by tests.
pub async fn bootstrap(paths: Paths, notifier: Option<Arc<dyn Notifier>>) -> Result<Arc<AppState>> {
    std::fs::create_dir_all(&paths.data)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = std::fs::set_permissions(&paths.data, std::fs::Permissions::from_mode(0o700));
    }
    let db = Db::open(&paths.db()).context("open database")?;
    let backend = key_backend(&paths)?;
    let vault = Arc::new(Vault::open(db.clone(), backend.clone()).map_err(|e| anyhow!("{e}"))?);
    let creds = Arc::new(Credentials::new(vault.clone(), backend.secure()));
    let cf = creds.clone();
    let cred_fn: CredentialFn = Arc::new(move |r: &str| cf.get(r));
    let registry = Arc::new(Registry::new(cred_fn));

    // Policies: install defaults on first run.
    if db.active_policies()?.is_empty() {
        for r in default_policy(&default_category_choices()).rules {
            db.put_policy(&r, "builtin")?;
        }
    }
    let policy = PolicySet { rules: db.active_policies()? };
    policy.validate().map_err(|e| anyhow!("stored policy invalid: {e}"))?;
    let settings: Settings = db.setting("engine")?.unwrap_or_default();

    let detector = Arc::new(Detector::default());
    detector.set_settings(db.setting::<DetectorSettings>("detector")?.unwrap_or_default());

    let recorder = Arc::new(Recorder::default());
    let base: Arc<dyn Notifier> = notifier.unwrap_or_else(|| Arc::new(Desktop));
    let fanout: Arc<dyn Notifier> = Arc::new(Fanout(vec![base, recorder.clone()]));
    let nsettings: NotificationSettings = db.setting("notifications")?.unwrap_or_default();
    let rl = Arc::new(RateLimited::new(fanout, nsettings));

    let engine = Arc::new(Engine::new(db.clone(), vault.clone(), detector.clone(), registry.clone(), rl.clone(), policy, settings));
    engine.reload_exact().map_err(|e| anyhow!(e))?;

    let models = Arc::new(ModelManager::new(paths.clone(), detector.clone()));
    let state = Arc::new(AppState {
        admin_token: load_or_create_admin_token(&paths)?,
        paths,
        engine,
        models,
        sessions: crate::auth::Sessions::default(),
        port: std::sync::atomic::AtomicU16::new(DEFAULT_PORT),
        started: chrono::Utc::now(),
        key_backend: backend,
        recorder,
        notify_settings: rl,
        shutdown: tokio::sync::Notify::new(),
        creds,
    });
    reload_concepts(&state)?;
    reload_providers(&state)?;
    let sel: ClassifierSelection = state.engine.db.setting("classifier")?.unwrap_or_default();
    state.models.apply_selection(&sel).await;
    state.models.load_span_model();
    state.engine.housekeeping();
    Ok(state)
}

struct Fanout(Vec<Arc<dyn Notifier>>);
impl Notifier for Fanout {
    fn notify(&self, n: pv_proxy::notify::Notification) {
        for x in &self.0 {
            x.notify(n.clone());
        }
    }
}

impl AppState {
    pub fn creds(&self) -> Arc<Credentials> {
        self.creds.clone()
    }
    pub fn db(&self) -> &Db {
        &self.engine.db
    }
    pub fn vault(&self) -> &Arc<Vault> {
        &self.engine.vault
    }
    pub fn base_url(&self) -> String {
        format!("http://127.0.0.1:{}/v1", self.port.load(std::sync::atomic::Ordering::Relaxed))
    }
}

pub fn concepts(state: &AppState) -> Result<Vec<StoredConcept>> {
    let mut out = Vec::new();
    for (_, b) in state.vault().list_sealed("concept")? {
        out.push(serde_json::from_slice(&b)?);
    }
    Ok(out)
}

pub fn guidance(state: &AppState) -> Result<Vec<GuidanceNote>> {
    let mut out = Vec::new();
    for (_, b) in state.vault().list_sealed("guidance")? {
        out.push(serde_json::from_slice(&b)?);
    }
    Ok(out)
}

pub fn reload_concepts(state: &AppState) -> Result<()> {
    state.engine.detector.set_concepts(concepts(state)?.into_iter().map(|c| c.concept).collect());
    state.engine.detector.set_guidance(guidance(state)?.into_iter().map(|g| g.text).collect());
    Ok(())
}

pub fn reload_policy(state: &AppState) -> Result<()> {
    let p = PolicySet { rules: state.db().active_policies()? };
    p.validate().map_err(|e| anyhow!("{e}"))?;
    state.engine.set_policy(p);
    Ok(())
}

pub fn reload_providers(state: &AppState) -> Result<()> {
    let providers: Vec<ProviderConfig> = state.db().list_json(JsonTable::Providers)?;
    for p in providers.iter().filter(|p| p.kind == ProviderKind::NearAi) {
        let key = p.credential_ref.as_deref().and_then(|r| state.creds().get(r)).map(|k| k.to_string());
        if std::env::var("PV_NEAR_MOCK").is_ok() {
            continue; // tests install mock backends explicitly
        }
        match pv_provider::near::NearSdkBackend::new(&p.base_url, key) {
            Ok(b) => state.engine.registry.set_near_backend(&p.id, Arc::new(b)),
            Err(e) => tracing::error!("NEAR backend {}: {e}", p.id),
        }
    }
    state.engine.registry.set_providers(providers);
    Ok(())
}

/// Persist engine settings and apply them live.
pub fn save_settings(state: &AppState, s: &Settings, actor: &str) -> Result<()> {
    state.db().set_setting("engine", s, actor)?;
    state.engine.set_settings(s.clone());
    Ok(())
}

/// Create a local caller app; returns the key (shown once).
pub fn create_app(state: &AppState, name: &str, agent_id: Option<String>, destination_id: Option<String>) -> Result<(pv_audit::AppRecord, String)> {
    let key = format!("pvk_{}", random_hex(24));
    let rec = pv_audit::AppRecord {
        app_id: format!("app_{}", &random_hex(6)),
        name: name.to_string(),
        key_hash: crate::auth::key_hash(&key),
        agent_id,
        destination_id,
        created_at: chrono::Utc::now().to_rfc3339(),
        revoked_at: None,
    };
    state.db().put_app(&rec)?;
    Ok((rec, key))
}

pub fn classifier_kind_label(k: ClassifierKind) -> &'static str {
    match k {
        ClassifierKind::None => "none",
        ClassifierKind::Qwen3guard => "qwen3guard",
        ClassifierKind::Lfm3 => "lfm3",
    }
}
