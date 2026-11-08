//! Detection pipeline: built-in recognizers, exact values, encoded views,
//! GLiNER spans and the local semantic classifier.

pub mod builtin;
pub mod encoded;
pub mod exact;
pub mod normalize;
pub mod ollama;
pub mod semantic;
pub mod span;

use pv_core::category::{self, CLASSIFIER_FAILURE};
use pv_core::{ClassifierType, Finding, Sensitivity};
use semantic::{Concept, Segment, SemanticClassifier};
use serde::{Deserialize, Serialize};
use span::SpanModel;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum SemanticMode {
    /// Never call the generative classifier.
    Off,
    /// Call it only when semantic concepts are configured.
    WhenConcepts,
    /// Call it on every inbound request.
    #[default]
    Always,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectorSettings {
    pub semantic_mode: SemanticMode,
    /// Run the GLiNER span model when one is loaded.
    pub span_enabled: bool,
    /// If true, a missing/failed span model is a classifier failure (fail closed).
    pub span_required: bool,
    pub semantic_timeout_ms: u64,
}

impl Default for DetectorSettings {
    fn default() -> Self {
        DetectorSettings { semantic_mode: SemanticMode::Always, span_enabled: true, span_required: false, semantic_timeout_ms: 15_000 }
    }
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct DetectionReport {
    pub findings: Vec<Finding>,
    pub recognizer_versions: Vec<String>,
    pub failures: Vec<String>,
    pub semantic_latency_ms: Option<u64>,
    pub span_latency_ms: Option<u64>,
    pub semantic_tokens_per_sec: Option<f64>,
    pub injection_suspected: bool,
}

/// Thread-safe detector shared by all requests. Components are swapped atomically
/// when the owner edits secrets, concepts or the selected model.
pub struct Detector {
    pub exact: RwLock<Arc<exact::ExactMatcher>>,
    pub span: RwLock<Option<Arc<dyn SpanModel>>>,
    pub semantic: RwLock<Option<Arc<dyn SemanticClassifier>>>,
    pub concepts: RwLock<Arc<Vec<Concept>>>,
    pub guidance: RwLock<Arc<Vec<String>>>,
    pub settings: RwLock<DetectorSettings>,
}

impl Default for Detector {
    fn default() -> Self {
        Detector {
            exact: RwLock::new(Arc::new(exact::ExactMatcher::default())),
            span: RwLock::new(None),
            semantic: RwLock::new(None),
            concepts: RwLock::new(Arc::new(vec![])),
            guidance: RwLock::new(Arc::new(vec![])),
            settings: RwLock::new(DetectorSettings::default()),
        }
    }
}

/// Deterministic detection (built-in + exact) over raw, confusable-folded and
/// unescaped views, plus base64-decoded blobs. Pure and synchronous.
pub fn detect_deterministic(text: &str, exact: &exact::ExactMatcher) -> Vec<Finding> {
    detect_det_depth(text, exact, 2)
}

fn detect_det_depth(text: &str, exact: &exact::ExactMatcher, depth: u8) -> Vec<Finding> {
    let mut out = builtin::detect(text);
    out.extend(exact.find(text));
    let conf = normalize::view(text, normalize::NormOpts::confusables());
    if conf.text != text {
        for mut f in builtin::detect(&conf.text) {
            if let Some((s, e)) = conf.map_span(f.start_byte, f.end_byte) {
                f.start_byte = s;
                f.end_byte = e;
                f.evidence = format!("{}+unicode-normalized", f.evidence);
                out.push(f);
            }
        }
    }
    if let Some(v) = encoded::unescaped_view(text) {
        let mut inner = builtin::detect(&v.text);
        inner.extend(exact.find(&v.text));
        for mut f in inner {
            if let Some((s, e)) = v.map_span(f.start_byte, f.end_byte) {
                f.start_byte = s;
                f.end_byte = e;
                f.evidence = format!("{}+unescaped", f.evidence);
                out.push(f);
            }
        }
    }
    out.extend(encoded::base64_findings(text, depth, &|s, d| detect_det_depth(s, exact, d)));
    let allowed = exact.allowed_spans(text);
    if !allowed.is_empty() {
        out.retain(|f| f.sensitivity == Sensitivity::Critical || !allowed.iter().any(|&(s, e)| s <= f.start_byte && f.end_byte <= e));
    }
    builtin::dedupe(out)
}

fn failure(field_index: usize, len: usize, what: &str) -> Finding {
    let mut f = Finding::new(ClassifierType::Semantic, CLASSIFIER_FAILURE, 0, len, 1.0, what, "classifier-failure", Sensitivity::High);
    f.field_index = field_index;
    f.whole_field = true;
    f
}

impl Detector {
    pub fn set_exact(&self, m: exact::ExactMatcher) {
        *self.exact.write().unwrap() = Arc::new(m);
    }
    pub fn set_concepts(&self, c: Vec<Concept>) {
        *self.concepts.write().unwrap() = Arc::new(c);
    }
    pub fn set_guidance(&self, g: Vec<String>) {
        *self.guidance.write().unwrap() = Arc::new(g);
    }
    pub fn set_semantic(&self, s: Option<Arc<dyn SemanticClassifier>>) {
        *self.semantic.write().unwrap() = s;
    }
    pub fn set_span(&self, s: Option<Arc<dyn SpanModel>>) {
        *self.span.write().unwrap() = s;
    }
    pub fn set_settings(&self, s: DetectorSettings) {
        *self.settings.write().unwrap() = s;
    }
    pub fn settings(&self) -> DetectorSettings {
        self.settings.read().unwrap().clone()
    }

    /// Detect over all fields. `semantic` controls whether model classifiers run
    /// (outbound inspection uses deterministic + span only unless policy needs more).
    pub async fn detect(&self, fields: &[String], use_models: bool) -> DetectionReport {
        let exact = self.exact.read().unwrap().clone();
        let settings = self.settings();
        let mut rep = DetectionReport { recognizer_versions: vec![builtin::VERSION.into()], ..Default::default() };
        if !exact.is_empty() {
            rep.recognizer_versions.push("exact-v1".into());
        }
        for (i, t) in fields.iter().enumerate() {
            for mut f in detect_deterministic(t, &exact) {
                f.field_index = i;
                rep.findings.push(f);
            }
        }
        let nonempty: Vec<usize> = (0..fields.len()).filter(|&i| !fields[i].trim().is_empty()).collect();
        if !use_models || nonempty.is_empty() {
            return rep;
        }

        // Span model (GLiNER) on a blocking thread.
        let span = self.span.read().unwrap().clone();
        if settings.span_enabled {
            match span {
                Some(model) => {
                    rep.recognizer_versions.push(model.id());
                    let t = Instant::now();
                    let texts: Vec<(usize, String)> = nonempty.iter().map(|&i| (i, fields[i].clone())).collect();
                    let m = model.clone();
                    let res = tokio::task::spawn_blocking(move || {
                        let mut out = Vec::new();
                        for (i, t) in texts {
                            for mut f in m.detect(&t)? {
                                if f.validate_against(&t).is_ok() {
                                    f.field_index = i;
                                    out.push(f);
                                }
                            }
                        }
                        Ok::<_, String>(out)
                    })
                    .await;
                    rep.span_latency_ms = Some(t.elapsed().as_millis() as u64);
                    match res {
                        Ok(Ok(f)) => rep.findings.extend(f),
                        _ => {
                            rep.failures.push("span-model".into());
                            let last = *nonempty.last().unwrap();
                            rep.findings.push(failure(last, fields[last].len(), "gliner-failure"));
                        }
                    }
                }
                None if settings.span_required => {
                    rep.failures.push("span-model-missing".into());
                    let last = *nonempty.last().unwrap();
                    rep.findings.push(failure(last, fields[last].len(), "gliner-missing"));
                }
                None => {}
            }
        }

        // Semantic classifier.
        let concepts = self.concepts.read().unwrap().clone();
        let guidance = self.guidance.read().unwrap().clone();
        let run_semantic = match settings.semantic_mode {
            SemanticMode::Off => false,
            SemanticMode::WhenConcepts => !concepts.is_empty(),
            SemanticMode::Always => true,
        };
        if run_semantic {
            let classifier = self.semantic.read().unwrap().clone();
            let last = *nonempty.last().unwrap();
            match classifier {
                None => {
                    // Required but not installed/selected: fail closed.
                    rep.failures.push("semantic-classifier-missing".into());
                    rep.findings.push(failure(last, fields[last].len(), "semantic-missing"));
                }
                Some(c) => {
                    rep.recognizer_versions.push(c.id());
                    let segs: Vec<Segment> = nonempty.iter().map(|&i| Segment { field_index: i, text: &fields[i] }).collect();
                    let timeout = Duration::from_millis(settings.semantic_timeout_ms);
                    match tokio::time::timeout(timeout, c.classify(&segs, &concepts, &guidance)).await {
                        Ok(Ok(out)) => {
                            rep.semantic_latency_ms = Some(out.latency_ms);
                            let tps = out.stats.tokens_per_sec();
                            if tps > 0.0 {
                                rep.semantic_tokens_per_sec = Some(tps);
                            }
                            rep.injection_suspected = out.injection_suspected;
                            for f in out.findings {
                                let ok = fields.get(f.field_index).is_some_and(|t| f.validate_against(t).is_ok());
                                if ok {
                                    rep.findings.push(f);
                                }
                            }
                        }
                        _ => {
                            rep.failures.push("semantic-classifier".into());
                            rep.findings.push(failure(last, fields[last].len(), "semantic-failure"));
                        }
                    }
                }
            }
        }
        // A model's whole-field "possibly sensitive" judgement is redundant when
        // localized recognizers already found personal data in that field.
        let localized: Vec<usize> = rep.findings.iter().filter(|f| !f.whole_field && f.classifier_type == ClassifierType::Builtin).map(|f| f.field_index).collect();
        rep.findings.retain(|f| !(f.category == category::UNCERTAIN && f.whole_field && localized.contains(&f.field_index)));
        rep.findings = builtin::dedupe(std::mem::take(&mut rep.findings));
        rep
    }
}

/// True if any finding is critical by category.
pub fn has_critical(findings: &[Finding]) -> bool {
    findings.iter().any(|f| category::is_critical(&f.category) || f.category == category::EXACT_SECRET)
}

#[cfg(test)]
mod tests {
    use super::*;
    use exact::{ExactEntry, ExactKind, ExactMatcher};
    use zeroize::Zeroizing;

    #[test]
    fn confusable_ssn_found() {
        let t = "ssn １２３-４５-６７８９";
        let f = detect_deterministic(t, &ExactMatcher::default());
        let g = f.iter().find(|f| f.category == "GOVERNMENT_ID").unwrap();
        assert_eq!(&t[g.start_byte..g.end_byte], "１２３-４５-６７８９");
    }

    #[test]
    fn allowlist_suppresses_noncritical_only() {
        let m = ExactMatcher::new(vec![
            ExactEntry { secret_id: "a".into(), kind: ExactKind::Value, value: Zeroizing::new("help@acme.test".into()), norm: Default::default(), allow: true },
            ExactEntry { secret_id: "b".into(), kind: ExactKind::Value, value: Zeroizing::new("123-45-6789".into()), norm: Default::default(), allow: true },
        ]);
        let f = detect_deterministic("help@acme.test 123-45-6789", &m);
        assert!(!f.iter().any(|f| f.category == "EMAIL"));
        assert!(f.iter().any(|f| f.category == "GOVERNMENT_ID"));
    }

    #[tokio::test]
    async fn semantic_missing_fails_closed() {
        let d = Detector::default();
        let r = d.detect(&["hello".into()], true).await;
        assert!(r.findings.iter().any(|f| f.category == CLASSIFIER_FAILURE));
    }

    #[tokio::test]
    async fn semantic_failure_fails_closed() {
        let d = Detector::default();
        d.set_semantic(Some(Arc::new(semantic::FailingClassifier)));
        let r = d.detect(&["hello".into()], true).await;
        assert!(r.findings.iter().any(|f| f.category == CLASSIFIER_FAILURE));
        assert_eq!(r.failures, vec!["semantic-classifier"]);
    }

    #[tokio::test]
    async fn semantic_off_skips() {
        let d = Detector::default();
        d.set_settings(DetectorSettings { semantic_mode: SemanticMode::Off, ..Default::default() });
        let r = d.detect(&["hello".into()], true).await;
        assert!(r.findings.is_empty());
    }

    #[tokio::test]
    async fn keyword_concepts() {
        let d = Detector::default();
        d.set_semantic(Some(Arc::new(semantic::KeywordClassifier)));
        d.set_concepts(vec![Concept { id: "c1".into(), name: "n".into(), description: "d".into(), safe_examples: vec![], sensitive_examples: vec!["nightjar".into()] }]);
        let r = d.detect(&["sys".into(), "about Nightjar".into()], true).await;
        let f = r.findings.iter().find(|f| f.category == "CONCEPT:c1").unwrap();
        assert_eq!(f.field_index, 1);
    }
}
