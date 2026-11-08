//! Span-level PII recognition through an embedded GLiNER runtime (not Ollama).

use pv_core::category::*;
use pv_core::{ClassifierType, Finding};

pub trait SpanModel: Send + Sync {
    fn id(&self) -> String;
    /// Synchronous; callers run it on a blocking thread.
    fn detect(&self, text: &str) -> Result<Vec<Finding>, String>;
}

/// GLiNER labels requested from the model, with the built-in category each maps to.
pub const GLINER_LABELS: &[(&str, &str)] = &[
    ("name", PERSON),
    ("username", PERSON),
    ("email address", EMAIL),
    ("phone number", PHONE),
    ("location address", ADDRESS),
    ("location street", ADDRESS),
    ("dob", DOB),
    ("ssn", GOVERNMENT_ID),
    ("passport number", PASSPORT),
    ("driver license", DRIVER_LICENSE),
    ("credit card", PAYMENT_CARD),
    ("cvv", PAYMENT_CARD),
    ("bank account", FINANCIAL_ACCOUNT),
    ("account number", FINANCIAL_ACCOUNT),
    ("routing number", FINANCIAL_ACCOUNT),
    ("condition", HEALTH_INFORMATION),
    ("drug", HEALTH_INFORMATION),
    ("medical code", HEALTH_INFORMATION),
    ("healthcare number", HEALTH_INFORMATION),
    ("password", AUTH_SECRET),
];

pub fn label_to_category(label: &str) -> Option<&'static str> {
    GLINER_LABELS.iter().find(|(l, _)| *l == label).map(|(_, c)| *c)
}

/// Map a character-offset span (as some runtimes report) to byte offsets.
pub fn char_to_byte(text: &str, start_char: usize, end_char: usize) -> Option<(usize, usize)> {
    let mut idx: Vec<usize> = text.char_indices().map(|(b, _)| b).collect();
    idx.push(text.len());
    Some((*idx.get(start_char)?, *idx.get(end_char)?))
}

/// Locate a model-reported entity text near its reported offset, returning byte offsets.
pub fn locate_entity(text: &str, entity: &str, hint_byte: usize) -> Option<(usize, usize)> {
    if entity.is_empty() {
        return None;
    }
    let mut best: Option<(usize, usize)> = None;
    let mut from = 0;
    while let Some(p) = text[from..].find(entity) {
        let s = from + p;
        let d = s.abs_diff(hint_byte);
        if best.is_none_or(|(bs, _)| s.abs_diff(hint_byte) < bs.abs_diff(hint_byte)) {
            best = Some((s, s + entity.len()));
        }
        if d == 0 {
            break;
        }
        from = s + entity.len().max(1);
        if from >= text.len() {
            break;
        }
    }
    best
}

/// Shape checks applied to span-model output. GLiNER is good at context but
/// labels product names and countries as IDs/addresses; critical categories
/// block requests, so their spans must look like the thing they claim to be.
pub fn plausible(category: &str, text: &str) -> bool {
    let digits = text.chars().filter(|c| c.is_ascii_digit()).count();
    let letters = text.chars().filter(|c| c.is_alphabetic()).count();
    match category {
        ADDRESS => digits >= 1 && text.split_whitespace().count() >= 2,
        DRIVER_LICENSE | PASSPORT | GOVERNMENT_ID | FINANCIAL_ACCOUNT | PAYMENT_CARD => digits >= 5,
        PHONE => digits >= 7,
        EMAIL => text.contains('@'),
        DOB => digits >= 2,
        AUTH_SECRET => text.chars().count() >= 8 && !text.contains(char::is_whitespace) && digits >= 1 && letters >= 1,
        HEALTH_INFORMATION => letters >= 4 && !text.contains('%') && !(text.len() <= 5 && text.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())),
        PERSON => letters >= 2 && text.chars().next().is_some_and(|c| c.is_uppercase()),
        _ => true,
    }
}

pub fn make_finding(category: &str, s: usize, e: usize, prob: f32, version: &str) -> Finding {
    let mut f = Finding::new(ClassifierType::Builtin, category, s, e, prob.clamp(0.0, 1.0), "gliner-pii-edge", "span-model", sensitivity_of(category));
    f.classifier_version = version.into();
    f
}

#[cfg(feature = "gliner")]
pub mod gliner_impl {
    use super::*;
    use gliner::model::input::text::TextInput;
    use gliner::model::params::Parameters;
    use gliner::model::pipeline::token::TokenMode;
    use gliner::model::GLiNER;
    use orp::params::RuntimeParameters;
    use std::sync::Mutex;

    pub struct GlinerModel {
        model: Mutex<GLiNER<TokenMode>>,
        version: String,
    }

    impl GlinerModel {
        pub fn load(tokenizer: &str, onnx: &str, threshold: f32, version: &str) -> Result<Self, String> {
            let threads = std::thread::available_parallelism().map(|n| n.get().min(4)).unwrap_or(2);
            let model = GLiNER::<TokenMode>::new(
                Parameters::default().with_threshold(threshold).with_max_length(Some(512)),
                RuntimeParameters::default().with_threads(threads),
                tokenizer,
                onnx,
            )
            .map_err(|e| format!("gliner load: {e}"))?;
            Ok(GlinerModel { model: Mutex::new(model), version: version.into() })
        }
    }

    impl SpanModel for GlinerModel {
        fn id(&self) -> String {
            self.version.clone()
        }

        fn detect(&self, text: &str) -> Result<Vec<Finding>, String> {
            let labels: Vec<&str> = GLINER_LABELS.iter().map(|(l, _)| *l).collect();
            let mut out = Vec::new();
            // Chunk on line boundaries to stay inside the model's max length.
            let mut chunks: Vec<(usize, &str)> = Vec::new();
            let mut start = 0;
            while start < text.len() {
                let mut end = (start + 1500).min(text.len());
                while !text.is_char_boundary(end) {
                    end -= 1;
                }
                if end < text.len() {
                    if let Some(nl) = text[start..end].rfind(['\n', '.', ' ']) {
                        if nl > 200 {
                            end = start + nl + 1;
                        }
                    }
                }
                chunks.push((start, &text[start..end]));
                start = end;
            }
            let model = self.model.lock().map_err(|_| "gliner lock poisoned".to_string())?;
            for (base, chunk) in chunks {
                let input = TextInput::from_str(&[chunk], &labels).map_err(|e| e.to_string())?;
                let output = model.inference(input).map_err(|e| e.to_string())?;
                for spans in output.spans {
                    for s in spans {
                        let Some(cat) = label_to_category(s.class()) else { continue };
                        let (cs, _ce) = s.offsets();
                        let hint = char_to_byte(chunk, cs, cs).map(|(b, _)| b).unwrap_or(0);
                        if !plausible(cat, s.text()) {
                            continue;
                        }
                        if let Some((a, b)) = locate_entity(chunk, s.text(), hint) {
                            out.push(make_finding(cat, base + a, base + b, s.probability(), &self.version));
                        }
                    }
                }
            }
            Ok(out)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn plausibility_filters_known_false_positives() {
        assert!(!plausible(ADDRESS, "France"));
        assert!(!plausible(ADDRESS, "Springfield"));
        assert!(plausible(ADDRESS, "42 Oak Street"));
        assert!(!plausible(DRIVER_LICENSE, "Orion-7"));
        assert!(plausible(DRIVER_LICENSE, "D1234567"));
        assert!(!plausible(AUTH_SECRET, "HBM4"));
        assert!(!plausible(AUTH_SECRET, "OPENAI_API_KEY"));
        assert!(plausible(AUTH_SECRET, "Tr0ub4dor&3"));
        assert!(!plausible(HEALTH_INFORMATION, "FP8"));
        assert!(!plausible(HEALTH_INFORMATION, "12%"));
        assert!(plausible(HEALTH_INFORMATION, "type 2 diabetes"));
        assert!(plausible(PERSON, "Maria Gonzalez"));
    }

    #[test]
    fn mapping_and_locate() {
        assert_eq!(label_to_category("ssn"), Some(GOVERNMENT_ID));
        assert_eq!(label_to_category("money"), None);
        let t = "é Jane met Jane";
        assert_eq!(char_to_byte(t, 2, 6), Some((3, 7)));
        assert_eq!(locate_entity(t, "Jane", 12), Some((12, 16)));
        assert_eq!(locate_entity(t, "Jane", 0), Some((3, 7)));
    }
}
