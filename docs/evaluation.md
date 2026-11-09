# Evaluation

Reproduce: `python3 -I scripts/gen_eval_corpus.py > tests/fixtures/eval_corpus.jsonl` then `promptvpn eval --configs all --gliner-dir <gliner files> --out docs/eval/results.json`. Raw results for the run below: `docs/eval/results-2026-11-08.json` (and `.md`).

## Setup

- Corpus: 223 synthetic cases (seed 7), all values fake. 103 critical labels (SSNs incl. invalid ranges and undelimited, 7 API key formats, cards, PEM/OpenSSH keys, passwords, JWT, URL credentials, passports, driver's licenses), noncritical PII (emails in prose/code/markdown/JSON, phones, addresses, DOB, health, IBAN, accounts), names, overlaps, registered exact values with case/space variants, 8 semantic-only business disclosures across 3 concepts, encoding and Unicode evasion, tool arguments, tool results, logs, prompt injection, a ~20 KB context, 25 hard negatives, and 15 "hard" variants.
- Policy: defaults, destination `EXTERNAL_UNVERIFIED`, fallback block-and-review, concepts set to BLOCK.
- Hardware: Apple M-series Mac (18 cores, 48 GB), Ollama 0.40.12. Qwen3Guard: `hf.co/mradermacher/Qwen3Guard-Gen-0.6B-GGUF:Q8_0` (llama.cpp runner). LFM3: `lfm3:1.7b` (MLX nvfp4 runner on Apple Silicon).
- Each config includes the deterministic recognizers and exact matcher; "gliner" adds the span model; the generative configs add one classifier on top of deterministic (GLiNER off, to isolate its effect).

## Results (2026-11-08)

| config | critical escapes | decision accuracy | false-block rate | utility kept | p50 ms | p95 ms | peak RSS MB | tok/s |
|---|---|---|---|---|---|---|---|---|
| deterministic | 1/103 | 0.960 | 0.000 | 0.884 | 0.2 | 1.7 | 30 | - |
| gliner | 1/103 | 0.960 | 0.000 | 0.884 | 10.1 | 16.6 | 369 | - |
| qwen3guard | 0/103 | 0.955 | 0.009 | 0.884 | 82 | 114 | 372 | 174 |
| lfm3 | 0/103 | 0.928 | 0.134 | 0.854 | 848 | 3129 | 373 | 83 |

Semantic concept recall / precision (8 disclosures):

| config | accelerator specs | negotiations | unreleased financials |
|---|---|---|---|
| deterministic, gliner | 0 / - | 0 / - | 0 / - |
| qwen3guard | 0 / - | 0 / - | 0 / - |
| lfm3 | 1.00 / 0.75 | 1.00 / 0.16 | 0.50 / 1.00 |

Peak RSS is process-wide and cumulative across configs in one run (the first config's 30 MB is the deterministic baseline; GLiNER adds ~340 MB). Generative model memory lives in Ollama and is not included.

## What the numbers say

- **Deterministic recognizers carry the critical protection.** The single escape is an SSN spelled out in words ("two one nine, zero nine, ..."). Qwen3Guard and LFM3 catch it only as "possibly sensitive", which routes it to review.
- **GLiNER adds no measured benefit on this corpus**, because the corpus is dominated by structured identifiers the recognizers already cover. It earns its place on free-text names, conditions and lowercase or unstructured entities (it caught `maria gonzalez` and `metformin` in manual checks) at ~10 ms per request. Its raw output needed a plausibility filter: unfiltered, it labeled "France" an address and "Orion-7" a driver's license.
- **Qwen3Guard does not learn custom concepts.** Appending owner concepts as extra guard categories produced zero recall. It is a good, fast general PII backstop (0.9% false blocks) but cannot enforce Type 3 concepts. **Joshua: if semantic concepts matter, Qwen3Guard alone does not deliver them.**
- **LFM3 is the only configuration that enforces concepts**, at a cost: 13% of benign or PII-only prompts were blocked, almost all ordinary email prompts misread as the "confidential negotiations" concept, and p95 latency is 3 s on the MLX runner. Results vary between runs on the MLX runner (unreleased-financials recall was 1.0 in one run, 0.5 in this one). An evidence-grounding filter was tried and removed: it cut true matches without fixing the false ones.
- **Utility**: 85–88% of non-sensitive bytes survive in transformed requests; the remainder are context words captured inside spans (for example "DOB:" cues or address tails).

## Caveats

- The corpus was written alongside the recognizers, and 15 "hard" cases were added specifically to find gaps (8 were fixed afterwards). Treat deterministic recall as optimistic. Zero observed escapes is a finite-sample result on 103 critical labels, not a bound.
- Latency is classifier time only, measured in-process; end-to-end proxy overhead adds HTTP and policy time (sub-millisecond for policy).
- LFM3 ran on Ollama's MLX backend, which ignores the JSON schema; on platforms with GGUF + grammar enforcement its behavior may differ.
- Required for each release: rerun all four configs (`--configs all`); CI runs the deterministic privacy gate on every push.
