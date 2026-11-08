# Prompt VPN build progress

Tracks every requirement in `docs/spec-v1.4.md` against what is built and tested.
Status keys: `[ ]` not started, `[~]` partial, `[x]` done and tested, `[!]` blocked (see notes).

## Phase 0: contracts and threat model
- [x] Typed schemas (Policy, Finding, Decision, TransformMap, AuditEvent, PendingApproval, ProviderConfig, ClientIntegration) with version fields
- [~] JSON Schema export + TypeScript generation + OpenAPI
- [ ] Threat model + trust-boundary diagram (`docs/threat-model.md`)
- [ ] Policy semantics doc
- [x] Executable architecture tests: precedence, audit privacy, block behavior

## Phase 1: daemon, CLI, proxy, vault, dashboard shell
- [x] Axum daemon bound to 127.0.0.1 only, port-conflict strategy
- [x] Admin auth (install token), session login, CSRF/Origin/Host checks, no CORS
- [x] AEAD vault (XChaCha20-Poly1305), key IDs, OS keychain DEK, rotation, recovery export
- [x] SQLite with migrations + migration tests
- [x] Audit events: hash-chain + MAC, 30-day retention, export, delete, verify
- [x] Mock upstream recording exact bytes
- [ ] Gate: SSN never reaches mock upstream; tokenized email restored; events omit values

## Phase 2: classifiers, Ollama, policy editor
- [x] Built-in recognizers for all 15 concepts (checksums, context cues)
- [x] Encoded data (base64, URL, JSON escapes) and Unicode confusables
- [x] Exact-value matcher with policy-selected normalizations, keyed fingerprints
- [~] Semantic concepts via Ollama classifier (Qwen3Guard / LFM), one active
- [~] GLiNER PII Edge embedded span adapter
- [x] Overlap merge preserving secret findings
- [~] Ollama detect / install prompt / auto-pull with progress + identity check
- [~] models.lock.json
- [ ] Eval corpus + benchmark harness with required metrics
- [ ] Gate: reproducible metrics; model failure triggers fallback without leakage

## Phase 3: approvals, streaming, integrations
- [~] REQUIRE_APPROVAL / BLOCK_AND_REVIEW: immediate PV_APPROVAL_REQUIRED, encrypted 15-min pending
- [~] Approve once, deny, edit-and-retry, whitelist, blacklist, save-as-rule, guidance notes
- [~] Owner-only reveal of pending plaintext
- [~] Desktop notifications (macOS/Linux) with rate limit, no plaintext
- [x] Chat Completions: non-stream, stream, tools
- [x] Responses API: non-stream, stream, tools
- [x] Output inspection + bounded streaming safety buffer + restoration
- [ ] Client integrations with backup/rollback
- [ ] Gate: no bypass via streaming, retries, edits, approval reuse

## Phase 4: setup skill and packaging
- [ ] `skills/promptvpn-setup/SKILL.md` + scripts + tests + adapters
- [ ] Release packaging for macOS arm64/x86_64, Linux x86_64/arm64, checksums + signatures
- [ ] Daemon autostart (launchd / systemd user) with consent
- [ ] Uninstall preserving data by default
- [ ] Gate: clean-environment skill demo end-to-end

## Phase 5: NEAR AI Gateway
- [~] Model discovery, auth, OpenAI-compatible invocation
- [~] Attestation verification bound to model + nonce
- [~] Completion signature verification
- [~] PRIVATE_ROUTE only to verified eligible endpoints; no downgrade
- [ ] Gate: real NEAR inference + verification

## Dashboard
- [ ] Onboarding wizard (6 steps, consent never pre-checked)
- [ ] Overview, Activity, Event detail, Policies + playground, Categories, Secrets, Concepts, Apps, Models/Destinations, Approvals, Settings, Health

## Docs
- [ ] README with limitations and coverage boundary
- [ ] docs/deviations.md

## Log
- 2026-11-08: pv-core, detectors, audit, vault, transform, provider, proxy, daemon built; 120+ unit tests; 13 HTTP gate tests green.
- 2026-11-08: NEAR live check: DeepSeek-V4.1-Flash-1017 verifies (gateway TLS-bound + model TDX + NRAS GPU); spec's DeepSeek-V4-Flash is an alias of z-ai/glm-5.3-flash and is rejected. No NEAR API key on this machine, so live inference is blocked on Joshua.
- 2026-11-08: gline-rs vendored with two ModernBERT fixes; GLiNER edge finds name/email/phone/SSN/health in ~20 ms.
- 2026-11-08: Qwen3Guard (hf.co/mradermacher Q8_0) verified by weight sha256; lfm3:1.7b on macOS resolves to MLX nvfp4, pinned by platform manifest digest.
