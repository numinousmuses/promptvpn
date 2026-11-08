# Prompt VPN build progress

Tracks every requirement in `docs/spec-v1.4.md` against what is built and tested.
Status keys: `[ ]` not started, `[~]` partial, `[x]` done and tested, `[!]` blocked (see notes).

## Phase 0: contracts and threat model
- [ ] Typed schemas (Policy, Finding, Decision, TransformMap, AuditEvent, PendingApproval, ProviderConfig, ClientIntegration) with version fields
- [ ] JSON Schema export + TypeScript generation + OpenAPI
- [ ] Threat model + trust-boundary diagram (`docs/threat-model.md`)
- [ ] Policy semantics doc
- [ ] Executable architecture tests: precedence, audit privacy, block behavior

## Phase 1: daemon, CLI, proxy, vault, dashboard shell
- [ ] Axum daemon bound to 127.0.0.1 only, port-conflict strategy
- [ ] Admin auth (install token), session login, CSRF/Origin/Host checks, no CORS
- [ ] AEAD vault (XChaCha20-Poly1305), key IDs, OS keychain DEK, rotation, recovery export
- [ ] SQLite with migrations + migration tests
- [ ] Audit events: hash-chain + MAC, 30-day retention, export, delete, verify
- [ ] Mock upstream recording exact bytes
- [ ] Gate: SSN never reaches mock upstream; tokenized email restored; events omit values

## Phase 2: classifiers, Ollama, policy editor
- [ ] Built-in recognizers for all 15 concepts (checksums, context cues)
- [ ] Encoded data (base64, URL, JSON escapes) and Unicode confusables
- [ ] Exact-value matcher with policy-selected normalizations, keyed fingerprints
- [ ] Semantic concepts via Ollama classifier (Qwen3Guard / LFM), one active
- [ ] GLiNER PII Edge embedded span adapter
- [ ] Overlap merge preserving secret findings
- [ ] Ollama detect / install prompt / auto-pull with progress + identity check
- [ ] models.lock.json
- [ ] Eval corpus + benchmark harness with required metrics
- [ ] Gate: reproducible metrics; model failure triggers fallback without leakage

## Phase 3: approvals, streaming, integrations
- [ ] REQUIRE_APPROVAL / BLOCK_AND_REVIEW: immediate PV_APPROVAL_REQUIRED, encrypted 15-min pending
- [ ] Approve once, deny, edit-and-retry, whitelist, blacklist, save-as-rule, guidance notes
- [ ] Owner-only reveal of pending plaintext
- [ ] Desktop notifications (macOS/Linux) with rate limit, no plaintext
- [ ] Chat Completions: non-stream, stream, tools
- [ ] Responses API: non-stream, stream, tools
- [ ] Output inspection + bounded streaming safety buffer + restoration
- [ ] Client integrations with backup/rollback
- [ ] Gate: no bypass via streaming, retries, edits, approval reuse

## Phase 4: setup skill and packaging
- [ ] `skills/promptvpn-setup/SKILL.md` + scripts + tests + adapters
- [ ] Release packaging for macOS arm64/x86_64, Linux x86_64/arm64, checksums + signatures
- [ ] Daemon autostart (launchd / systemd user) with consent
- [ ] Uninstall preserving data by default
- [ ] Gate: clean-environment skill demo end-to-end

## Phase 5: NEAR AI Gateway
- [ ] Model discovery, auth, OpenAI-compatible invocation
- [ ] Attestation verification bound to model + nonce
- [ ] Completion signature verification
- [ ] PRIVATE_ROUTE only to verified eligible endpoints; no downgrade
- [ ] Gate: real NEAR inference + verification

## Dashboard
- [ ] Onboarding wizard (6 steps, consent never pre-checked)
- [ ] Overview, Activity, Event detail, Policies + playground, Categories, Secrets, Concepts, Apps, Models/Destinations, Approvals, Settings, Health

## Docs
- [ ] README with limitations and coverage boundary
- [ ] docs/deviations.md

## Log
