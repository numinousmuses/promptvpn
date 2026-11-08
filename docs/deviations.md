# Deviations from spec v1.4

Each entry: what differs, why, user-visible impact. Items marked **needs Joshua** are product or access decisions I did not make unilaterally.

## Provider and model facts that contradict the spec

1. **`deepseek-ai/DeepSeek-V4-Flash` is not a NEAR TEE model (needs Joshua).** On the live gateway (checked 2026-11-08) this ID is an alias of `z-ai/glm-5.3-flash`. Without `x-no-aliasing`, a request for "DeepSeek" silently runs GLM and returns GLM's attestation. Prompt VPN sends `x-no-aliasing: true` and checks the catalog, so this ID is rejected as not eligible. The NEAR-operated TEE DeepSeek is `deepseek-ai/DeepSeek-V4.1-Flash-1017`, which passes full verification live. The wizard proposes it as the candidate but the user must select it explicitly, as section 2.4 requires when the preferred model is not eligible. Impact: the spec's default cannot be honored; Joshua should confirm V4.1-Flash-1017 (or another verified model) as the new preferred default.

2. **Real NEAR inference gate not yet run (needs Joshua).** There is no NEAR AI API key on this machine. Attestation verification works without a key and passes live (`cargo test -p pv-provider --test live_near -- --ignored`). Chat inference, E2EE and response-signature verification need a key; the code path is the official SDK's and is exercised with a mock backend in tests. Run `promptvpn near login` then `promptvpn near test` to close Phase 5's gate.

3. **LFM3 on Apple Silicon with Ollama 0.40.12.** `lfm3:1.7b` resolves to an MLX nvfp4 build that ignores the JSON schema in `format`. The explicit GGUF tag needs a newer Ollama, and Liquid's GGUF fails on 0.40.12 (`unknown model architecture: 'lfm3'`). Prompt VPN keeps the schema and adds a bounded recovery parser that extracts concept matches from malformed output; recovered matches are never treated as isolated spans (so they block rather than transform), and output with nothing recognizable still fails closed. Identity: the platform manifest digest is pinned for the MLX build and the GGUF weight hash for other platforms. Impact: LFM3 works but is the slowest and least precise configuration (see evaluation).

4. **LFM3 license (needs Joshua).** LFM Open License v1.0 permits commercial use only for organizations under USD 10M annual revenue. The wizard and skill show this; Qwen3Guard (Apache-2.0) is the unrestricted option.

5. **Qwen3Guard has no official Ollama package.** Prompt VPN pulls `hf.co/mradermacher/Qwen3Guard-Gen-0.6B-GGUF:Q8_0`, verifies the weight blob SHA-256, and builds the model's official prompt-moderation template itself (`raw` generate), because Ollama does not reproduce the guard template for hf.co pulls. Owner concepts are appended as extra guard categories; Qwen3Guard was not trained on custom categories, so concept recall is measured, not assumed.

6. **GLiNER runtime is vendored and patched.** gline-rs 1.1.0 assumed DeBERTa token IDs and an older logits layout; with `gliner-pii-edge-v1.0` every score was negative. `third_party/gline-rs/PROMPTVPN_PATCH.md` documents both fixes. GLiNER output also passes a shape check (an ID needs digits, an address needs a number) because the model labels product names and countries as IDs and addresses.

## Behavioral choices made within the contract

7. **Responses API on private routes is translated to Chat Completions.** NEAR field E2EE covers Chat only. Clients still receive Responses-format output.
8. **Streamed NEAR responses carry a gateway signature**, not a model-TEE signature (SDK and gateway behavior). Receipts record which kind was verified.
9. **Placeholder scope without a conversation header** is `app:<hash of the first two content fields>`. Clients that send `X-PromptVPN-Conversation` get exact scoping.
10. **`FALLBACK` action.** An internal policy action that resolves to `PRIVATE_ROUTE` or `REQUIRE_APPROVAL` from the owner's fallback setting, so default rules don't hardcode a choice the user makes in onboarding.
11. **Local private handling without TEE consent.** With TEE routing selected and only "allow local model" enabled, uncertain content goes to local Ollama (it never leaves the device). With block-and-review selected it is always held.
12. **Whitelist / blacklist on held requests.** Whitelist registers the flagged noncritical values as allowlisted and approves once; critical values cannot be allowlisted. Blacklist registers flagged values as blocked exact secrets and denies.
13. **Redundant model judgements are dropped.** A semantic classifier's whole-field "other personal data" flag is ignored for a field where deterministic recognizers already localized personal data. Before this, LFM3 sent 38% of ordinary PII requests to review.
14. **Additional error codes**: `PV_UNAUTHORIZED`, `PV_BAD_REQUEST`, `PV_PAYLOAD_TOO_LARGE`, `PV_OUTPUT_BLOCKED`. Approval-required uses HTTP 428.
15. **Exact values default to case-insensitive, Unicode-folded, whitespace-normalized matching.** Separator stripping stays opt-in to avoid broad collisions.
16. **Client integrations** cover Codex, Aider, opencode and environment variables. Other clients get instructions only, per the skill's stop conditions.

## Verification gaps

17. **Linux runtime not exercised on this machine.** There is no Docker or Linux host available locally. `.github/workflows/ci.yml` runs the full test suite, skill tests and the privacy gate on Ubuntu x86_64 and ARM64 (and both macOS architectures) once the repository is pushed. The Linux keyring backend (`linux-native-sync-persistent`) and `notify-send` notifications are untested until then.
18. **Release signing key** was generated locally (`~/.promptvpn-release/release_key`, private key not in the repo; public key in `skills/promptvpn-setup/scripts/release-key.pub`). For real releases the private key should move to a CI secret (`PROMPTVPN_RELEASE_SSH_KEY`) and the local copy be removed.
19. **Desktop notifications** use `osascript` (macOS) and `notify-send` (Linux) without an app bundle identity, so macOS shows them as Script Editor notifications.
