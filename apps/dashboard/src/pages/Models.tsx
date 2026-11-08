import { useEffect, useState } from 'react';
import {
  del,
  get,
  post,
  type ClassifierKindName,
  type ModelsStatus,
  type NearModel,
  type NearVerification,
  type ProviderConfig,
  type ProviderEntry,
  type ProviderTest,
  type SettingsResponse,
} from '../api';
import { dateTime, shortHash } from '../format';
import {
  Badge,
  Button,
  Card,
  Check,
  ConfirmDialog,
  Dialog,
  Empty,
  ErrorText,
  Field,
  KV,
  Loading,
  Notice,
  PageHeader,
  Radio,
  SecretInput,
  TierBadge,
  type Loaded,
  useAction,
  useLoad,
} from '../ui';

export const DEFAULT_NEAR_CANDIDATE = 'deepseek-ai/DeepSeek-V4.1-Flash-1017';
export const LFM_LICENSE_NOTE = 'LFM Open License v1.0: commercial use is licensed only for organizations under USD 10M annual revenue.';

export const CLASSIFIERS: { kind: ClassifierKindName; name: string; blurb: string }[] = [
  { kind: 'qwen3guard', name: 'Qwen3Guard-Gen-0.6B', blurb: 'Small guard model for prompt moderation and PII categories. Apache-2.0.' },
  { kind: 'lfm3', name: 'LFM3-1.7B', blurb: 'Concept classifier with schema-constrained output. Better at your custom concepts.' },
  { kind: 'none', name: 'No generative classifier', blurb: 'Built-in recognizers, GLiNER and exact values only. Semantic concepts will not be checked.' },
];

/** TEE-capable NEAR candidates (before attestation). */
export const isTeeCandidate = (m: NearModel) => m.attestation_supported && (m.privacy_tier === 'PRIVATE_TEE' || m.privacy_tier === 'PRIVATE_3P_TEE');

// ------------------------------------------------------------------ pull progress

export function usePull(onDone?: () => void) {
  const [job, setJob] = useState<ModelsStatus['jobs'][number] | null>(null);
  const [jobId, setJobId] = useState<string | null>(null);
  const act = useAction();
  useEffect(() => {
    if (!jobId) return;
    let stop = false;
    const tick = async () => {
      try {
        const j = await get<ModelsStatus['jobs'][number]>('/models/jobs/' + encodeURIComponent(jobId));
        if (stop) return;
        setJob(j);
        if (j.done) {
          setJobId(null);
          onDone?.();
          return;
        }
      } catch (e) {
        act.setError(e instanceof Error ? e.message : String(e));
        setJobId(null);
        return;
      }
      if (!stop) window.setTimeout(tick, 1000);
    };
    void tick();
    return () => {
      stop = true;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [jobId]);
  const start = (kind: ClassifierKindName) =>
    act.run(async () => {
      setJob(null);
      const r = await post<{ job: string }>('/models/pull', { kind });
      setJobId(r.job);
    });
  return { job, running: !!jobId, start, error: act.error, busy: act.busy };
}

export function PullProgress({ job }: { job: ModelsStatus['jobs'][number] | null }) {
  if (!job) return null;
  const pct = job.total > 0 ? Math.min(100, Math.round((job.completed / job.total) * 100)) : job.done ? 100 : 0;
  return (
    <div className="stack-s">
      <div className="row between small">
        <span>
          {job.model}: {job.status}
        </span>
        <span className="muted">{job.total ? `${pct}%` : ''}</span>
      </div>
      <div className="progress" role="progressbar" aria-valuenow={pct} aria-valuemin={0} aria-valuemax={100}>
        <span style={{ width: `${pct}%` }} />
      </div>
      {job.error ? <Notice tone="error">{job.error}</Notice> : null}
      {job.done && !job.error && job.verified_digest ? <p className="small muted mono">verified {shortHash(job.verified_digest, 24)}</p> : null}
    </div>
  );
}

// ------------------------------------------------------------------ attestation

export function AttestationDetails({ v }: { v: NearVerification }) {
  return (
    <KV
      rows={[
        ['Result', v.eligible ? <Badge tone="dark">Eligible: {v.tier}</Badge> : <Badge tone="red">Not eligible</Badge>],
        ['Model', <span className="mono">{v.model}</span>],
        ['Error', v.error],
        ['Gateway signer', v.gateway_signer ? <span className="mono small">{v.gateway_signer}</span> : null],
        ['Gateway TCB', v.gateway_tcb],
        ['Gateway TLS key (SPKI)', v.gateway_tls_spki ? <span className="mono small">{v.gateway_tls_spki}</span> : null],
        ['Model signers', v.model_signers?.length ? <span className="mono small">{v.model_signers.join(', ')}</span> : null],
        ['Model TCB', v.model_tcb?.join(', ')],
        ['GPU attested', v.gpu_verified ? 'Yes' : 'No'],
        ['End-to-end encryption key', v.e2ee_key ? 'Present' : 'Missing'],
        ['Verifier', <span className="small">{v.verifier}</span>],
        ['Checked', dateTime(v.checked_at)],
      ]}
    />
  );
}

// ------------------------------------------------------------------ page

export default function ModelsPage() {
  const models = useLoad(() => get<ModelsStatus>('/models'), []);
  const providers = useLoad(() => get<{ providers: ProviderEntry[]; verifications: NearVerification[] }>('/providers'), []);
  const settings = useLoad(() => get<SettingsResponse>('/settings'), []);

  return (
    <div className="content">
      <PageHeader title="Models & destinations" subtitle="Local models that inspect prompts, and the destinations that generate replies. Every destination carries a privacy tier that policy enforces." />
      <div className="grid-2">
        <ClassifierCard m={models} />
        <SpanCard m={models} />
      </div>
      <DestinationsCard providers={providers} settings={settings.data} />
      <NearCard verifications={providers.data?.verifications ?? []} onChanged={() => providers.reload()} hasNear={!!providers.data?.providers.some((p) => p.config.kind === 'NEAR_AI')} />
      <div className="grid-2">
        <OllamaGenCard m={models.data} onSaved={() => providers.reload()} />
        <CustomEndpointCard onSaved={() => providers.reload()} />
      </div>
    </div>
  );
}

function ClassifierCard({ m }: { m: Loaded<ModelsStatus> }) {
  const act = useAction();
  const pull = usePull(() => void m.reload());
  const test = useAction();
  const [testRes, setTestRes] = useState<Record<string, unknown> | null>(null);
  const d = m.data;
  const lock = d?.lock?.generative ?? {};
  return (
    <Card title="Generative classifier">
      {!d ? (
        <>
          <ErrorText error={m.error} />
          <Loading />
        </>
      ) : (
        <div className="stack">
          <div className="stack-s">
            {CLASSIFIERS.map((c) => {
              const installed = c.kind === 'none' || d.ollama.installed?.[c.kind as 'lfm3' | 'qwen3guard'];
              return (
                <div key={c.kind} className={`radio-card${d.selection.kind === c.kind ? ' selected' : ''}`}>
                  <Radio name="classifier" checked={d.selection.kind === c.kind} disabled={act.busy} onChange={() => act.run(async () => { await post('/models/select', { kind: c.kind }); await m.reload(); })}>
                    <strong>{lock[c.kind]?.display_name ?? c.name}</strong>
                    <div className="muted small">{c.blurb}</div>
                    {c.kind === 'lfm3' ? <div className="small" style={{ marginTop: 4 }}>{lock.lfm3?.license ?? LFM_LICENSE_NOTE}</div> : null}
                    {c.kind !== 'none' ? (
                      <div className="small" style={{ marginTop: 4 }}>
                        {installed ? <Badge tone="neutral">installed</Badge> : <Badge tone="outline">not installed</Badge>}
                      </div>
                    ) : null}
                  </Radio>
                </div>
              );
            })}
          </div>
          <KV
            rows={[
              ['Status', d.classifier.active ? <Badge tone="green">active</Badge> : <Badge tone="outline">inactive</Badge>],
              ['Model', d.classifier.model ? <span className="mono">{d.classifier.model}</span> : null],
              ['Identity digest', d.classifier.verified_digest ? <span className="mono small">{d.classifier.verified_digest}</span> : null],
              ['Error', d.classifier.error],
              ['Ollama', d.ollama.reachable ? `reachable at ${d.ollama.url} (v${d.ollama.version})` : <span>not reachable at {d.ollama.url}</span>],
            ]}
          />
          {!d.ollama.reachable ? <Notice tone="warn">{d.ollama.install ?? 'Install Ollama from https://ollama.com/download'}</Notice> : null}
          {d.selection.kind !== 'none' ? (
            <div className="row gap-s">
              <Button small busy={pull.busy || pull.running} disabled={!d.ollama.reachable} onClick={() => pull.start(d.selection.kind)}>
                {d.ollama.installed?.[d.selection.kind] ? 'Re-pull and verify' : 'Pull model'}
              </Button>
              <Button small busy={test.busy} onClick={() => test.run(async () => setTestRes(await post('/models/test', {})))}>
                Test detectors
              </Button>
            </div>
          ) : null}
          <PullProgress job={pull.job} />
          {testRes ? (
            <KV
              rows={[
                ['Categories', (testRes.categories as string[]).join(', ')],
                ['Total latency', `${String(testRes.latency_ms)} ms`],
                ['Semantic', testRes.semantic_latency_ms != null ? `${String(testRes.semantic_latency_ms)} ms` : null],
                ['Span (GLiNER)', testRes.span_latency_ms != null ? `${String(testRes.span_latency_ms)} ms` : null],
                ['Failures', (testRes.failures as string[]).join('; ')],
              ]}
            />
          ) : null}
          <ErrorText error={act.error || pull.error || test.error} />
        </div>
      )}
    </Card>
  );
}

function SpanCard({ m }: { m: Loaded<ModelsStatus> }) {
  const act = useAction();
  const d = m.data;
  const lock = d?.lock?.span?.['gliner-pii-edge'];
  return (
    <Card title="GLiNER PII Edge">
      {!d ? (
        <Loading />
      ) : (
        <div className="stack">
          <p className="muted small">Span-level PII recognizer running in an embedded ONNX runtime (not Ollama). Installed by default.</p>
          <KV
            rows={[
              ['Status', d.span.loaded ? <Badge tone="green">loaded</Badge> : d.span.provisioned ? <Badge tone="outline">provisioned, not loaded</Badge> : <Badge tone="outline">not installed</Badge>],
              ['Runtime compiled in', d.span.compiled ? 'Yes' : 'No'],
              ['Revision', d.span.revision ? <span className="mono small">{d.span.revision}</span> : null],
              ['License', lock?.license],
              ['Enabled in detector', d.detector.span_enabled ? 'Yes' : 'No'],
              ['Error', d.span.error],
            ]}
          />
          <div>
            <Button
              small
              busy={act.busy}
              disabled={!d.span.compiled}
              onClick={() =>
                act.run(async () => {
                  await post('/models/gliner/install');
                  await m.reload();
                })
              }
            >
              {d.span.provisioned ? 'Reinstall and verify' : 'Install GLiNER'}
            </Button>
          </div>
          <ErrorText error={act.error} />
        </div>
      )}
    </Card>
  );
}

function DestinationsCard({ providers, settings }: { providers: Loaded<{ providers: ProviderEntry[]; verifications: NearVerification[] }>; settings: SettingsResponse | null }) {
  const [tests, setTests] = useState<Record<string, ProviderTest | string>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [deleting, setDeleting] = useState<ProviderConfig | null>(null);
  const list = providers.data?.providers ?? [];
  const def = settings?.engine.default_destination;
  const priv = settings?.engine.private_destination;
  const failover = settings?.engine.failover ?? [];
  return (
    <Card title="Destinations">
      <ErrorText error={providers.error} />
      {providers.loading && !providers.data ? (
        <Loading />
      ) : !list.length ? (
        <Empty>No destinations. Add NEAR AI, a local Ollama model, or a custom endpoint below.</Empty>
      ) : (
        <div className="list">
          {list.map(({ config: c, has_credential }) => {
            const t = tests[c.id];
            return (
              <div key={c.id} className="list-item" style={{ alignItems: 'flex-start', flexDirection: 'column', gap: 10 }}>
                <div className="row gap" style={{ width: '100%' }}>
                  <div className="li-main">
                    <div className="li-title row gap-s">
                      {c.display_name}
                      {c.id === def ? <Badge tone="dark">default</Badge> : null}
                      {c.id === priv ? <Badge tone="dark">private route</Badge> : null}
                      {failover.includes(c.id) ? <Badge tone="outline">failover</Badge> : null}
                      {c.enabled === false ? <Badge tone="outline">disabled</Badge> : null}
                    </div>
                    <div className="li-sub">
                      <span className="mono">{c.id}</span> · {c.kind} · <span className="mono">{c.base_url}</span> · model <span className="mono">{c.default_model}</span>
                      {c.kind !== 'OLLAMA' ? ` · ${has_credential ? 'credential stored' : 'no credential'}` : ''}
                    </div>
                  </div>
                  <TierBadge tier={c.declared_tier} />
                  <Button
                    small
                    busy={busy === c.id}
                    onClick={async () => {
                      setBusy(c.id);
                      try {
                        const r = await post<ProviderTest>(`/providers/${encodeURIComponent(c.id)}/test`);
                        setTests((s) => ({ ...s, [c.id]: r }));
                      } catch (e) {
                        setTests((s) => ({ ...s, [c.id]: e instanceof Error ? e.message : String(e) }));
                      } finally {
                        setBusy(null);
                      }
                    }}
                  >
                    Test
                  </Button>
                  <Button small variant="danger" onClick={() => setDeleting(c)}>
                    Remove
                  </Button>
                </div>
                {t ? (
                  typeof t === 'string' ? (
                    <Notice tone="error">{t}</Notice>
                  ) : (
                    <Notice tone={t.ok ? 'ok' : 'error'}>
                      {t.ok ? 'Reachable' : 'Failed'} · tier {t.tier} · model {t.model} · {t.latency_ms} ms
                      {t.detail.reply ? ` · reply "${String(t.detail.reply).slice(0, 80)}"` : ''}
                      {t.detail.error ? ` · ${t.detail.error}` : ''}
                    </Notice>
                  )
                ) : null}
              </div>
            );
          })}
        </div>
      )}
      <p className="muted small" style={{ marginTop: 12 }}>
        LOCAL stays on this computer. ATTESTED_TEE is a NEAR model whose hardware attestation verified. EXTERNAL_UNVERIFIED is any other remote endpoint; it never replaces a TEE for prompts that require one. Change the default and failover order in Settings.
      </p>
      {deleting ? (
        <ConfirmDialog
          title={`Remove ${deleting.display_name}?`}
          danger
          confirmLabel="Remove destination"
          onClose={() => setDeleting(null)}
          onConfirm={async () => {
            await del('/providers/' + encodeURIComponent(deleting.id));
            await providers.reload();
          }}
        >
          <p>Its stored credential is deleted from the OS credential store. Apps routed to it fall back per your failover settings or get an error.</p>
        </ConfirmDialog>
      ) : null}
    </Card>
  );
}

/** NEAR model list with per-model attestation verification. */
function NearCard({ verifications, onChanged, hasNear }: { verifications: NearVerification[]; onChanged: () => void; hasNear: boolean }) {
  const near = useLoad(() => get<{ models: NearModel[]; spec_preferred: string }>('/near/models'), []);
  const [showAll, setShowAll] = useState(false);
  const [results, setResults] = useState<Record<string, NearVerification>>({});
  const [busy, setBusy] = useState<string | null>(null);
  const [err, setErr] = useState<string | null>(null);
  const [detail, setDetail] = useState<NearVerification | null>(null);
  const [setup, setSetup] = useState<string | null>(null);
  const cached = Object.fromEntries(verifications.map((v) => [v.model, v]));
  const all = near.data?.models ?? [];
  const shown = showAll ? all : all.filter(isTeeCandidate);
  const verify = async (model: string) => {
    setBusy(model);
    setErr(null);
    try {
      const v = await post<NearVerification>('/near/verify', { model });
      setResults((r) => ({ ...r, [model]: v }));
      setDetail(v);
    } catch (e) {
      setErr(e instanceof Error ? e.message : String(e));
    } finally {
      setBusy(null);
    }
  };
  const aliasOf = near.data ? all.find((m) => m.aliases.includes(near.data!.spec_preferred)) : undefined;
  return (
    <Card
      title="NEAR AI private inference"
      actions={
        <Check checked={showAll} onChange={setShowAll}>
          Show non-TEE models
        </Check>
      }
    >
      <div className="stack">
        <p className="muted small">
          NEAR AI runs models inside hardware TEEs and publishes attestation. Prompt VPN only treats a model as ATTESTED_TEE after verifying its attestation report here. {hasNear ? '' : 'NEAR is not configured yet; verify a model, then use it.'}
        </p>
        {aliasOf ? (
          <Notice tone="info">
            The spec's preferred <span className="mono">{near.data!.spec_preferred}</span> is currently an alias of <span className="mono">{aliasOf.id}</span>, so it is not offered. The current DeepSeek TEE model is{' '}
            <span className="mono">{DEFAULT_NEAR_CANDIDATE}</span>.
          </Notice>
        ) : null}
        <ErrorText error={near.error || err} />
        {near.loading && !near.data ? (
          <Loading what="Discovering NEAR models" />
        ) : (
          <div className="table-wrap">
            <table className="table">
              <thead>
                <tr>
                  <th>Model</th>
                  <th>Privacy tier</th>
                  <th>Attestation</th>
                  <th />
                </tr>
              </thead>
              <tbody>
                {shown.map((m) => {
                  const v = results[m.id] ?? cached[m.id];
                  return (
                    <tr key={m.id}>
                      <td>
                        <div className="mono small" style={{ fontWeight: 600 }}>
                          {m.id}
                        </div>
                        <div className="muted small">
                          {m.name}
                          {m.id === DEFAULT_NEAR_CANDIDATE ? ' · recommended' : ''}
                        </div>
                      </td>
                      <td>
                        <TierBadge tier={m.privacy_tier} />
                      </td>
                      <td className="small">
                        {v ? (
                          <Button variant="link" onClick={() => setDetail(v)}>
                            {v.eligible ? 'Verified eligible' : 'Not eligible'}
                          </Button>
                        ) : m.attestation_supported ? (
                          <span className="muted">not checked</span>
                        ) : (
                          <span className="muted">not supported</span>
                        )}
                      </td>
                      <td className="right nowrap">
                        <div className="row gap-s" style={{ justifyContent: 'flex-end' }}>
                          {m.attestation_supported ? (
                            <Button small busy={busy === m.id} onClick={() => verify(m.id)}>
                              Verify
                            </Button>
                          ) : null}
                          {v?.eligible ? (
                            <Button small variant="primary" onClick={() => setSetup(m.id)}>
                              Use
                            </Button>
                          ) : null}
                        </div>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
      {detail ? (
        <Dialog wide title="Attestation" onClose={() => setDetail(null)} footer={<Button onClick={() => setDetail(null)}>Close</Button>}>
          <AttestationDetails v={detail} />
        </Dialog>
      ) : null}
      {setup ? <NearSetupDialog model={setup} onClose={() => setSetup(null)} onSaved={onChanged} /> : null}
    </Card>
  );
}

function NearSetupDialog({ model, onClose, onSaved }: { model: string; onClose: () => void; onSaved: () => void }) {
  const [key, setKey] = useState('');
  const act = useAction();
  return (
    <Dialog
      title="Use NEAR AI"
      onClose={onClose}
      footer={
        <>
          <Button onClick={onClose}>Cancel</Button>
          <Button
            variant="primary"
            busy={act.busy}
            onClick={() =>
              act.run(async () => {
                const cfg: ProviderConfig & { api_key?: string } = {
                  schema_version: 1,
                  id: 'near',
                  kind: 'NEAR_AI',
                  display_name: 'NEAR AI',
                  base_url: 'https://cloud-api.near.ai/v1',
                  default_model: model,
                  declared_tier: 'ATTESTED_TEE',
                  credential_ref: 'provider:near',
                  enabled: true,
                  allow_failover: true,
                  supports_responses: true,
                  timeout_secs: 180,
                };
                if (key) cfg.api_key = key;
                await post('/providers', cfg);
                setKey('');
                onSaved();
                onClose();
              })
            }
          >
            Save destination
          </Button>
        </>
      }
    >
      <p>
        Saves NEAR AI as destination <span className="mono">near</span> with model <span className="mono">{model}</span>. Attestation is re-verified before private routing. Set it as the default or private route in Settings.
      </p>
      <Field label="NEAR AI API key" hint="Stored in the OS credential store. Leave blank to keep an existing key.">
        <SecretInput value={key} onChange={setKey} />
      </Field>
      <ErrorText error={act.error} />
    </Dialog>
  );
}

function OllamaGenCard({ m, onSaved }: { m: ModelsStatus | null; onSaved: () => void }) {
  const [model, setModel] = useState('');
  const [url, setUrl] = useState('http://127.0.0.1:11434/v1');
  const [done, setDone] = useState(false);
  const act = useAction();
  const tags = (m?.ollama.models ?? []).filter((t) => !/qwen3guard|lfm3/i.test(t));
  return (
    <Card title="Local Ollama generation model">
      <div className="stack">
        <p className="muted small">Generates replies on this computer (tier LOCAL). Used as a fallback when NEAR is unavailable, and for private handling if you allow it in Settings.</p>
        <Field label="Model" hint={m?.ollama.reachable ? 'Pick an installed model or type a name' : 'Ollama is not reachable'}>
          <input className="input mono" list="ollama-tags" value={model} onChange={(e) => setModel(e.target.value)} placeholder="qwen3.5:4b" />
          <datalist id="ollama-tags">
            {tags.map((t) => (
              <option key={t} value={t} />
            ))}
          </datalist>
        </Field>
        <Field label="Ollama URL" hint="Must be loopback">
          <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} />
        </Field>
        {done ? <Notice tone="ok">Saved destination ollama.</Notice> : null}
        <ErrorText error={act.error} />
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <Button
            variant="primary"
            busy={act.busy}
            disabled={!model.trim()}
            onClick={() =>
              act.run(async () => {
                const cfg: ProviderConfig = {
                  schema_version: 1,
                  id: 'ollama',
                  kind: 'OLLAMA',
                  display_name: `Ollama (${model.trim()})`,
                  base_url: url.trim(),
                  default_model: model.trim(),
                  declared_tier: 'LOCAL',
                  credential_ref: null,
                  enabled: true,
                  allow_failover: true,
                  supports_responses: false,
                  timeout_secs: 300,
                };
                await post('/providers', cfg);
                setDone(true);
                onSaved();
              })
            }
          >
            Save Ollama destination
          </Button>
        </div>
      </div>
    </Card>
  );
}

function CustomEndpointCard({ onSaved }: { onSaved: () => void }) {
  const [id, setId] = useState('custom');
  const [name, setName] = useState('');
  const [url, setUrl] = useState('');
  const [model, setModel] = useState('');
  const [key, setKey] = useState('');
  const [failover, setFailover] = useState(false);
  const [ack, setAck] = useState(false);
  const [done, setDone] = useState(false);
  const act = useAction();
  return (
    <Card title="Custom OpenAI-compatible endpoint">
      <div className="stack">
        <div className="form-grid">
          <Field label="ID">
            <input className="input mono" value={id} onChange={(e) => setId(e.target.value)} />
          </Field>
          <Field label="Display name">
            <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Company gateway" />
          </Field>
          <div className="full">
            <Field label="Base URL" hint="https, or http on loopback only">
              <input className="input mono" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="https://llm.example.com/v1" />
            </Field>
          </div>
          <Field label="Model">
            <input className="input mono" value={model} onChange={(e) => setModel(e.target.value)} />
          </Field>
          <Field label="API key" hint="Optional. Stored in the OS credential store.">
            <SecretInput value={key} onChange={setKey} />
          </Field>
        </div>
        <Check checked={failover} onChange={setFailover}>
          Allow as failover when the default is unavailable
        </Check>
        <div className="alert alert-warn">
          <Check checked={ack} onChange={setAck}>
            I understand this endpoint is <strong>EXTERNAL_UNVERIFIED</strong>: Prompt VPN cannot verify where it runs or who can read the prompts. It receives only content your policy already allows for external destinations, and it never replaces a verified TEE.
          </Check>
        </div>
        {done ? <Notice tone="ok">Saved destination {id}.</Notice> : null}
        <ErrorText error={act.error} />
        <div className="row" style={{ justifyContent: 'flex-end' }}>
          <Button
            variant="primary"
            busy={act.busy}
            disabled={!ack || !url.trim() || !model.trim() || !id.trim()}
            onClick={() =>
              act.run(async () => {
                const cfg: ProviderConfig & { api_key?: string } = {
                  schema_version: 1,
                  id: id.trim(),
                  kind: 'OPENAI_COMPATIBLE',
                  display_name: name.trim() || 'Custom endpoint',
                  base_url: url.trim(),
                  default_model: model.trim(),
                  declared_tier: 'EXTERNAL_UNVERIFIED',
                  credential_ref: null,
                  enabled: true,
                  allow_failover: failover,
                  supports_responses: false,
                  timeout_secs: 180,
                };
                if (key) cfg.api_key = key;
                await post('/providers', cfg);
                setKey('');
                setDone(true);
                onSaved();
              })
            }
          >
            Save endpoint
          </Button>
        </div>
      </div>
    </Card>
  );
}
