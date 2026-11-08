import { useState } from 'react';
import { get, post, type Health } from '../api';
import { duration, shortHash, timeAgo } from '../format';
import { Badge, Button, Card, ErrorText, KV, Loading, Notice, PageHeader, TierBadge, useAction, useLoad } from '../ui';

interface SentNotification {
  kind?: string;
  title?: string;
  body?: string;
  at?: string;
  [k: string]: unknown;
}

export default function HealthPage() {
  const h = useLoad(() => get<Health>('/health'), [], 15_000);
  const notes = useLoad(() => get<{ notifications: SentNotification[] }>('/notifications/recent'), []);
  const act = useAction();
  const [verify, setVerify] = useState<{ ok: boolean; verified_events?: number; error?: string } | null>(null);
  const d = h.data;
  return (
    <div className="content">
      <PageHeader
        title="Health"
        subtitle="Diagnostics for the local daemon, detectors, vault and destinations."
        actions={
          <Button small busy={act.busy} onClick={() => act.run(async () => setVerify(await post('/events/verify')))}>
            Verify audit chain
          </Button>
        }
      />
      <ErrorText error={h.error || act.error} />
      {verify ? verify.ok ? <Notice tone="ok">Audit chain intact: {verify.verified_events} events verified.</Notice> : <Notice tone="error">Audit chain verification failed: {verify.error}</Notice> : null}
      {!d ? (
        <Loading />
      ) : (
        <>
          <Card>
            <div className="row between gap wrap">
              <div className="row gap-s">
                <h2>Status</h2>
                {d.status === 'ok' ? <Badge tone="green">ok</Badge> : <Badge tone="amber">{d.status}</Badge>}
              </div>
              <span className="muted small">
                v{d.version} · up {duration(d.uptime_secs)} · {d.base_url}
              </span>
            </div>
            {d.warnings.length ? (
              <ul style={{ margin: '14px 0 0', paddingLeft: 18 }} className="stack-s">
                {d.warnings.map((w, i) => (
                  <li key={i}>{w}</li>
                ))}
              </ul>
            ) : (
              <p className="muted" style={{ marginTop: 10 }}>
                No warnings.
              </p>
            )}
          </Card>

          <Card title="Coverage boundary">
            <p>{d.coverage}</p>
          </Card>

          <div className="grid-2">
            <Card title="Audit and storage">
              <KV
                rows={[
                  ['Audit chain', d.audit_chain.ok ? `intact, ${d.audit_chain.events} events` : <span style={{ color: 'var(--red)' }}>{d.audit_chain.error}</span>],
                  ['Database', `schema v${d.database.schema_version ?? '?'} · integrity ${d.database.integrity_ok ? 'ok' : 'FAILED'}`],
                  ['Vault backend', <span>{d.vault.backend} {d.vault.secure ? <Badge tone="green">secure</Badge> : <Badge tone="red">degraded</Badge>}</span>],
                  ['Active key', <span className="mono">{d.vault.active_key}</span>],
                  ['Pending approvals', String(d.pending_approvals)],
                  ['Emergency stop', d.emergency_stop ? <Badge tone="red">engaged</Badge> : 'off'],
                ]}
              />
            </Card>
            <Card title="Detectors">
              <KV
                rows={[
                  ['Classifier', `${d.classifier.selected}${d.classifier.active ? ' (active)' : ' (inactive)'}`],
                  ['Classifier model', d.classifier.model ? <span className="mono">{d.classifier.model}</span> : null],
                  ['Identity digest', d.classifier.verified_digest ? <span className="mono small">{shortHash(d.classifier.verified_digest, 28)}</span> : null],
                  ['Classifier error', d.classifier.error],
                  ['GLiNER', d.span.loaded ? 'loaded' : d.span.provisioned ? 'provisioned, not loaded' : 'not installed'],
                  ['GLiNER revision', d.span.revision ? <span className="mono small">{d.span.revision.slice(0, 12)}</span> : null],
                  ['GLiNER error', d.span.error],
                ]}
              />
            </Card>
          </div>

          <div className="grid-2">
            <Card title="Routing">
              <KV
                rows={[
                  ['Default destination', d.default_destination],
                  ['Fallback', d.fallback.mode],
                  ['TEE consent', d.fallback.tee_consent ? 'granted' : 'not granted'],
                  ['Local private handling', d.fallback.local_private_handling ? 'allowed' : 'not allowed'],
                  ['NEAR', <Badge tone={d.near.status === 'NEAR_CONFIGURED' ? 'dark' : 'outline'}>{d.near.status}</Badge>],
                  ['NEAR verifications', d.near.verifications.length ? d.near.verifications.map((v) => `${v.model}: ${v.eligible ? 'eligible' : 'not eligible'}`).join('; ') : null],
                ]}
              />
            </Card>
            <Card title="Destinations">
              {d.destinations.length ? (
                <div className="list">
                  {d.destinations.map((x) => (
                    <div className="list-item" key={x.id}>
                      <div className="li-main">
                        <div className="li-title mono">{x.id}</div>
                        <div className="li-sub">
                          {x.kind}
                          {x.enabled ? '' : ' · disabled'}
                        </div>
                      </div>
                      <TierBadge tier={x.declared_tier} />
                    </div>
                  ))}
                </div>
              ) : (
                <p className="muted">None configured.</p>
              )}
            </Card>
          </div>

          <Card title="Recent notifications">
            {!notes.data?.notifications.length ? (
              <p className="muted">No desktop notifications sent since the daemon started.</p>
            ) : (
              <div className="list">
                {notes.data.notifications.map((n, i) => (
                  <div className="list-item" key={i}>
                    <div className="li-main">
                      <div className="li-title">{n.title ?? n.kind ?? 'Notification'}</div>
                      <div className="li-sub">{n.body ?? ''}</div>
                    </div>
                    <span className="li-meta">{n.at ? timeAgo(String(n.at)) : n.kind}</span>
                  </div>
                ))}
              </div>
            )}
          </Card>
        </>
      )}
    </div>
  );
}
