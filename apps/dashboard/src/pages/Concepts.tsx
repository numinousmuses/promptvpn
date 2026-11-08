import { useState } from 'react';
import { del, get, post, type Action, type GuidanceNote, type StoredConcept } from '../api';
import { dateTime } from '../format';
import { Badge, Button, Card, ConfirmDialog, Empty, ErrorText, Field, Loading, Notice, PageHeader, useAction, useLoad } from '../ui';
import { ActionSelect } from './ApprovalDetail';

export const CONCEPT_ACTIONS: Action[] = ['BLOCK', 'REQUIRE_APPROVAL', 'PRIVATE_ROUTE', 'FALLBACK', 'REDACT', 'TOKENIZE', 'ALLOW'];

export interface ConceptDraft {
  name: string;
  description: string;
  sensitive_examples: string[];
  safe_examples: string[];
  action: Action;
}

const lines = (s: string) =>
  s
    .split('\n')
    .map((x) => x.trim())
    .filter(Boolean);

/** Form used here and in onboarding step 3. */
export function ConceptForm({ onSubmit, submitLabel, busy }: { onSubmit: (c: ConceptDraft) => Promise<boolean | void>; submitLabel: string; busy?: boolean }) {
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [sens, setSens] = useState('');
  const [safe, setSafe] = useState('');
  const [action, setAction] = useState<Action>('BLOCK');
  return (
    <div className="stack">
      <div className="form-grid">
        <Field label="Name">
          <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="Unreleased product specs" />
        </Field>
        <Field label="Action">
          <ActionSelect value={action} onChange={setAction} options={CONCEPT_ACTIONS} />
        </Field>
        <div className="full">
          <Field label="Description" hint="What counts, in plain words. The local classifier reads this; nothing leaves the device.">
            <textarea className="input" rows={3} value={description} onChange={(e) => setDescription(e.target.value)} />
          </Field>
        </div>
        <Field label="Sensitive examples" hint="One per line. Use made-up examples.">
          <textarea className="input" rows={3} value={sens} onChange={(e) => setSens(e.target.value)} />
        </Field>
        <Field label="Safe examples" hint="Near misses that should pass. One per line.">
          <textarea className="input" rows={3} value={safe} onChange={(e) => setSafe(e.target.value)} />
        </Field>
      </div>
      <div className="row" style={{ justifyContent: 'flex-end' }}>
        <Button
          variant="primary"
          busy={busy}
          disabled={!name.trim() || !description.trim()}
          onClick={async () => {
            const ok = await onSubmit({ name: name.trim(), description: description.trim(), sensitive_examples: lines(sens), safe_examples: lines(safe), action });
            if (ok !== false) {
              setName('');
              setDescription('');
              setSens('');
              setSafe('');
            }
          }}
        >
          {submitLabel}
        </Button>
      </div>
    </div>
  );
}

export default function ConceptsPage() {
  const concepts = useLoad(() => get<{ concepts: StoredConcept[] }>('/concepts'), []);
  const guidance = useLoad(() => get<{ guidance: GuidanceNote[] }>('/guidance'), []);
  const add = useAction();
  const addNote = useAction();
  const [note, setNote] = useState('');
  const [notice, setNotice] = useState<string | null>(null);
  const [removing, setRemoving] = useState<{ kind: 'concept' | 'guidance'; id: string; name: string } | null>(null);

  return (
    <div className="content narrow">
      <PageHeader
        title="Concepts"
        subtitle="Semantic concepts catch sensitive topics that have no fixed format, like unreleased specs or deal terms. The local classifier model evaluates them on this device."
      />
      {notice ? <Notice tone="ok">{notice}</Notice> : null}
      <Card title="Add a concept">
        <ConceptForm
          submitLabel="Add concept"
          busy={add.busy}
          onSubmit={async (c) => {
            const r = await add.run(async () => {
              await post('/concepts', c);
              setNotice(`Added concept "${c.name}".`);
              await concepts.reload();
              return true;
            });
            return r === true;
          }}
        />
        <ErrorText error={add.error} />
      </Card>

      <Card title="Concepts">
        <ErrorText error={concepts.error} />
        {concepts.loading && !concepts.data ? (
          <Loading />
        ) : !concepts.data?.concepts.length ? (
          <Empty>No concepts yet.</Empty>
        ) : (
          <div className="list">
            {concepts.data.concepts.map(({ concept: c, action, created_at }) => (
              <div className="list-item" key={c.id} style={{ alignItems: 'flex-start' }}>
                <div className="li-main stack-s">
                  <div className="li-title">{c.name}</div>
                  <div className="li-sub">{c.description}</div>
                  {c.sensitive_examples.length ? (
                    <div className="small">
                      <span className="muted">Sensitive: </span>
                      {c.sensitive_examples.join('; ')}
                    </div>
                  ) : null}
                  {c.safe_examples.length ? (
                    <div className="small">
                      <span className="muted">Safe: </span>
                      {c.safe_examples.join('; ')}
                    </div>
                  ) : null}
                  <div className="faint small mono">
                    {c.id} · {dateTime(created_at)}
                  </div>
                </div>
                <Badge tone={action === 'BLOCK' ? 'red' : 'outline'}>{action}</Badge>
                <Button small variant="danger" onClick={() => setRemoving({ kind: 'concept', id: c.id, name: c.name })}>
                  Remove
                </Button>
              </div>
            ))}
          </div>
        )}
      </Card>

      <Card title="Guidance notes">
        <div className="stack">
          <p className="muted small">Short instructions added to the classifier prompt, for example "Internal ticket numbers like OPS-1234 are not sensitive."</p>
          <div className="row gap-s start">
            <textarea className="input grow" rows={2} maxLength={1000} value={note} onChange={(e) => setNote(e.target.value)} aria-label="New guidance note" />
            <Button
              variant="primary"
              busy={addNote.busy}
              disabled={!note.trim()}
              onClick={() =>
                addNote.run(async () => {
                  await post('/guidance', { text: note });
                  setNote('');
                  await guidance.reload();
                })
              }
            >
              Add note
            </Button>
          </div>
          <ErrorText error={addNote.error || guidance.error} />
          {!guidance.data?.guidance.length ? (
            <Empty>No guidance notes.</Empty>
          ) : (
            <div className="list">
              {guidance.data.guidance.map((g) => (
                <div className="list-item" key={g.id}>
                  <div className="li-main">
                    <div>{g.text}</div>
                    <div className="faint small">{dateTime(g.created_at)}</div>
                  </div>
                  <Button small variant="danger" onClick={() => setRemoving({ kind: 'guidance', id: g.id, name: 'this note' })}>
                    Remove
                  </Button>
                </div>
              ))}
            </div>
          )}
        </div>
      </Card>

      {removing ? (
        <ConfirmDialog
          title={`Remove ${removing.kind === 'concept' ? `"${removing.name}"` : removing.name}?`}
          danger
          confirmLabel="Remove"
          onClose={() => setRemoving(null)}
          onConfirm={async () => {
            await del(`/${removing.kind === 'concept' ? 'concepts' : 'guidance'}/${encodeURIComponent(removing.id)}`);
            if (removing.kind === 'concept') await concepts.reload();
            else await guidance.reload();
          }}
        >
          <p>{removing.kind === 'concept' ? 'The concept and its policy rule are deactivated. Prompts about this topic will no longer be flagged by it.' : 'The classifier stops using this note.'}</p>
        </ConfirmDialog>
      ) : null}
    </div>
  );
}
