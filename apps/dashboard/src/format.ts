import type { AuditEvent } from './generated/types';

export function timeAgo(iso: string | null | undefined): string {
  if (!iso) return '';
  const t = new Date(iso).getTime();
  if (Number.isNaN(t)) return iso;
  const s = Math.round((Date.now() - t) / 1000);
  if (s < 0) return 'in ' + duration(-s);
  if (s < 45) return 'just now';
  return duration(s) + ' ago';
}

export function duration(s: number): string {
  if (s < 60) return `${s} sec`;
  const m = Math.round(s / 60);
  if (m < 60) return `${m} min`;
  const h = Math.round(m / 60);
  if (h < 48) return `${h} hr`;
  return `${Math.round(h / 24)} days`;
}

export function dateTime(iso: string | null | undefined): string {
  if (!iso) return '';
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) return iso;
  return d.toLocaleString(undefined, { month: 'short', day: 'numeric', year: 'numeric', hour: 'numeric', minute: '2-digit' });
}

export function shortHash(h: string | null | undefined, n = 12): string {
  if (!h) return '';
  const [algo, rest] = h.includes(':') ? h.split(/:(.*)/s) : ['', h];
  return (algo ? algo + ':' : '') + rest.slice(0, n);
}

export function num(n: number | undefined | null): string {
  return (n ?? 0).toLocaleString();
}

export function titleCase(id: string): string {
  return id
    .toLowerCase()
    .split(/[_\s-]+/)
    .map((w) => w.charAt(0).toUpperCase() + w.slice(1))
    .join(' ');
}

/** Pill badge label + tone for an event's action. */
export type Tone = 'neutral' | 'dark' | 'red' | 'amber' | 'green' | 'outline';

export function actionBadge(action: string): { label: string; tone: Tone } {
  switch (action) {
    case 'ALLOW':
      return { label: 'Allowed', tone: 'neutral' };
    case 'TRANSFORM':
    case 'TOKENIZE':
    case 'REDACT':
    case 'GENERALIZE':
      return { label: 'Redacted', tone: 'outline' };
    case 'BLOCK':
    case 'OUTPUT_BLOCK':
      return { label: 'Blocked', tone: 'red' };
    case 'REQUIRE_APPROVAL':
      return { label: 'Review', tone: 'dark' };
    case 'PRIVATE_ROUTE':
      return { label: 'Private route', tone: 'outline' };
    case 'ERROR':
      return { label: 'Error', tone: 'red' };
    default:
      return { label: titleCase(action), tone: 'neutral' };
  }
}

export function eventTitle(e: AuditEvent): string {
  if (e.kind === 'request' || e.kind === 'response') {
    const out = e.kind === 'response' || e.direction === 'outbound';
    const noun = out ? 'Response' : 'Prompt';
    switch (e.action) {
      case 'ALLOW':
        return `${noun} processed`;
      case 'TRANSFORM':
        return `${noun} redacted`;
      case 'BLOCK':
      case 'OUTPUT_BLOCK':
        return `${noun} blocked`;
      case 'REQUIRE_APPROVAL':
        return `${noun} held for review`;
      case 'PRIVATE_ROUTE':
        return `${noun} sent to private model`;
      case 'ERROR':
        return `${noun} failed`;
    }
  }
  return titleCase(e.kind) + ': ' + titleCase(e.action);
}

export function categoryLabel(c: string): string {
  if (c.startsWith('CONCEPT:')) return 'Concept ' + c.slice(8);
  if (c.startsWith('EXACT_SECRET:')) return 'Exact value ' + c.slice(13);
  return titleCase(c);
}

export function download(filename: string, text: string, type = 'application/json'): void {
  const url = URL.createObjectURL(new Blob([text], { type }));
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
}
