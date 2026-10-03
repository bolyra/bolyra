import type { Origin } from './portal';

export type Portal = 'A' | 'B';
export type PresentationId = 'P1' | 'P2' | 'none';
export interface Scene {
  id: number;
  portal: Portal;
  path: string;
  presentation: PresentationId;
  /** What the published verifier (or the portal) is expected to decide, and why. */
  expect: { status: number; code?: string; origin: Origin; detail?: Record<string, string> };
  decider: string;
  narration: string;
}

export const SCENES: Scene[] = [
  { id: 1, portal: 'A', path: '/public/stats', presentation: 'P1', expect: { status: 200, origin: 'cli' },
    decider: 'bolyra verify: proof + root + binding signature ok; read:public-stats → READ_DATA ⊆ proven bitmask 3; fresh nullifier burned',
    narration: 'Allow (verdict). The portal serves mock public data only after this verdict.' },
  { id: 2, portal: 'A', path: '/internal/files', presentation: 'P1', expect: { status: 403, code: 'request_mismatch', origin: 'cli', detail: { field: 'granted_capabilities', capability: 'read:internal-files' } },
    decider: 'bolyra verify: binding-capability rejection — the signed binding does not cover read:internal-files',
    narration: 'The route requires a capability the operator never signed for this agent.' },
  { id: 3, portal: 'B', path: '/public/stats', presentation: 'P1', expect: { status: 403, code: 'request_mismatch', origin: 'cli', detail: { field: 'project_key', request: 'https://internal.example.gov', binding: 'https://stats.example.gov' } },
    decider: 'bolyra verify: literal audience rejection — portal B put ITS OWN audience in request.project_key; compared byte-for-byte to the signed binding',
    narration: 'The same presentation, replayed at another audience, is refused before any capability check.' },
  { id: 4, portal: 'A', path: '/public/stats', presentation: 'P1', expect: { status: 403, code: 'nonce_replayed', origin: 'cli' },
    decider: 'bolyra verify: the proof’s nullifier was burned by scene 1 in portal A’s local store',
    narration: 'Replaying the exact presentation to the same portal is refused (local nonce mode, 30-day retention).' },
  { id: 5, portal: 'A', path: '/public/stats', presentation: 'none', expect: { status: 401, code: 'missing_authorization', origin: 'portal' },
    decider: 'portal-local: no x-bolyra-authorization header; the verifier is not consulted',
    narration: 'A gate-local decision, labelled as such.' },
  { id: 6, portal: 'A', path: '/internal/files', presentation: 'P2', expect: { status: 403, code: 'scope_exceeded', origin: 'cli', detail: { required_scope: '129', effective_scope: '3', excess_bits: '128' } },
    decider: 'bolyra verify: subset check against the PROOF-ANCHORED bitmask — the operator signed a binding naming read:internal-files, but the proven credential bitmask (3) lacks ACCESS_PII (bit 7)',
    narration: 'This is the zk scope check: a signature cannot grant what the proof does not carry.' },
];

export interface SceneResult { id: number; status: number; code: string | null; origin: Origin; detail: Record<string, unknown> }

/** Pure: compare observed results with the scene table. */
export function judge(results: SceneResult[]): { ok: boolean; failures: string[] } {
  const failures: string[] = [];
  const seen = new Set<number>();
  for (const r of results) {
    if (seen.has(r.id)) { failures.push(`duplicate result for scene ${r.id}`); continue; }
    seen.add(r.id);
    const s = SCENES.find((x) => x.id === r.id);
    if (!s) { failures.push(`unexpected scene ${r.id}`); continue; }
    if (r.status !== s.expect.status) failures.push(`scene ${s.id}: status ${r.status} != ${s.expect.status}`);
    if ((r.code ?? null) !== (s.expect.code ?? null)) failures.push(`scene ${s.id}: code ${r.code} != ${s.expect.code ?? 'allow'}`);
    if (r.origin !== s.expect.origin) failures.push(`scene ${s.id}: origin ${r.origin} != ${s.expect.origin}`);
    for (const [k, v] of Object.entries(s.expect.detail ?? {})) if (r.detail?.[k] !== v) failures.push(`scene ${s.id}: detail.${k} ${JSON.stringify(r.detail?.[k])} != ${JSON.stringify(v)}`);
  }
  for (const s of SCENES) if (!seen.has(s.id)) failures.push(`scene ${s.id} missing`);
  return { ok: failures.length === 0, failures };
}
