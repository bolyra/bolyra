import { test, after } from 'node:test';
import assert from 'node:assert/strict';
import { createPortal, HEADER, type PortalConfig } from '../src/portal';
import { buildPresentation, PUBLIC_STATS_BINDING, OVERREACH_BINDING, AUDIENCE } from '../src/credential';
import { startChildPortal, request, type ChildPortal } from './helpers';

const OTHER_AUDIENCE = 'https://internal.example.gov';
const started: ChildPortal[] = [];
after(async () => { for (const p of started) await p.stop(); });
const child = async (audience: string) => { const p = await startChildPortal(audience); started.push(p); return p; };

const p1 = buildPresentation(PUBLIC_STATS_BINDING);
const p2 = buildPresentation(OVERREACH_BINDING);
const withP = async (p: Promise<{ header: string }>) => ({ [HEADER]: (await p).header });
const problem = (r: any) => { assert.equal(r.headers['content-type'], 'application/problem+json'); assert.equal(r.body.status, r.status); assert.ok(!('table' in r.body) && !('rows' in r.body), 'denials carry no table data'); return r.body; };

test('scenes 1,2,4,6 on portal A; scene 3 on portal B; fresh-store deny → allow → replay order', { timeout: 180_000 }, async () => {
  const A = await child(AUDIENCE);
  const B = await child(OTHER_AUDIENCE);
  // fresh store: a policy denial FIRST must not consume the nullifier
  const s2 = await request(A.port, 'GET', '/internal/files', await withP(p1));
  assert.equal(s2.status, 403); const b2 = problem(s2);
  assert.equal(b2.code, 'request_mismatch'); assert.equal(b2.origin, 'cli'); assert.deepEqual(b2.verifier_detail, { field: 'granted_capabilities', capability: 'read:internal-files' });
  const s1 = await request(A.port, 'GET', '/public/stats', await withP(p1));
  assert.equal(s1.status, 200); assert.equal(s1.headers['content-type'], 'application/json'); assert.equal(s1.body.source, 'mock'); assert.equal(s1.body.origin, 'cli'); assert.ok(Array.isArray(s1.body.rows) && s1.body.rows.length > 0);
  assert.ok(!s1.text.includes((await p1).header.slice(0, 40)), 'response never echoes the presentation');
  const s4 = await request(A.port, 'GET', '/public/stats', await withP(p1));
  assert.equal(s4.status, 403); const b4 = problem(s4); assert.equal(b4.code, 'nonce_replayed'); assert.equal(b4.origin, 'cli');
  const s3 = await request(B.port, 'GET', '/public/stats', await withP(p1));
  assert.equal(s3.status, 403); const b3 = problem(s3); assert.equal(b3.code, 'request_mismatch'); assert.deepEqual(b3.verifier_detail, { field: 'project_key', request: OTHER_AUDIENCE, binding: AUDIENCE });
  const s6 = await request(A.port, 'GET', '/internal/files', await withP(p2));
  assert.equal(s6.status, 403); const b6 = problem(s6); assert.equal(b6.code, 'scope_exceeded'); assert.deepEqual(b6.verifier_detail, { required_scope: '129', effective_scope: '3', excess_bits: '128' });
  // problem shape comes from @bolyra/mpp verbatim
  assert.equal(b6.type, 'https://bolyra.ai/problems/mpp/scope-exceeded'); assert.equal(typeof b6.title, 'string');
  // audience is the portal's own identity: spoofed Host / X-Forwarded-Host on B change nothing
  const spoof = await request(B.port, 'GET', '/public/stats', { ...(await withP(p1)), host: 'stats.example.gov', 'x-forwarded-host': 'stats.example.gov' });
  assert.equal(spoof.status, 403); assert.equal(problem(spoof).verifier_detail.request, OTHER_AUDIENCE);
});

test('audience is compared byte-for-byte: a trailing slash is a different audience', { timeout: 60_000 }, async () => {
  const C = await child(AUDIENCE + '/');
  const r = await request(C.port, 'GET', '/public/stats', await withP(p1));
  assert.equal(r.status, 403); const b = problem(r); assert.equal(b.code, 'request_mismatch'); assert.equal(b.verifier_detail.field, 'project_key'); assert.equal(b.verifier_detail.request, AUDIENCE + '/');
});

test('published-CLI rejections: garbage header, unsigned binding mutation, corrupted proof', { timeout: 90_000 }, async () => {
  const A = await child(AUDIENCE);
  const g = await request(A.port, 'GET', '/public/stats', { [HEADER]: 'not-a-bundle' });
  assert.equal(g.status, 401); assert.equal(problem(g).code, 'invalid_bundle'); assert.equal(g.body.origin, 'cli');
  const mutated = JSON.parse(JSON.stringify((await p1).bundle)); mutated.binding.capabilities.push('read:internal-files');
  const m = await request(A.port, 'GET', '/internal/files', { [HEADER]: Buffer.from(JSON.stringify(mutated)).toString('base64url') });
  assert.equal(m.status, 401); assert.equal(problem(m).code, 'invalid_signature');
  const corrupt = JSON.parse(JSON.stringify((await p1).bundle)); corrupt.agent.envelope.proof.pi_a[0] = (BigInt(corrupt.agent.envelope.proof.pi_a[0]) ^ 1n).toString();
  const c = await request(A.port, 'GET', '/public/stats', { [HEADER]: Buffer.from(JSON.stringify(corrupt)).toString('base64url') });
  assert.equal(c.status, 401); assert.equal(problem(c).code, 'invalid_proof');
});

// ---- in-process cases that never reach the verifier, or use a stub verifier ----
function inProcess(overrides: Partial<PortalConfig> = {}) {
  let calls = 0;
  const cfg: PortalConfig = { audience: AUDIENCE, routes: { '/public/stats': 'read:public-stats', '/internal/files': 'read:internal-files' }, expectedAgent: { agent_name: 'stats-research-agent', program: 'demo', model: 'opus-4.1' }, verifier: { command: process.execPath, args: ['-e', 'process.exit(7)'], timeoutMs: 5_000 }, onVerifierCall: () => { calls += 1; }, ...overrides };
  const server = createPortal(cfg);
  return new Promise<{ port: number; calls: () => number; close: () => Promise<void> }>((resolve) => server.listen(0, '127.0.0.1', () => resolve({ port: (server.address() as any).port, calls: () => calls, close: () => new Promise((r) => server.close(() => r())) })));
}

test('portal-local decisions never consult the verifier: 404, 405, 401 missing header, Authorization ignored', async () => {
  const s = await inProcess();
  try {
    const nf = await request(s.port, 'GET', '/nope', await withP(p1)); assert.equal(nf.status, 404); assert.equal(nf.body.origin, 'portal');
    const mna = await request(s.port, 'POST', '/public/stats', await withP(p1)); assert.equal(mna.status, 405); assert.equal(mna.headers.allow, 'GET'); assert.equal(mna.body.origin, 'portal');
    const miss = await request(s.port, 'GET', '/public/stats'); assert.equal(miss.status, 401); assert.equal(problem(miss).code, 'missing_authorization'); assert.equal(miss.body.origin, 'portal');
    const blank = await request(s.port, 'GET', '/public/stats', { [HEADER]: '   ' }); assert.equal(blank.status, 401); assert.equal(problem(blank).code, 'missing_authorization');
    const auth = await request(s.port, 'GET', '/public/stats', { authorization: `Bolyra ${(await p1).header}` }); assert.equal(auth.status, 401); assert.equal(problem(auth).code, 'missing_authorization');
    assert.equal(s.calls(), 0, 'verifier never invoked');
  } finally { await s.close(); }
});

test('runner fail-closed cases are attributed to the runner; an allow with consume_nonces is refused by the portal', async () => {
  const cases: Array<[string, string[], number, string, string]> = [
    ['non-zero exit', ['-e', 'process.exit(3)'], 500, 'internal_error', 'runner'],
    ['hang', ['-e', 'setInterval(()=>{},1000)'], 500, 'internal_error', 'runner'],
    ['invalid verdict', ['-e', 'process.stdout.write("{\\"verdict\\":\\"maybe\\"}")'], 500, 'internal_error', 'runner'],
    ['allow with consume_nonces', ['-e', 'process.stdout.write(JSON.stringify({verdict:"allow",consume_nonces:[{issuer_key:"k",nonce:"1",retain_until:4102444800}]}))'], 500, 'internal_error', 'portal'],
    // The runner passes a CLI-emitted internal_error through (even with a non-zero exit); origin = cli.
    ['cli-emitted internal_error', ['-e', 'process.stdout.write(JSON.stringify({verdict:"deny",code:"internal_error",message:"no roots"})); process.exit(1)'], 500, 'internal_error', 'cli'],
  ];
  for (const [label, args, status, code, origin] of cases) {
    const s = await inProcess({ verifier: { command: process.execPath, args, timeoutMs: 300 } });
    try {
      const r = await request(s.port, 'GET', '/public/stats', await withP(p1));
      assert.equal(r.status, status, label); assert.equal(problem(r).code, code, label); assert.equal(r.body.origin, origin, label); assert.equal(s.calls(), 1, label);
    } finally { await s.close(); }
  }
});
