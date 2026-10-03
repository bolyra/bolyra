/**
 * Narrated demo: two portal processes (A = https://stats.example.gov, B = https://internal.example.gov),
 * each with its own HOME (own local nonce store), one demo presentation per binding, six scenes.
 * Prints the disclosure BEFORE any result, a table, and a machine-readable `RESULT {json}` line.
 * Exits 1 if any scene deviates from the table in src/scenes.ts.
 */
import { spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';
import * as http from 'node:http';
import * as os from 'node:os';
import * as path from 'node:path';
import { buildPresentation, PUBLIC_STATS_BINDING, OVERREACH_BINDING, AUDIENCE, OPERATOR_PRIV } from './credential';
import { HEADER } from './portal';
import { SCENES, judge, type SceneResult } from './scenes';

const OTHER_AUDIENCE = 'https://internal.example.gov';

interface Portal { label: string; audience: string; port: number; home: string; child: ChildProcess }

async function startPortal(label: string, audience: string): Promise<Portal> {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), `gsp-${label}-`));
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, PORTAL_AUDIENCE: audience };
  delete env.BOLYRA_TRUSTED_ROOTS;
  const child = spawn(process.execPath, [path.join(__dirname, 'portal-main.js')], { env, stdio: ['ignore', 'pipe', 'inherit'] });
  const port = await new Promise<number>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error(`portal ${label} did not start within 15 s`)), 15_000);
    let buf = '';
    child.stdout!.on('data', (d) => { buf += d.toString(); const m = /\{"port":(\d+)\}/.exec(buf); if (m) { clearTimeout(timer); resolve(Number(m[1])); } });
    child.on('exit', (code) => { clearTimeout(timer); reject(new Error(`portal ${label} exited early (${code})`)); });
  });
  return { label, audience, port, home, child };
}

function stopPortal(p: Portal): Promise<void> {
  return new Promise((resolve) => {
    p.child.once('exit', () => { fs.rmSync(p.home, { recursive: true, force: true }); resolve(); });
    p.child.kill('SIGTERM');
    setTimeout(() => p.child.kill('SIGKILL'), 5_000).unref();
  });
}

function get(port: number, urlPath: string, headers: Record<string, string>): Promise<{ status: number; body: any }> {
  return new Promise((resolve, reject) => {
    const req = http.request({ host: '127.0.0.1', port, method: 'GET', path: urlPath, headers, timeout: 60_000 }, (res) => {
      let text = ''; res.on('data', (d) => { text += d; });
      res.on('end', () => { let body: any = null; try { body = JSON.parse(text); } catch { /* ignore */ } resolve({ status: res.statusCode ?? 0, body }); });
    });
    req.on('timeout', () => req.destroy(new Error('timeout')));
    req.on('error', reject);
    req.end();
  });
}

async function main(): Promise<number> {
  console.log('DISCLOSURE (read before the results)');
  console.log('  - The published verifier (@bolyra/cli `bolyra verify`) performs real Groth16 verification against fixture roots.');
  console.log('  - The proof is the repository test vector integrations/cli/test/fixtures/verify/allow-agent-only, reused UNCHANGED.');
  console.log(`  - The operator-signed bindings are re-signed with the PUBLICLY KNOWN test private key ${OPERATOR_PRIV}n; anyone can reproduce them.`);
  console.log('  - This demonstrates ENFORCEMENT by a relying party, not operator identity and not production issuance.');
  console.log('  - The "domains" are configured audience strings on loopback servers; no DNS or TLS is involved. Data is invented.');
  console.log('  - Decision origin per scene: cli = verdict returned by the published verifier; runner = @bolyra/mpp synthesized a fail-closed error; portal = decided locally without the verifier.');
  console.log('');
  const [p1, p2] = await Promise.all([buildPresentation(PUBLIC_STATS_BINDING), buildPresentation(OVERREACH_BINDING)]);
  const A = await startPortal('A', AUDIENCE);
  const B = await startPortal('B', OTHER_AUDIENCE);
  const results: SceneResult[] = [];
  try {
    for (const s of SCENES) {
      const portal = s.portal === 'A' ? A : B;
      const headers: Record<string, string> = s.presentation === 'P1' ? { [HEADER]: p1.header } : s.presentation === 'P2' ? { [HEADER]: p2.header } : {};
      const r = await get(portal.port, s.path, headers);
      const code = r.status === 200 ? null : (r.body?.code ?? null);
      const origin = r.body?.origin ?? 'portal';
      const detail = r.body?.verifier_detail ?? {};
      results.push({ id: s.id, status: r.status, code, origin, detail });
      console.log(`Scene ${s.id}: GET ${portal.label} (${portal.audience}) ${s.path} with ${s.presentation}`);
      console.log(`  → HTTP ${r.status} ${code ?? 'allow (verdict)'} [origin: ${origin}]${Object.keys(detail).length ? ' ' + JSON.stringify(detail) : ''}`);
      console.log(`  decider: ${s.decider}`);
      console.log(`  ${s.narration}`);
    }
  } finally {
    await Promise.all([stopPortal(A), stopPortal(B)]);
  }
  const verdict = judge(results);
  console.log('');
  console.log(verdict.ok ? 'All six scenes matched the expected verdicts.' : `DEVIATIONS:\n  - ${verdict.failures.join('\n  - ')}`);
  console.log('Not shown: revocation, delegation, human proofs, host-nonce mode. Only a relying party that verifies gets any of this.');
  console.log(`RESULT ${JSON.stringify({ ok: verdict.ok, scenes: results, failures: verdict.failures })}`);
  return verdict.ok ? 0 : 1;
}

main().then((code) => process.exit(code), (err) => { console.error(err); process.exit(1); });
