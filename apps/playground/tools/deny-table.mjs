/**
 * Code → HTTP status/title/type from the PUBLISHED `@bolyra/mpp` (the only place
 * that mapping exists). Loaded in a child process so the build never requires
 * @bolyra/mpp in-process (its dependency tree keeps handles open).
 */
import { spawnSync } from 'node:child_process';
import { createRequire } from 'node:module';

const CHILD = `
const m = require('@bolyra/mpp');
const codes = JSON.parse(process.argv[1]);
const row = (code) => { const p = m.denyProblem({ code, message: '' }); return { code, status: p.status, title: p.title, type: p.type }; };
const extra = Object.keys(m.DENY_STATUS).filter((c) => !codes.includes(c));
process.stdout.write(JSON.stringify({ mppVersion: require('@bolyra/mpp/package.json').version, registry: codes.map(row), gateLocal: extra.map(row), statusKeys: Object.keys(m.DENY_STATUS) }));
process.exit(0);
`;

export function denyTable(registryCodes) {
  const require = createRequire(import.meta.url);
  const mppDir = require.resolve('@bolyra/mpp/package.json').replace(/package\.json$/, '');
  const r = spawnSync(process.execPath, ['-e', CHILD, JSON.stringify(registryCodes)], { cwd: mppDir, encoding: 'utf8', timeout: 60_000 });
  if (r.status !== 0) throw new Error(`deny-table child failed (status ${r.status}): ${r.stderr}`);
  const t = JSON.parse(r.stdout);
  if (JSON.stringify(t.gateLocal.map((x) => x.code)) !== JSON.stringify(['missing_authorization'])) throw new Error(`unexpected gate-local deny codes: ${JSON.stringify(t.gateLocal.map((x) => x.code))}`);
  for (const row of [...t.registry, ...t.gateLocal]) if (![401, 403, 500].includes(row.status)) throw new Error(`unexpected status ${row.status} for ${row.code}`);
  t.gateLocal = t.gateLocal.map((x) => ({ ...x, note: 'gate-local to @bolyra/mpp; not in the EVC §9 registry' }));
  return t;
}
