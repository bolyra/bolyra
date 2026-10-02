import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { spawnSync } from 'node:child_process';
import crypto from 'node:crypto';
import { fileURLToPath } from 'node:url';
import { extractBundle, externalScripts } from './lib/extract.mjs';
import { runBundle } from './lib/run-bundle.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const APP = path.resolve(here, '..');
const ROOT = path.resolve(APP, '../..');
const COMMITTED = path.join(ROOT, 'landing/playground.html');
const pkg = JSON.parse(fs.readFileSync(path.join(APP, 'package.json'), 'utf8'));
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-build-'));
const build = (args, env = {}) => spawnSync(process.execPath, [path.join(APP, 'build.mjs'), ...args], { cwd: APP, encoding: 'utf8', env: { ...process.env, ...env }, timeout: 120_000 });

test('--check passes against the committed page and writes nothing', () => {
  const before = fs.statSync(COMMITTED).mtimeMs;
  const r = build(['--check']);
  assert.equal(r.status, 0, r.stderr + r.stdout);
  assert.equal(fs.statSync(COMMITTED).mtimeMs, before);
});

test('the build is byte-deterministic and a one-byte mutation fails --check', () => {
  const a = path.join(tmp, 'a.html'), b = path.join(tmp, 'b.html');
  assert.equal(build(['--out', a]).status, 0); assert.equal(build(['--out', b]).status, 0);
  const bytes = fs.readFileSync(a);
  assert.ok(bytes.equals(fs.readFileSync(b)), 'two builds differ');
  assert.ok(bytes.equals(fs.readFileSync(COMMITTED)), 'committed page is stale: run npm run build');
  const mutated = Buffer.from(bytes); const i = mutated.lastIndexOf(Buffer.from('</html>')) - 2; mutated[i] = mutated[i] === 0x41 ? 0x42 : 0x41;
  const m = path.join(tmp, 'mutated.html'); fs.writeFileSync(m, mutated);
  assert.notEqual(build(['--check', m]).status, 0);
});

test('page statics: no Babel, no CDN React, pin text, licenses block, escaped bundle', () => {
  const html = fs.readFileSync(COMMITTED, 'utf8');
  assert.ok(!/text\/babel/i.test(html)); assert.ok(!/unpkg\.com/.test(html)); assert.ok(!/cdnjs|jsdelivr/.test(html));
  assert.deepEqual(externalScripts(html), []);
  assert.ok(html.includes(`@bolyra/receipts@${pkg.config.receiptsVersion}`));
  assert.ok(html.includes('<details class="licenses">'));
  for (const [name, ver] of Object.entries({ react: '18.3.1', 'react-dom': '18.3.1', '@bolyra/receipts': pkg.config.receiptsVersion, '@noble/secp256k1': pkg.dependencies['@noble/secp256k1'], '@noble/hashes': pkg.dependencies['@noble/hashes'] })) assert.ok(html.includes(`${name}@${ver}`), `${name}@${ver} in licenses`);
  const bundle = extractBundle(html);
  assert.ok(!/<\/script/i.test(bundle), 'unescaped </script inside the bundle');
  assert.ok(!bundle.includes('<!--'), 'HTML comment opener inside the bundle');
  assert.ok(!html.includes('\r'), 'CRLF'); assert.ok(html.endsWith('\n'));
});

test('hostile sample text survives embedding and decodes unchanged', () => {
  const hostile = '{"a":"</script><script>alert(1)</script>","b":"<!-- x --> --> \\u2028 $& $1"}';
  const extra = path.join(tmp, 'extra.json'); fs.writeFileSync(extra, JSON.stringify({ hostile: { label: 'hostile', text: hostile } }));
  const out = path.join(tmp, 'hostile.html');
  const r = build(['--out', out], { PLAYGROUND_EXTRA_SAMPLES: extra });
  assert.equal(r.status, 0, r.stderr);
  const bundle = extractBundle(fs.readFileSync(out, 'utf8'));
  assert.ok(!/<\/script/i.test(bundle)); assert.ok(!bundle.includes('<!--'));
  const bf = path.join(tmp, 'hostile-bundle.js'); fs.writeFileSync(bf, bundle);
  const [sample] = runBundle(bf, [{ op: 'sample', key: 'hostile' }]);
  assert.equal(sample.text, hostile);
});

test('@bolyra/mpp is not bundled', () => {
  const meta = path.join(tmp, 'meta.json');
  assert.equal(build(['--out', path.join(tmp, 'm.html'), '--meta', meta]).status, 0);
  const inputs = Object.keys(JSON.parse(fs.readFileSync(meta, 'utf8')).inputs);
  assert.ok(inputs.length > 0); assert.ok(inputs.every((i) => !i.includes('@bolyra/mpp')), inputs.filter((i) => i.includes('mpp')).join(','));
});

// --- Phase B ---------------------------------------------------------------
test('phase B statics: needles, payment-protocols pin, no oracle in the bundle, spec hash define', () => {
  const html = fs.readFileSync(COMMITTED, 'utf8');
  for (const needle of ['Decode a 402', 'EVC wire shapes', `@bolyra/payment-protocols@${pkg.config.paymentProtocolsVersion}`]) assert.ok(html.includes(needle), needle);
  const meta = path.join(tmp, 'meta-b.json');
  assert.equal(build(['--out', path.join(tmp, 'b2.html'), '--meta', meta]).status, 0);
  const inputs = Object.keys(JSON.parse(fs.readFileSync(meta, 'utf8')).inputs);
  assert.ok(inputs.every((i) => !/@bolyra\/(payment-protocols|mpp)|node_modules\/jose\//.test(i)), inputs.filter((i) => /payment-protocols|mpp|jose/.test(i)).join(','));
  const specSha = crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, 'spec/external-verifier-contract-v1.md'))).digest('hex');
  assert.ok(html.includes(specSha.slice(0, 12)), 'spec sha256 prefix rendered on the page');
});

// --- usage signals -----------------------------------------------------------
test('usage statics: no Plausible, the exact privacy sentence, no stale analytics claim', () => {
  const html = fs.readFileSync(COMMITTED, 'utf8');
  assert.ok(!html.includes('plausible.io'), 'no plausible.io reference');
  assert.ok(html.includes('Pasted content is processed in your browser and is never included in analytics requests.'));
  assert.ok(html.includes('Our hosting access logs record request metadata, including IP addresses and browser information.'));
  assert.ok(!html.includes('loads Plausible analytics'));
  const visible = html.replace(/<script id="playground-bundle">[\s\S]*?<\/script>/, '');
  assert.ok(!/anonymous/i.test(visible), 'page copy never describes the logs as anonymous');
});
