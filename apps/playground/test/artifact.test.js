/**
 * Extracted-artifact test: the COMMITTED page (or the one named by
 * PLAYGROUND_HTML, e.g. bytes fetched from the live site) is executed in a
 * child process and driven with repository fixtures. The expectations below
 * come from the repository, never from the bundle's own samples.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { extractBundle, externalScripts } from './lib/extract.mjs';
import { runBundle } from './lib/run-bundle.mjs';

const here = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(here, '../../..');
const HTML_PATH = process.env.PLAYGROUND_HTML ?? path.join(ROOT, 'landing/playground.html');
const pkg = JSON.parse(fs.readFileSync(path.join(here, '../package.json'), 'utf8'));
const html = fs.readFileSync(HTML_PATH, 'utf8');
const bundleFile = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'pg-artifact-')), 'bundle.js');
fs.writeFileSync(bundleFile, extractBundle(html));
const run = (ops) => runBundle(bundleFile, ops);

const corpus = (f) => fs.readFileSync(path.join(ROOT, 'examples/receipt-scoring-kit/corpus', f), 'utf8');
const conf = (f) => fs.readFileSync(path.join(ROOT, 'spec/fixtures/receipt-conformance', f), 'utf8');
const manifest = JSON.parse(corpus('manifest.json')).chains['operator-b.jsonl'];
const CHAIN = corpus('operator-b.jsonl');
const lines = (t) => t.split('\n').filter(Boolean);

test('page shape: one bundle marker, Plausible is the only external script', () => {
  assert.doesNotThrow(() => extractBundle(html));
  assert.deepEqual(externalScripts(html), ['https://plausible.io/js/script.js']);
  assert.ok(!/text\/babel/.test(html)); assert.ok(!/unpkg\.com/.test(html));
  assert.ok(html.includes(`@bolyra/receipts@${pkg.config.receiptsVersion}`), 'visible version pin');
});

test('bundle metadata matches the package pin', () => {
  const [meta] = run([{ op: 'meta' }]);
  assert.equal(meta.RECEIPTS_VERSION, pkg.config.receiptsVersion);
  for (const k of ['verifyAll', 'newSession', 'decide', 'resetSession', 'exportJsonl', 'signerDoc', 'chainInfo']) assert.ok(meta.exports.includes(k), k);
});

test('sample chain with the manifest checkpoint verifies; tampering, truncation and a wrong signer fail', () => {
  const [a, b, c] = lines(CHAIN);
  const flipped = JSON.parse(b); flipped.payload.issuedAt += 1;
  const [ok, flip, wrong, trunc, tampered] = run([
    { op: 'verify', text: CHAIN, options: { expectedSigner: manifest.signer, expectedCount: manifest.count, expectedHeadHash: manifest.head } },
    { op: 'verify', text: [a, JSON.stringify(flipped), c].join('\n'), options: { expectedSigner: manifest.signer } },
    { op: 'verify', text: CHAIN, options: { expectedSigner: '0x' + '00'.repeat(20) } },
    { op: 'verify', text: [a, b].join('\n'), options: { expectedCount: manifest.count, expectedHeadHash: manifest.head } },
    { op: 'verify', text: corpus('tampered.jsonl'), options: {} },
  ]);
  assert.equal(ok.overall, 'ok'); assert.equal(ok.checkpoint.state, 'matched'); assert.ok(ok.rows.every((r) => r.signature === 'valid' && r.signerMatch === 'matched'));
  assert.equal(flip.overall, 'failed'); assert.equal(flip.rows[1].signature, 'invalid');
  assert.equal(wrong.overall, 'failed'); assert.ok(wrong.rows.every((r) => r.signerMatch === 'mismatch'));
  assert.equal(trunc.overall, 'failed'); assert.equal(trunc.checkpoint.state, 'mismatch');
  const codes = tampered.chain.issues.map((i) => `${i.index}:${i.code}`);
  for (const want of ['2:signature-invalid', '2:receipt-hash-mismatch', '3:prev-hash-mismatch']) assert.ok(codes.includes(want), want);
});

test('forged instance ref: signature valid, instance ref_mismatch, overall failed; unsupported and empty inputs are never ok', () => {
  const rs256 = JSON.parse(lines(CHAIN)[0]); rs256.signature.alg = 'RS256';
  const [forged, bad, empty] = run([
    { op: 'verify', text: conf('forged-ref.json'), options: {} },
    { op: 'verify', text: JSON.stringify(rs256), options: {} },
    { op: 'verify', text: '', options: {} },
  ]);
  assert.equal(forged.rows[0].signature, 'valid'); assert.equal(forged.rows[0].instance.code, 'ref_mismatch'); assert.equal(forged.overall, 'failed');
  assert.equal(bad.overall, 'failed'); assert.equal(bad.rows[0].signature, 'not-run');
  assert.equal(empty.overall, 'invalid');
});

test('simulate: presets sign real chained receipts that verify with the library; reset starts chain 2', () => {
  const [sim] = run([{ op: 'simulate', steps: [{ tier: 'small', amount: '25' }, { tier: 'small', amount: '500' }, { tier: 'small', amount: 'x' }], reset: true }]);
  assert.deepEqual(sim.results.map((r) => r.outcome), ['allow', 'deny', 'invalid']);
  assert.equal(sim.results[1].reasonCode, 'request_mismatch');
  assert.equal(sim.chain.seq, 2);
  const [check] = run([{ op: 'verify', text: sim.jsonl, options: { expectedSigner: sim.signer.signer, expectedCount: sim.chain.seq, expectedHeadHash: sim.chain.headHash } }]);
  assert.equal(check.overall, 'ok');
  assert.equal(sim.afterReset.chainId, 2); assert.equal(sim.afterReset.chain.seq, 0); assert.notEqual(sim.afterReset.signer, sim.signer.signer);
});
