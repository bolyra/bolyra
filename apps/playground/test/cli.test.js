/**
 * test:cli — verifies the bytes the BROWSER downloaded (test:browser must run
 * first) with the published CLI at the pinned version. Needs network for npx.
 * PLAYGROUND_OFFLINE=1 skips this on a developer machine only; CI and
 * landing/deploy.sh refuse to run with it set.
 */
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';

const APP = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const ROOT = path.resolve(APP, '../..');
const pkg = JSON.parse(fs.readFileSync(path.join(APP, 'package.json'), 'utf8'));
const CLI = `@bolyra/cli@${pkg.config.cliVersion}`;
const skip = process.env.PLAYGROUND_OFFLINE ? 'PLAYGROUND_OFFLINE set (developer machine only)' : false;

function latestRunDir() {
  if (process.env.PLAYGROUND_RUN_DIR) return path.resolve(process.env.PLAYGROUND_RUN_DIR);
  const base = path.join(APP, '.playground-run');
  if (!fs.existsSync(base)) return null;
  const dirs = fs.readdirSync(base).sort();
  return dirs.length ? path.join(base, dirs[dirs.length - 1]) : null;
}
const cli = (args) => spawnSync('npx', ['-y', CLI, 'receipt', 'verify-chain', ...args], { encoding: 'utf8', timeout: 180_000 });

test(`browser-downloaded JSONL verifies with ${CLI}`, { skip }, () => {
  const dir = latestRunDir();
  assert.ok(dir && fs.existsSync(dir), 'no PLAYGROUND_RUN_DIR: run `npm run test:browser` first');
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
  const committedSha = crypto.createHash('sha256').update(fs.readFileSync(path.join(ROOT, 'landing/playground.html'))).digest('hex');
  assert.equal(manifest.htmlSha256, committedSha, 'the browser run tested a different page than the committed one; rerun test:browser');
  const receipts = path.join(dir, manifest.files.receipts);
  const signer = JSON.parse(fs.readFileSync(path.join(dir, manifest.files.signer), 'utf8'));
  assert.ok(fs.statSync(receipts).size > 0);
  assert.equal(signer.signer, manifest.signer);

  const ok = cli([receipts, '--signer', signer.signer, '--expect-count', String(manifest.expectedCount), '--expect-head', manifest.expectedHead]);
  assert.equal(ok.status, 0, `CLI rejected the browser export:\n${ok.stdout}\n${ok.stderr}`);
  assert.match(ok.stdout + ok.stderr, /PASS/);

  // The CLI must actually be checking: a flipped byte in a copy fails.
  const bytes = Buffer.from(fs.readFileSync(receipts));
  const i = bytes.indexOf(Buffer.from('"issuedAt":')) + '"issuedAt":'.length;
  bytes[i] = bytes[i] === 0x31 ? 0x32 : 0x31;
  const flipped = path.join(dir, 'receipts.flipped.jsonl'); fs.writeFileSync(flipped, bytes);
  const bad = cli([flipped, '--signer', signer.signer, '--expect-count', String(manifest.expectedCount), '--expect-head', manifest.expectedHead]);
  assert.notEqual(bad.status, 0, 'CLI accepted a tampered export');
  const wrongSigner = cli([receipts, '--signer', '0x' + '00'.repeat(20)]);
  assert.notEqual(wrongSigner.status, 0, 'CLI accepted a wrong signer');
});
