import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';

const ROOT = path.join(__dirname, '..', '..');
const CLI = path.join(ROOT, 'dist', 'src', 'report', 'cli.js');
const FIX = path.join(ROOT, 'test', 'report-fixtures', 'dry-run');
const summary = JSON.parse(fs.readFileSync(path.join(FIX, 'summary.json'), 'utf8'));
const signer = JSON.parse(fs.readFileSync(path.join(FIX, 'signer.json'), 'utf8')).signer as string;

function tmp(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'trial-report-'));
}
function runCli(args: string[]) {
  const r = spawnSync(process.execPath, [CLI, ...args], { encoding: 'utf8' });
  return { code: r.status, out: r.stdout, err: r.stderr };
}
function snapshot(dir: string): string {
  return fs
    .readdirSync(dir)
    .sort()
    .map((n) => {
      const st = fs.statSync(path.join(dir, n));
      return `${n}:${st.size}:${st.mtimeMs}`;
    })
    .join('|');
}

test('cli: writes report.html and report.json, leaves the bundle untouched, exit 0', () => {
  const bundle = path.join(tmp(), 'bundle');
  fs.cpSync(FIX, bundle, { recursive: true });
  const before = snapshot(bundle);
  const out = path.join(tmp(), 'out');
  const r = runCli(['--bundle', bundle, '--signer', signer, '--expect-count', String(summary.receiptCount), '--expect-head', summary.headReceiptHash, '--out', out]);
  assert.equal(r.code, 0, r.err);
  assert.equal(snapshot(bundle), before, 'bundle directory changed');
  const html = fs.readFileSync(path.join(out, 'report.html'), 'utf8');
  const json = JSON.parse(fs.readFileSync(path.join(out, 'report.json'), 'utf8'));
  assert.ok(html.startsWith('<!doctype html>'));
  assert.equal(json.anchors.signer, signer);
  assert.ok(Array.isArray(json.findings) && json.findings.length > 30);
  assert.ok(!json.findings.some((f: { status: string }) => f.status === 'FAILED'), 'clean bundle has no FAILED rows');
  assert.match(r.out, /report\.html/);
  assert.match(r.out, /FAILED: 0/);
});

test('cli: a failing bundle still gets a report and exit 0; the summary line counts FAILED rows', () => {
  const bundle = path.join(tmp(), 'bundle');
  fs.cpSync(FIX, bundle, { recursive: true });
  const out = path.join(tmp(), 'out');
  const r = runCli(['--bundle', bundle, '--signer', '0x' + '3'.repeat(40), '--out', out]);
  assert.equal(r.code, 0, r.err);
  const json = JSON.parse(fs.readFileSync(path.join(out, 'report.json'), 'utf8'));
  assert.ok(json.findings.some((f: { claim: string; status: string }) => f.claim === 'B1' && f.status === 'FAILED'));
  assert.doesNotMatch(r.out, /FAILED: 0\b/);
});

test('cli: missing --signer exits 2 with usage', () => {
  const r = runCli(['--bundle', FIX]);
  assert.equal(r.code, 2);
  assert.match(r.err, /--signer/);
  assert.match(r.err, /Usage/);
});

test('cli: --out inside the bundle is rejected with exit 2; bundle untouched', () => {
  const bundle = path.join(tmp(), 'bundle');
  fs.cpSync(FIX, bundle, { recursive: true });
  const before = snapshot(bundle);
  const r = runCli(['--bundle', bundle, '--signer', signer, '--out', path.join(bundle, 'report')]);
  assert.equal(r.code, 2);
  assert.match(r.err, /inside the bundle/);
  assert.equal(snapshot(bundle), before);
  const r2 = runCli(['--bundle', bundle, '--signer', signer, '--out', bundle]);
  assert.equal(r2.code, 2);
});

test('cli: unreadable bundle (missing receipts.jsonl) exits 2', () => {
  const bundle = tmp();
  fs.writeFileSync(path.join(bundle, 'summary.json'), '{}');
  const r = runCli(['--bundle', bundle, '--signer', signer, '--out', path.join(tmp(), 'o')]);
  assert.equal(r.code, 2);
  assert.match(r.err, /receipts\.jsonl/);
});

test('cli: malformed anchors are rejected before anything is read', () => {
  for (const args of [
    ['--signer', 'not-an-address'],
    ['--signer', signer, '--expect-count', 'three'],
    ['--signer', signer, '--expect-count', '-1'],
    ['--signer', signer, '--expect-head', '0x12'],
  ]) {
    const r = runCli(['--bundle', FIX, ...args, '--out', path.join(tmp(), 'o')]);
    assert.equal(r.code, 2, args.join(' '));
  }
});
