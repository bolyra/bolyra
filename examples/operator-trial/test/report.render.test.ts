import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { classify } from '../src/report/classify';
import type { Anchors, Report } from '../src/report/classify';
import { render, buildVerifyCommand } from '../src/report/render';
import { ANCHORS_WORDING, DEV_MODE_DISCLOSURE, STATUS_LEGEND, TAMPER_INSTRUCTION } from '../src/report/claims';

const FIX = path.join(__dirname, '..', '..', 'test', 'report-fixtures', 'dry-run');
const read = (n: string) => fs.readFileSync(path.join(FIX, n), 'utf8');
const summary = JSON.parse(read('summary.json'));
const signer = JSON.parse(read('signer.json')).signer as string;

function report(over: { receiptsJsonl?: string; summaryJson?: string } = {}, anchors: Anchors = { signer, expectCount: summary.receiptCount as number, expectHead: summary.headReceiptHash as string }): Report {
  return classify(
    { receiptsJsonl: read('receipts.jsonl'), summaryJson: read('summary.json'), signerJson: read('signer.json'), verifyTxt: read('VERIFY.txt'), ...over },
    anchors,
    { now: new Date('2026-10-10T17:00:00Z'), bundleName: 'dry-run' },
  );
}

test('render: self-contained, no executable markup or external resource loads', () => {
  const html = render(report(), { receiptsPath: './receipts.jsonl' });
  assert.match(html, /^<!doctype html>/i);
  for (const bad of [/<script/i, /<link/i, /<img/i, /<iframe/i, /<object/i, /<embed/i, /@import/i, /url\(/i, /\son[a-z]+=/i, /javascript:/i]) {
    assert.doesNotMatch(html, bad, String(bad));
  }
});

test('render: every finding id appears exactly once as a row anchor; fixed wording present verbatim', () => {
  const r = report();
  const html = render(r, { receiptsPath: './receipts.jsonl' });
  for (const f of r.findings) {
    const needle = `id="f-${f.id}"`;
    assert.equal(html.split(needle).length - 1, 1, needle);
  }
  assert.ok(html.includes(esc(ANCHORS_WORDING)), 'anchors wording');
  // Literal, so a drift in claims.ts is caught here rather than mirrored.
  assert.ok(html.includes(esc('Values were supplied through command-line flags. Their independence from this bundle is unknown. Copying signer/count/head from bundle files establishes consistency with those supplied values; it does not establish signer identity or independently establish completeness. External assurance requires a separately trusted signer reference and checkpoint.')), 'anchors wording (literal)');
  assert.ok(html.includes(esc('FAIL line <n>: [signature-invalid]')), 'tamper instruction (literal)');
  assert.ok(html.includes(esc(DEV_MODE_DISCLOSURE)), 'dev-mode disclosure');
  assert.ok(html.includes(esc(TAMPER_INSTRUCTION)), 'tamper instruction');
  for (const [k, v] of Object.entries(STATUS_LEGEND)) {
    assert.ok(html.includes(`<dt>${k}</dt>`), `legend ${k}`);
    assert.ok(html.includes(esc(v)), `legend text ${k}`);
  }
  // Disclosure precedes the first finding.
  assert.ok(html.indexOf(esc(DEV_MODE_DISCLOSURE)) < html.indexOf('id="f-'));
});

test('render: the verify command is pinned to the trial CLI version and carries the anchors', () => {
  const r = report();
  const cmd = buildVerifyCommand(r, './receipts.jsonl');
  assert.ok(cmd.startsWith('npx @bolyra/cli@0.9.0 receipt verify-chain '), cmd);
  assert.ok(cmd.includes(`--signer ${signer}`));
  assert.ok(cmd.includes(`--expect-count ${summary.receiptCount}`));
  assert.ok(cmd.includes(`--expect-head ${summary.headReceiptHash}`));
  const html = render(r, { receiptsPath: './receipts.jsonl' });
  assert.ok(html.includes(esc(cmd)));

  const partial = buildVerifyCommand(report({}, { signer }), "./odd path/it's.jsonl");
  assert.ok(!partial.includes('--expect-count') && !partial.includes('--expect-head'));
  assert.ok(partial.includes(`'./odd path/it'\\''s.jsonl'`), partial);
});

test('render: bundle values are escaped (injection in a summary field)', () => {
  const s = JSON.parse(read('summary.json'));
  s.action.name = '<img src=x onerror=alert(1)>';
  s.action.path = '/"><script>alert(2)</script>';
  const html = render(report({ summaryJson: JSON.stringify(s) }), { receiptsPath: './receipts.jsonl' });
  assert.doesNotMatch(html, /<img/i);
  assert.doesNotMatch(html, /<script/i);
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
});

test('render: unattributed receipts get their own section; attempts get one section each', () => {
  const s = JSON.parse(read('summary.json'));
  s.attempts[0].receiptId = '0x' + '0'.repeat(16);
  const html = render(report({ summaryJson: JSON.stringify(s) }), { receiptsPath: './receipts.jsonl' });
  assert.ok(html.includes('id="attempt-1"') && html.includes('id="attempt-2"') && html.includes('id="attempt-3"'));
  assert.ok(html.includes('id="unattributed"'));
  assert.ok(html.includes('id="f-A2:L1"'));
  const clean = render(report(), { receiptsPath: './receipts.jsonl' });
  assert.ok(!clean.includes('id="unattributed"'));
});

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
