import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { buildPacket, serialize, writePacket } from '../src/generate';
import { readPacket, verifyPacket } from '../src/verify';
import { actionDigest, parseReason, ReasonFormatError } from '../src/digest';

const ROOT = path.join(__dirname, '..', '..');
const FIX = path.join(ROOT, 'fixtures');
const signerOf = () => JSON.parse(fs.readFileSync(path.join(FIX, 'signer.json'), 'utf8')).signer as string;
const st = (fs: ReturnType<typeof verifyPacket>, id: string) => fs.find((f) => f.id === id)!.status;

test('regeneration is byte-identical to the committed fixtures', () => {
  const files = serialize(buildPacket());
  for (const [name, text] of Object.entries(files)) {
    assert.equal(fs.readFileSync(path.join(FIX, name), 'utf8'), text, name);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ale-'));
  writePacket(tmp);
  for (const name of Object.keys(files)) assert.equal(fs.readFileSync(path.join(tmp, name), 'utf8'), files[name]);
});

test('clean packet: V1-V4 DERIVED, V5-V6 ABSENT, signer.json matches', () => {
  const r = verifyPacket(readPacket(FIX), { signer: signerOf() });
  for (const id of ['V1', 'V2', 'V3', 'V4', 'S']) assert.equal(st(r, id), 'DERIVED', id);
  for (const id of ['V5', 'V6']) assert.equal(st(r, id), 'ABSENT', id);
  assert.ok(!r.some((f) => f.status === 'FAILED'));
});

test('altered arguments: only V3 fails', () => {
  const r = verifyPacket(readPacket(FIX, path.join(FIX, 'tampered', 'execution-altered-args.json')), { signer: signerOf() });
  assert.equal(st(r, 'V3'), 'FAILED');
  assert.match(r.find((f) => f.id === 'V3')!.note, /execution\.json\.action digest differs/);
  for (const id of ['V1', 'V2', 'V4', 'S']) assert.equal(st(r, id), 'DERIVED', id);
});

test('altered receipt (allowed flipped, not re-signed): V1, V2 and V3 fail; V4-V6 unchanged', () => {
  const files = readPacket(FIX);
  files.receipt = JSON.parse(JSON.stringify(files.receipt));
  files.receipt.payload.decision.allowed = false;
  const r = verifyPacket(files, { signer: signerOf() });
  assert.equal(st(r, 'V1'), 'FAILED');
  assert.equal(st(r, 'V2'), 'FAILED');
  assert.equal(st(r, 'V3'), 'FAILED');
  assert.match(r.find((f) => f.id === 'V3')!.note, /dependency failed/);
  assert.equal(st(r, 'V4'), 'DERIVED');
  assert.equal(st(r, 'V5'), 'ABSENT');
});

test('wrong signer anchor: V1 fails, V3 fails by dependency, signer.json comparison fails, V2 still consistent', () => {
  const r = verifyPacket(readPacket(FIX), { signer: '0x' + '1'.repeat(40) });
  assert.equal(st(r, 'V1'), 'FAILED');
  assert.equal(st(r, 'V3'), 'FAILED');
  assert.equal(st(r, 'S'), 'FAILED');
  assert.equal(st(r, 'V2'), 'DERIVED');
});

test('receipt id tampered: V2 fails, V1 unaffected', () => {
  const files = readPacket(FIX);
  files.receipt = JSON.parse(JSON.stringify(files.receipt));
  files.receipt.id = '0x' + '0'.repeat(16);
  const r = verifyPacket(files, { signer: signerOf() });
  assert.equal(st(r, 'V1'), 'DERIVED');
  assert.equal(st(r, 'V2'), 'FAILED');
});

test('reason convention is strict: missing, malformed and duplicate entries are rejected', () => {
  const good = 'approved | action_digest=' + 'a'.repeat(64) + ' | tool=zendesk.post_reply';
  assert.deepEqual(parseReason(good), { digest: 'a'.repeat(64), tool: 'zendesk.post_reply' });
  for (const bad of [
    'denied | action_digest=' + 'a'.repeat(64) + ' | tool=zendesk.post_reply',
    'approved | tool=zendesk.post_reply',
    'approved | action_digest=' + 'a'.repeat(63) + ' | tool=zendesk.post_reply',
    good + ' | action_digest=' + 'b'.repeat(64),
    good + ' | extra=1',
    'approved | action_digest=' + 'a'.repeat(64),
    42,
  ]) assert.throws(() => parseReason(bad), ReasonFormatError, String(bad));
});

test('digest covers tenant, server, tool, resource and arguments', () => {
  const a = buildPacket()['action.json'];
  const d = actionDigest(a);
  assert.notEqual(actionDigest({ ...a, tenant: 'org_other' }), d);
  assert.notEqual(actionDigest({ ...a, resource: { ...a.resource, id: 'tkt_9' } }), d);
  assert.notEqual(actionDigest({ ...a, arguments: { ...a.arguments, body: 'x' } }), d);
  assert.equal(actionDigest(JSON.parse(JSON.stringify({ arguments: a.arguments, tool: a.tool, tenant: a.tenant, server: a.server, resource: a.resource }))), d, 'key order does not matter (JCS)');
});

test('export metadata respects the documented limits (50 keys, 40-char names, 500-char values) and is strings only', () => {
  for (const e of buildPacket()['export.jsonl']) {
    const keys = Object.keys(e.metadata);
    assert.ok(keys.length <= 50);
    for (const k of keys) {
      assert.ok(k.length <= 40, k);
      assert.equal(typeof e.metadata[k], 'string', k);
      assert.ok(e.metadata[k].length <= 500, k);
    }
  }
});

test('CLI: produces a report with exit 0; usage error exits 2', () => {
  const cli = path.join(ROOT, 'dist', 'src', 'verify.js');
  const ok = spawnSync(process.execPath, [cli, '--fixtures', FIX, '--signer', signerOf()], { encoding: 'utf8' });
  assert.equal(ok.status, 0, ok.stderr);
  assert.match(ok.stdout, /V3  DERIVED/);
  assert.match(ok.stdout, /Trust assumptions/);
  const bad = spawnSync(process.execPath, [cli, '--fixtures', FIX], { encoding: 'utf8' });
  assert.equal(bad.status, 2);
});

test('missing or duplicated events are failures, never silently picked', () => {
  const base = readPacket(FIX);
  const noExec = { ...base, events: base.events.filter((e) => e.action !== 'tool.executed') };
  let r = verifyPacket(noExec, { signer: signerOf() });
  assert.equal(st(r, 'V2'), 'FAILED');
  assert.equal(st(r, 'V3'), 'FAILED');
  assert.match(r.find((f) => f.id === 'V3')!.note, /exactly one tool.executed event, found 0/);
  assert.equal(st(r, 'V1'), 'DERIVED');
  const dup = JSON.parse(JSON.stringify(base.events.find((e) => e.action === 'tool.executed')));
  dup.metadata.action_digest = 'f'.repeat(64);
  r = verifyPacket({ ...base, events: [...base.events, dup] }, { signer: signerOf() });
  assert.equal(st(r, 'V2'), 'FAILED');
  assert.equal(st(r, 'V3'), 'FAILED');
  assert.match(r.find((f) => f.id === 'V3')!.note, /found 2/);
});

test('CLI: bad flags and unreadable input exit 2, never 1', () => {
  const cli = path.join(ROOT, 'dist', 'src', 'verify.js');
  for (const args of [['--bogus'], ['--fixtures', FIX, '--signer'], ['--fixtures', '/nonexistent', '--signer', signerOf()]]) {
    const r = spawnSync(process.execPath, [cli, ...args], { encoding: 'utf8' });
    assert.equal(r.status, 2, args.join(' ') + ' → ' + r.stderr);
  }
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'ale-bad-'));
  fs.cpSync(FIX, tmp, { recursive: true });
  fs.writeFileSync(path.join(tmp, 'export.jsonl'), '{"action":"tool.approval_resolved"}\n{"action":"tool.executed"}\n');
  const r = spawnSync(process.execPath, [cli, '--fixtures', tmp, '--signer', signerOf()], { encoding: 'utf8' });
  assert.equal(r.status, 0, 'malformed event metadata still yields a report: ' + r.stderr);
  assert.match(r.stdout, /V2  FAILED/);
});
