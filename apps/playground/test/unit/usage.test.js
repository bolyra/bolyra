import { test } from 'node:test';
import assert from 'node:assert/strict';
import { EVENTS, createTracker, EVENT_CAP, beaconUrl, BEACON_INIT } from '../../src/core/usage.js';

const EXPECTED = ['interacted', 'tab_verify', 'tab_simulate', 'tab_decode', 'tab_evc', 'sample_verify', 'sample_simulate', 'sample_decode', 'run_verify', 'run_simulate', 'run_decode', 'verify_ok', 'verify_failed', 'verify_invalid', 'simulate_ok', 'simulate_failed', 'simulate_invalid', 'decode_ok', 'decode_invalid', 'copy_clicked', 'export_clicked'];
const recorder = () => { const sent = []; return { sent, send: (url, init) => { sent.push({ url, init }); return Promise.resolve(); } }; };

test('allowlist is exactly the v1 set and frozen', () => {
  assert.deepEqual([...EVENTS].sort(), [...EXPECTED].sort());
  assert.ok(Object.isFrozen(EVENTS));
  assert.ok(!EVENTS.includes('decode_failed'));
});

test('URL and fetch options are exactly as specified', () => {
  assert.equal(beaconUrl('tab_decode'), '/e?v=1&ev=tab_decode');
  assert.deepEqual(BEACON_INIT, { method: 'GET', credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store', keepalive: true, redirect: 'error' });
  assert.ok(Object.isFrozen(BEACON_INIT));
});

test('first event is preceded by interacted; each event at most once', () => {
  const r = recorder(); const t = createTracker({ send: r.send });
  t.track('tab_decode'); t.track('tab_decode'); t.track('run_decode'); t.track('interacted');
  assert.deepEqual(r.sent.map((s) => s.url), ['/e?v=1&ev=interacted', '/e?v=1&ev=tab_decode', '/e?v=1&ev=run_decode']);
  for (const s of r.sent) assert.deepEqual(s.init, BEACON_INIT);
});

test('unknown names and input-shaped values never send; strict mode throws', () => {
  const r = recorder(); const t = createTracker({ send: r.send });
  for (const bad of ['decode_failed', 'tab_wire', 'run_decode&x=1', 'secret-canary-123', '', undefined, null, 5, { toString: () => 'tab_verify' }]) t.track(bad);
  assert.equal(r.sent.length, 0);
  const s = createTracker({ send: r.send, strict: true });
  assert.throws(() => s.track('nope'), /not an allowlisted usage event/);
});

test('hard cap of sends per document', () => {
  assert.equal(EVENT_CAP, 32);
  const r = recorder(); const t = createTracker({ send: r.send, cap: 3 });
  for (const ev of ['tab_verify', 'tab_simulate', 'tab_decode', 'tab_evc']) t.track(ev);
  assert.equal(r.sent.length, 3);
});

test('transport failures are swallowed (sync throw and rejected promise)', async () => {
  const t1 = createTracker({ send: () => { throw new Error('boom'); } });
  assert.doesNotThrow(() => t1.track('tab_verify'));
  const t2 = createTracker({ send: () => Promise.reject(new Error('boom')) });
  assert.doesNotThrow(() => t2.track('tab_verify'));
  await new Promise((r) => setTimeout(r, 10));
});

test('default transport is a no-op where fetch is unavailable', () => {
  const t = createTracker({ fetchImpl: undefined });
  assert.doesNotThrow(() => t.track('tab_verify'));
});
