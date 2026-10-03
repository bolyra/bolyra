import { test } from 'node:test';
import assert from 'node:assert/strict';
import { SCENES, judge, type SceneResult } from '../src/scenes';

const good = (): SceneResult[] => SCENES.map((s) => ({ id: s.id, status: s.expect.status, code: s.expect.code ?? null, origin: s.expect.origin, detail: s.expect.detail ?? {} }));

test('the scene table has six scenes with the planned codes and origins', () => {
  assert.deepEqual(SCENES.map((s) => [s.id, s.expect.status, s.expect.code ?? 'allow', s.expect.origin]), [
    [1, 200, 'allow', 'cli'], [2, 403, 'request_mismatch', 'cli'], [3, 403, 'request_mismatch', 'cli'],
    [4, 403, 'nonce_replayed', 'cli'], [5, 401, 'missing_authorization', 'portal'], [6, 403, 'scope_exceeded', 'cli'],
  ]);
  assert.deepEqual(judge(good()), { ok: true, failures: [] });
});

test('judge flags wrong status, wrong code, missing, duplicate, unexpected, and wrong detail', () => {
  const r = good();
  assert.match(judge(r.map((x) => (x.id === 1 ? { ...x, status: 403 } : x))).failures.join(' '), /scene 1.*status/);
  assert.match(judge(r.map((x) => (x.id === 2 ? { ...x, code: 'scope_exceeded' } : x))).failures.join(' '), /scene 2.*code/);
  assert.match(judge(r.filter((x) => x.id !== 6)).failures.join(' '), /scene 6.*missing/);
  assert.match(judge([...r, r[0]]).failures.join(' '), /duplicate/);
  assert.match(judge([...r, { id: 9, status: 200, code: null, origin: 'cli', detail: {} }]).failures.join(' '), /unexpected scene 9/);
  assert.match(judge(r.map((x) => (x.id === 3 ? { ...x, detail: { ...x.detail, field: 'granted_capabilities' } } : x))).failures.join(' '), /scene 3.*detail/);
  assert.match(judge(r.map((x) => (x.id === 5 ? { ...x, origin: 'cli' } : x))).failures.join(' '), /scene 5.*origin/);
});
