import { test } from 'node:test';
import assert from 'node:assert/strict';
import * as path from 'node:path';
import { spawnSync } from 'node:child_process';
import { SCENES } from '../src/scenes';

test('the narrated demo runs the six scenes against two portal processes and exits 0', { timeout: 240_000 }, () => {
  const r = spawnSync(process.execPath, [path.join(__dirname, '..', 'src', 'demo.js')], { encoding: 'utf8', timeout: 220_000, env: { ...process.env } });
  assert.equal(r.status, 0, r.stdout + r.stderr);
  const line = r.stdout.split('\n').find((l) => l.startsWith('RESULT '));
  assert.ok(line, 'RESULT line present');
  const result = JSON.parse(line!.slice('RESULT '.length));
  assert.equal(result.ok, true);
  assert.deepEqual(result.scenes.map((s: any) => [s.id, s.status, s.code, s.origin]), SCENES.map((s) => [s.id, s.expect.status, s.expect.code ?? null, s.expect.origin]));
  assert.ok(r.stdout.indexOf('DISCLOSURE') < r.stdout.indexOf('Scene 1'), 'disclosure printed before results');
  assert.ok(!/would have (stopped|prevented)/i.test(r.stdout), 'no incident claims');
});
