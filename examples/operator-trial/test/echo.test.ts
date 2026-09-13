import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import { startEcho } from '../src/echo';

test('echo counts requests and returns the configured status', async () => {
  const echo = await startEcho();
  try {
    const r1 = await fetch(echo.url, { method: 'POST', body: '{}' });
    assert.equal(r1.status, 200);
    assert.deepEqual(await r1.json(), { echoed: true });
    await (await fetch(echo.url, { method: 'POST', body: '{}' })).arrayBuffer();
    assert.equal(echo.requestCount, 2);
  } finally {
    await echo.close();
  }
});

test('echo can answer with a redirect that is not followed', async () => {
  const echo = await startEcho({ status: 302 });
  try {
    const r = await fetch(echo.url, { method: 'POST', body: '{}', redirect: 'manual' });
    assert.equal(r.status, 302);
    assert.equal(r.headers.get('location'), '/elsewhere');
    assert.equal(echo.requestCount, 1);
  } finally {
    await echo.close();
  }
});
