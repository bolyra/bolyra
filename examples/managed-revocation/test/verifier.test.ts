import test from 'node:test';
import assert from 'node:assert/strict';
import { issueMandate } from '@bolyra/mpp';
import { AUDIENCE, MODEL } from '../src/server.js';
import { DiagnosticError, assertVerifierOrigin, verify, type HostedVerifier } from '../src/verifier.js';

const issue = () =>
  issueMandate({ operatorPrivateKey: 42n, agentName: 'unit-agent', audience: AUDIENCE, model: MODEL, tier: 'small', expiry: Math.floor(Date.now() / 1000) + 3600 });

/** Replace fetch with a stub answering every POST with `respond`, recording the URLs hit. */
function stubFetch(respond: () => Response): { urls: string[]; restore: () => void } {
  const real = globalThis.fetch;
  const urls: string[] = [];
  globalThis.fetch = async (input) => {
    urls.push(typeof input === 'string' ? input : input instanceof URL ? input.href : input.url);
    return respond();
  };
  return { urls, restore: () => { globalThis.fetch = real; } };
}

const hosted = (url: string): HostedVerifier => ({ url, adminToken: 'admin-token', verifierToken: 'verifier-token' });

test('verify() POSTs to <VERIFY_URL>/v1/verify and returns the status, verdict, and headers', async () => {
  const stub = stubFetch(() =>
    Response.json({ verdict: 'allow', kind: 'classical' }, { headers: { 'x-bolyra-credential-id': 'cd'.repeat(32), 'x-bolyra-receipt': 'e30' } }),
  );
  try {
    const out = await verify(hosted('https://verify.test'), await issue());
    assert.deepEqual(stub.urls, ['https://verify.test/v1/verify']);
    assert.equal(out.status, 200);
    assert.equal(out.verdict.verdict, 'allow');
    assert.equal(out.credentialIdHeader, 'cd'.repeat(32));
    assert.equal(out.receiptHeader, 'e30');
    // The route is explicit, so a path-prefixed URL reaches <prefix>/v1/verify, the same
    // concatenation /health and /v1/credentials use (run.ts refuses such a URL up front).
    await verify(hosted('https://verify.test/prefix'), await issue());
    assert.equal(stub.urls[1], 'https://verify.test/prefix/v1/verify');
  } finally {
    stub.restore();
  }
});

test('a non-200/500 verifier status (a wrong token) is a DiagnosticError naming the status, not a deny row', async () => {
  const stub = stubFetch(() => Response.json({ error: 'unauthorized' }, { status: 401 }));
  try {
    await assert.rejects(verify(hosted('https://verify.test'), await issue()), (e: unknown) => {
      assert.ok(e instanceof DiagnosticError);
      assert.equal(e.message, 'POST /v1/verify → HTTP 401 (body withheld)');
      return true;
    });
  } finally {
    stub.restore();
  }
});

test('assertVerifierOrigin accepts an origin and refuses a path or an unparseable value in its own words', () => {
  assertVerifierOrigin('http://127.0.0.1:8787');
  assertVerifierOrigin('https://verify.example/');
  for (const bad of [
    'https://verify.example/prefix', 'https://verify.example/?x=1', 'https://verify.example/#f', 'https://u:pw@verify.example/',
    // the SDK reads the spelling as written, so what the URL parser would normalize away must be refused too
    'https://verify.example/prefix/..', 'https://verify.example/%2e', 'https://verify.example ', ' https://verify.example',
    'https://verify.example\\', 'ftp://verify.example', 'not a url secret-ish',
  ]) {
    assert.throws(() => assertVerifierOrigin(bad), (e: unknown) => {
      assert.ok(e instanceof DiagnosticError);
      assert.equal(e.message, 'VERIFY_URL must be the verifier origin with no path (value withheld)');
      return true;
    });
  }
});
