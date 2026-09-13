import { test } from 'node:test';
import * as assert from 'node:assert/strict';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';
import { verifyReceipt } from '@bolyra/receipts';
import { Audit } from '../src/audit';
import { buildGatewayConfig } from '../src/gateway-config';
import { createDemoAgent, buildDevBundle, requiredMask, withheldMask, PERMISSION_NAMES } from '../src/agents';
import type { PermissionName } from '../src/agents';
import type { TrialConfig } from '../src/config';
import { startEcho } from '../src/echo';
import { startHost } from '../src/host';
import type { TrialHost } from '../src/host';

interface Fixture {
  host: TrialHost;
  audit: Audit;
  granted: ReturnType<typeof createDemoAgent>;
  withheld: ReturnType<typeof createDemoAgent>;
  echo: Awaited<ReturnType<typeof startEcho>>;
  close(): Promise<void>;
}

async function fixture(permission: PermissionName = 'WRITE_DATA', echoStatus = 200, audit?: Partial<{ io: ConstructorParameters<typeof Audit>[0]['io'] }>): Promise<Fixture> {
  const echo = await startEcho({ status: echoStatus });
  const granted = createDemoAgent('granted', requiredMask(permission));
  const withheld = createDemoAgent('withheld', withheldMask(permission));
  const gatewayConfig = buildGatewayConfig('refund', requiredMask(permission), granted, withheld);
  const config: TrialConfig = {
    action: 'refund',
    method: 'POST',
    url: new URL(echo.url),
    headers: {},
    requiredPermission: permission,
    secrets: [],
  };
  const runDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trial-host-')), 'run');
  const auditInstance = new Audit({ runDir, gatewayConfig, io: audit?.io });
  const host = await startHost({ config, gatewayConfig, audit: auditInstance });
  return {
    host,
    audit: auditInstance,
    granted,
    withheld,
    echo,
    close: async () => {
      await host.close();
      await echo.close();
    },
  };
}

async function call(host: TrialHost, action: string, authHeader?: string, method = 'POST') {
  const headers: Record<string, string> = { 'content-type': 'application/json' };
  if (authHeader) headers.authorization = authHeader;
  const res = await fetch(`${host.url}/action/${action}`, { method, headers, body: method === 'GET' ? undefined : '{}' });
  await res.arrayBuffer();
  return res.status;
}

test('allow: dispatched once, receipted, upstream status recorded', async () => {
  const f = await fixture();
  try {
    const status = await call(f.host, 'refund', buildDevBundle(f.granted).header);
    assert.equal(status, 200);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'allow');
    assert.equal(r.dispatched, true);
    assert.equal(r.upstreamStatus, 200);
    assert.equal(r.outcome, 'completed');
    assert.equal(f.echo.requestCount, 1);
    assert.equal(f.host.dispatchCount, 1);
    const receipts = f.audit.readReceipts();
    assert.equal(receipts.length, 1);
    assert.equal(receipts[0].id, r.receiptId);
    assert.ok(verifyReceipt(receipts[0], f.audit.signerInfo.signer));
    assert.match(receipts[0].payload.decision.reasonCode ?? '', /allowed \| action=refund POST 127\.0\.0\.1:\d+\/echo/);
  } finally {
    await f.close();
  }
});

test('policy deny: 403, not dispatched, receipted with the denial reason', async () => {
  const f = await fixture();
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.withheld).header), 403);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'deny');
    assert.equal(r.stage, 'policy_denied');
    assert.equal(r.dispatched, false);
    assert.equal(r.outcome, 'not_dispatched');
    assert.equal(f.echo.requestCount, 0);
    const receipts = f.audit.readReceipts();
    assert.equal(receipts[0].payload.decision.allowed, false);
    assert.match(receipts[0].payload.decision.reasonCode ?? '', /policy_denied.*\| action=refund/);
  } finally {
    await f.close();
  }
});

test('replay: same header twice is 401 nonce reuse, receipt carries a derived DID', async () => {
  const f = await fixture();
  try {
    const auth = buildDevBundle(f.granted).header;
    assert.equal(await call(f.host, 'refund', auth), 200);
    await f.host.nextResult();
    assert.equal(await call(f.host, 'refund', auth), 401);
    const r = await f.host.nextResult();
    assert.equal(r.stage, 'verification_failed');
    assert.match(r.reason, /Nonce already used/);
    assert.equal(r.dispatched, false);
    assert.equal(f.echo.requestCount, 1);
    const [, replay] = f.audit.readReceipts();
    assert.notEqual(replay.payload.subject.rootDid, '');
    assert.match(replay.payload.subject.rootDid, /^did:bolyra:dev:/);
  } finally {
    await f.close();
  }
});

test('route bypass: other paths and methods are 404 and not receipted (spec test 4)', async () => {
  const f = await fixture();
  try {
    assert.equal(await call(f.host, 'other', buildDevBundle(f.granted).header), 404);
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header, 'GET'), 404);
    assert.equal(f.audit.readReceipts().length, 0);
    assert.equal(f.host.results.length, 0);
  } finally {
    await f.close();
  }
});

test('credential mismatch: forged mask is 401 credential_mismatch (spec test 5)', async () => {
  const f = await fixture('WRITE_DATA');
  try {
    const forged = buildDevBundle({ ...f.granted, permissionBitmask: f.granted.permissionBitmask | 128n });
    assert.equal(await call(f.host, 'refund', forged.header), 401);
    const r = await f.host.nextResult();
    assert.equal(r.stage, 'credential_binding_failed');
    assert.match(r.reason, /^credential_mismatch/);
    assert.equal(r.dispatched, false);
    assert.equal(f.audit.readReceipts().length, 1);
  } finally {
    await f.close();
  }
});

test('bundle-less denial is receipted anonymously (spec test 12)', async () => {
  const f = await fixture();
  try {
    const empty = 'Bolyra ' + Buffer.from('{}').toString('base64');
    assert.equal(await call(f.host, 'refund', empty), 401);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, false);
    const [receipt] = f.audit.readReceipts();
    assert.equal(receipt.payload.subject.credentialCommitment, '0');
  } finally {
    await f.close();
  }
});

test('redirect is dispatched once and recorded as not_followed (spec test 6)', async () => {
  const f = await fixture('WRITE_DATA', 302);
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, true);
    assert.equal(r.upstreamStatus, 302);
    assert.equal(r.outcome, 'not_followed');
    assert.equal(f.echo.requestCount, 1);
  } finally {
    await f.close();
  }
});

test('allow receipt write failure: 500, not dispatched, receiptError (spec test 10)', async () => {
  const f = await fixture('WRITE_DATA', 200, {
    io: {
      appendFileSync() {
        throw new Error('disk full');
      },
    },
  });
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 500);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'allow');
    assert.equal(r.dispatched, false);
    assert.match(r.receiptError ?? '', /disk full/);
    assert.equal(f.echo.requestCount, 0);
  } finally {
    await f.close();
  }
});

test('corrupted persisted allow receipt: 500, not dispatched (persistence is what is verified)', async () => {
  const f = await fixture('WRITE_DATA', 200, {
    io: {
      appendFileSync(p, data) {
        fs.appendFileSync(p, data.replace('"allowed":true', '"allowed":false'));
      },
    },
  });
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 500);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, false);
    assert.match(r.receiptError ?? '', /persisted receipt/);
    assert.equal(f.echo.requestCount, 0);
    assert.equal(f.host.dispatchCount, 0);
  } finally {
    await f.close();
  }
});

test('permission matrix: granted passes, withheld fails, for every name (spec test 7)', async () => {
  for (const name of PERMISSION_NAMES) {
    const f = await fixture(name);
    try {
      assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200, `${name}: granted`);
      const a = await f.host.nextResult();
      assert.equal(a.decision, 'allow', name);
      assert.equal(await call(f.host, 'refund', buildDevBundle(f.withheld).header), 403, `${name}: withheld`);
      const d = await f.host.nextResult();
      assert.equal(d.stage, 'policy_denied', name);
    } finally {
      await f.close();
    }
  }
});

async function fixtureWithFetch(fetchImpl: typeof fetch) {
  const granted = createDemoAgent('granted', requiredMask('WRITE_DATA'));
  const withheld = createDemoAgent('withheld', withheldMask('WRITE_DATA'));
  const gatewayConfig = buildGatewayConfig('refund', requiredMask('WRITE_DATA'), granted, withheld);
  const config: TrialConfig = {
    action: 'refund',
    method: 'POST',
    url: new URL('http://127.0.0.1:9/never-reached'),
    headers: {},
    requiredPermission: 'WRITE_DATA',
    secrets: [],
  };
  const runDir = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'trial-host-fetch-')), 'run');
  const audit = new Audit({ runDir, gatewayConfig });
  const host = await startHost({ config, gatewayConfig, audit, fetchImpl });
  return { host, granted, close: () => host.close() };
}

test('upstream timeout: dispatched, outcome timeout, status null, counter 1', async () => {
  const timeoutFetch: typeof fetch = async () => {
    throw new DOMException('The operation was aborted due to timeout', 'TimeoutError');
  };
  const f = await fixtureWithFetch(timeoutFetch);
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200);
    const r = await f.host.nextResult();
    assert.equal(r.decision, 'allow');
    assert.equal(r.dispatched, true);
    assert.equal(r.outcome, 'timeout');
    assert.equal(r.upstreamStatus, null);
    assert.equal(f.host.dispatchCount, 1);
  } finally {
    await f.close();
  }
});

test('upstream network error: dispatched, outcome network_error, status null, counter 1', async () => {
  const failingFetch: typeof fetch = async () => {
    throw new TypeError('fetch failed');
  };
  const f = await fixtureWithFetch(failingFetch);
  try {
    assert.equal(await call(f.host, 'refund', buildDevBundle(f.granted).header), 200);
    const r = await f.host.nextResult();
    assert.equal(r.dispatched, true);
    assert.equal(r.outcome, 'network_error');
    assert.equal(r.upstreamStatus, null);
    assert.equal(f.host.dispatchCount, 1);
  } finally {
    await f.close();
  }
});
