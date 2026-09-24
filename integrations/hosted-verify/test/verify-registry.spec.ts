/**
 * The verify path consults the tenant's registry AFTER every classical check:
 * only an ACTIVE credential allows. Registry failures and the deadline are the
 * fail-closed 500 verdict. Storage isolation is per file: reset() per test.
 */
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { SELF, env, reset } from 'cloudflare:test';
import { canonicalize } from '@bolyra/receipts';

import worker from '../src/index';
import { REGISTRY_DEADLINE_MS } from '../src/deadlines';
import { bindingDigest } from '../src/verify/binding';
import { credentialId } from '../src/credential-id';
import { postVerify, postRevoke, getCredential, registerFixture, fixtureRegistration, cloneWithBundle, decodeReceipt, BASE, TOKENS, ORGS } from './helpers';
import { validateVerdictSchema } from './verdict-schema';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import mandate from './fixtures/mandate.json';

async function verdictOf(res: Response): Promise<Record<string, unknown>> {
  const v = (await res.json()) as Record<string, unknown>;
  expect(validateVerdictSchema(v)).toEqual({ ok: true });
  return v;
}

const fixtureBundle = JSON.parse(allowAgentOnly.bundle) as {
  binding: Record<string, unknown>;
  agent: { credential: { operator_pubkey: { x: string; y: string } } };
};
const FIXTURE_ID = credentialId(
  { x: BigInt(fixtureBundle.agent.credential.operator_pubkey.x), y: BigInt(fixtureBundle.agent.credential.operator_pubkey.y) },
  bindingDigest(fixtureBundle.binding as never),
);

beforeEach(async () => {
  await reset();
});

/** process 'unhandledRejection' listener count before the contention test added its own. */
let contentionListenerBaseline: number | undefined;

describe('registry membership on /v1/verify', () => {
  it('unregistered → deny untrusted_root with reason credential_not_active and the derivable id; no header', async () => {
    const res = await postVerify(allowAgentOnly);
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('untrusted_root');
    expect(v.detail).toEqual({ reason: 'credential_not_active', credential_id: FIXTURE_ID });
    expect(res.headers.get('x-bolyra-credential-id')).toBeNull();
  });

  it('registered → allow; the header equals the id POST /v1/credentials returned', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    expect(id).toBe(FIXTURE_ID);
    const res = await postVerify(allowAgentOnly);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('allow');
    expect(res.headers.get('x-bolyra-credential-id')).toBe(id);
    expect(Array.isArray(v.consume_nonces)).toBe(true);
  });

  it('revoked → deny with the SAME reason as unregistered; the admin still sees REVOKED', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    expect((await postRevoke(id)).status).toBe(204);
    const v = await verdictOf(await postVerify(allowAgentOnly));
    expect(v.code).toBe('untrusted_root');
    expect((v.detail as { reason: string }).reason).toBe('credential_not_active');
    expect(((await (await getCredential(id)).json()) as { status: string }).status).toBe('REVOKED');
  });

  it('a FRESH presentation of a revoked binding (new nullifier, new envelope) is denied: the id derives from the binding, not the presentation', async () => {
    await registerFixture(mandate.registration, 'A');
    const a = await verdictOf(await postVerify(mandate.request_a));
    expect(a.verdict).toBe('allow');
    const id = credentialId(
      { x: BigInt(mandate.registration.operator_pubkey.x), y: BigInt(mandate.registration.operator_pubkey.y) },
      bindingDigest(mandate.registration.binding as never),
    );
    expect((await postRevoke(id)).status).toBe(204);
    const b = await verdictOf(await postVerify(mandate.request_b));
    expect(b.verdict).toBe('deny');
    expect(b.code).toBe('untrusted_root');
    expect((b.detail as { credential_id: string }).credential_id).toBe(id);
  });

  it('an mpp-issued spend mandate verifies under the capability map the deployment must carry', async () => {
    await registerFixture(mandate.registration, 'A');
    const res = await postVerify(mandate.request_a);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('allow');
    expect(res.headers.get('x-bolyra-credential-id')).toMatch(/^[0-9a-f]{64}$/);
    // Without the map the same request is denied unknown_capability BEFORE the registry is consulted.
    const bare = await worker.fetch(
      new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(mandate.request_a) }),
      { ...env, CAPABILITY_MAP: '' },
    );
    expect((await verdictOf(bare)).code).toBe('unknown_capability');
  });

  it('the same binding registered in A and C, revoked only in A: A denies, C still allows', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    expect(await registerFixture(fixtureRegistration(allowAgentOnly), 'C')).toBe(id);
    expect((await postRevoke(id)).status).toBe(204);
    expect((await verdictOf(await postVerify(allowAgentOnly, { token: TOKENS.A.verifier }))).code).toBe('untrusted_root');
    expect((await verdictOf(await postVerify(allowAgentOnly, { token: TOKENS.C.verifier }))).verdict).toBe('allow');
  });

  it('a registration in org-c does not allow org-a (same operator, separate registries)', async () => {
    await registerFixture(fixtureRegistration(allowAgentOnly), 'C');
    expect((await verdictOf(await postVerify(allowAgentOnly, { token: TOKENS.C.verifier }))).verdict).toBe('allow');
    expect((await verdictOf(await postVerify(allowAgentOnly, { token: TOKENS.A.verifier }))).code).toBe('untrusted_root');
  });

  it('org-b (does not trust the operator) is denied by the trust check, with NO registry detail and no registry read', async () => {
    const v = await verdictOf(await postVerify(allowAgentOnly, { token: TOKENS.B.verifier }));
    expect(v.code).toBe('untrusted_root');
    expect((v.detail as Record<string, unknown>).reason).toBeUndefined();
  });
});

describe('ordering: classical checks come first', () => {
  it('an invalid bundle keeps its validation denial even when the registry is unreachable', async () => {
    const throwing = { get: () => ({ status: async () => { throw new Error('Network connection lost.'); } }), idFromName: (n: string) => env.TENANT.idFromName(n) } as unknown as typeof env.TENANT;
    const req = { ...allowAgentOnly, version: 2 };
    const res = await worker.fetch(
      new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(req) }),
      { ...env, TENANT: throwing },
    );
    expect(res.status).toBe(200);
    expect((await verdictOf(res)).code).toBe('unsupported_version');
  });

  it('a valid presentation during a registry outage → 500 internal_error, receipt anonymous, no header', async () => {
    const throwing = { get: () => ({ status: async () => { throw new Error('Network connection lost.'); } }), idFromName: (n: string) => env.TENANT.idFromName(n) } as unknown as typeof env.TENANT;
    const res = await worker.fetch(
      new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
      { ...env, TENANT: throwing },
    );
    expect(res.status).toBe(500);
    const v = await verdictOf(res);
    expect(v.code).toBe('internal_error');
    expect(v.message).toBe('registry unavailable');
    expect(v).not.toHaveProperty('detail');
    expect(res.headers.get('x-bolyra-credential-id')).toBeNull();
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    expect(decodeReceipt(header!).payload.subject.rootDid).toBe('did:bolyra:preview:anonymous');
  });

  it('a registry status the union does not name → 500 internal_error', async () => {
    const alien = { get: () => ({ status: async () => 'something_new' }), idFromName: (n: string) => env.TENANT.idFromName(n) } as unknown as typeof env.TENANT;
    const res = await worker.fetch(
      new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
      { ...env, TENANT: alien },
    );
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).code).toBe('internal_error');
  });

  it(`a registry read that never resolves → 500 "registry timeout" at the ${REGISTRY_DEADLINE_MS} ms deadline`, async () => {
    vi.useFakeTimers();
    try {
      const hanging = { get: () => ({ status: () => new Promise<never>(() => {}) }), idFromName: (n: string) => env.TENANT.idFromName(n) } as unknown as typeof env.TENANT;
      const pending = worker.fetch(
        new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
        { ...env, TENANT: hanging },
      );
      await vi.advanceTimersByTimeAsync(REGISTRY_DEADLINE_MS + 1);
      const res = await pending;
      expect(res.status).toBe(500);
      const v = await verdictOf(res);
      expect(v.code).toBe('internal_error');
      expect(v.message).toBe('registry timeout');
    } finally {
      vi.useRealTimers();
    }
  });

  it('a read that resolves ACTIVE after the deadline is still the timeout verdict, never an allow', async () => {
    vi.useFakeTimers();
    try {
      const late = {
        get: () => ({ status: () => new Promise((r) => setTimeout(() => r('ACTIVE'), REGISTRY_DEADLINE_MS * 2)) }),
        idFromName: (n: string) => env.TENANT.idFromName(n),
      } as unknown as typeof env.TENANT;
      const pending = worker.fetch(
        new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
        { ...env, TENANT: late },
      );
      await vi.advanceTimersByTimeAsync(REGISTRY_DEADLINE_MS * 3);
      const res = await pending;
      expect(res.status).toBe(500);
      const v = await verdictOf(res);
      expect(v.code).toBe('internal_error');
      expect(v.message).toBe('registry timeout');
      expect(res.headers.get('x-bolyra-credential-id')).toBeNull();
    } finally {
      vi.useRealTimers();
    }
  });

  it('25 concurrent reads that all miss the deadline → 25 timeout verdicts; their LATE rejections are all absorbed, no timer left', async () => {
    const N = 25;
    const rejects: Array<(e: Error) => void> = [];
    const contended = {
      get: () => ({
        status: () =>
          new Promise<never>((_resolve, reject) => {
            rejects.push(reject);
          }),
      }),
      idFromName: (n: string) => env.TENANT.idFromName(n),
    } as unknown as typeof env.TENANT;

    // Both observers fire in the workers pool (probed: a deliberately unobserved derived
    // promise on the read makes this test fail with 2 × 25 'late failure' events).
    const unhandled: unknown[] = [];
    const onWorkerEvent = (event: Event) => unhandled.push((event as PromiseRejectionEvent).reason);
    const onProcess = (reason: unknown) => unhandled.push(reason);
    contentionListenerBaseline = process.listenerCount('unhandledRejection');
    self.addEventListener('unhandledrejection', onWorkerEvent);
    process.on('unhandledRejection', onProcess);
    try {
      vi.useFakeTimers();
      try {
        const pending = Array.from({ length: N }, () =>
          worker.fetch(
            new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
            { ...env, TENANT: contended },
          ),
        );
        await vi.advanceTimersByTimeAsync(REGISTRY_DEADLINE_MS + 1);
        const responses = await Promise.all(pending);
        expect(rejects).toHaveLength(N); // every request reached the registry read
        for (const res of responses) {
          expect(res.status).toBe(500);
          const v = await verdictOf(res);
          expect(v.code).toBe('internal_error');
          expect(v.message).toBe('registry timeout');
        }
        expect(vi.getTimerCount()).toBe(0);

        // Now the orphaned RPCs fail — explicitly, after the verdicts were sent.
        for (const reject of rejects) reject(new Error('late failure'));
        await vi.advanceTimersByTimeAsync(0);
        expect(vi.getTimerCount()).toBe(0);
      } finally {
        vi.useRealTimers();
      }
      // Give the runtime a real macrotask turn to dispatch any unhandled-rejection event.
      await new Promise((r) => setTimeout(r, 20));
      expect(unhandled).toEqual([]);
    } finally {
      // Removed whatever happened above: a leaked process listener would silence Node's
      // default unhandled-rejection reporting for the rest of this file.
      self.removeEventListener('unhandledrejection', onWorkerEvent);
      process.off('unhandledRejection', onProcess);
    }
  });

  it('the contention test leaves no unhandled-rejection listener behind, pass or fail', () => {
    expect(contentionListenerBaseline).toBeDefined();
    expect(process.listenerCount('unhandledRejection')).toBe(contentionListenerBaseline);
  });

  it("the object's own storage_error result → 500, never an allow", async () => {
    await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    const failing = { get: () => ({ status: async () => 'storage_error' }), idFromName: (n: string) => env.TENANT.idFromName(n) } as unknown as typeof env.TENANT;
    const res = await worker.fetch(
      new Request(`${BASE}/v1/verify`, { method: 'POST', headers: { authorization: `Bearer ${TOKENS.A.verifier}`, 'content-type': 'application/json' }, body: JSON.stringify(allowAgentOnly) }),
      { ...env, TENANT: failing },
    );
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).message).toBe('registry unavailable');
  });
});

describe('the credential id is a pure function of the signed binding', () => {
  /** base64url (RFC 4648 §5, unpadded) of a UTF-8 string — the other transport encoding the bundle parser accepts. */
  function base64url(text: string): string {
    const bytes = new TextEncoder().encode(text);
    let binary = '';
    for (const b of bytes) binary += String.fromCharCode(b);
    return btoa(binary).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
  }

  it('re-encoding the bundle (raw JSON vs base64url) changes neither the id nor the decision, before and after revocation', async () => {
    const id = await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
    const rawJson = cloneWithBundle(allowAgentOnly).commit(); // bundle re-serialized as raw JSON text
    const encoded = { ...rawJson, bundle: base64url(rawJson.bundle) };
    expect(encoded.bundle).not.toBe(rawJson.bundle);
    expect(encoded.bundle.startsWith('{')).toBe(false);

    for (const req of [rawJson, encoded]) {
      const res = await postVerify(req);
      expect((await verdictOf(res)).verdict).toBe('allow');
      expect(res.headers.get('x-bolyra-credential-id')).toBe(id);
    }
    expect(canonicalize(fixtureBundle.binding)).toBe(JSON.stringify(((await (await getCredential(id)).json()) as { binding: unknown }).binding));

    expect((await postRevoke(id)).status).toBe(204);
    for (const req of [rawJson, encoded]) {
      const res = await postVerify(req);
      const v = await verdictOf(res);
      expect(res.status).toBe(200);
      expect(v.verdict).toBe('deny');
      expect(v.code).toBe('untrusted_root');
      expect(v.detail).toEqual({ reason: 'credential_not_active', credential_id: id });
      expect(res.headers.get('x-bolyra-credential-id')).toBeNull();
    }
  });
});
