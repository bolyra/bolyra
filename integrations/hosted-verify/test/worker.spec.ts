/**
 * HTTP-surface + classical-pipeline tests for the hosted verify preview:
 * auth, routing, body bounds, fail-closed denials, zk rejection, receipts,
 * and env fail-closed behavior.
 */

import { beforeAll, describe, expect, it } from 'vitest';
import { SELF, env, createExecutionContext } from 'cloudflare:test';
import { verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';

import worker from '../src/index';
import { bindingDigest } from '../src/verify/binding';
import type { Binding } from '../src/verify/bundle';
import { requiredBits, DEFAULT_CAPABILITY_MAP } from '../src/verify/capabilities';
import { verifyClassical } from '../src/verify/core';
import { VerifyDenial } from '../src/verify/verdict';
import {
  postVerify,
  cloneWithBundle,
  BASE,
  TOKENS,
  ORGS,
  buildTestTenants,
  registerFixture,
  fixtureRegistration,
  FIXTURE_OPERATOR_KEY,
} from './helpers';
import { validateVerdictSchema } from './verdict-schema';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import allowHuman from '../../cli/test/fixtures/verify/allow-human/request.json';
import allowDelegation from '../../cli/test/fixtures/verify/allow-delegation-1hop/request.json';

const LEGACY_NAMES = /TRUSTED_OPERATORS|PARTNER_TOKENS|PREVIEW_TOKEN/;

// Every allow in this file presents the conformance fixture: register it for
// the tenants that trust its operator (org-a and org-c). Per-file isolation.
beforeAll(async () => {
  await registerFixture(fixtureRegistration(allowAgentOnly), 'A');
  await registerFixture(fixtureRegistration(allowAgentOnly), 'C');
});

async function verdictOf(res: Response): Promise<Record<string, unknown>> {
  const v = (await res.json()) as Record<string, unknown>;
  expect(validateVerdictSchema(v)).toEqual({ ok: true });
  expect(v.kind).toBe('classical');
  return v;
}

function decodeReceipt(header: string): SignedReceipt {
  const b64 = header.replace(/-/g, '+').replace(/_/g, '/');
  const bytes = Uint8Array.from(atob(b64), (c) => c.charCodeAt(0));
  return JSON.parse(new TextDecoder().decode(bytes)) as SignedReceipt;
}

function verifyReq(token: string, body: unknown = allowAgentOnly): Request {
  return new Request(`${BASE}/v1/verify`, {
    method: 'POST',
    headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
    body: JSON.stringify(body),
  });
}

describe('binding v2 digest conformance', () => {
  // CROSS-IMPLEMENTATION CONFORMANCE VECTOR (binding v2). The SAME fixed binding
  // and expected digest are pinned in @bolyra/mpp (classical.test.ts) and
  // `bolyra verify` (cli binding.test.ts). If any of the three bindingDigest
  // implementations drifts, exactly its own pinned test breaks — the three
  // cannot silently diverge and produce mutually unverifiable bundles.
  it('matches the shared v2 binding-digest conformance vector', () => {
    const vector: Binding = {
      agent_name: 'conformance-agent',
      project_key: 'api.merchant.example',
      program: 'mpp',
      model: 'opus-4.1',
      capabilities: ['mpp:financial:small', 'mpp:financial:medium'],
      expiry: 1893456000,
    };
    expect(bindingDigest(vector).toString()).toBe(
      '6852214223979096266887740803477328516969972228468997483569432332607241636802',
    );
  });
});

describe('routing + auth', () => {
  it('GET /health is public and prominently labeled as a preview', async () => {
    const res = await SELF.fetch(`${BASE}/health`);
    expect(res.status).toBe(200);
    expect(res.headers.get('x-bolyra-preview')).toBe('design-partner-preview');
    const body = (await res.json()) as Record<string, unknown>;
    expect(body.status).toBe('ok');
    expect(String(body.phase)).toContain('DESIGN PARTNER PREVIEW');
    expect(body.verifier_kind).toBe('classical');
    expect(body.nonce_mode).toBe('host');
    expect(body.tenants).toBe('ok');
    expect(body.registry).toBe('durable-object');
    expect(body.registry_enforced).toBe(true);
    expect(String(body.trust_policy)).toContain('ACTIVE');
    expect(String(body.trust_model)).toContain('registry');
    expect((body.checks_authenticated as string[]).join(' ')).toContain('trusted-operator');
    expect((body.checks_consistency_only as string[]).length).toBeGreaterThan(3);
    expect((body.checks_not_performed as string[]).join(' ')).toContain('Groth16');
    expect(String(body.trust_model)).toContain('proof itself is NOT verified');
    // The legacy configuration names must not survive on any public surface.
    expect(JSON.stringify(body)).not.toMatch(LEGACY_NAMES);
  });

  it('GET /health reports tenants:"invalid" at 200 when TENANTS is malformed', async () => {
    const res = await worker.fetch(new Request(`${BASE}/health`), { ...env, TENANTS: '{not json' });
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenants: string }).tenants).toBe('invalid');
  });

  it('unknown route → 404; wrong methods → 405', async () => {
    expect((await SELF.fetch(`${BASE}/`)).status).toBe(404);
    expect((await SELF.fetch(`${BASE}/health`, { method: 'POST' })).status).toBe(405);
    expect((await SELF.fetch(`${BASE}/v1/verify`, { method: 'GET' })).status).toBe(405);
  });

  it('POST /v1/verify without a token → 401 with the unchanged error body', async () => {
    const res = await postVerify(allowAgentOnly, { token: null });
    expect(res.status).toBe(401);
    expect(await res.json()).toEqual({ error: 'unauthorized', hint: 'Authorization: Bearer <token>' });
  });

  it('POST /v1/verify with a wrong token → 401', async () => {
    const res = await postVerify(allowAgentOnly, { token: 'wrong-token' });
    expect(res.status).toBe(401);
  });

  it('an ADMIN token on /v1/verify → 403 with exactly { error: "forbidden" }', async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.A.admin });
    expect(res.status).toBe(403);
    expect(await res.json()).toEqual({ error: 'forbidden' });
  });

  it("another tenant's verifier (org-b does not trust the fixture operator) → deny untrusted_root", async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.B.verifier });
    expect(res.status).toBe(200);
    expect((await verdictOf(res)).code).toBe('untrusted_root');
  });

  it('a second tenant trusting the same operator (org-c) → allow', async () => {
    const res = await postVerify(allowAgentOnly, { token: TOKENS.C.verifier });
    expect((await verdictOf(res)).verdict).toBe('allow');
  });

  it('a disabled tenant → 500 deny internal_error; other tenants unaffected', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const disabled = await worker.fetch(verifyReq(TOKENS.A.verifier), e);
    expect(disabled.status).toBe(500);
    expect((await verdictOf(disabled)).code).toBe('internal_error');
    const other = await worker.fetch(verifyReq(TOKENS.C.verifier), e);
    expect(other.status).toBe(200);
    expect((await verdictOf(other)).verdict).toBe('allow');
    createExecutionContext(); // keep the import exercised under the workers pool
  });

  it("a disabled tenant's ADMIN token on /v1/verify → the quarantine 500, not a 403 (no route serves it)", async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(verifyReq(TOKENS.A.admin), e);
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).code).toBe('internal_error');
  });

  it('GET /health reports tenants:"ok" for a parseable map even when a tenant is disabled (parseability, not availability)', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(new Request(`${BASE}/health`), e);
    expect(res.status).toBe(200);
    expect(((await res.json()) as { tenants: string }).tenants).toBe('ok');
  });
});

describe('fail-closed input handling', () => {
  it('truncated JSON body → deny malformed_input (spec §13.5)', async () => {
    const res = await postVerify('{"version":1,"bun');
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('malformed_input');
  });

  it('non-object JSON body → deny malformed_input', async () => {
    const v = await verdictOf(await postVerify('42'));
    expect(v.code).toBe('malformed_input');
  });

  it('oversized body (> 1 MiB) → deny malformed_input (spec §6 bound)', async () => {
    const huge = { ...allowAgentOnly, padding: 'x'.repeat(1_100_000) };
    const v = await verdictOf(await postVerify(huge));
    expect(v.code).toBe('malformed_input');
  });

  it('request version 2 → deny unsupported_version', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, version: 2 }));
    expect(v.code).toBe('unsupported_version');
  });

  it('undecodable bundle → deny invalid_bundle', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, bundle: '!!not-base64url!!' }));
    expect(v.code).toBe('invalid_bundle');
  });

  it('bvp version 2 → deny unsupported_version', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    bundle.bvp = 2;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('unsupported_version');
  });
});

describe('classical-only scope', () => {
  it('explicit request kind "zk" → clear deny', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, kind: 'zk' }));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect(String(v.message)).toContain('classical');
    expect(String(v.message)).toContain('zk');
  });

  it('explicit request kind "classical" is accepted', async () => {
    const v = await verdictOf(await postVerify({ ...allowAgentOnly, kind: 'classical' }));
    expect(v.verdict).toBe('allow');
  });

  it('human-backed bundle → deny (zk-only slot)', async () => {
    const v = await verdictOf(await postVerify(allowHuman));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect((v.detail as Record<string, unknown>).slots).toEqual(['human']);
  });

  it('delegation-bearing bundle → deny (zk-only slot)', async () => {
    const v = await verdictOf(await postVerify(allowDelegation));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_proof');
    expect((v.detail as Record<string, unknown>).slots).toEqual(['delegation']);
  });
});

describe('classical pipeline', () => {
  it('valid agent-only bundle → allow with host-mode consume_nonces', async () => {
    const res = await postVerify(allowAgentOnly);
    expect(res.status).toBe(200);
    const v = await verdictOf(res);
    expect(v.verdict).toBe('allow');

    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      agent: {
        envelope: { publicSignals: string[] };
        credential: { operator_pubkey: { x: string; y: string }; expiry: number };
      };
    };
    const nonces = v.consume_nonces as Array<Record<string, unknown>>;
    expect(nonces).toHaveLength(1);
    expect(nonces[0]!.nonce).toBe(bundle.agent.envelope.publicSignals[1]);
    expect(nonces[0]!.issuer_key).toBe(
      `${bundle.agent.credential.operator_pubkey.x}:${bundle.agent.credential.operator_pubkey.y}`,
    );
    expect(nonces[0]!.retain_until).toBe(bundle.agent.credential.expiry);
  });

  it('inflated permission bitmask → deny invalid_proof (scope anchor, F2)', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.agent as { credential: { permission_bitmask: string } }).credential.permission_bitmask =
      '255';
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('invalid_proof');
  });

  it('binding v2: signed binding.expiry ≠ credential.expiry → deny invalid_bundle', async () => {
    // The signed binding.expiry is unchanged (signature still verifies) but the
    // credential.expiry the strict-expiry check would consume is re-anchored
    // forward — the §5b equality catches the divergence.
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.agent as { credential: { expiry: number } }).credential.expiry = 4200000000;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('invalid_bundle');
  });

  it('binding v2: an obsolete v1 binding (no expiry) → deny unsupported_version', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    delete (bundle.binding as Record<string, unknown>).expiry;
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('unsupported_version');
  });

  it("operator key not in the tenant's trusted_operators → deny untrusted_root", async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    // A different (untrusted) operator key. The signature will not verify
    // either, but the trust-anchor gate fires first.
    (bundle.agent as { credential: { operator_pubkey: { x: string; y: string } } }).credential
      .operator_pubkey = { x: '12345', y: '67890' };
    const v = await verdictOf(await postVerify(commit()));
    expect(v.code).toBe('untrusted_root');
  });

  // Regression for the Codex P1: WITHOUT proof verification, an attacker who
  // generates their own operator key, copies a trusted root into the public
  // signals, recomputes the scopeCommitment, and self-signs the binding must
  // STILL be denied — the trust anchor is the operator key set, not the
  // (unverified) Merkle root.
  it('forged bundle signed by an attacker-generated key → deny (not allow)', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    const agent = bundle.agent as {
      envelope: { publicSignals: string[] };
      credential: { operator_pubkey: { x: string; y: string }; permission_bitmask: string };
    };
    // Attacker-chosen operator key + a fresh (non-trusted) signature would be
    // needed; even copying the trusted root into signals[0] must not help.
    agent.envelope.publicSignals[0] =
      '18320371612677943971623074242238461500910720206465255065323445886458846517670';
    agent.credential.operator_pubkey = { x: '99999999', y: '88888888' };
    const v = await verdictOf(await postVerify(commit()));
    expect(v.verdict).toBe('deny');
    expect(v.code).toBe('untrusted_root');
  });

  it('tampered binding → deny invalid_signature', async () => {
    const { bundle, commit } = cloneWithBundle(allowAgentOnly);
    (bundle.binding as { program: string }).program = 'other-program';
    const req = commit();
    (req.request as { program: string }).program = 'other-program';
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('invalid_signature');
  });

  it('request not matching the signed binding → deny request_mismatch', async () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.agent_name = 'someone-else';
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('request_mismatch');
  });

  it('granted capability outside the signed set → deny request_mismatch', async () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.granted_capabilities = ['fetch_inbox', 'broadcast'];
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('request_mismatch');
  });

  it('now_unix == expiry → deny expired (STRICT boundary)', async () => {
    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      agent: { credential: { expiry: number } };
    };
    const req = { ...allowAgentOnly, now_unix: bundle.agent.credential.expiry };
    const v = await verdictOf(await postVerify(req));
    expect(v.code).toBe('expired');
  });

  it('unmapped capability fails closed with unknown_capability (unit)', () => {
    expect(() => requiredBits(DEFAULT_CAPABILITY_MAP, ['no_such_capability'])).toThrowError(
      expect.objectContaining({ code: 'unknown_capability' }) as Error,
    );
    expect(new VerifyDenial('unknown_capability', 'x').toVerdict().kind).toBe('classical');
  });

  it('verifyClassical exposes the verified binding and operator on allow, and nothing on deny (unit)', () => {
    const trusted = new Set([FIXTURE_OPERATOR_KEY]);
    const ok = verifyClassical(allowAgentOnly, trusted, DEFAULT_CAPABILITY_MAP);
    expect(ok.verdict.verdict).toBe('allow');
    const verified = ok.verified;
    expect(verified).toBeDefined();
    const bundle = JSON.parse(allowAgentOnly.bundle) as {
      binding: Record<string, unknown>;
      agent: { credential: { operator_pubkey: { x: string; y: string } } };
    };
    expect(verified?.binding).toEqual(bundle.binding);
    expect(verified?.operator).toEqual({
      x: BigInt(bundle.agent.credential.operator_pubkey.x),
      y: BigInt(bundle.agent.credential.operator_pubkey.y),
    });

    const denied = verifyClassical({ ...allowAgentOnly, version: 2 }, trusted, DEFAULT_CAPABILITY_MAP);
    expect(denied.verdict.verdict).toBe('deny');
    expect(denied.verified).toBeUndefined();
  });

  it('a request denied AFTER the operator was checked still exposes nothing (unit)', () => {
    const req = structuredClone(allowAgentOnly) as typeof allowAgentOnly;
    req.request.granted_capabilities = ['fetch_inbox', 'broadcast'];
    const denied = verifyClassical(req, new Set([FIXTURE_OPERATOR_KEY]), DEFAULT_CAPABILITY_MAP);
    expect(denied.verdict.verdict).toBe('deny');
    expect((denied.verdict as { code: string }).code).toBe('request_mismatch');
    expect(denied.verified).toBeUndefined();

    // The operator gate really did run first: the same request against an
    // untrusted set stops earlier, at untrusted_root.
    expect(
      (verifyClassical(req, new Set<string>(), DEFAULT_CAPABILITY_MAP).verdict as { code: string }).code,
    ).toBe('untrusted_root');
  });
});

describe('fail-closed configuration (config errors are a 500 VERDICT, never a bare error body)', () => {
  it.each([
    ['TENANTS unset', { TENANTS: '' }],
    ['TENANTS malformed', { TENANTS: '{not json' }],
    ['TENANTS with an empty trusted_operators list', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: [] },
      }),
    }],
    ['TENANTS with a malformed operator entry', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['nope'] },
      }),
    }],
    ['TENANTS with one token value used by two tenants', {
      TENANTS: JSON.stringify({
        [ORGS.A]: { admin_token: TOKENS.A.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['1:2'] },
        [ORGS.B]: { admin_token: TOKENS.B.admin, verifier_token: TOKENS.A.verifier, trusted_operators: ['1:2'] },
      }),
    }],
    ['CAPABILITY_MAP malformed', { CAPABILITY_MAP: '{not json' }],
    ['CAPABILITY_MAP naming an unknown permission', {
      CAPABILITY_MAP: JSON.stringify({ send_message: ['NO_SUCH_PERMISSION'] }),
    }],
  ])('%s → HTTP 500 deny internal_error', async (_name, overrides) => {
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), { ...env, ...overrides });
    expect(res.status).toBe(500);
    const v = await verdictOf(res);
    expect(v.code).toBe('internal_error');
    expect(v.message).toBe('missing or invalid trust configuration');
    expect(v).not.toHaveProperty('detail'); // config internals never reach the wire
    expect(JSON.stringify(v)).not.toMatch(LEGACY_NAMES);
  });

  it('a configuration defect is the 500 verdict for EVERY caller — no token, wrong token, admin token', async () => {
    const e = { ...env, CAPABILITY_MAP: '{not json' };
    for (const token of [null, 'not-a-real-token-0000000000000000000', TOKENS.A.admin]) {
      const headers: Record<string, string> = { 'content-type': 'application/json' };
      if (token !== null) headers['authorization'] = `Bearer ${token}`;
      const res = await worker.fetch(
        new Request(`${BASE}/v1/verify`, { method: 'POST', headers, body: JSON.stringify(allowAgentOnly) }),
        e,
      );
      expect(res.status).toBe(500);
      expect((await verdictOf(res)).code).toBe('internal_error');
    }
  });

  it('a duplicate JSON member in TENANTS is a defect (the last value must never silently win)', async () => {
    const raw = `{"${ORGS.A}":{"admin_token":"${TOKENS.A.admin}","verifier_token":"${TOKENS.A.verifier}","trusted_operators":["${FIXTURE_OPERATOR_KEY}"],"disabled":true,"disabled":false}}`;
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), { ...env, TENANTS: raw });
    expect(res.status).toBe(500);
    expect((await verdictOf(res)).code).toBe('internal_error');
  });
});

describe('signed receipts (X-Bolyra-Receipt)', () => {
  it('allow responses carry a verifiable ES256K receipt', async () => {
    const res = await postVerify(allowAgentOnly);
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(verifyReceipt(receipt)).toBe(true);
    expect(receipt.payload.decision.allowed).toBe(true);
    expect(receipt.payload.decision.reasonCode).toBe('allow');
    expect(receipt.payload.issuer).toBe('bolyra-hosted-verify-preview');
  });

  it('deny responses carry a receipt with the deny code as reason', async () => {
    const res = await postVerify({ ...allowAgentOnly, version: 2 });
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(verifyReceipt(receipt)).toBe(true);
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toBe('unsupported_version');
  });

  it('receipts are omitted when RECEIPT_SIGNER_KEY is unset', async () => {
    const req = verifyReq(TOKENS.A.verifier);
    const res = await worker.fetch(req, { ...env, RECEIPT_SIGNER_KEY: '' });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-bolyra-receipt')).toBeNull();
  });

  it('401 and 403 carry no receipt (they are not verdicts)', async () => {
    expect((await postVerify(allowAgentOnly, { token: null })).headers.get('x-bolyra-receipt')).toBeNull();
    expect((await postVerify(allowAgentOnly, { token: TOKENS.A.admin })).headers.get('x-bolyra-receipt')).toBeNull();
  });

  it('the disabled-tenant 500 receipt is anonymous and names no tenant or token', async () => {
    const e = { ...env, TENANTS: buildTestTenants(FIXTURE_OPERATOR_KEY, { disabled: [ORGS.A] }) };
    const res = await worker.fetch(verifyReq(TOKENS.A.verifier), e);
    const header = res.headers.get('x-bolyra-receipt');
    expect(header).not.toBeNull();
    const receipt = decodeReceipt(header!);
    expect(receipt.payload.subject.rootDid).toBe('did:bolyra:preview:anonymous');
    expect(JSON.stringify(receipt)).not.toContain(ORGS.A);
    expect(JSON.stringify(receipt)).not.toContain(TOKENS.A.verifier);
  });
});
