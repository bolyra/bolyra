/**
 * HTTP-surface + classical-pipeline tests for the hosted verify preview:
 * auth, routing, body bounds, fail-closed denials, zk rejection, receipts,
 * and env fail-closed behavior.
 */

import { describe, expect, it } from 'vitest';
import { SELF, env, createExecutionContext } from 'cloudflare:test';
import { verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';

import worker from '../src/index';
import { requiredBits, DEFAULT_CAPABILITY_MAP } from '../src/verify/capabilities';
import { VerifyDenial } from '../src/verify/verdict';
import { postVerify, cloneWithBundle, BASE, TOKEN } from './helpers';
import { validateVerdictSchema } from './verdict-schema';

import allowAgentOnly from '../../cli/test/fixtures/verify/allow-agent-only/request.json';
import allowHuman from '../../cli/test/fixtures/verify/allow-human/request.json';
import allowDelegation from '../../cli/test/fixtures/verify/allow-delegation-1hop/request.json';

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
    expect((body.checks_authenticated as string[]).join(' ')).toContain('trusted-operator');
    expect((body.checks_consistency_only as string[]).length).toBeGreaterThan(3);
    expect((body.checks_not_performed as string[]).join(' ')).toContain('Groth16');
    expect(String(body.trust_model)).toContain('proof itself is NOT verified');
  });

  it('unknown route → 404; wrong methods → 405', async () => {
    expect((await SELF.fetch(`${BASE}/`)).status).toBe(404);
    expect((await SELF.fetch(`${BASE}/health`, { method: 'POST' })).status).toBe(405);
    expect((await SELF.fetch(`${BASE}/v1/verify`, { method: 'GET' })).status).toBe(405);
  });

  it('POST /v1/verify without a token → 401', async () => {
    const res = await postVerify(allowAgentOnly, { token: null });
    expect(res.status).toBe(401);
  });

  it('POST /v1/verify with a wrong token → 401', async () => {
    const res = await postVerify(allowAgentOnly, { token: 'wrong-token' });
    expect(res.status).toBe(401);
  });

  it('fails closed (401) when PREVIEW_TOKEN is not configured', async () => {
    const req = new Request(`${BASE}/v1/verify`, {
      method: 'POST',
      headers: { authorization: 'Bearer anything' },
      body: JSON.stringify(allowAgentOnly),
    });
    const res = await worker.fetch(req, { ...env, PREVIEW_TOKEN: '' });
    expect(res.status).toBe(401);
    createExecutionContext(); // keep the import exercised under the workers pool
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

  it('operator key not in TRUSTED_OPERATORS → deny untrusted_root', async () => {
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
});

describe('fail-closed configuration', () => {
  it('no TRUSTED_OPERATORS configured → HTTP 500 deny internal_error (spec §12)', async () => {
    const req = new Request(`${BASE}/v1/verify`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify(allowAgentOnly),
    });
    const res = await worker.fetch(req, { ...env, TRUSTED_OPERATORS: '' });
    expect(res.status).toBe(500);
    const v = await verdictOf(res);
    expect(v.code).toBe('internal_error');
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
    const req = new Request(`${BASE}/v1/verify`, {
      method: 'POST',
      headers: { authorization: `Bearer ${TOKEN}` },
      body: JSON.stringify(allowAgentOnly),
    });
    const res = await worker.fetch(req, { ...env, RECEIPT_SIGNER_KEY: '' });
    expect(res.status).toBe(200);
    expect(res.headers.get('x-bolyra-receipt')).toBeNull();
  });
});
