/**
 * In-process classical verification pipeline. Mirrors the checks and denial
 * codes of the `bolyra verify` classical subset / hosted-verify preview.
 */

import { Permission } from '@bolyra/sdk';
import { bindingDigest, verifyClassical } from '../src/classical';
import type { BindingClaim } from '../src/bundle';
import type { VerifierRequest } from '../src/types';
import {
  AUDIENCE,
  EXPIRY,
  NOW_UNIX,
  makeBundle,
  operatorKey,
  fixtureRequestContext,
  OTHER_OPERATOR_PRIV,
} from './helpers';

function request(bundle: string, overrides: Partial<Record<string, unknown>> = {}): VerifierRequest {
  return {
    version: 1,
    bundle,
    request: fixtureRequestContext(overrides) as VerifierRequest['request'],
    now_unix: NOW_UNIX,
  };
}

describe('verifyClassical', () => {
  test('allows a well-formed bundle signed by a trusted operator', async () => {
    const bundle = await makeBundle();
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toEqual({ verdict: 'allow', kind: 'classical' });
  });

  test('accepts base64url-encoded bundles', async () => {
    const bundle = await makeBundle({ base64: true });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict.verdict).toBe('allow');
  });

  test('denies untrusted_root for an operator outside the trusted set', async () => {
    const bundle = await makeBundle({ operatorPriv: OTHER_OPERATOR_PRIV });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
  });

  test('fails closed (internal_error) when no trusted operator is configured', async () => {
    const bundle = await makeBundle();
    const verdict = await verifyClassical(request(bundle), []);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
  });

  test('denies invalid_signature for a corrupted binding signature', async () => {
    const bundle = await makeBundle({ breakSignature: true });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_signature' });
  });

  test('denies request_mismatch when the audience differs from the signed binding', async () => {
    const bundle = await makeBundle(); // binding signed for AUDIENCE
    const verdict = await verifyClassical(
      request(bundle, { project_key: 'api.other.example' }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({
      verdict: 'deny',
      code: 'request_mismatch',
      detail: expect.objectContaining({ field: 'project_key' }),
    });
  });

  test('denies request_mismatch when the granted capability exceeds the signed set', async () => {
    const bundle = await makeBundle(); // binding covers mpp:financial:small only
    const verdict = await verifyClassical(
      request(bundle, { granted_capabilities: ['mpp:financial:medium'] }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  test('denies scope_exceeded when the revealed bitmask lacks the required tier bits', async () => {
    // Binding SIGNS the medium capability, but the revealed credential
    // bitmask only carries the small tier — the consistency subset check
    // catches the shortfall.
    const bundle = await makeBundle({
      binding: { capabilities: ['mpp:financial:small', 'mpp:financial:medium'] },
      permissions: [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
    });
    const verdict = await verifyClassical(
      request(bundle, { granted_capabilities: ['mpp:financial:medium'] }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
  });

  test('denies expired strictly: now == expiry is expired', async () => {
    const bundle = await makeBundle({ expiry: EXPIRY });
    const atExpiry = { ...request(bundle), now_unix: EXPIRY };
    const verdict = await verifyClassical(atExpiry, [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'expired' });

    const past = { ...request(bundle), now_unix: EXPIRY - 1 };
    expect((await verifyClassical(past, [await operatorKey()])).verdict).toBe('allow');
  });

  test('denies model_mismatch when the credential hash does not match the model', async () => {
    // Binding and request agree on the model (so request↔binding passes),
    // but the revealed credential's model_hash commits to something else.
    const bundle = await makeBundle({ binding: { model: 'model-alpha' } });
    const raw = JSON.parse(bundle) as {
      agent: { credential: { model_hash: string } };
    } & Record<string, unknown>;
    raw.agent.credential.model_hash = '12345';
    const verdict = await verifyClassical(
      request(JSON.stringify(raw), { model: 'model-alpha' }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'model_mismatch' });
  });

  test('denies invalid_proof when the scopeCommitment does not anchor the preimage', async () => {
    const bundle = await makeBundle();
    const raw = JSON.parse(bundle) as {
      agent: { credential: { permission_bitmask: string } };
    } & Record<string, unknown>;
    // Inflate the revealed bitmask without recomputing the commitment.
    raw.agent.credential.permission_bitmask = '31';
    const verdict = await verifyClassical(request(JSON.stringify(raw)), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
  });

  test('denies zk-only bundles (human slot) rather than half-verifying', async () => {
    const bundle = await makeBundle({ withHumanSlot: true });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toMatchObject({
      verdict: 'deny',
      code: 'invalid_proof',
      detail: expect.objectContaining({ slots: ['human'] }),
    });
  });

  test('denies malformed bundles as invalid_bundle', async () => {
    for (const bad of ['not json', 'eyJ%%%', '[]', '"str"']) {
      const verdict = await verifyClassical(request(bad), [await operatorKey()]);
      expect(verdict).toMatchObject({ verdict: 'deny' });
      expect(['invalid_bundle', 'unsupported_version']).toContain(
        (verdict as { code: string }).code,
      );
    }
  });

  test('denies unsupported_version for bvp != 1', async () => {
    const verdict = await verifyClassical(
      request(JSON.stringify({ bvp: 2 })),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'unsupported_version' });
  });

  test('audience is compared byte-literally (no path normalization)', async () => {
    const bundle = await makeBundle({ binding: { project_key: `${AUDIENCE}/` } });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  // CROSS-IMPLEMENTATION CONFORMANCE VECTOR (binding v2). The SAME fixed binding
  // and expected digest are pinned in `bolyra verify` (cli binding.test.ts) and
  // the hosted-verify worker (binding.spec.ts). If any of the three
  // bindingDigest implementations drifts (DST, canonicalization, field
  // reduction), exactly its own pinned test breaks — the three cannot silently
  // diverge and produce mutually unverifiable bundles.
  test('matches the shared v2 binding-digest conformance vector', () => {
    const vector: BindingClaim = {
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
