/**
 * THE re-anchored-expiry attack (binding v2 motivation, Codex round-1 P1).
 *
 * Classical mode checks the operator's EdDSA signature over the request
 * binding. Under binding v1 that signature did NOT cover `expiry`; the scope
 * commitment referencing expiry is recomputable from public fields, so a
 * presenter holding an EXPIRED mandate could rewrite `credential.expiry` and
 * re-derive `publicSignals[2]` — and still verify `allow` at the granted tier.
 *
 * Binding v2 binds `expiry` into the signed binding digest. These tests pin the
 * attack DENIED end to end:
 *   - re-anchor credential.expiry only        → deny (signed binding.expiry no
 *     longer equals the credential expiry the scope math uses)
 *   - re-anchor binding.expiry too            → deny invalid_signature (the
 *     signature covers expiry now)
 *   - honest expired mandate                  → deny expired (control)
 *   - honest live mandate                     → allow (control)
 */

import { eddsaSign, poseidon3, poseidon5 } from '@bolyra/sdk';
import { bindingDigest, verifyClassical } from '../src/classical';
import type { VerifierRequest } from '../src/types';
import { NOW_UNIX, OPERATOR_PRIV, makeBundle, operatorKey, fixtureRequestContext } from './helpers';

/** A mandate that expired an hour before the verifier's clock. */
const PAST_EXPIRY = NOW_UNIX - 3600;
/** Where the attacker re-anchors it: ten years after the clock. */
const REBOUND_EXPIRY = NOW_UNIX + 10 * 365 * 86400;

function request(bundle: string): VerifierRequest {
  return {
    version: 1,
    bundle,
    request: fixtureRequestContext() as VerifierRequest['request'],
    now_unix: NOW_UNIX,
  };
}

/** Minimal typed view of the parts of the raw bundle the attacker rewrites. */
interface RawBundle {
  agent: {
    envelope: { publicSignals: string[] };
    credential: {
      model_hash: string;
      operator_pubkey: { x: string; y: string };
      permission_bitmask: string;
      expiry: number;
    };
  };
  binding: Record<string, unknown>;
  sig: unknown;
}

/**
 * The attack: given an issued (expired) presentation, rewrite the self-asserted
 * `credential.expiry` to `newExpiry` and recompute the scope-commitment public
 * signal from the revealed preimage — everything the classical verifier
 * cross-checks EXCEPT the operator signature. Leaves binding + sig untouched.
 */
async function reanchorCredentialExpiry(bundleJson: string, newExpiry: number): Promise<RawBundle> {
  const raw = JSON.parse(bundleJson) as RawBundle;
  const cred = raw.agent.credential;
  cred.expiry = newExpiry;
  const credentialCommitment = await poseidon5(
    BigInt(cred.model_hash),
    BigInt(cred.operator_pubkey.x),
    BigInt(cred.operator_pubkey.y),
    BigInt(cred.permission_bitmask),
    BigInt(newExpiry),
  );
  const scopeCommitment = await poseidon3(
    BigInt(cred.permission_bitmask),
    credentialCommitment,
    BigInt(newExpiry),
  );
  raw.agent.envelope.publicSignals[2] = scopeCommitment.toString();
  raw.agent.envelope.publicSignals[4] = String(newExpiry);
  return raw;
}

describe('re-anchored expiry attack (classical binding v2)', () => {
  test('control: an honestly expired mandate denies expired', async () => {
    const bundle = await makeBundle({ expiry: PAST_EXPIRY });
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
  });

  test('ATTACK: re-anchoring credential.expiry + recomputing the scope commitment must DENY', async () => {
    const bundle = await makeBundle({ expiry: PAST_EXPIRY });
    const rebound = await reanchorCredentialExpiry(bundle, REBOUND_EXPIRY);
    const verdict = await verifyClassical(request(JSON.stringify(rebound)), [await operatorKey()]);
    // Binding v1 allowed this (the signature did not cover expiry). v2 must deny.
    expect(verdict.verdict).toBe('deny');
  });

  test('ATTACK variant: also re-anchoring the signed binding.expiry denies invalid_signature', async () => {
    const bundle = await makeBundle({ expiry: PAST_EXPIRY });
    const rebound = await reanchorCredentialExpiry(bundle, REBOUND_EXPIRY);
    rebound.binding.expiry = REBOUND_EXPIRY;
    const verdict = await verifyClassical(request(JSON.stringify(rebound)), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_signature' });
  });

  test('control: an honest live mandate still allows', async () => {
    const bundle = await makeBundle(); // helper default: far-future expiry
    const verdict = await verifyClassical(request(bundle), [await operatorKey()]);
    expect(verdict).toEqual({ verdict: 'allow', kind: 'classical' });
  });

  test('an obsolete v1 binding (no expiry) is rejected unsupported_version', async () => {
    const raw = JSON.parse(await makeBundle()) as { binding: Record<string, unknown> };
    delete raw.binding.expiry; // strip back to the five-field v1 shape
    const verdict = await verifyClassical(request(JSON.stringify(raw)), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'unsupported_version' });
  });

  test('binding.expiry not equal to credential.expiry denies invalid_bundle', async () => {
    // A validly-SIGNED binding whose expiry differs from the credential expiry.
    // The signature verifies (it covers this binding.expiry) but the equality
    // check (4b) catches the divergence. Built by re-signing directly, since the
    // single minting path refuses to emit a mismatch.
    const raw = JSON.parse(await makeBundle()) as {
      binding: Record<string, unknown> & { expiry: number };
      sig: { R8: { x: string; y: string }; S: string };
    };
    raw.binding.expiry = REBOUND_EXPIRY; // credential.expiry stays at EXPIRY
    const sig = await eddsaSign(OPERATOR_PRIV, bindingDigest(raw.binding as never));
    raw.sig = {
      R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
      S: sig.S.toString(),
    };
    const verdict = await verifyClassical(request(JSON.stringify(raw)), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_bundle' });
  });

  test('a non-integer binding.expiry denies invalid_bundle', async () => {
    const raw = JSON.parse(await makeBundle()) as { binding: Record<string, unknown> };
    raw.binding.expiry = 'soon';
    const verdict = await verifyClassical(request(JSON.stringify(raw)), [await operatorKey()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_bundle' });
  });
});
