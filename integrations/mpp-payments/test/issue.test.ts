/**
 * Operator-side mandate issuance (`issueMandate`) — the real minting path that
 * replaces the inline `bvp/1` construction the demo and fixtures used to carry.
 *
 * These tests exercise the FULL issue → present → classical-verify loop against
 * the same `verifyClassical` the gate uses, so an issued mandate is proven to
 * round-trip through the verifier a payment route runs.
 */

import { derivePublicKey } from '@bolyra/sdk';
import { issueMandate } from '../src/issue';
import { verifyClassical } from '../src/classical';
import { parseBundle } from '../src/bundle';
import type { OperatorKey, VerifierRequest } from '../src/types';

const OPERATOR_PRIV = 42n;
const AGENT = 'shopper-bot';
const AUDIENCE = 'api.merchant.example';
const MODEL = 'opus-4.1';
const EXPIRY = 4102444800; // 2100-01-01
const NOW = 1751990400;

async function operatorKey(priv: bigint = OPERATOR_PRIV): Promise<OperatorKey> {
  const pub = await derivePublicKey(priv);
  return { x: pub.x.toString(), y: pub.y.toString() };
}

function verifierRequest(
  presentation: string,
  opts: { granted?: string[]; audience?: string; model?: string; now?: number } = {},
): VerifierRequest {
  return {
    version: 1,
    bundle: presentation,
    request: {
      agent_name: AGENT,
      project_key: opts.audience ?? AUDIENCE,
      program: 'mpp',
      model: opts.model ?? MODEL,
      granted_capabilities: opts.granted ?? ['mpp:financial:small'],
    },
    now_unix: opts.now ?? NOW,
  };
}

describe('issueMandate', () => {
  test('issues a small-tier mandate that round-trips through classical verify (allow)', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    expect(mandate.tier).toBe('small');
    expect(mandate.capabilities).toEqual(['mpp:financial:small']);

    const verdict = await verifyClassical(verifierRequest(mandate.presentation), [
      await operatorKey(),
    ]);
    expect(verdict).toMatchObject({ verdict: 'allow' });
  });

  test('defaults to base64url encoding but honors json encoding', async () => {
    const b64 = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    expect(b64.presentation.trimStart().startsWith('{')).toBe(false);

    const json = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
      encoding: 'json',
    });
    expect(json.presentation.trimStart().startsWith('{')).toBe(true);
    // Both decode to the same agent-only bvp/1 shape.
    expect(parseBundle(b64.presentation).binding).toEqual(parseBundle(json.presentation).binding);
  });

  test('a medium mandate covers a small spend AND a medium spend (cumulative)', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'medium',
      expiry: EXPIRY,
    });
    expect(mandate.capabilities).toEqual(['mpp:financial:small', 'mpp:financial:medium']);

    const small = await verifyClassical(
      verifierRequest(mandate.presentation, { granted: ['mpp:financial:small'] }),
      [await operatorKey()],
    );
    expect(small).toMatchObject({ verdict: 'allow' });

    const medium = await verifyClassical(
      verifierRequest(mandate.presentation, { granted: ['mpp:financial:medium'] }),
      [await operatorKey()],
    );
    expect(medium).toMatchObject({ verdict: 'allow' });
  });

  test('a small mandate is DENIED an over-tier (medium) spend', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    const verdict = await verifyClassical(
      verifierRequest(mandate.presentation, { granted: ['mpp:financial:medium'] }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  test('maps a max USD amount to the smallest covering tier', async () => {
    const cases: Array<[string | number, string]> = [
      [50, 'small'],
      ['99.99', 'small'],
      [100, 'medium'],
      [5000, 'medium'],
      [10000, 'unlimited'],
      [50000, 'unlimited'],
    ];
    for (const [maxUsd, tier] of cases) {
      const mandate = await issueMandate({
        operatorPrivateKey: OPERATOR_PRIV,
        agentName: AGENT,
        audience: AUDIENCE,
        model: MODEL,
        maxUsd,
        expiry: EXPIRY,
      });
      expect(mandate.tier).toBe(tier);
    }
  });

  test('an expired mandate is denied at or after expiry', async () => {
    const shortExpiry = NOW + 3600;
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: shortExpiry,
    });
    const expired = await verifyClassical(
      verifierRequest(mandate.presentation, { now: shortExpiry }),
      [await operatorKey()],
    );
    expect(expired).toMatchObject({ verdict: 'deny', code: 'expired' });

    const live = await verifyClassical(
      verifierRequest(mandate.presentation, { now: shortExpiry - 1 }),
      [await operatorKey()],
    );
    expect(live).toMatchObject({ verdict: 'allow' });
  });

  test('a mandate for a different audience is denied request_mismatch', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    const verdict = await verifyClassical(
      verifierRequest(mandate.presentation, { audience: 'api.attacker.example' }),
      [await operatorKey()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  test('a tampered binding signature is denied invalid_signature', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
      encoding: 'json',
    });
    const obj = JSON.parse(mandate.presentation);
    obj.sig.S = (BigInt(obj.sig.S) + 1n).toString();
    const verdict = await verifyClassical(verifierRequest(JSON.stringify(obj)), [
      await operatorKey(),
    ]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_signature' });
  });

  test('a mandate from an untrusted operator is denied untrusted_root', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: 43n, // not in the trusted set
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    const verdict = await verifyClassical(verifierRequest(mandate.presentation), [
      await operatorKey(42n),
    ]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
  });

  test('accepts a 32-byte Buffer operator key (the CLI key-file shape)', async () => {
    const keyBuf = Buffer.from(OPERATOR_PRIV.toString(16).padStart(64, '0'), 'hex');
    const mandate = await issueMandate({
      operatorPrivateKey: keyBuf,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
    });
    const verdict = await verifyClassical(verifierRequest(mandate.presentation), [
      await operatorKey(),
    ]);
    expect(verdict).toMatchObject({ verdict: 'allow' });
  });

  test('carries the delegation nonce/id in the presentation when provided', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      tier: 'small',
      expiry: EXPIRY,
      nonce: 'mandate-2026-07-16-001',
      encoding: 'json',
    });
    expect(mandate.nonce).toBe('mandate-2026-07-16-001');
    expect(JSON.parse(mandate.presentation).nonce).toBe('mandate-2026-07-16-001');
    // The nonce never breaks classical verification (standing authorization).
    const verdict = await verifyClassical(verifierRequest(mandate.presentation), [
      await operatorKey(),
    ]);
    expect(verdict).toMatchObject({ verdict: 'allow' });
  });

  describe('fail-closed input validation', () => {
    const base = {
      operatorPrivateKey: OPERATOR_PRIV,
      agentName: AGENT,
      audience: AUDIENCE,
      model: MODEL,
      expiry: EXPIRY,
    };

    test('rejects neither tier nor maxUsd', async () => {
      await expect(issueMandate({ ...base } as never)).rejects.toThrow(/tier|maxUsd/i);
    });

    test('rejects both tier and maxUsd', async () => {
      await expect(
        issueMandate({ ...base, tier: 'small', maxUsd: 50 } as never),
      ).rejects.toThrow(/both|exactly one/i);
    });

    test('rejects an invalid tier', async () => {
      await expect(
        issueMandate({ ...base, tier: 'huge' } as never),
      ).rejects.toThrow(/tier/i);
    });

    test('rejects a non-decimal maxUsd', async () => {
      await expect(
        issueMandate({ ...base, maxUsd: '-5' } as never),
      ).rejects.toThrow();
    });

    test('rejects an empty audience', async () => {
      await expect(
        issueMandate({ ...base, audience: '', tier: 'small' } as never),
      ).rejects.toThrow(/audience/i);
    });

    test('rejects a non-positive expiry', async () => {
      await expect(
        issueMandate({ ...base, expiry: 0, tier: 'small' } as never),
      ).rejects.toThrow(/expiry/i);
    });

    test('rejects an unknown encoding (does not silently emit JSON)', async () => {
      await expect(
        issueMandate({ ...base, tier: 'small', encoding: 'hex' } as never),
      ).rejects.toThrow(/encoding/i);
    });
  });
});
