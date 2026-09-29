/**
 * x402 EVC authorization-evidence profile tests (spec/x402-evc-profile-v0.md).
 *
 * Real verification path: mandates are minted with @bolyra/mpp's issueMandate
 * and verified through the in-process classical verifier — no ZK artifacts
 * needed. Covers:
 *   - allow within mandate tier ($25 under a small-tier mandate)
 *   - deny over-amount (tier ceiling exceeded)
 *   - deny wrong payee/audience (request_mismatch)
 *   - deny expired challenge context (host-owned expires_at)
 *   - deny challenge-nonce replay (host reserve-before-act)
 *   - deny missing header (missing_authorization, 401)
 *   - fail-closed on invalid verifier verdicts (hostile verifier)
 *   - profile extension shape rides the EVC envelope without touching §2.1
 */

import { issueMandate, NonceStore } from '@bolyra/mpp';

import {
  X402_EVC_PROFILE,
  X402_EVC_AUTHORIZATION_HEADER,
  buildX402EvcRequest,
  verifyX402EvcAuthorization,
  type X402EvcContext,
  type X402EvcRequirements,
} from '../src/x402-evc';

const OPERATOR_PRIVATE_KEY = 42n; // test only
const AUDIENCE = 'api.merchant.example';
const NOW = 1_755_900_000;

// x402 v2 vocabulary: network / payTo / atomic-unit string amount (USDC, 6dp).
const REQS_25_USD: X402EvcRequirements = {
  network: 'base-sepolia',
  asset: 'USDC',
  amount: '25000000', // 25 USDC in atomic units
  payTo: AUDIENCE,
  assetDecimals: 6, // A2: the host asserts the 1:1-USD asset explicitly
};

const REQS_500_USD: X402EvcRequirements = {
  ...REQS_25_USD,
  amount: '500000000',
};

function context(
  requirements: X402EvcRequirements,
  overrides: Partial<X402EvcContext> = {},
): X402EvcContext {
  return {
    resource: 'https://api.merchant.example/reports/q3',
    requirements,
    nonce: 'challenge-nonce-1',
    expiresAt: NOW + 300,
    ...overrides,
  };
}

async function smallMandate() {
  return issueMandate({
    operatorPrivateKey: OPERATOR_PRIVATE_KEY,
    agentName: 'reports-agent',
    audience: AUDIENCE,
    model: 'test-model',
    program: 'x402',
    maxUsd: '99',
    expiry: NOW + 3_600,
  });
}

describe('profile constants', () => {
  test('profile id and header are stable', () => {
    expect(X402_EVC_PROFILE).toBe('x402_evc/0');
    expect(X402_EVC_AUTHORIZATION_HEADER).toBe('x-bolyra-authorization');
  });
});

describe('buildX402EvcRequest', () => {
  test('builds an EVC §2.1 request with the profile extension at envelope level', async () => {
    const mandate = await smallMandate();
    const request = buildX402EvcRequest({
      bundle: mandate.presentation,
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    // Core §2.1 members untouched by the profile.
    expect(request.version).toBe(1);
    expect(request.bundle).toBe(mandate.presentation);
    expect(request.now_unix).toBe(NOW);
    expect(request.request.agent_name).toBe('reports-agent');
    expect(request.request.project_key).toBe(AUDIENCE);
    expect(request.request.program).toBe('x402');
    expect(request.request.granted_capabilities).toHaveLength(1);

    // Profile extension.
    expect(request.x402_evc.profile).toBe(X402_EVC_PROFILE);
    expect(request.x402_evc.resource).toBe('https://api.merchant.example/reports/q3');
    expect(request.x402_evc.amount).toBe('25');
    expect(request.x402_evc.asset).toBe('USDC');
    expect(request.x402_evc.network).toBe('base-sepolia');
    expect(request.x402_evc.payee).toBe(AUDIENCE);
    expect(request.x402_evc.nonce).toBe('challenge-nonce-1');
    expect(request.x402_evc.expires_at).toBe(NOW + 300);
    expect(request.x402_evc.verifier).toBe('classical');
  });

  test('unresolvable amounts fail closed', async () => {
    const mandate = await smallMandate();
    expect(() =>
      buildX402EvcRequest({
        bundle: mandate.presentation,
        context: context({ ...REQS_25_USD, amount: 'not-a-number' }),
        audience: AUDIENCE,
        verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
        now: () => NOW,
      }),
    ).toThrow(/amount/i);
  });
});

describe('verifyX402EvcAuthorization', () => {
  test('allows a $25 spend under a small-tier mandate', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(true);
    expect(decision.status).toBe(200);
    expect(decision.verdict.verdict).toBe('allow');
    expect(decision.problem).toBeUndefined();
  });

  test('denies a $500 spend against the same small-tier mandate', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_500_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.problem).toBeDefined();
    expect(decision.problem?.code).toMatch(/request_mismatch|scope_exceeded|unknown_capability/);
    expect(decision.problem?.type).toContain('bolyra.ai/problems');
  });

  test('denies a mandate signed for a different payee', async () => {
    const mandate = await issueMandate({
      operatorPrivateKey: OPERATOR_PRIVATE_KEY,
      agentName: 'reports-agent',
      audience: 'api.other-merchant.example',
      model: 'test-model',
      program: 'x402',
      maxUsd: '99',
      expiry: NOW + 3_600,
    });
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.problem?.code).toBe('request_mismatch');
  });

  test('denies a stale challenge context (expired, host-owned)', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD, { expiresAt: NOW - 1 }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.problem?.code).toBe('expired');
  });

  test('denies challenge-nonce replay via reserve-before-act', async () => {
    const mandate = await smallMandate();
    const nonceStore = new NonceStore();
    const opts = {
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical' as const, trustedOperators: [mandate.operatorPublicKey] },
      nonceStore,
      now: () => NOW,
    };

    const first = await verifyX402EvcAuthorization(mandate.presentation, opts);
    expect(first.allowed).toBe(true);

    const replay = await verifyX402EvcAuthorization(mandate.presentation, opts);
    expect(replay.allowed).toBe(false);
    expect(replay.status).toBe(403);
    expect(replay.problem?.code).toBe('nonce_replayed');
  });

  test('denies an audience/payTo mismatch before any verifier runs (host-owned)', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context({ ...REQS_25_USD, payTo: '0x000000000000000000000000000000000000beef' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(403);
    expect(decision.problem?.code).toBe('request_mismatch');
  });

  test('a payeeMatches callback can canonicalize audience→payTo mapping', async () => {
    const mandate = await smallMandate();
    const payTo = '0x000000000000000000000000000000000000beef';
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context({ ...REQS_25_USD, payTo }, { nonce: 'challenge-payee-cb' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      payeeMatches: (audience, p) => audience === AUDIENCE && p === payTo,
      now: () => NOW,
    });

    expect(decision.allowed).toBe(true);
  });

  test('denies replay through the DEFAULT nonce store (no store injected)', async () => {
    const mandate = await smallMandate();
    const opts = {
      context: context(REQS_25_USD, { nonce: 'default-store-nonce-1' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical' as const, trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    };

    const first = await verifyX402EvcAuthorization(mandate.presentation, opts);
    expect(first.allowed).toBe(true);

    const replay = await verifyX402EvcAuthorization(mandate.presentation, opts);
    expect(replay.allowed).toBe(false);
    expect(replay.problem?.code).toBe('nonce_replayed');
  });

  test('denies a missing authorization header with 401', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(undefined, {
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(401);
    expect(decision.problem?.code).toBe('missing_authorization');
  });

  test('fails closed (500 internal_error) when the nonce store throws synchronously', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD, { nonce: 'store-throws-sync' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      nonceStore: {
        reserve(): boolean {
          throw new Error('store down');
        },
      },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(500);
    expect(decision.problem?.code).toBe('internal_error');
  });

  test('fails closed (500 internal_error) when the nonce store rejects asynchronously', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD, { nonce: 'store-rejects-async' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      nonceStore: {
        reserve(): Promise<boolean> {
          return Promise.reject(new Error('store down'));
        },
      },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(500);
    expect(decision.problem?.code).toBe('internal_error');
  });

  test('fails closed when a command verifier emits an invalid verdict', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD),
      audience: AUDIENCE,
      verifier: {
        kind: 'command',
        command: process.execPath,
        args: ['-e', 'process.stdout.write(JSON.stringify({verdict:"allow",bonus:"nope"}))'],
      },
      now: () => NOW,
    });

    expect(decision.allowed).toBe(false);
    expect(decision.status).toBe(500);
    expect(decision.problem?.code).toBe('internal_error');
  });
});

// ---------------------------------------------------------------------------
// A1-A3 pre-fixes (plan 2026-09-29): hook result discipline, asset-aware
// amounts, finite-time guards. Each of these was a fail-open or silent
// mis-scaling path before.
// ---------------------------------------------------------------------------

describe('A1: payeeMatches must return literal true', () => {
  const payTo = '0x000000000000000000000000000000000000beef';

  async function decide(payeeMatches: unknown, nonce: string) {
    const mandate = await smallMandate();
    return verifyX402EvcAuthorization(mandate.presentation, {
      context: context({ ...REQS_25_USD, payTo }, { nonce }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      // Deliberately wrong types: what a JS caller can hand us.
      payeeMatches: payeeMatches as (a: string, p: string) => boolean,
      now: () => NOW,
    });
  }

  test('a Promise-returning hook (resolving true) denies request_mismatch instead of failing open', async () => {
    const decision = await decide(async () => true, 'a1-promise');
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('request_mismatch');
  });

  test('a rejecting Promise hook denies and leaves no unhandled rejection', async () => {
    const unhandled: unknown[] = [];
    const onUnhandled = (reason: unknown) => { unhandled.push(reason); };
    process.on('unhandledRejection', onUnhandled);
    try {
      const decision = await decide(() => Promise.reject(new Error('boom')), 'a1-reject');
      expect(decision.allowed).toBe(false);
      expect(decision.problem?.code).toBe('request_mismatch');
      await new Promise((r) => setImmediate(r));
      await new Promise((r) => setImmediate(r));
      expect(unhandled).toEqual([]);
    } finally {
      process.off('unhandledRejection', onUnhandled);
    }
  });

  test('a then-only thenable (no .catch) denies without throwing', async () => {
    const thenOnly = { then(onFulfilled: (v: boolean) => void) { onFulfilled(true); } };
    const decision = await decide(() => thenOnly, 'a1-thenonly');
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('request_mismatch');
  });

  test('a truthy non-boolean (the string "true") denies', async () => {
    const decision = await decide(() => 'true', 'a1-string');
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('request_mismatch');
  });
});

describe('A2: asset-aware USD amount resolution', () => {
  async function built(requirements: X402EvcRequirements) {
    const mandate = await smallMandate();
    return buildX402EvcRequest({
      bundle: mandate.presentation,
      context: context(requirements),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });
  }
  const atomic = (amount: string, extra: Partial<X402EvcRequirements> = {}): X402EvcRequirements =>
    ({ network: 'base-sepolia', asset: 'USDC', amount, payTo: AUDIENCE, assetDecimals: 6, ...extra });

  test('iso4217:USD amounts are decimal USD already (Tavily agent-pay shape)', async () => {
    const req = await built({ network: 'aws:base', asset: 'iso4217:USD', amount: '0.016', payTo: AUDIENCE });
    expect(req.x402_evc.amount).toBe('0.016');
  });

  test('atomic amounts map to exact decimal strings at tier boundaries', async () => {
    expect((await built(atomic('99999999'))).x402_evc.amount).toBe('99.999999');
    expect((await built(atomic('100000000'))).x402_evc.amount).toBe('100');
    expect((await built(atomic('1'))).x402_evc.amount).toBe('0.000001');
    expect((await built(atomic('25000000'))).x402_evc.amount).toBe('25');
  });

  test.each([
    ['iso4217:EUR without a converter', { network: 'n', asset: 'iso4217:EUR', amount: '1.00', payTo: AUDIENCE }],
    ['malformed iso4217 identifier', { network: 'n', asset: 'iso4217:usd', amount: '1.00', payTo: AUDIENCE }],
    ['non-ISO asset with assetDecimals omitted', { network: 'n', asset: 'USDC', amount: '25000000', payTo: AUDIENCE }],
    ['fractional atomic amount', atomic('25000000.5')],
    ['exponent syntax', atomic('2.5e7')],
    ['zero amount', atomic('0')],
    ['iso4217:USD exponent syntax', { network: 'n', asset: 'iso4217:USD', amount: '1.6e-8', payTo: AUDIENCE }],
    ['overlong amount', atomic('1'.repeat(41))],
    ['assetDecimals out of range', atomic('25000000', { assetDecimals: 37 })],
  ])('fails closed (internal_error) on %s', async (_label, requirements) => {
    await expect(built(requirements as X402EvcRequirements)).rejects.toMatchObject({ code: 'internal_error' });
  });
});

describe('A3: finite-time guards', () => {
  test('a NaN challenge expiresAt fails closed instead of bypassing the expiry check', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD, { nonce: 'a3-nan-exp', expiresAt: Number.NaN }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => NOW,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('internal_error');
  });

  test('a NaN clock fails closed', async () => {
    const mandate = await smallMandate();
    const decision = await verifyX402EvcAuthorization(mandate.presentation, {
      context: context(REQS_25_USD, { nonce: 'a3-nan-now' }),
      audience: AUDIENCE,
      verifier: { kind: 'classical', trustedOperators: [mandate.operatorPublicKey] },
      now: () => Number.NaN,
    });
    expect(decision.allowed).toBe(false);
    expect(decision.problem?.code).toBe('internal_error');
  });
});
