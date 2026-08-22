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
