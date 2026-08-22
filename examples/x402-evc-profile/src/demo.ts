/**
 * x402 EVC authorization-evidence profile — runnable demo.
 *
 * One operator-signed spend mandate, three x402 retries against a paid route:
 *   [1] $25  → ALLOW  (within the small tier the operator signed)
 *   [2] $500 → DENY 403 request_mismatch/scope (over the signed ceiling)
 *   [3] $25 replayed challenge nonce → DENY 403 nonce_replayed
 *
 * Gate 1 only (authorization evidence). Payment settlement (x402 proper) and
 * payee risk (gate 2) are deliberately out of frame — see
 * spec/x402-evc-profile-v0.md and drafts/revettr-two-gates-note.md.
 */

import { NonceStore, issueMandate } from '@bolyra/mpp';
import {
  verifyX402EvcAuthorization,
  X402_EVC_AUTHORIZATION_HEADER,
  type X402EvcContext,
  type X402EvcRequirements,
} from '@bolyra/payment-protocols';

const OPERATOR_PRIVATE_KEY = 42n; // demo only — never a real key
const AUDIENCE = 'api.merchant.example';

// x402 v2 vocabulary: network / payTo / atomic-unit string amount (USDC, 6dp).
function requirements(atomicUsdc: string): X402EvcRequirements {
  return {
    network: 'base-sepolia',
    asset: 'USDC',
    amount: atomicUsdc,
    payTo: AUDIENCE,
  };
}

function challenge(atomicUsdc: string, nonce: string): X402EvcContext {
  return {
    resource: 'https://api.merchant.example/reports/q3',
    requirements: requirements(atomicUsdc),
    nonce,
    expiresAt: Math.floor(Date.now() / 1000) + 300,
  };
}

async function main(): Promise<void> {
  console.log('x402 EVC authorization-evidence profile demo');
  console.log('(one signed mandate, three x402 retries — gate 1 only)\n');

  // OPERATOR: mint one small-tier spend mandate for this payee.
  const mandate = await issueMandate({
    operatorPrivateKey: OPERATOR_PRIVATE_KEY,
    agentName: 'reports-agent',
    audience: AUDIENCE,
    model: 'demo-model',
    program: 'x402',
    maxUsd: '99',
    expiry: Math.floor(Date.now() / 1000) + 3600,
  });
  console.log(`[operator] issued mandate: tier=${mandate.tier} payee=${mandate.audience}`);
  console.log(`[agent]    presents it in ${X402_EVC_AUTHORIZATION_HEADER}\n`);

  const verifier = { kind: 'classical' as const, trustedOperators: [mandate.operatorPublicKey] };
  const nonceStore = new NonceStore();

  // [1] $25 within the signed tier → ALLOW.
  const allow25 = await verifyX402EvcAuthorization(mandate.presentation, {
    context: challenge('25000000', 'challenge-1'),
    audience: AUDIENCE,
    verifier,
    nonceStore,
  });
  console.log(`[1] $25  → ${allow25.allowed ? 'ALLOW' : 'DENY'} (HTTP ${allow25.status})`);

  // [2] $500 over the signed ceiling → DENY 403, RFC 9457 body.
  const deny500 = await verifyX402EvcAuthorization(mandate.presentation, {
    context: challenge('500000000', 'challenge-2'),
    audience: AUDIENCE,
    verifier,
    nonceStore,
  });
  console.log(`[2] $500 → ${deny500.allowed ? 'ALLOW' : 'DENY'} (HTTP ${deny500.status})`);
  console.log(`    problem+json: ${JSON.stringify(deny500.problem)}`);

  // [3] replay the first challenge nonce → DENY 403 nonce_replayed.
  const replay = await verifyX402EvcAuthorization(mandate.presentation, {
    context: challenge('25000000', 'challenge-1'),
    audience: AUDIENCE,
    verifier,
    nonceStore,
  });
  console.log(`[3] $25 (replayed nonce) → ${replay.allowed ? 'ALLOW' : 'DENY'} (HTTP ${replay.status})`);
  console.log(`    problem+json: ${JSON.stringify(replay.problem)}\n`);

  const ok = allow25.allowed && !deny500.allowed && !replay.allowed;
  console.log(ok ? 'demo: PASS' : 'demo: FAIL');
  if (!ok) process.exitCode = 1;
}

main().catch((err) => {
  console.error(err);
  process.exitCode = 1;
});
