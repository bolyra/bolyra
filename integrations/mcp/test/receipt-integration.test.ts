/**
 * Tests for receipt integration in verifyBundle.
 *
 * Validates that:
 * - verifyBundle attaches a SignedReceipt when receiptSigner is configured
 * - verifyBundle omits receipt when receiptSigner is absent
 * - dev mode never produces receipts
 * - produced receipts pass verifyReceipt()
 */

import { verifyBundle } from '../src/verify';
import { verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import type { BolyraProofBundle, BolyraMcpConfig } from '../src/types';

jest.mock('@bolyra/sdk', () => ({
  verifyHandshake: jest.fn(),
  verifyDelegation: jest.fn(),
  poseidon3: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const sdk = require('@bolyra/sdk');

// Deterministic test key (do NOT use in production).
const TEST_PRIVATE_KEY =
  '0xac0974bec39a17e36ba4a6b4d238ff944bacb478cbed5efcae784d7bf4f2ff80';

function makeNonce(): string {
  const ts = BigInt(Math.floor(Date.now() / 1000));
  return String((ts << 64n) | 0xdeadbeefcafe1234n);
}

function makeBundle(overrides: Partial<BolyraProofBundle> = {}): BolyraProofBundle {
  return {
    v: 1,
    humanProof: {
      pi_a: [],
      pi_b: [],
      pi_c: [],
      protocol: 'groth16',
      curve: 'bn128',
      publicSignals: ['100', '200', '300'],
    } as any,
    agentProof: {
      pi_a: [],
      pi_b: [],
      pi_c: [],
      protocol: 'groth16',
      curve: 'bn128',
      publicSignals: ['400', '500', '600', '7'],
    } as any,
    nonce: makeNonce(),
    credentialCommitment: '12345',
    ...overrides,
  };
}

function makeConfig(overrides: Partial<BolyraMcpConfig> = {}): BolyraMcpConfig {
  return {
    resolveCredential: jest.fn(async () => ({
      modelHash: 1n,
      operatorPublicKey: { x: 1n, y: 2n },
      permissionBitmask: 0b111n,
      expiryTimestamp: BigInt(Math.floor(Date.now() / 1000) + 86400),
      signature: { R8: { x: 1n, y: 2n }, S: 3n },
      commitment: 12345n,
    } as any)),
    ...overrides,
  };
}

function makeSignerConfig() {
  return {
    issuer: 'test-mcp-server',
    keyId: 'key-001',
    privateKey: TEST_PRIVATE_KEY,
  };
}

beforeEach(() => {
  sdk.verifyHandshake.mockReset();
  sdk.poseidon3.mockReset();
  sdk.verifyHandshake.mockResolvedValue({
    humanNullifier: 1n,
    agentNullifier: 2n,
    sessionNonce: BigInt(Math.floor(Date.now() / 1000)),
    scopeCommitment: 999n,
    verified: true,
  });
  sdk.poseidon3.mockResolvedValue(999n);
});

describe('receipt integration', () => {
  it('attaches a SignedReceipt when receiptSigner is configured', async () => {
    const config = makeConfig({ receiptSigner: makeSignerConfig() });
    const ctx = await verifyBundle(makeBundle(), config);

    expect(ctx.verified).toBe(true);
    expect(ctx.receipt).toBeDefined();
    const receipt = ctx.receipt as SignedReceipt;
    expect(receipt.payload.v).toBe(1);
    expect(receipt.payload.kind).toBe('bolyra.auth');
    expect(receipt.payload.issuer).toBe('test-mcp-server');
    expect(receipt.payload.decision.allowed).toBe(true);
    expect(receipt.payload.decision.score).toBe(ctx.score);
    expect(receipt.signature.alg).toBe('ES256K');
    expect(receipt.signature.value).toMatch(/^0x[0-9a-f]{130}$/);
  });

  it('omits receipt when receiptSigner is not configured', async () => {
    const config = makeConfig();
    const ctx = await verifyBundle(makeBundle(), config);

    expect(ctx.verified).toBe(true);
    expect(ctx.receipt).toBeUndefined();
  });

  it('does not produce a receipt in dev mode', async () => {
    const config = makeConfig({
      devMode: true,
      receiptSigner: makeSignerConfig(),
    });
    const bundle = makeBundle({ _dev: true });
    const ctx = await verifyBundle(bundle, config);

    expect(ctx.verified).toBe(true);
    expect(ctx.receipt).toBeUndefined();
  });

  it('produced receipt passes verifyReceipt()', async () => {
    const config = makeConfig({ receiptSigner: makeSignerConfig() });
    const ctx = await verifyBundle(makeBundle(), config);

    expect(ctx.receipt).toBeDefined();
    const receipt = ctx.receipt as SignedReceipt;
    const valid = verifyReceipt(receipt);
    expect(valid).toBe(true);
  });

  it('produced receipt passes verifyReceipt() with signer check', async () => {
    const config = makeConfig({ receiptSigner: makeSignerConfig() });
    const ctx = await verifyBundle(makeBundle(), config);

    const receipt = ctx.receipt as SignedReceipt;
    // The signer address is derived from the test private key
    const valid = verifyReceipt(receipt, receipt.signature.signer);
    expect(valid).toBe(true);
  });

  it('attaches receipt on failed verification too', async () => {
    sdk.verifyHandshake.mockResolvedValue({
      humanNullifier: 1n,
      agentNullifier: 2n,
      sessionNonce: 0n,
      scopeCommitment: 0n,
      verified: false,
    });
    // poseidon3 must match scopeCommitment=0n for binding check to pass
    sdk.poseidon3.mockResolvedValue(0n);

    const config = makeConfig({ receiptSigner: makeSignerConfig() });
    const ctx = await verifyBundle(makeBundle(), config);

    expect(ctx.verified).toBe(false);
    expect(ctx.receipt).toBeDefined();
    const receipt = ctx.receipt as SignedReceipt;
    expect(receipt.payload.decision.allowed).toBe(false);
    expect(receipt.payload.decision.reasonCode).toBeDefined();
  });

  it('does not attach receipt on early returns (malformed bundle)', async () => {
    // Malformed nonce triggers an early return before the final path
    const config = makeConfig({ receiptSigner: makeSignerConfig() });
    const ctx = await verifyBundle(
      makeBundle({ nonce: 'not-a-number' }),
      config,
    );

    expect(ctx.verified).toBe(false);
    expect(ctx.receipt).toBeUndefined();
  });
});
