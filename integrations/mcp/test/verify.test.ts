/**
 * Unit tests for the verify layer. We mock @bolyra/sdk so these run without
 * circuit artifacts — the goal here is to exercise the wrapper logic, not
 * re-test the SDK's proof verification.
 */

import { verifyBundle, checkToolPolicy } from '../src/verify';
import type { BolyraProofBundle, BolyraMcpConfig } from '../src/types';

jest.mock('@bolyra/sdk', () => ({
  verifyHandshake: jest.fn(),
}));

// eslint-disable-next-line @typescript-eslint/no-var-requires
const sdk = require('@bolyra/sdk');

function makeBundle(overrides: Partial<BolyraProofBundle> = {}): BolyraProofBundle {
  return {
    v: 1,
    humanProof: { pi_a: [], pi_b: [], pi_c: [], protocol: 'groth16', curve: 'bn128' } as any,
    agentProof: { pi_a: [], pi_b: [], pi_c: [], protocol: 'groth16', curve: 'bn128' } as any,
    nonce: String(Math.floor(Date.now() / 1000)),
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

beforeEach(() => {
  sdk.verifyHandshake.mockReset();
  sdk.verifyHandshake.mockResolvedValue({
    humanNullifier: 1n,
    agentNullifier: 2n,
    sessionNonce: BigInt(Math.floor(Date.now() / 1000)),
    scopeCommitment: 999n,
    verified: true,
  });
});

describe('verifyBundle', () => {
  it('returns verified=true with score 100 for a fresh, valid bundle', async () => {
    const ctx = await verifyBundle(makeBundle(), makeConfig());
    expect(ctx.verified).toBe(true);
    expect(ctx.score).toBe(100);
    expect(ctx.warnings).toHaveLength(0);
    expect(ctx.did).toMatch(/^did:bolyra:base-sepolia:/);
  });

  it('rejects unknown bundle versions', async () => {
    const ctx = await verifyBundle({ ...makeBundle(), v: 2 as any }, makeConfig());
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/Unsupported bundle version/);
  });

  it('rejects malformed nonce', async () => {
    const ctx = await verifyBundle(makeBundle({ nonce: 'not-a-number' }), makeConfig());
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/invalid nonce/);
  });

  it('rejects when credential not found', async () => {
    const config = makeConfig({ resolveCredential: jest.fn(async () => null) });
    const ctx = await verifyBundle(makeBundle(), config);
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/No credential found/);
  });

  it('returns verified=false when ZKP verification fails', async () => {
    sdk.verifyHandshake.mockResolvedValue({
      humanNullifier: 1n,
      agentNullifier: 2n,
      sessionNonce: 0n,
      scopeCommitment: 0n,
      verified: false,
    });
    const ctx = await verifyBundle(makeBundle(), makeConfig());
    expect(ctx.verified).toBe(false);
    expect(ctx.score).toBeLessThan(70);
  });

  it('rejects stale nonce', async () => {
    const oldNonce = String(Math.floor(Date.now() / 1000) - 600);
    const ctx = await verifyBundle(makeBundle({ nonce: oldNonce }), makeConfig({ maxProofAge: 300 }));
    expect(ctx.warnings.some((w) => /stale/i.test(w))).toBe(true);
  });

  it('catches verifyHandshake throws and reports as failure', async () => {
    sdk.verifyHandshake.mockRejectedValue(new Error('rpc unreachable'));
    const ctx = await verifyBundle(makeBundle(), makeConfig());
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/rpc unreachable/);
  });
});

describe('checkToolPolicy', () => {
  const baseCtx = {
    verified: true,
    score: 100,
    did: 'did:bolyra:base-sepolia:abc',
    permissionBitmask: 0b011n,
    warnings: [],
  };

  it('allows tools with no policy entry', () => {
    expect(checkToolPolicy('any_tool', baseCtx, makeConfig())).toBeNull();
  });

  it('allows tools whose required bits are covered', () => {
    const config = makeConfig({ toolPolicy: { read_file: 0b001n } });
    expect(checkToolPolicy('read_file', baseCtx, config)).toBeNull();
  });

  it('denies tools whose required bits exceed granted', () => {
    const config = makeConfig({ toolPolicy: { delete_file: 0b100n } });
    const result = checkToolPolicy('delete_file', baseCtx, config);
    expect(result).toMatch(/requires permissions/);
  });
});
