/**
 * Unit tests for the verify layer. We mock @bolyra/sdk so these run without
 * circuit artifacts — the goal here is to exercise the wrapper logic, not
 * re-test the SDK's proof verification.
 */

import { verifyBundle, checkToolPolicy } from '../src/verify';
import type { BolyraProofBundle, BolyraMcpConfig } from '../src/types';

jest.mock('@bolyra/sdk', () => ({
  verifyHandshake: jest.fn(),
  verifyDelegation: jest.fn(),
  poseidon3: jest.fn(),
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
  sdk.poseidon3.mockReset();
  sdk.verifyHandshake.mockResolvedValue({
    humanNullifier: 1n,
    agentNullifier: 2n,
    sessionNonce: BigInt(Math.floor(Date.now() / 1000)),
    scopeCommitment: 999n,
    verified: true,
  });
  // Default: poseidon3(credential fields) matches the mocked scopeCommitment
  // so the binding check passes for happy-path tests.
  sdk.poseidon3.mockResolvedValue(999n);
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
    const ctx = await verifyBundle({ ...makeBundle(), v: 999 as any }, makeConfig());
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/Unsupported bundle version/);
  });

  it('rejects v=1 bundles that carry a delegationChain', async () => {
    const ctx = await verifyBundle(
      { ...makeBundle(), delegationChain: [{} as any] },
      makeConfig(),
    );
    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/v=1 cannot carry a delegationChain/);
  });

  it('reports chainDepth=0 and effectiveCommitment=root for v=1 bundles', async () => {
    const ctx = await verifyBundle(makeBundle(), makeConfig());
    expect(ctx.chainDepth).toBe(0);
    expect(ctx.effectiveCommitment).toBe('12345');
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

  it('rejects when proof scopeCommitment does not match resolved credential (credential substitution)', async () => {
    // Credential A (attacker-owned): commitment 11111, scopeCommitment 999
    // Credential B (privileged): commitment 22222, scopeCommitment 888
    // Attack: proof was generated for A (scopeCommitment=999), but bundle
    // claims credentialCommitment=22222 (credential B).
    const credentialB = {
      modelHash: 1n,
      operatorPublicKey: { x: 1n, y: 2n },
      permissionBitmask: 0b11111111n, // privileged
      expiryTimestamp: BigInt(Math.floor(Date.now() / 1000) + 86400),
      signature: { R8: { x: 1n, y: 2n }, S: 3n },
      commitment: 22222n,
    };

    const config = makeConfig({
      resolveCredential: jest.fn(async () => credentialB as any),
    });

    // verifyHandshake returns scopeCommitment=999 (from credential A's proof)
    sdk.verifyHandshake.mockResolvedValue({
      humanNullifier: 1n,
      agentNullifier: 2n,
      sessionNonce: BigInt(Math.floor(Date.now() / 1000)),
      scopeCommitment: 999n,
      verified: true,
    });

    // poseidon3(B.permissionBitmask, B.commitment, B.expiryTimestamp) → 888
    // This does NOT match the proof's scopeCommitment of 999.
    sdk.poseidon3.mockResolvedValue(888n);

    const bundle = makeBundle({ credentialCommitment: '22222' });
    const ctx = await verifyBundle(bundle, config);

    expect(ctx.verified).toBe(false);
    expect(ctx.reason).toMatch(/not bound to the claimed credential/);
    expect(ctx.warnings).toEqual(
      expect.arrayContaining([expect.stringMatching(/credential substitution/)]),
    );
    expect(ctx.permissionBitmask).toBe(0n);
  });
});

describe('chain verification', () => {
  // Build a v=2 bundle with N hops. Each hop's delegateeScope/etc are decimal
  // strings; the mocked sdk lets us script which hops pass and which fail.
  function makeChainBundle(hops: number): BolyraProofBundle {
    return makeBundle({
      v: 2,
      delegationChain: Array.from({ length: hops }, (_, i) => ({
        proof: { proof: {}, publicSignals: [`${1000 + i}`, '0', '0', '0', '0', '0'] } as any,
        delegateeCommitment: `${50000 + i}`,
        delegateeScope: i === hops - 1 ? '3' : '15', // leaf=0b11, mid=0b1111
        delegateeExpiry: String(Math.floor(Date.now() / 1000) + 86400),
        currentTimestamp: String(Math.floor(Date.now() / 1000)),
      })),
    });
  }

  beforeEach(() => {
    sdk.verifyDelegation.mockReset();
    sdk.poseidon3.mockReset();
  });

  it('verifies a 2-hop chain and reports leaf scope as effective bitmask', async () => {
    sdk.verifyDelegation.mockResolvedValue({} as any);
    // First call: binding check (credential → scopeCommitment must match proof output).
    // Subsequent calls: per-hop newScopeCommitment recomputation.
    sdk.poseidon3
      .mockResolvedValueOnce(999n)  // binding check (matches verifyHandshake mock)
      .mockResolvedValueOnce(1000n) // hop 0 newScopeCommitment
      .mockResolvedValueOnce(1001n); // hop 1 newScopeCommitment

    const ctx = await verifyBundle(makeChainBundle(2), makeConfig());

    expect(ctx.verified).toBe(true);
    expect(ctx.chainDepth).toBe(2);
    expect(ctx.permissionBitmask).toBe(3n);
    expect(ctx.effectiveCommitment).toBe('50001');
  });

  it('rejects when a hop newScopeCommitment formula does not match', async () => {
    sdk.verifyDelegation.mockResolvedValue({} as any);
    sdk.poseidon3
      .mockResolvedValueOnce(999n)   // binding check passes
      .mockResolvedValueOnce(9999n); // doesn't match publicSignals[0]=1000

    const ctx = await verifyBundle(makeChainBundle(1), makeConfig());

    expect(ctx.verified).toBe(false);
    expect(ctx.warnings.some((w) => /newScopeCommitment mismatch/.test(w))).toBe(true);
  });

  it('rejects when verifyDelegation throws on a hop', async () => {
    sdk.poseidon3.mockResolvedValueOnce(999n); // binding check passes
    sdk.verifyDelegation.mockRejectedValue(new Error('bad signature'));

    const ctx = await verifyBundle(makeChainBundle(1), makeConfig());

    expect(ctx.verified).toBe(false);
    expect(ctx.warnings.some((w) => /verification failed/.test(w))).toBe(true);
  });

  it('rejects expired hops', async () => {
    sdk.verifyDelegation.mockResolvedValue({} as any);
    sdk.poseidon3
      .mockResolvedValueOnce(999n)   // binding check passes
      .mockResolvedValue(1000n);     // chain hop recomputation
    const expired = makeBundle({
      v: 2,
      delegationChain: [
        {
          proof: { proof: {}, publicSignals: ['1000', '0', '0', '0', '0', '0'] } as any,
          delegateeCommitment: '50000',
          delegateeScope: '3',
          delegateeExpiry: '100', // ancient
          currentTimestamp: '1000', // newer than expiry
        },
      ],
    });

    const ctx = await verifyBundle(expired, makeConfig());

    expect(ctx.verified).toBe(false);
    expect(ctx.warnings.some((w) => /expired/.test(w))).toBe(true);
  });
});

describe('checkToolPolicy', () => {
  const baseCtx = {
    verified: true,
    score: 100,
    did: 'did:bolyra:base-sepolia:abc',
    permissionBitmask: 0b011n,
    warnings: [],
    chainDepth: 0,
    effectiveCommitment: '12345',
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
