import { proveHandshake, verifyHandshake, defaultNonce } from '../src/handshake';
import { ProofGenerationError } from '../src/errors';
import { HumanIdentity, AgentCredential } from '../src/types';

const mockHuman: HumanIdentity = {
  secret: 1n,
  publicKey: { x: 100n, y: 200n },
  commitment: 300n,
};

const mockAgent: AgentCredential = {
  modelHash: 1n,
  operatorPublicKey: { x: 100n, y: 200n },
  permissionBitmask: 1n,
  expiryTimestamp: 9999999999n,
  signature: { R8: { x: 1n, y: 2n }, S: 3n },
  commitment: 400n,
};

describe('proveHandshake nonce unit', () => {
  it('defaultNonce embeds Unix seconds in upper bits with random entropy', () => {
    const now = BigInt(Math.floor(Date.now() / 1000));
    const nonce = defaultNonce();
    // Upper bits (>> 64) must be within 2 seconds of current Unix time
    const ts = nonce >> 64n;
    expect(ts).toBeGreaterThanOrEqual(now - 2n);
    expect(ts).toBeLessThanOrEqual(now + 2n);
    // Lower 64 bits are random entropy — must not be zero (astronomically unlikely)
    const entropy = nonce & ((1n << 64n) - 1n);
    expect(entropy).not.toBe(0n);
  });

  it('defaultNonce produces distinct values on consecutive calls', () => {
    const a = defaultNonce();
    const b = defaultNonce();
    expect(a).not.toBe(b);
  });
});

describe('proveHandshake', () => {
  it('throws ProofGenerationError when circuit artifacts are missing', async () => {
    // With no real circuit files at the default path in test env,
    // this should throw a ProofGenerationError (not NOT_IMPLEMENTED)
    await expect(
      proveHandshake(mockHuman, mockAgent, {
        config: { circuitDir: '/nonexistent/path' },
      }),
    ).rejects.toThrow(ProofGenerationError);
  });

  it('accepts scope and nonce options', async () => {
    await expect(
      proveHandshake(mockHuman, mockAgent, {
        scope: 42n,
        nonce: 12345n,
        config: { circuitDir: '/nonexistent/path' },
      }),
    ).rejects.toThrow(ProofGenerationError);
  });
});

describe('verifyHandshake', () => {
  // HumanUniqueness publicSignals layout (length 5):
  //   [0] humanMerkleRoot [1] nullifierHash [2] nonceBinding
  //   [3] scope           [4] sessionNonce
  const makeHumanProof = (sessionNonce: string) => ({
    proof: {},
    publicSignals: ['10', '11', '12', '13', sessionNonce],
  });
  // AgentPolicy publicSignals layout (length 6):
  //   [0] agentMerkleRoot [1] nullifierHash [2] scopeCommitment
  //   [3] requiredScopeMask [4] currentTimestamp [5] sessionNonce
  const makeAgentProof = (sessionNonce: string) => ({
    proof: {},
    publicSignals: ['20', '21', '22', '23', '24', sessionNonce],
  });

  it('rejects proofs with too few public signals', async () => {
    const shortProof = { proof: {}, publicSignals: ['0', '1', '2'] };
    await expect(
      verifyHandshake(shortProof, shortProof, 1n, {
        circuitDir: '/nonexistent/path',
      }),
    ).rejects.toThrow(/public signals/);
  });

  it('returns verified=false when human sessionNonce does not match arg', async () => {
    const nonce = 1234n;
    const result = await verifyHandshake(
      makeHumanProof('9999'), // committed nonce != 1234
      makeAgentProof(nonce.toString()),
      nonce,
      { circuitDir: '/nonexistent/path' },
    );
    expect(result.verified).toBe(false);
    expect(result.sessionNonce).toBe(nonce);
  });

  it('returns verified=false when agent sessionNonce does not match arg', async () => {
    const nonce = 1234n;
    const result = await verifyHandshake(
      makeHumanProof(nonce.toString()),
      makeAgentProof('9999'), // committed nonce != 1234
      nonce,
      { circuitDir: '/nonexistent/path' },
    );
    expect(result.verified).toBe(false);
  });

  it('returns verified=false on malformed public signals (fail-closed)', async () => {
    const nonce = 1234n;
    const garbage = {
      proof: {},
      publicSignals: ['not-a-number', 'also-bad', 'still-bad', 'x', 'y', 'z'],
    };
    const result = await verifyHandshake(garbage, garbage, nonce, {
      circuitDir: '/nonexistent/path',
    });
    expect(result.verified).toBe(false);
    expect(result.sessionNonce).toBe(nonce);
    expect(result.humanNullifier).toBe(0n);
    expect(result.agentNullifier).toBe(0n);
    expect(result.scopeCommitment).toBe(0n);
  });

  it('throws when both nonces match but vkey files are absent', async () => {
    const nonce = 1234n;
    await expect(
      verifyHandshake(
        makeHumanProof(nonce.toString()),
        makeAgentProof(nonce.toString()),
        nonce,
        { circuitDir: '/nonexistent/path' },
      ),
    ).rejects.toThrow(/vkey/i);
  });
});
