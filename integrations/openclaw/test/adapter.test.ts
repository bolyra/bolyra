import {
  computeTrustScore,
  scoreToGrade,
  buildDid,
  createBolyraPlugin,
} from '../src/adapter';
import type { HandshakeResult, AgentCredential } from '@bolyra/sdk';

// Mock handshake result
function makeHandshake(overrides: Partial<HandshakeResult> = {}): HandshakeResult {
  return {
    humanNullifier: 123n,
    agentNullifier: 456n,
    sessionNonce: BigInt(Math.floor(Date.now())),
    scopeCommitment: 999n,
    verified: true,
    ...overrides,
  };
}

// Mock agent credential
function makeCredential(overrides: Partial<AgentCredential> = {}): AgentCredential {
  return {
    modelHash: 12345n,
    operatorPublicKey: { x: 1n, y: 2n },
    permissionBitmask: 0b00000111n, // READ + WRITE + FINANCIAL_SMALL
    expiryTimestamp: BigInt(Math.floor(Date.now() / 1000) + 86400), // +1 day
    signature: { R8: { x: 3n, y: 4n }, S: 5n },
    commitment: 67890n,
    ...overrides,
  };
}

describe('computeTrustScore', () => {
  it('returns 100 for a fully valid handshake', () => {
    const handshake = makeHandshake();
    const credential = makeCredential();
    const { score, warnings } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(100);
    expect(warnings).toHaveLength(0);
  });

  it('returns 0 and warnings when everything fails', () => {
    const handshake = makeHandshake({
      verified: false,
      scopeCommitment: 0n,
      sessionNonce: 0n, // ancient nonce
    });
    const credential = makeCredential({
      expiryTimestamp: 0n,
      permissionBitmask: 0n,
    });
    const { score, warnings } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(0);
    expect(warnings.length).toBeGreaterThanOrEqual(4);
  });

  it('deducts 40 pts for invalid proofs', () => {
    const handshake = makeHandshake({ verified: false });
    const credential = makeCredential();
    const { score } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(60);
  });

  it('deducts 20 pts for expired credential', () => {
    const handshake = makeHandshake();
    const credential = makeCredential({ expiryTimestamp: 0n });
    const { score, warnings } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(80);
    expect(warnings.some(w => w.includes('expired'))).toBe(true);
  });

  it('deducts 20 pts for no permissions', () => {
    const handshake = makeHandshake();
    const credential = makeCredential({ permissionBitmask: 0n });
    const { score, warnings } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(80);
    expect(warnings.some(w => w.includes('permission'))).toBe(true);
  });

  it('deducts 10 pts for zero scope commitment', () => {
    const handshake = makeHandshake({ scopeCommitment: 0n });
    const credential = makeCredential();
    const { score } = computeTrustScore(handshake, credential, 300);
    expect(score).toBe(90);
  });
});

describe('scoreToGrade', () => {
  it('maps score ranges to correct grades', () => {
    expect(scoreToGrade(100)).toBe('A');
    expect(scoreToGrade(90)).toBe('A');
    expect(scoreToGrade(89)).toBe('B');
    expect(scoreToGrade(70)).toBe('B');
    expect(scoreToGrade(69)).toBe('C');
    expect(scoreToGrade(50)).toBe('C');
    expect(scoreToGrade(49)).toBe('D');
    expect(scoreToGrade(30)).toBe('D');
    expect(scoreToGrade(29)).toBe('F');
    expect(scoreToGrade(0)).toBe('F');
  });
});

describe('buildDid', () => {
  it('constructs a valid did:bolyra DID', () => {
    const did = buildDid('base-sepolia', 255n);
    expect(did).toBe('did:bolyra:base-sepolia:00000000000000000000000000000000000000000000000000000000000000ff');
  });

  it('pads small commitments to 64 hex chars', () => {
    const did = buildDid('base', 1n);
    expect(did).toMatch(/^did:bolyra:base:0{63}1$/);
  });
});

describe('createBolyraPlugin', () => {
  it('returns an object with onAgentVerify', () => {
    const plugin = createBolyraPlugin(
      { secret: 1n, publicKey: { x: 1n, y: 2n }, commitment: 3n },
      async () => null,
    );
    expect(plugin.onAgentVerify).toBeDefined();
    expect(typeof plugin.onAgentVerify).toBe('function');
  });

  it('returns grade F when no credential is found', async () => {
    const plugin = createBolyraPlugin(
      { secret: 1n, publicKey: { x: 1n, y: 2n }, commitment: 3n },
      async () => null,
    );
    const result = await plugin.onAgentVerify!('unknown-agent');
    expect(result.verified).toBe(false);
    expect(result.grade).toBe('F');
    expect(result.score).toBe(0);
    expect(result.warnings).toContain('No Bolyra credential found for agent: unknown-agent');
  });
});
