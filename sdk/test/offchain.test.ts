import {
  OffchainVerificationBatch,
  computeSessionCommitment,
  verifyMerkleInclusion,
} from '../src/offchain';
import { HandshakeResult } from '../src/types';
import { VerificationError } from '../src/errors';

// Helper to build a mock verified HandshakeResult with unique values
function mockResult(index: number): HandshakeResult {
  return {
    humanNullifier: BigInt(1000 + index),
    agentNullifier: BigInt(2000 + index),
    sessionNonce: BigInt(3000 + index),
    scopeCommitment: BigInt(4000 + index),
    verified: true,
  };
}

function mockUnverifiedResult(): HandshakeResult {
  return {
    humanNullifier: 999n,
    agentNullifier: 888n,
    sessionNonce: 777n,
    scopeCommitment: 666n,
    verified: false,
  };
}

describe('OffchainVerificationBatch', () => {
  describe('add()', () => {
    it('accumulates sessions and tracks size', async () => {
      const batch = new OffchainVerificationBatch();
      expect(batch.size).toBe(0);

      const r1 = await batch.add(mockResult(0));
      expect(batch.size).toBe(1);
      expect(r1.batchIndex).toBe(0);

      const r2 = await batch.add(mockResult(1));
      expect(batch.size).toBe(2);
      expect(r2.batchIndex).toBe(1);

      const r3 = await batch.add(mockResult(2));
      expect(batch.size).toBe(3);
      expect(r3.batchIndex).toBe(2);
    });

    it('rejects unverified handshake results', async () => {
      const batch = new OffchainVerificationBatch();
      await expect(batch.add(mockUnverifiedResult())).rejects.toThrow(VerificationError);
    });

    it('preserves original HandshakeResult fields', async () => {
      const batch = new OffchainVerificationBatch();
      const original = mockResult(42);
      const result = await batch.add(original);

      expect(result.humanNullifier).toBe(original.humanNullifier);
      expect(result.agentNullifier).toBe(original.agentNullifier);
      expect(result.sessionNonce).toBe(original.sessionNonce);
      expect(result.scopeCommitment).toBe(original.scopeCommitment);
      expect(result.verified).toBe(true);
    });
  });

  describe('getMerkleRoot()', () => {
    it('returns 0n for empty batch', async () => {
      const batch = new OffchainVerificationBatch();
      expect(await batch.getMerkleRoot()).toBe(0n);
    });

    it('returns deterministic root for same sessions', async () => {
      const batch1 = new OffchainVerificationBatch();
      const batch2 = new OffchainVerificationBatch();

      await batch1.add(mockResult(0));
      await batch1.add(mockResult(1));
      await batch2.add(mockResult(0));
      await batch2.add(mockResult(1));

      const root1 = await batch1.getMerkleRoot();
      const root2 = await batch2.getMerkleRoot();

      expect(root1).toBe(root2);
      expect(typeof root1).toBe('bigint');
      expect(root1).not.toBe(0n);
    });

    it('produces different roots for different sessions', async () => {
      const batch1 = new OffchainVerificationBatch();
      const batch2 = new OffchainVerificationBatch();

      await batch1.add(mockResult(0));
      await batch2.add(mockResult(1));

      const root1 = await batch1.getMerkleRoot();
      const root2 = await batch2.getMerkleRoot();

      expect(root1).not.toBe(root2);
    });

    it('caches root and invalidates on add', async () => {
      const batch = new OffchainVerificationBatch();
      await batch.add(mockResult(0));

      const root1 = await batch.getMerkleRoot();
      // Calling again should return cached value (same result)
      const root1b = await batch.getMerkleRoot();
      expect(root1).toBe(root1b);

      // Adding a session should change the root
      await batch.add(mockResult(1));
      const root2 = await batch.getMerkleRoot();
      expect(root2).not.toBe(root1);
    });
  });

  describe('getProofOfInclusion()', () => {
    it('generates valid inclusion proof for each session', async () => {
      const batch = new OffchainVerificationBatch();
      await batch.add(mockResult(0));
      await batch.add(mockResult(1));
      await batch.add(mockResult(2));

      const root = await batch.getMerkleRoot();

      // Verify inclusion for each session
      for (let i = 0; i < 3; i++) {
        const proof = await batch.getProofOfInclusion(i);
        const commitment = batch.getCommitment(i);

        expect(proof.siblings.length).toBe(proof.pathIndices.length);
        expect(proof.siblings.length).toBeGreaterThan(0);

        // Verify the proof against the root
        const valid = await verifyMerkleInclusion(
          commitment,
          proof.siblings,
          proof.pathIndices,
          root,
        );
        expect(valid).toBe(true);
      }
    });

    it('throws for out-of-bounds index', async () => {
      const batch = new OffchainVerificationBatch();
      await batch.add(mockResult(0));

      await expect(batch.getProofOfInclusion(-1)).rejects.toThrow(VerificationError);
      await expect(batch.getProofOfInclusion(1)).rejects.toThrow(VerificationError);
      await expect(batch.getProofOfInclusion(100)).rejects.toThrow(VerificationError);
    });

    it('proof is invalid against wrong root', async () => {
      const batch = new OffchainVerificationBatch();
      await batch.add(mockResult(0));

      const proof = await batch.getProofOfInclusion(0);
      const commitment = batch.getCommitment(0);

      const valid = await verifyMerkleInclusion(
        commitment,
        proof.siblings,
        proof.pathIndices,
        12345n, // wrong root
      );
      expect(valid).toBe(false);
    });

    it('proof is invalid for wrong commitment', async () => {
      const batch = new OffchainVerificationBatch();
      await batch.add(mockResult(0));
      await batch.add(mockResult(1));

      const root = await batch.getMerkleRoot();
      const proof = await batch.getProofOfInclusion(0);

      // Use commitment from session 1 with proof for session 0
      const wrongCommitment = batch.getCommitment(1);
      const valid = await verifyMerkleInclusion(
        wrongCommitment,
        proof.siblings,
        proof.pathIndices,
        root,
      );
      expect(valid).toBe(false);
    });
  });
});

describe('computeSessionCommitment()', () => {
  it('produces deterministic output for same input', async () => {
    const result = mockResult(0);
    const c1 = await computeSessionCommitment(result);
    const c2 = await computeSessionCommitment(result);
    expect(c1).toBe(c2);
  });

  it('produces different output for different inputs', async () => {
    const c1 = await computeSessionCommitment(mockResult(0));
    const c2 = await computeSessionCommitment(mockResult(1));
    expect(c1).not.toBe(c2);
  });

  it('returns a bigint', async () => {
    const c = await computeSessionCommitment(mockResult(0));
    expect(typeof c).toBe('bigint');
  });
});

describe('verifyMerkleInclusion()', () => {
  it('returns false for mismatched siblings/pathIndices lengths', async () => {
    const valid = await verifyMerkleInclusion(
      1n,
      [2n, 3n],
      [0],
      99n,
    );
    expect(valid).toBe(false);
  });
});
