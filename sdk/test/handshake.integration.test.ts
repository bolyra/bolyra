import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  proveHandshake,
  verifyHandshake,
} from '../src';

// Skip in CI — requires circuit artifacts
const describeIntegration = process.env.CI ? describe.skip : describe;

describeIntegration('Handshake E2E (requires circuit artifacts)', () => {
  it(
    'should generate and verify a mutual handshake',
    async () => {
      // 1. Create identities
      const human = await createHumanIdentity(123456789n);
      const operatorKey = 42n;
      const agent = await createAgentCredential(
        12345n,
        operatorKey,
        [Permission.READ_DATA, Permission.WRITE_DATA],
        BigInt(Math.floor(Date.now() / 1000) + 86400),
      );

      // 2. Generate mutual handshake proofs (parallel)
      const { humanProof, agentProof, nonce } = await proveHandshake(
        human,
        agent,
      );

      // 3. Verify both proofs exist
      expect(humanProof.proof).toBeDefined();
      expect(humanProof.publicSignals).toBeDefined();
      expect(humanProof.publicSignals.length).toBeGreaterThan(0);

      expect(agentProof.proof).toBeDefined();
      expect(agentProof.publicSignals).toBeDefined();
      expect(agentProof.publicSignals.length).toBeGreaterThan(0);

      expect(nonce).toBeGreaterThan(0n);

      // 4. Verify locally
      const result = await verifyHandshake(humanProof, agentProof, nonce);

      expect(result.verified).toBe(true);
      expect(result.humanNullifier).toBeDefined();
      expect(result.agentNullifier).toBeDefined();
      expect(result.sessionNonce).toBe(nonce);
      expect(result.scopeCommitment).toBeDefined();
    },
    60000, // 60s timeout for proof generation
  );

  it(
    'should produce different nullifiers for different scopes',
    async () => {
      const human = await createHumanIdentity(987654321n);
      const agent = await createAgentCredential(
        54321n,
        99n,
        [Permission.READ_DATA],
        BigInt(Math.floor(Date.now() / 1000) + 86400),
      );

      const [result1, result2] = await Promise.all([
        proveHandshake(human, agent, { scope: 1n, nonce: 100n }),
        proveHandshake(human, agent, { scope: 2n, nonce: 200n }),
      ]);

      // Different scopes should produce different human nullifiers
      expect(result1.humanProof.publicSignals[1]).not.toBe(
        result2.humanProof.publicSignals[1],
      );
    },
    120000,
  );
});
