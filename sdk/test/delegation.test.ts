import {
  createAgentCredential,
  delegate,
  Permission,
  verifyDelegation,
} from '../src';
import {
  BolyraError,
  ScopeEscalationError,
  VerificationError,
} from '../src/errors';
import { poseidon3 } from '../src/utils';

const FUTURE_EXPIRY = BigInt(Math.floor(Date.now() / 1000) + 86400);

describe('delegate — input validation (no proving)', () => {
  it('rejects scope escalation before paying for proof generation', async () => {
    const operatorKey = 42n;
    const delegator = await createAgentCredential(
      111n,
      operatorKey,
      [Permission.READ_DATA],
      FUTURE_EXPIRY,
    );

    await expect(
      delegate({
        delegator,
        delegatorOperatorPrivateKey: operatorKey,
        delegateeCommitment: 999n,
        // delegator only has READ_DATA (bit 0); ask for READ + WRITE (bits 0+1).
        delegateeScope: 0b11n,
        delegateeExpiry: FUTURE_EXPIRY - 100n,
        previousScopeCommitment: 0n,
        sessionNonce: 1n,
      }),
    ).rejects.toBeInstanceOf(ScopeEscalationError);
  });

  it('rejects expiry escalation', async () => {
    const operatorKey = 42n;
    const delegator = await createAgentCredential(
      111n,
      operatorKey,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      FUTURE_EXPIRY,
    );

    await expect(
      delegate({
        delegator,
        delegatorOperatorPrivateKey: operatorKey,
        delegateeCommitment: 999n,
        delegateeScope: 1n,
        delegateeExpiry: FUTURE_EXPIRY + 1000n, // beyond delegator
        previousScopeCommitment: 0n,
        sessionNonce: 1n,
      }),
    ).rejects.toMatchObject({ code: 'EXPIRY_ESCALATION' });
  });

  it('rejects a previousScopeCommitment that does not match the delegator chain link', async () => {
    const operatorKey = 42n;
    const delegator = await createAgentCredential(
      111n,
      operatorKey,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      FUTURE_EXPIRY,
    );

    await expect(
      delegate({
        delegator,
        delegatorOperatorPrivateKey: operatorKey,
        delegateeCommitment: 999n,
        delegateeScope: 1n,
        delegateeExpiry: FUTURE_EXPIRY - 100n,
        previousScopeCommitment: 12345n, // arbitrary, will not match
        sessionNonce: 1n,
      }),
    ).rejects.toMatchObject({ code: 'CHAIN_LINK_MISMATCH' });
  });
});

describe('verifyDelegation — structural validation', () => {
  it('rejects malformed proof input', async () => {
    // @ts-expect-error — deliberately invalid
    await expect(verifyDelegation(null, 0n, 0n, 0n)).rejects.toBeInstanceOf(
      VerificationError,
    );
  });

  it('rejects a proof whose publicSignals do not match the expected previousScopeCommitment', async () => {
    const bogus = {
      proof: {},
      publicSignals: ['0', '0', '0', '999', '1', '0'],
    };
    await expect(
      verifyDelegation(bogus as any, 12345n, 1n, 0n),
    ).rejects.toBeInstanceOf(VerificationError);
  });

  it('rejects a proof whose sessionNonce does not match', async () => {
    const bogus = {
      proof: {},
      publicSignals: ['0', '0', '0', '999', '7', '0'],
    };
    await expect(
      verifyDelegation(bogus as any, 999n, 1n, 0n),
    ).rejects.toBeInstanceOf(VerificationError);
  });
});

// Real-proof integration. Skipped in CI (requires circuit artifacts on disk).
const describeIntegration = process.env.CI ? describe.skip : describe;

describeIntegration('Delegation E2E (requires circuit artifacts)', () => {
  it(
    'generates a valid single-hop delegation proof and verifies it off-chain',
    async () => {
      const operatorKey = 42n;
      const delegator = await createAgentCredential(
        111n,
        operatorKey,
        [
          Permission.READ_DATA,
          Permission.WRITE_DATA,
          Permission.FINANCIAL_SMALL,
        ],
        FUTURE_EXPIRY,
      );

      // Chain seed = Poseidon3(delegatorScope, delegatorCredCommitment, delegatorExpiry).
      // In production this comes from the handshake's scopeCommitment output.
      const previousScopeCommitment = await poseidon3(
        delegator.permissionBitmask,
        delegator.commitment,
        delegator.expiryTimestamp,
      );

      const sessionNonce = 42n;
      const currentTimestamp = BigInt(Math.floor(Date.now() / 1000));
      const delegateeCommitment = 12345n;
      const delegateeScope = 0b011n; // READ + WRITE — narrower than delegator
      const delegateeExpiry = FUTURE_EXPIRY - 3600n;

      const { proof, result } = await delegate({
        delegator,
        delegatorOperatorPrivateKey: operatorKey,
        delegateeCommitment,
        delegateeScope,
        delegateeExpiry,
        previousScopeCommitment,
        sessionNonce,
        currentTimestamp,
      });

      expect(proof.proof).toBeDefined();
      expect(proof.publicSignals).toHaveLength(6);
      expect(result.newScopeCommitment).toBeGreaterThan(0n);
      expect(result.delegationNullifier).toBeGreaterThan(0n);
      expect(result.delegateeMerkleRoot).toBeGreaterThan(0n);

      // Off-chain verify — confirms the proof is mathematically valid.
      const verified = await verifyDelegation(
        proof,
        previousScopeCommitment,
        sessionNonce,
        currentTimestamp,
      );
      expect(verified.newScopeCommitment).toBe(result.newScopeCommitment);
      expect(verified.delegationNullifier).toBe(result.delegationNullifier);
    },
    120000,
  );

  it(
    'produces different nullifiers for different session nonces',
    async () => {
      const operatorKey = 99n;
      const delegator = await createAgentCredential(
        222n,
        operatorKey,
        [Permission.READ_DATA, Permission.WRITE_DATA],
        FUTURE_EXPIRY,
      );

      const previousScopeCommitment = await poseidon3(
        delegator.permissionBitmask,
        delegator.commitment,
        delegator.expiryTimestamp,
      );

      const baseInput = {
        delegator,
        delegatorOperatorPrivateKey: operatorKey,
        delegateeCommitment: 5555n,
        delegateeScope: 1n,
        delegateeExpiry: FUTURE_EXPIRY - 100n,
        previousScopeCommitment,
        currentTimestamp: BigInt(Math.floor(Date.now() / 1000)),
      };

      const [{ result: r1 }, { result: r2 }] = await Promise.all([
        delegate({ ...baseInput, sessionNonce: 1n }),
        delegate({ ...baseInput, sessionNonce: 2n }),
      ]);

      expect(r1.delegationNullifier).not.toBe(r2.delegationNullifier);
      // newScopeCommitment is identity-bound and not nonce-bound, so it should match.
      expect(r1.newScopeCommitment).toBe(r2.newScopeCommitment);
    },
    120000,
  );
});
