import { Permission } from '../src/types';
import type {
  HumanIdentity,
  AgentCredential,
  HandshakeResult,
  DelegationResult,
  Proof,
  BolyraConfig,
} from '../src/types';

describe('Permission enum', () => {
  it('has exactly 8 values', () => {
    const values = Object.values(Permission).filter(
      (v) => typeof v === 'number',
    );
    expect(values).toHaveLength(8);
  });

  it('has correct numeric values for all members', () => {
    expect(Permission.READ_DATA).toBe(0);
    expect(Permission.WRITE_DATA).toBe(1);
    expect(Permission.FINANCIAL_SMALL).toBe(2);
    expect(Permission.FINANCIAL_MEDIUM).toBe(3);
    expect(Permission.FINANCIAL_UNLIMITED).toBe(4);
    expect(Permission.SIGN_ON_BEHALF).toBe(5);
    expect(Permission.SUB_DELEGATE).toBe(6);
    expect(Permission.ACCESS_PII).toBe(7);
  });

  it('reverse mapping works (numeric enum)', () => {
    expect(Permission[0]).toBe('READ_DATA');
    expect(Permission[7]).toBe('ACCESS_PII');
  });

  it('bit values are sequential from 0 to 7', () => {
    const values = Object.values(Permission).filter(
      (v) => typeof v === 'number',
    ) as number[];
    const sorted = [...values].sort((a, b) => a - b);
    expect(sorted).toEqual([0, 1, 2, 3, 4, 5, 6, 7]);
  });
});

describe('Type shape contracts (compile-time + runtime guards)', () => {
  it('HumanIdentity matches expected shape', () => {
    const identity: HumanIdentity = {
      secret: 42n,
      publicKey: { x: 1n, y: 2n },
      commitment: 3n,
    };
    expect(identity.secret).toBe(42n);
    expect(identity.publicKey.x).toBe(1n);
    expect(identity.publicKey.y).toBe(2n);
    expect(identity.commitment).toBe(3n);
  });

  it('AgentCredential matches expected shape', () => {
    const cred: AgentCredential = {
      modelHash: 1n,
      operatorPublicKey: { x: 2n, y: 3n },
      permissionBitmask: 7n,
      expiryTimestamp: 1700000000n,
      signature: { R8: { x: 4n, y: 5n }, S: 6n },
      commitment: 7n,
    };
    expect(cred.modelHash).toBe(1n);
    expect(cred.operatorPublicKey).toEqual({ x: 2n, y: 3n });
    expect(cred.permissionBitmask).toBe(7n);
    expect(cred.expiryTimestamp).toBe(1700000000n);
    expect(cred.signature.R8).toEqual({ x: 4n, y: 5n });
    expect(cred.signature.S).toBe(6n);
    expect(cred.commitment).toBe(7n);
  });

  it('HandshakeResult matches expected shape', () => {
    const result: HandshakeResult = {
      humanNullifier: 1n,
      agentNullifier: 2n,
      sessionNonce: 3n,
      scopeCommitment: 4n,
      verified: true,
    };
    expect(result.humanNullifier).toBe(1n);
    expect(result.agentNullifier).toBe(2n);
    expect(result.sessionNonce).toBe(3n);
    expect(result.scopeCommitment).toBe(4n);
    expect(result.verified).toBe(true);
  });

  it('DelegationResult matches expected shape', () => {
    const result: DelegationResult = {
      newScopeCommitment: 1n,
      delegationNullifier: 2n,
      hopIndex: 0,
    };
    expect(result.newScopeCommitment).toBe(1n);
    expect(result.delegationNullifier).toBe(2n);
    expect(result.hopIndex).toBe(0);
  });

  it('Proof matches expected shape', () => {
    const proof: Proof = {
      proof: { pi_a: [], pi_b: [], pi_c: [] },
      publicSignals: ['1', '2', '3'],
    };
    expect(proof.publicSignals).toHaveLength(3);
    expect(proof.proof).toBeDefined();
  });

  it('BolyraConfig all fields are optional', () => {
    const emptyConfig: BolyraConfig = {};
    expect(emptyConfig.rpcUrl).toBeUndefined();
    expect(emptyConfig.registryAddress).toBeUndefined();
    expect(emptyConfig.circuitDir).toBeUndefined();
    expect(emptyConfig.zkeyDir).toBeUndefined();
  });

  it('BolyraConfig accepts all fields', () => {
    const config: BolyraConfig = {
      rpcUrl: 'https://sepolia.base.org',
      registryAddress: '0x1234567890abcdef1234567890abcdef12345678',
      circuitDir: '/circuits',
      zkeyDir: '/zkeys',
    };
    expect(config.rpcUrl).toBe('https://sepolia.base.org');
    expect(config.registryAddress).toContain('0x');
    expect(config.circuitDir).toBe('/circuits');
    expect(config.zkeyDir).toBe('/zkeys');
  });
});
