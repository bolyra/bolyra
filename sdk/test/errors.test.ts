import {
  BolyraError,
  ProofGenerationError,
  VerificationError,
  InvalidPermissionError,
  ExpiredCredentialError,
  ScopeEscalationError,
  StaleProofError,
} from '../src/errors';

describe('BolyraError', () => {
  it('has correct name, code, and message', () => {
    const err = new BolyraError('test message', 'TEST_CODE', { key: 'val' });
    expect(err.name).toBe('BolyraError');
    expect(err.message).toBe('test message');
    expect(err.code).toBe('TEST_CODE');
    expect(err.details).toEqual({ key: 'val' });
    expect(err instanceof Error).toBe(true);
  });
});

describe('ProofGenerationError', () => {
  it('formats message with circuit and reason', () => {
    const err = new ProofGenerationError('MutualHandshake', 'invalid witness');
    expect(err.code).toBe('PROOF_GENERATION_FAILED');
    expect(err.message).toContain('MutualHandshake');
    expect(err.message).toContain('invalid witness');
    expect(err.details).toEqual({
      circuit: 'MutualHandshake',
      reason: 'invalid witness',
    });
  });
});

describe('VerificationError', () => {
  it('includes reason in message', () => {
    const err = new VerificationError('root mismatch');
    expect(err.code).toBe('VERIFICATION_FAILED');
    expect(err.message).toContain('root mismatch');
  });
});

describe('InvalidPermissionError', () => {
  it('has INVALID_PERMISSION code', () => {
    const err = new InvalidPermissionError('bad bitmask');
    expect(err.code).toBe('INVALID_PERMISSION');
    expect(err.message).toBe('bad bitmask');
  });
});

describe('ExpiredCredentialError', () => {
  it('includes timestamp in message and details', () => {
    const err = new ExpiredCredentialError(1700000000n);
    expect(err.code).toBe('CREDENTIAL_EXPIRED');
    expect(err.message).toContain('1700000000');
    expect(err.details).toEqual({ expiryTimestamp: '1700000000' });
  });
});

describe('ScopeEscalationError', () => {
  it('includes both scopes', () => {
    const err = new ScopeEscalationError(100n, 999n);
    expect(err.code).toBe('SCOPE_ESCALATION');
    expect(err.message).toContain('100');
    expect(err.message).toContain('999');
    expect(err.details).toEqual({
      delegatorScope: '100',
      requestedScope: '999',
    });
  });
});

describe('StaleProofError', () => {
  it('includes rootType in message', () => {
    const humanErr = new StaleProofError('human');
    expect(humanErr.code).toBe('STALE_MERKLE_ROOT');
    expect(humanErr.message).toContain('human');
    expect(humanErr.details).toEqual({ rootType: 'human' });

    const agentErr = new StaleProofError('agent');
    expect(agentErr.message).toContain('agent');
  });
});
