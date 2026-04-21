import {
  BolyraError,
  ProofGenerationError,
  VerificationError,
  InvalidPermissionError,
  ExpiredCredentialError,
  ScopeEscalationError,
  StaleProofError,
  InvalidSecretError,
  CircuitArtifactNotFoundError,
  MerkleTreeError,
  ConfigurationError,
} from '../src/errors';

describe('BolyraError — extended', () => {
  it('is an instance of Error', () => {
    const err = new BolyraError('msg', 'CODE');
    expect(err).toBeInstanceOf(Error);
  });

  it('details is undefined when not provided', () => {
    const err = new BolyraError('msg', 'CODE');
    expect(err.details).toBeUndefined();
  });

  it('preserves complex details object', () => {
    const details = { nested: { arr: [1, 2, 3] }, flag: true };
    const err = new BolyraError('msg', 'CODE', details);
    expect(err.details).toEqual(details);
  });

  it('has a proper stack trace', () => {
    const err = new BolyraError('msg', 'CODE');
    expect(err.stack).toBeDefined();
    expect(err.stack).toContain('BolyraError');
  });

  it('name is always BolyraError for the base class', () => {
    const err = new BolyraError('msg', 'ANY_CODE');
    expect(err.name).toBe('BolyraError');
  });
});

describe('ProofGenerationError — extended', () => {
  it('has code PROOF_GENERATION_FAILED', () => {
    const err = new ProofGenerationError('TestCircuit', 'witness mismatch');
    expect(err.code).toBe('PROOF_GENERATION_FAILED');
  });

  it('is instanceof BolyraError', () => {
    const err = new ProofGenerationError('X', 'Y');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('details includes circuit and reason', () => {
    const err = new ProofGenerationError('AgentAuth', 'missing input');
    expect(err.details).toEqual({ circuit: 'AgentAuth', reason: 'missing input' });
  });

  it('message format is "Failed to generate <circuit> proof: <reason>"', () => {
    const err = new ProofGenerationError('Delegation', 'timeout');
    expect(err.message).toBe('Failed to generate Delegation proof: timeout');
  });
});

describe('VerificationError — extended', () => {
  it('has code VERIFICATION_FAILED', () => {
    const err = new VerificationError('invalid proof');
    expect(err.code).toBe('VERIFICATION_FAILED');
  });

  it('is instanceof BolyraError', () => {
    const err = new VerificationError('reason');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('details includes reason', () => {
    const err = new VerificationError('pairing check failed');
    expect(err.details).toEqual({ reason: 'pairing check failed' });
  });

  it('message format is "On-chain verification failed: <reason>"', () => {
    const err = new VerificationError('nullifier reused');
    expect(err.message).toBe('On-chain verification failed: nullifier reused');
  });
});

describe('InvalidPermissionError — extended', () => {
  it('has code INVALID_PERMISSION', () => {
    const err = new InvalidPermissionError('details');
    expect(err.code).toBe('INVALID_PERMISSION');
  });

  it('is instanceof BolyraError', () => {
    const err = new InvalidPermissionError('x');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('details is undefined (no extra details passed)', () => {
    const err = new InvalidPermissionError('bit violation');
    expect(err.details).toBeUndefined();
  });

  it('message is preserved verbatim', () => {
    const msg = 'FINANCIAL_UNLIMITED (bit 4) requires FINANCIAL_MEDIUM (bit 3)';
    const err = new InvalidPermissionError(msg);
    expect(err.message).toBe(msg);
  });
});

describe('ExpiredCredentialError — extended', () => {
  it('has code CREDENTIAL_EXPIRED', () => {
    const err = new ExpiredCredentialError(0n);
    expect(err.code).toBe('CREDENTIAL_EXPIRED');
  });

  it('is instanceof BolyraError', () => {
    const err = new ExpiredCredentialError(123n);
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('serializes bigint expiry as string in details', () => {
    const ts = 1713600000n;
    const err = new ExpiredCredentialError(ts);
    expect(err.details!.expiryTimestamp).toBe('1713600000');
  });

  it('handles zero timestamp', () => {
    const err = new ExpiredCredentialError(0n);
    expect(err.message).toContain('0');
    expect(err.details).toEqual({ expiryTimestamp: '0' });
  });

  it('handles max uint64 timestamp', () => {
    const maxUint64 = 18446744073709551615n;
    const err = new ExpiredCredentialError(maxUint64);
    expect(err.details!.expiryTimestamp).toBe('18446744073709551615');
    expect(err.message).toContain('18446744073709551615');
  });
});

describe('ScopeEscalationError — extended', () => {
  it('has code SCOPE_ESCALATION', () => {
    const err = new ScopeEscalationError(1n, 2n);
    expect(err.code).toBe('SCOPE_ESCALATION');
  });

  it('is instanceof BolyraError', () => {
    const err = new ScopeEscalationError(1n, 2n);
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('serializes both scopes as strings', () => {
    const err = new ScopeEscalationError(255n, 511n);
    expect(err.details).toEqual({
      delegatorScope: '255',
      requestedScope: '511',
    });
  });

  it('message contains both scope values', () => {
    const err = new ScopeEscalationError(7n, 15n);
    expect(err.message).toContain('7');
    expect(err.message).toContain('15');
    expect(err.message).toContain('subset');
  });
});

describe('StaleProofError — extended', () => {
  it('has code STALE_MERKLE_ROOT', () => {
    const err = new StaleProofError('human');
    expect(err.code).toBe('STALE_MERKLE_ROOT');
  });

  it('is instanceof BolyraError', () => {
    const err = new StaleProofError('agent');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('human variant has correct details', () => {
    const err = new StaleProofError('human');
    expect(err.details).toEqual({ rootType: 'human' });
  });

  it('agent variant has correct details', () => {
    const err = new StaleProofError('agent');
    expect(err.details).toEqual({ rootType: 'agent' });
  });

  it('message mentions regeneration', () => {
    const err = new StaleProofError('human');
    expect(err.message).toContain('Regenerate');
  });

  it('message mentions the root type', () => {
    const err = new StaleProofError('agent');
    expect(err.message).toContain('agent');
    expect(err.message).toContain('Merkle root');
  });
});

describe('InvalidSecretError', () => {
  it('has code INVALID_SECRET', () => {
    const err = new InvalidSecretError('too small');
    expect(err.code).toBe('INVALID_SECRET');
  });

  it('is instanceof BolyraError', () => {
    const err = new InvalidSecretError('reason');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('message includes the reason and guidance', () => {
    const err = new InvalidSecretError('secret must be non-zero');
    expect(err.message).toContain('secret must be non-zero');
    expect(err.message).toContain('BN254');
  });

  it('details includes reason', () => {
    const err = new InvalidSecretError('negative value');
    expect(err.details).toEqual({ reason: 'negative value' });
  });
});

describe('CircuitArtifactNotFoundError', () => {
  it('has code CIRCUIT_ARTIFACT_NOT_FOUND', () => {
    const err = new CircuitArtifactNotFoundError('/path/to/file.wasm', 'wasm');
    expect(err.code).toBe('CIRCUIT_ARTIFACT_NOT_FOUND');
  });

  it('is instanceof ProofGenerationError and BolyraError', () => {
    const err = new CircuitArtifactNotFoundError('/path/file.zkey', 'zkey');
    expect(err).toBeInstanceOf(ProofGenerationError);
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('details includes artifactPath and artifactType', () => {
    const err = new CircuitArtifactNotFoundError('/circuits/test.wasm', 'wasm');
    expect(err.details).toMatchObject({
      artifactPath: '/circuits/test.wasm',
      artifactType: 'wasm',
    });
  });

  it('message mentions the missing path', () => {
    const err = new CircuitArtifactNotFoundError('/missing/path.zkey', 'zkey');
    expect(err.message).toContain('/missing/path.zkey');
  });

  it('handles vkey artifact type', () => {
    const err = new CircuitArtifactNotFoundError('/path/vkey.json', 'vkey');
    expect(err.code).toBe('CIRCUIT_ARTIFACT_NOT_FOUND');
    expect(err.details).toMatchObject({ artifactType: 'vkey' });
  });
});

describe('MerkleTreeError', () => {
  it('has code MERKLE_TREE_ERROR', () => {
    const err = new MerkleTreeError('leaf not found');
    expect(err.code).toBe('MERKLE_TREE_ERROR');
  });

  it('is instanceof BolyraError', () => {
    const err = new MerkleTreeError('overflow');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('message includes reason and guidance', () => {
    const err = new MerkleTreeError('index out of bounds');
    expect(err.message).toContain('index out of bounds');
    expect(err.message).toContain('Merkle tree');
  });

  it('details includes reason and extra details', () => {
    const err = new MerkleTreeError('full', { maxLeaves: 1024 });
    expect(err.details).toMatchObject({ reason: 'full', maxLeaves: 1024 });
  });
});

describe('ConfigurationError', () => {
  it('has code CONFIGURATION_ERROR', () => {
    const err = new ConfigurationError('rpcUrl', 'must be a valid URL');
    expect(err.code).toBe('CONFIGURATION_ERROR');
  });

  it('is instanceof BolyraError', () => {
    const err = new ConfigurationError('field', 'reason');
    expect(err).toBeInstanceOf(BolyraError);
  });

  it('message includes field name and reason', () => {
    const err = new ConfigurationError('registryAddress', 'invalid checksum');
    expect(err.message).toContain('registryAddress');
    expect(err.message).toContain('invalid checksum');
  });

  it('details includes field and reason', () => {
    const err = new ConfigurationError('circuitDir', 'path does not exist');
    expect(err.details).toEqual({ field: 'circuitDir', reason: 'path does not exist' });
  });
});

describe('Error hierarchy — all errors extend BolyraError', () => {
  const errors = [
    new ProofGenerationError('C', 'R'),
    new VerificationError('R'),
    new InvalidPermissionError('M'),
    new ExpiredCredentialError(1n),
    new ScopeEscalationError(1n, 2n),
    new StaleProofError('human'),
    new InvalidSecretError('reason'),
    new CircuitArtifactNotFoundError('/path', 'wasm'),
    new MerkleTreeError('reason'),
    new ConfigurationError('field', 'reason'),
  ];

  it.each(errors)('%# is instanceof BolyraError', (err) => {
    expect(err).toBeInstanceOf(BolyraError);
  });

  it.each(errors)('%# is instanceof Error', (err) => {
    expect(err).toBeInstanceOf(Error);
  });

  it.each(errors)('%# has a non-empty code', (err) => {
    expect(err.code).toBeTruthy();
    expect(typeof err.code).toBe('string');
  });
});
