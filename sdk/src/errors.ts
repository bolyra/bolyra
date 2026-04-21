export class BolyraError extends Error {
  constructor(
    message: string,
    public code: string,
    public details?: Record<string, unknown>
  ) {
    super(message);
    this.name = 'BolyraError';
  }
}

export class ProofGenerationError extends BolyraError {
  constructor(circuit: string, reason: string) {
    super(
      `Failed to generate ${circuit} proof: ${reason}`,
      'PROOF_GENERATION_FAILED',
      { circuit, reason }
    );
  }
}

export class VerificationError extends BolyraError {
  constructor(reason: string) {
    super(
      `On-chain verification failed: ${reason}`,
      'VERIFICATION_FAILED',
      { reason }
    );
  }
}

export class InvalidPermissionError extends BolyraError {
  constructor(message: string) {
    super(message, 'INVALID_PERMISSION');
  }
}

export class ExpiredCredentialError extends BolyraError {
  constructor(expiryTimestamp: bigint) {
    super(
      `Agent credential expired at ${expiryTimestamp}`,
      'CREDENTIAL_EXPIRED',
      { expiryTimestamp: expiryTimestamp.toString() }
    );
  }
}

export class ScopeEscalationError extends BolyraError {
  constructor(delegatorScope: bigint, requestedScope: bigint) {
    super(
      `Delegation scope escalation: delegatee scope (${requestedScope}) is not a subset of delegator scope (${delegatorScope})`,
      'SCOPE_ESCALATION',
      {
        delegatorScope: delegatorScope.toString(),
        requestedScope: requestedScope.toString(),
      }
    );
  }
}

export class StaleProofError extends BolyraError {
  constructor(rootType: 'human' | 'agent') {
    super(
      `${rootType} Merkle root is stale — the tree was updated after proof generation. Regenerate the proof.`,
      'STALE_MERKLE_ROOT',
      { rootType }
    );
  }
}

export class InvalidSecretError extends BolyraError {
  constructor(reason: string) {
    super(
      `Invalid secret: ${reason}. Provide a non-zero bigint less than the BN254 scalar field order (approx 2^254).`,
      'INVALID_SECRET',
      { reason }
    );
  }
}

export class CircuitArtifactNotFoundError extends ProofGenerationError {
  constructor(artifactPath: string, artifactType: 'wasm' | 'zkey' | 'vkey') {
    super(
      artifactType === 'vkey' ? 'verification' : 'proof generation',
      `Circuit artifact not found: ${artifactPath}. ` +
        `Ensure the ${artifactType} file exists at this path. ` +
        `If using a custom circuitDir, verify it contains the compiled circuit outputs. ` +
        `Run the circuit build script or download trusted artifacts from the Bolyra release.`
    );
    this.code = 'CIRCUIT_ARTIFACT_NOT_FOUND';
    this.details = { ...this.details, artifactPath, artifactType };
  }
}

export class MerkleTreeError extends BolyraError {
  constructor(reason: string, details?: Record<string, unknown>) {
    super(
      `Merkle tree operation failed: ${reason}. ` +
        `Check that the tree is properly initialized and the leaf index is within bounds.`,
      'MERKLE_TREE_ERROR',
      { reason, ...details }
    );
  }
}

export class ConfigurationError extends BolyraError {
  constructor(field: string, reason: string) {
    super(
      `Invalid SDK configuration for "${field}": ${reason}. ` +
        `Review the BolyraConfig interface and ensure all required fields are set correctly.`,
      'CONFIGURATION_ERROR',
      { field, reason }
    );
  }
}
