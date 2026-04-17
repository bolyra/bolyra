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
