/**
 * LangChain credential middleware — accepts and emits ProofEnvelope.
 *
 * Replaces the previous ad-hoc proof serialization with the canonical
 * application/bolyra+json envelope format.
 */

import type { BaseCallbackHandler } from '@langchain/core/callbacks';
import {
  BOLYRA_CONTENT_TYPE,
  ProofType,
  deserializeEnvelope,
  serializeEnvelope,
  validateEnvelope,
  EnvelopeValidationError,
} from '@bolyra/sdk';
import type { ProofEnvelope } from '@bolyra/sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface BolyraCredentialContext {
  /** The validated proof envelope. */
  envelope: ProofEnvelope;
  /** Whether the proof was verified on-chain. */
  verified: boolean;
}

export interface BolyraMiddlewareOptions {
  /**
   * Proof types this middleware accepts.
   * Defaults to all types.
   */
  acceptProofTypes?: ProofType[];
  /**
   * Custom verification function. Receives the validated envelope and
   * should return true if the proof passes on-chain verification.
   * If omitted, proofs are accepted without on-chain check.
   */
  verifyProof?: (envelope: ProofEnvelope) => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Middleware
// ---------------------------------------------------------------------------

/**
 * Extract a Bolyra proof envelope from a LangChain run's metadata.
 *
 * Usage:
 * ```ts
 * import { extractBolyraCredential } from '@bolyra/langchain';
 *
 * const cred = extractBolyraCredential(runMetadata);
 * if (cred) {
 *   console.log(cred.envelope.proofType); // 'handshake'
 * }
 * ```
 */
export function extractBolyraCredential(
  metadata: Record<string, unknown>,
): BolyraCredentialContext | null {
  const raw = metadata['bolyra_proof'];
  if (!raw) return null;

  if (typeof raw === 'string') {
    const envelope = deserializeEnvelope(raw);
    return { envelope, verified: false };
  }

  if (typeof raw === 'object') {
    const envelope = validateEnvelope(raw);
    return { envelope, verified: false };
  }

  return null;
}

/**
 * Inject a Bolyra proof envelope into LangChain run metadata.
 *
 * ```ts
 * const metadata = injectBolyraCredential({}, envelope);
 * // Pass metadata to chain.invoke({ ... }, { metadata })
 * ```
 */
export function injectBolyraCredential(
  metadata: Record<string, unknown>,
  envelope: ProofEnvelope,
): Record<string, unknown> {
  validateEnvelope(envelope);
  return {
    ...metadata,
    bolyra_proof: serializeEnvelope(envelope),
    bolyra_content_type: BOLYRA_CONTENT_TYPE,
  };
}

/**
 * LangChain callback handler that validates Bolyra proof envelopes
 * on chain start.
 */
export class BolyraCredentialHandler implements Partial<BaseCallbackHandler> {
  name = 'BolyraCredentialHandler';
  private options: BolyraMiddlewareOptions;

  constructor(options: BolyraMiddlewareOptions = {}) {
    this.options = options;
  }

  async handleChainStart(
    _chain: unknown,
    inputs: Record<string, unknown>,
    _runId: string,
    _parentRunId?: string,
    _tags?: string[],
    metadata?: Record<string, unknown>,
  ): Promise<void> {
    if (!metadata) return;

    const cred = extractBolyraCredential(metadata);
    if (!cred) return;

    // Check proof type filter
    const accepted = this.options.acceptProofTypes;
    if (accepted && !accepted.includes(cred.envelope.proofType)) {
      throw new EnvelopeValidationError(
        'PROOF_TYPE_REJECTED',
        `Proof type "${cred.envelope.proofType}" is not accepted by this middleware. ` +
          `Accepted: ${accepted.join(', ')}`,
      );
    }

    // Optional on-chain verification
    if (this.options.verifyProof) {
      const ok = await this.options.verifyProof(cred.envelope);
      if (!ok) {
        throw new EnvelopeValidationError(
          'PROOF_VERIFICATION_FAILED',
          'On-chain proof verification failed',
        );
      }
    }
  }
}
