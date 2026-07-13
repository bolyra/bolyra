/**
 * Receipt Signer Discovery v1 — canonical parser/validator.
 * Spec: spec/receipt-signer-discovery-v1.md. Discovery is not endorsement:
 * this module validates document SHAPE; deciding to trust the origin that
 * served it stays with the consumer.
 */

const SIGNER_RE = /^0x[0-9a-fA-F]{40}$/;

export class SignerDiscoveryError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'SignerDiscoveryError';
  }
}

export interface DiscoveredSigner {
  keyId: string;
  alg: 'ES256K';
  signer: string;
  label?: string;
}

export interface SignerDiscoveryDocument {
  v: 1;
  issuer: string;
  updatedAt: number;
  signers: DiscoveredSigner[];
}

function bad(field: string, why: string): never {
  throw new SignerDiscoveryError(`signer discovery document invalid: ${field} ${why}`);
}

/**
 * Validate an untrusted JSON value as a v1 signer discovery document.
 * Throws SignerDiscoveryError on any spec violation (consumers MUST treat
 * that as verification failure — fail closed). Unknown fields are ignored.
 */
export function parseSignerDiscovery(input: unknown): SignerDiscoveryDocument {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    bad('document', 'must be a JSON object');
  }
  const doc = input as Record<string, unknown>;

  if (doc.v !== 1) bad('v', 'must be the number 1');
  if (typeof doc.issuer !== 'string' || doc.issuer.length === 0) {
    bad('issuer', 'must be a non-empty string');
  }
  if (typeof doc.updatedAt !== 'number' || !Number.isFinite(doc.updatedAt)) {
    bad('updatedAt', 'must be a number (unix seconds)');
  }
  if (!Array.isArray(doc.signers) || doc.signers.length === 0) {
    bad('signers', 'must be a non-empty array');
  }

  const byKeyId = new Map<string, string>();
  const signers: DiscoveredSigner[] = doc.signers.map((raw, i) => {
    if (typeof raw !== 'object' || raw === null || Array.isArray(raw)) {
      bad(`signers[${i}]`, 'must be an object');
    }
    const e = raw as Record<string, unknown>;
    if (typeof e.keyId !== 'string' || e.keyId.length === 0) {
      bad(`signers[${i}].keyId`, 'must be a non-empty string');
    }
    if (e.alg !== 'ES256K') {
      bad(`signers[${i}].alg`, 'must be "ES256K" in v1 (closed set)');
    }
    if (typeof e.signer !== 'string' || !SIGNER_RE.test(e.signer)) {
      bad(`signers[${i}].signer`, 'must match ^0x[0-9a-fA-F]{40}$');
    }
    if (e.label !== undefined && typeof e.label !== 'string') {
      bad(`signers[${i}].label`, 'must be a string when present');
    }
    const keyId = e.keyId as string;
    const signer = (e.signer as string).toLowerCase();
    const seen = byKeyId.get(keyId);
    if (seen !== undefined && seen !== signer) {
      bad(`signers[${i}].keyId`, `"${keyId}" appears twice with conflicting signer values`);
    }
    byKeyId.set(keyId, signer);
    return {
      keyId,
      alg: 'ES256K' as const,
      signer: e.signer as string,
      ...(e.label !== undefined ? { label: e.label as string } : {}),
    };
  });

  return { v: 1, issuer: doc.issuer as string, updatedAt: doc.updatedAt as number, signers };
}

/** Lowercased accepted signer addresses from a validated document. */
export function acceptedSigners(doc: SignerDiscoveryDocument): Set<string> {
  return new Set(doc.signers.map((s) => s.signer.toLowerCase()));
}
