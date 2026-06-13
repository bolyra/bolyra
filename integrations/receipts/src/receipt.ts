import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical';
import type { AuthReceiptInput, CommerceReceiptInput, ReceiptPayload } from './types';

function sha256Hex(data: string): string {
  const encoder = new TextEncoder();
  return bytesToHex(sha256(encoder.encode(data)));
}

export function createAuthReceipt(
  input: AuthReceiptInput,
  config: { issuer: string; keyId: string },
): ReceiptPayload {
  const humanProofHash = sha256Hex(canonicalize(input.humanProof.proof));
  const agentProofHash = sha256Hex(canonicalize(input.agentProof.proof));
  const publicSignalsHash = sha256Hex(
    canonicalize([...input.humanPublicSignals, ...input.agentPublicSignals]),
  );
  const delegationChainHash = input.delegationChain
    ? sha256Hex(canonicalize(input.delegationChain))
    : undefined;

  return {
    v: 1,
    kind: 'bolyra.auth',
    issuedAt: Math.floor(Date.now() / 1000),
    issuer: config.issuer,
    keyId: config.keyId,
    subject: {
      rootDid: input.rootDid,
      actingDid: input.actingDid,
      credentialCommitment: input.credentialCommitment,
      effectiveCommitment: input.effectiveCommitment,
    },
    decision: {
      allowed: input.allowed,
      ...(input.reasonCode !== undefined && { reasonCode: input.reasonCode }),
      score: input.score,
      permissionBitmask: input.permissionBitmask,
      chainDepth: input.chainDepth,
    },
    proof: {
      bundleVersion: input.bundleVersion,
      nonce: input.nonce,
      humanProofHash,
      agentProofHash,
      publicSignalsHash,
      ...(delegationChainHash !== undefined && { delegationChainHash }),
    },
  };
}

export function createCommerceReceipt(
  input: CommerceReceiptInput,
  config: { issuer: string; keyId: string },
): ReceiptPayload {
  const base = createAuthReceipt(input, config);
  return {
    ...base,
    kind: 'bolyra.commerce',
    commerce: input.commerce,
  };
}
