/**
 * The action digest and the example-specific reason-text convention.
 *
 * `actionDigest` = SHA-256 over the JCS canonical form (RFC 8785, via
 * @bolyra/receipts' canonicalize) of the full action object: tenant, server,
 * tool, resource and arguments. Any change to any of them changes the digest.
 *
 * The digest rides in the receipt's free-text `decision.reasonCode` under ONE
 * unambiguous format. This is a convention of this example, not a field of the
 * receipt schema; a verifier that does not know the convention sees only text.
 */

import { createHash } from 'node:crypto';
import { canonicalize } from '@bolyra/receipts';

export interface Action {
  tenant: string;
  server: string;
  tool: string;
  resource: { type: string; id: string };
  arguments: Record<string, unknown>;
}

export function actionDigest(action: Action): string {
  return createHash('sha256').update(canonicalize(action), 'utf8').digest('hex');
}

export const REASON_PREFIX = 'approved';

/** `approved | action_digest=<64 hex> | tool=<server>.<tool>` */
export function formatReason(digest: string, action: Action): string {
  if (!/^[0-9a-f]{64}$/.test(digest)) throw new Error('digest must be 64 lowercase hex characters');
  return `${REASON_PREFIX} | action_digest=${digest} | tool=${action.server}.${action.tool}`;
}

export class ReasonFormatError extends Error {}

/** Strict parse: exactly one action_digest entry, exactly one tool entry, nothing else. */
export function parseReason(reason: unknown): { digest: string; tool: string } {
  if (typeof reason !== 'string') throw new ReasonFormatError('reasonCode is not a string');
  const parts = reason.split(' | ');
  if (parts[0] !== REASON_PREFIX) throw new ReasonFormatError(`reasonCode does not start with "${REASON_PREFIX}"`);
  let digest: string | undefined;
  let tool: string | undefined;
  for (const part of parts.slice(1)) {
    const m = /^([a-z_]+)=(.*)$/.exec(part);
    if (!m) throw new ReasonFormatError(`malformed entry "${part}"`);
    const [, key, value] = m;
    if (key === 'action_digest') {
      if (digest !== undefined) throw new ReasonFormatError('duplicate action_digest entry');
      if (!/^[0-9a-f]{64}$/.test(value)) throw new ReasonFormatError('action_digest is not 64 lowercase hex characters');
      digest = value;
    } else if (key === 'tool') {
      if (tool !== undefined) throw new ReasonFormatError('duplicate tool entry');
      if (!/^[a-z0-9_-]+\.[a-z0-9_-]+$/.test(value)) throw new ReasonFormatError('tool is not <server>.<tool>');
      tool = value;
    } else {
      throw new ReasonFormatError(`unknown entry "${key}"`);
    }
  }
  if (digest === undefined) throw new ReasonFormatError('missing action_digest entry');
  if (tool === undefined) throw new ReasonFormatError('missing tool entry');
  return { digest, tool };
}
