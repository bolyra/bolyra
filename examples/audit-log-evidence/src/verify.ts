/**
 * Offline verification of the packet (spec §3). Pure `verifyPacket` plus a CLI:
 *   npm run verify -- --fixtures <dir> --signer <0xaddr> [--execution <file>]
 * Anchors come from the flags; signer.json is compared, never used as the anchor.
 * Exit 0 when a report was produced (whatever it says); 2 on unreadable input.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { computeReceiptHash, hashPayload, verifyReceipt } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { actionDigest, parseReason, ReasonFormatError } from './digest';
import type { Action } from './digest';
import type { AuditEvent, Execution } from './generate';

export type Status = 'SIGNED' | 'OBSERVED' | 'DERIVED' | 'ABSENT' | 'FAILED';

export interface Finding {
  id: string;
  title: string;
  status: Status;
  note: string;
}

export interface PacketFiles {
  action: Action;
  receipt: SignedReceipt;
  execution: Execution;
  events: AuditEvent[];
  signerFile?: { signer?: unknown };
}

export const TRUST_ASSUMPTIONS = [
  'A signature authenticates the signer\'s assertion; it does not establish that the assertion is true.',
  'The digest binds the approval to one exact call; it does not establish enforcement (that no other call ran) or execution (that this call ran).',
  'Timestamps and actor identities in the export are unsigned host assertions.',
  'Completeness is unproven; a trusted external checkpoint covering the relevant scope and sequence would be required.',
  'The demo private key is public, so anyone can forge replacement receipts under it; this packet demonstrates verification mechanics, not a trust anchor.',
];

export function verifyPacket(files: PacketFiles, anchors: { signer: string }): Finding[] {
  const signer = anchors.signer.toLowerCase();
  const out: Finding[] = [];
  const { receipt, events, execution, action } = files;

  // V1: anchored signature + payload hash + allowed === true
  let v1 = false;
  try {
    v1 = verifyReceipt(receipt, signer) && receipt.payload.decision.allowed === true;
  } catch {
    v1 = false;
  }
  out.push({
    id: 'V1',
    title: 'Receipt signature recovers to the anchored signer; payload hash recomputes; signed decision.allowed is true',
    status: v1 ? 'DERIVED' : 'FAILED',
    note: v1
      ? `verifyReceipt(@bolyra/receipts) with expectedSigner ${signer}; decision.allowed = true.`
      : receipt.payload?.decision?.allowed === true
        ? 'signature-invalid: the signature did not recover to the anchored signer or the payload hash did not recompute.'
        : 'signed decision.allowed is not true, or the signature did not verify.',
  });

  // V2: join consistency
  const expectedId = typeof receipt.signature?.payloadHash === 'string' ? receipt.signature.payloadHash.slice(0, 18) : '';
  let recomputedHash = '';
  let recomputedPayloadHash = '';
  try {
    recomputedHash = computeReceiptHash(receipt);
    recomputedPayloadHash = hashPayload(receipt.payload);
  } catch {
    /* reported below */
  }
  const idOk = receipt.id === expectedId && recomputedPayloadHash === receipt.signature?.payloadHash;
  const approval = events.find((e) => e.action === 'tool.approval_resolved');
  const executed = events.find((e) => e.action === 'tool.executed');
  const joinProblems: string[] = [];
  if (!approval) joinProblems.push('no tool.approval_resolved event');
  if (!executed) joinProblems.push('no tool.executed event');
  if (!idOk) joinProblems.push('receipt id does not equal the first 18 characters of the recomputed payload hash');
  for (const [label, ev] of [['approval event', approval], ['executed event', executed]] as const) {
    if (!ev) continue;
    if (ev.metadata.receipt_id !== receipt.id) joinProblems.push(`${label} receipt_id differs from the receipt id`);
    if (ev.metadata.receipt_hash !== recomputedHash) joinProblems.push(`${label} receipt_hash differs from computeReceiptHash(receipt)`);
  }
  if (execution.receipt_id !== receipt.id) joinProblems.push('execution.receipt_id differs from the receipt id');
  const v2 = joinProblems.length === 0;
  out.push({
    id: 'V2',
    title: 'Join consistency: both events and the execution record name this receipt by id and by recomputed hash',
    status: v2 ? 'DERIVED' : 'FAILED',
    note: v2 ? `receipt id ${receipt.id}; receiptHash ${recomputedHash}. Consistency only; it does not authenticate the events.` : joinProblems.join('; ') + '.',
  });

  // V3: recorded action matches the digest in the verified approval assertion
  if (!v1) {
    out.push({ id: 'V3', title: 'Recorded action matches the digest in the verified approval assertion', status: 'FAILED', note: 'verification dependency failed (V1); the reason text is not a verified assertion.' });
  } else {
    let note = '';
    let ok = false;
    try {
      const { digest: signedDigest, tool } = parseReason(receipt.payload.decision.reasonCode);
      const fromAction = actionDigest(action);
      const fromExecution = actionDigest(execution.action);
      const problems: string[] = [];
      if (fromAction !== signedDigest) problems.push('action.json digest differs from the signed digest');
      if (fromExecution !== signedDigest) problems.push('execution.json.action digest differs from the signed digest');
      if (approval && approval.metadata.action_digest !== signedDigest) problems.push('approval event action_digest differs from the signed digest');
      if (executed && executed.metadata.action_digest !== signedDigest) problems.push('executed event action_digest differs from the signed digest');
      if (tool !== `${execution.action.server}.${execution.action.tool}`) problems.push('signed tool name differs from the executed tool');
      ok = problems.length === 0;
      note = ok
        ? `sha256(canonicalize(action)) = ${signedDigest} in action.json, execution.json, the signed reason text and both events. Establishes neither execution nor enforcement.`
        : problems.join('; ') + '.';
    } catch (err) {
      ok = false;
      note = err instanceof ReasonFormatError ? `reason text convention violated: ${err.message}.` : `digest could not be computed: ${(err as Error).message}.`;
    }
    out.push({ id: 'V3', title: 'Recorded action matches the digest in the verified approval assertion', status: ok ? 'DERIVED' : 'FAILED', note });
  }

  // V4: ordering of unsigned timestamps
  const tA = approval ? Date.parse(approval.occurred_at) : NaN;
  const tE = Date.parse(execution.executed_at);
  const v4 = Number.isFinite(tA) && Number.isFinite(tE) && tA < tE;
  out.push({
    id: 'V4',
    title: 'Approval occurred_at precedes executed_at (comparison of unsigned timestamps; actual chronology unproven)',
    status: Number.isFinite(tA) && Number.isFinite(tE) ? (v4 ? 'DERIVED' : 'FAILED') : 'ABSENT',
    note: Number.isFinite(tA) && Number.isFinite(tE) ? `${approval!.occurred_at} vs ${execution.executed_at}; both timestamps are OBSERVED (unsigned).` : 'a timestamp is missing or unparsable.',
  });

  out.push({ id: 'V5', title: 'The action executed as recorded', status: 'ABSENT', note: 'no independent evidence of execution in the packet; execution.json and the tool.executed event are unsigned host assertions.' });
  out.push({ id: 'V6', title: 'The approver is the authenticated person named', status: 'ABSENT', note: 'the export actor is an unsigned host assertion; the receipt subject is a simulated agent credential. Authenticated approver identity is not established.' });

  // signer.json comparison (never an anchor)
  if (files.signerFile) {
    const same = typeof files.signerFile.signer === 'string' && files.signerFile.signer.toLowerCase() === signer;
    out.push({ id: 'S', title: 'signer.json equals the supplied signer anchor', status: same ? 'DERIVED' : 'FAILED', note: same ? 'matches; compared only, not used as the anchor.' : 'signer.json names a different address than the anchor.' });
  }
  return out;
}

export function readPacket(dir: string, executionOverride?: string): PacketFiles {
  const read = (n: string) => fs.readFileSync(path.join(dir, n), 'utf8');
  const events = read('export.jsonl').split('\n').filter((l) => l.trim() !== '').map((l) => JSON.parse(l) as AuditEvent);
  let signerFile: { signer?: unknown } | undefined;
  try {
    signerFile = JSON.parse(read('signer.json'));
  } catch {
    signerFile = undefined;
  }
  return {
    action: JSON.parse(read('action.json')),
    receipt: JSON.parse(read('approval-receipt.json')),
    execution: JSON.parse(executionOverride ? fs.readFileSync(executionOverride, 'utf8') : read('execution.json')),
    events,
    signerFile,
  };
}

export function renderTable(findings: Finding[]): string {
  const lines = findings.map((f) => `${f.id.padEnd(3)} ${f.status.padEnd(8)} ${f.title}\n    ${f.note}`);
  return lines.join('\n') + '\n\nTrust assumptions:\n' + TRUST_ASSUMPTIONS.map((t) => `- ${t}`).join('\n') + '\n';
}

if (require.main === module) {
  const { values } = parseArgs({ options: { fixtures: { type: 'string' }, signer: { type: 'string' }, execution: { type: 'string' } } });
  if (!values.fixtures || !values.signer || !/^0x[0-9a-fA-F]{40}$/.test(values.signer)) {
    process.stderr.write('Usage: npm run verify -- --fixtures <dir> --signer <0xaddress> [--execution <file>]\n');
    process.exitCode = 2;
  } else {
    let files: PacketFiles;
    try {
      files = readPacket(values.fixtures, values.execution);
    } catch (err) {
      process.stderr.write(`cannot read packet: ${(err as Error).message}\n`);
      process.exitCode = 2;
      files = undefined as never;
    }
    if (files) process.stdout.write(renderTable(verifyPacket(files, { signer: values.signer })));
  }
}
