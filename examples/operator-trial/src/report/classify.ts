/**
 * Bundle + reviewer anchors → findings (spec §4–§5). Pure: it is handed file
 * contents and returns a Report; it never touches the filesystem or network.
 *
 * Authenticity comes from the published @bolyra/receipts verifier
 * (verifyReceipt, verifyReceiptChain). One check is report-local and stated
 * as such in the output: the receipt `id` is neither signed nor hashed by the
 * published verifier, so an id-only edit passes anchored verification; B1a
 * checks it here.
 */

import { verifyReceipt, verifyReceiptChain } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { CLI_VERSION, PACKAGES, TRIAL_VERSION } from '../versions';
import { CLAIM_TITLES } from './claims';
import type { Status } from './claims';

export type { Status } from './claims';

export interface Evidence {
  file: string;
  path?: string;
  line?: number;
}

export interface Finding {
  id: string;
  claim: string;
  title: string;
  status: Status;
  attempt?: number;
  receiptLine?: number;
  evidence: Evidence[];
  note?: string;
  /** What a DERIVED or FAILED row was computed from. */
  inputs?: string[];
}

export interface Anchors {
  signer: string;
  expectCount?: number;
  expectHead?: string;
}

export interface BundleFiles {
  receiptsJsonl: string;
  summaryJson: string;
  signerJson?: string;
  verifyTxt?: string;
}

export interface Report {
  tool: { name: string; version: string; receipts: string; cli: string };
  generatedAt: string;
  bundle: string;
  anchors: Anchors;
  attempts: number[];
  unattributedLines: number[];
  findings: Finding[];
}

export class BundleInputError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'BundleInputError';
  }
}

interface ParsedReceipt {
  line: number;
  receipt: SignedReceipt;
  verified: boolean;
  idOk: boolean;
}

interface SummaryAttempt {
  n: number;
  credential?: string;
  decision?: string;
  stage?: string;
  reason?: string;
  dispatched?: boolean;
  upstreamStatus?: number | null;
  receiptId?: string | null;
}

interface Summary {
  dryRun?: unknown;
  action?: { name?: string; method?: string; host?: string; path?: string };
  attempts?: SummaryAttempt[];
  receiptCount?: unknown;
  headReceiptHash?: unknown;
  note?: unknown;
}

const RECEIPTS = 'receipts.jsonl';
const SUMMARY = 'summary.json';
const SIGNER = 'signer.json';
const DESCRIPTOR = / \| action=([a-z][a-z0-9_-]{0,63}) ([A-Z]+) ([^/\s]+)(\/\S*)$/;
const REQUIRED_MASK = /requires permissions (\S+), agent has (\S+)/;

export function classify(files: BundleFiles, anchors: Anchors, opts: { now?: Date; bundleName?: string } = {}): Report {
  const findings: Finding[] = [];
  const add = (f: Omit<Finding, 'id' | 'title'>): Finding => {
    const id = f.attempt !== undefined ? `${f.claim}@${f.attempt}` : f.receiptLine !== undefined ? `${f.claim}:L${f.receiptLine}` : f.claim;
    const full: Finding = { id, title: CLAIM_TITLES[f.claim] ?? f.claim, ...f };
    findings.push(full);
    return full;
  };

  const summary = parseSummary(files.summaryJson);
  const parsed = parseReceipts(files.receiptsJsonl, anchors.signer, add);

  // ---- Bundle-level ----
  const chainInput = parsed.map((p) => p.receipt);
  const chain = verifyReceiptChain(chainInput, { expectedSigner: anchors.signer });
  const codes = Array.from(new Set(chain.issues.map((i) => i.code)));
  add({
    claim: 'B2',
    status: chain.ok ? 'DERIVED' : 'FAILED',
    evidence: [{ file: RECEIPTS }],
    inputs: ['verifyReceiptChain(@bolyra/receipts) with expectedSigner = anchor'],
    note: chain.ok
      ? `${chain.total} receipt(s), ${chain.chained} chained; recomputed head hash ${chain.headHash ?? '(none)'}`
      : `issues: ${codes.join(', ')}; ${chain.issues.map((i) => `line ${lineOfIndex(parsed, i.index)}: ${i.message}`).join(' | ')}`,
  });

  const observedCount = typeof summary.receiptCount === 'number' ? ` summary.json receiptCount (unsigned): ${summary.receiptCount}.` : '';
  if (anchors.expectCount === undefined) {
    add({ claim: 'B3a', status: 'ABSENT', evidence: [], note: `--expect-count was not supplied; tail truncation is not excluded by count.${observedCount}` });
  } else {
    const ok = parsed.length === anchors.expectCount;
    add({
      claim: 'B3a',
      status: ok ? 'DERIVED' : 'FAILED',
      evidence: [{ file: RECEIPTS }],
      inputs: [`--expect-count ${anchors.expectCount}`, `receipt lines parsed: ${parsed.length}`],
      note: (ok ? 'count matches the supplied checkpoint.' : `count-mismatch: log holds ${parsed.length}, checkpoint says ${anchors.expectCount}.`) + observedCount,
    });
  }
  const observedHead = typeof summary.headReceiptHash === 'string' ? ` summary.json headReceiptHash (unsigned): ${summary.headReceiptHash}.` : '';
  if (anchors.expectHead === undefined) {
    add({ claim: 'B3b', status: 'ABSENT', evidence: [], note: `--expect-head was not supplied; tail truncation is not excluded by head hash.${observedHead}` });
  } else {
    const ok = chain.headHash !== undefined && chain.headHash.toLowerCase() === anchors.expectHead.toLowerCase();
    add({
      claim: 'B3b',
      status: ok ? 'DERIVED' : 'FAILED',
      evidence: [{ file: RECEIPTS }],
      inputs: [`--expect-head ${anchors.expectHead}`, `recomputed head: ${chain.headHash ?? '(chain did not verify)'}`],
      note: (ok ? 'head hash matches the supplied checkpoint.' : 'head-hash-mismatch: recomputed head differs from the checkpoint.') + observedHead,
    });
  }

  // B4 / B6: signer.json compared against the anchor, never used as one.
  const signerFile = parseJsonOrNull(files.signerJson) as { signer?: unknown; ephemeral?: unknown } | null;
  if (!signerFile) {
    add({ claim: 'B4', status: 'ABSENT', evidence: [], note: 'signer.json is missing or unreadable; nothing to compare against the anchor.' });
    add({ claim: 'B6', status: 'ABSENT', evidence: [], note: 'signer.json is missing or unreadable.' });
  } else {
    const same = typeof signerFile.signer === 'string' && signerFile.signer.toLowerCase() === anchors.signer.toLowerCase();
    const verifyMentions = typeof files.verifyTxt === 'string' ? files.verifyTxt.toLowerCase().includes(anchors.signer.toLowerCase()) : undefined;
    add({
      claim: 'B4',
      status: same ? 'DERIVED' : 'FAILED',
      evidence: [{ file: SIGNER, path: 'signer' }],
      inputs: [`--signer ${anchors.signer}`],
      note:
        (same ? 'matches the supplied anchor.' : `signer.json names ${String(signerFile.signer)}, the anchor is ${anchors.signer}.`) +
        (verifyMentions === undefined ? '' : verifyMentions ? ' VERIFY.txt mentions the anchored signer.' : ' VERIFY.txt does not mention the anchored signer.'),
    });
    add({
      claim: 'B6',
      status: signerFile.ephemeral === true ? 'OBSERVED' : 'ABSENT',
      evidence: signerFile.ephemeral === true ? [{ file: SIGNER, path: 'ephemeral' }, { file: SUMMARY, path: 'note' }] : [],
      note: signerFile.ephemeral === true ? 'the host asserts the key was generated for this run; no key-destruction claim follows.' : 'signer.json does not assert an ephemeral key.',
    });
  }
  add({
    claim: 'B5',
    status: 'ABSENT',
    evidence: [],
    note:
      'the bundle does not record whether proofs were verified. The shipped operator-trial 0.1.0 runs the gateway with devMode: true and static simulated credentials (examples/operator-trial/src/gateway-config.ts); that is a property of the implementation, not authenticated provenance of this bundle.',
  });
  add({
    claim: 'B7',
    status: 'OBSERVED',
    evidence: [{ file: SUMMARY, path: 'dryRun' }],
    note: summary.dryRun === true ? 'dryRun: true (the host reports the built-in echo endpoint was used).' : `dryRun: ${JSON.stringify(summary.dryRun)}.`,
  });

  // ---- Attempt linking (A1) ----
  const attempts = (summary.attempts ?? []).filter((a) => typeof a?.n === 'number');
  const byId = new Map<string, ParsedReceipt[]>();
  for (const p of parsed) {
    if (!p.idOk) continue;
    const list = byId.get(p.receipt.id) ?? [];
    list.push(p);
    byId.set(p.receipt.id, list);
  }
  const claimedBy = new Map<string, number[]>();
  for (const a of attempts) {
    if (typeof a.receiptId === 'string') claimedBy.set(a.receiptId, [...(claimedBy.get(a.receiptId) ?? []), a.n]);
  }
  const linked = new Map<number, ParsedReceipt>();
  for (const a of attempts) {
    const idx = attempts.indexOf(a);
    const ev: Evidence[] = [{ file: SUMMARY, path: `attempts[${idx}].receiptId` }];
    if (typeof a.receiptId !== 'string') {
      add({ claim: 'A1', attempt: a.n, status: 'FAILED', evidence: ev, note: 'the summary records no receipt id for this attempt.' });
      continue;
    }
    const candidates = byId.get(a.receiptId) ?? [];
    const claimers = claimedBy.get(a.receiptId) ?? [];
    if (candidates.length !== 1) {
      add({
        claim: 'A1',
        attempt: a.n,
        status: 'FAILED',
        evidence: ev,
        inputs: [`receiptId ${a.receiptId}`],
        note: candidates.length === 0 ? 'no receipt in the log carries this id with a valid id check (B1a); no receipt is attributed by position.' : 'more than one receipt carries this id; attribution is ambiguous.',
      });
      continue;
    }
    if (claimers.length !== 1) {
      add({ claim: 'A1', attempt: a.n, status: 'FAILED', evidence: ev, inputs: [`receiptId ${a.receiptId}`], note: `attempts ${claimers.join(', ')} all name this receipt; attribution is ambiguous.` });
      continue;
    }
    linked.set(a.n, candidates[0]);
    add({ claim: 'A1', attempt: a.n, status: 'DERIVED', evidence: [...ev, { file: RECEIPTS, line: candidates[0].line, path: 'id' }], inputs: [`receiptId ${a.receiptId}`], note: `names receipt line ${candidates[0].line}.` });
  }
  const linkedLines = new Set(Array.from(linked.values()).map((p) => p.line));
  const unattributedLines = parsed.map((p) => p.line).filter((l) => !linkedLines.has(l));

  // ---- Per attempt ----
  const action = summary.action ?? {};
  const actionText = `${action.name ?? '?'} ${action.method ?? '?'} ${action.host ?? '?'}${action.path ?? ''}`;
  for (const a of attempts) {
    const idx = attempts.indexOf(a);
    const p = linked.get(a.n);
    if (p) payloadRows(p, add, a.n, { summaryAttempt: a, summaryIndex: idx, action });
    else unattributedRows(add, a.n);
    add({ claim: 'A4a', attempt: a.n, status: 'OBSERVED', evidence: [{ file: SUMMARY, path: 'action' }], note: actionText });
    add({ claim: 'A7a', attempt: a.n, status: 'ABSENT', evidence: [], note: 'the required permission is host configuration; the bundle does not carry it in signed or unsigned form.' });
    add({ claim: 'A9b', attempt: a.n, status: 'ABSENT', evidence: [], note: 'proof verification is disabled in dev mode (see B5); the signed hashes (A9a) name proofs that were not verified.' });
    add({
      claim: 'A10',
      attempt: a.n,
      status: 'OBSERVED',
      evidence: [{ file: SUMMARY, path: `attempts[${idx}].dispatched` }],
      note: `dispatched: ${String(a.dispatched)}. 'dispatched' means the host reports invoking fetch; delivery and execution at the endpoint are not proven.`,
    });
    if (typeof a.upstreamStatus === 'number') {
      add({ claim: 'A11', attempt: a.n, status: 'OBSERVED', evidence: [{ file: SUMMARY, path: `attempts[${idx}].upstreamStatus` }], note: `upstreamStatus: ${a.upstreamStatus} (as observed by the host).` });
    } else {
      add({ claim: 'A11', attempt: a.n, status: 'ABSENT', evidence: [], note: 'no upstream status was recorded (nothing was dispatched).' });
    }
    add({ claim: 'A12', attempt: a.n, status: 'ABSENT', evidence: [], note: "the bundle holds no ordering evidence. The host's code verifies the persisted receipt before dispatching, but the bundle does not record that." });
    add({ claim: 'A13', attempt: a.n, status: 'ABSENT', evidence: [], note: 'never claimed by the trial; an upstream status is the host\'s observation of a response, not proof of execution.' });
    add({ claim: 'A14', attempt: a.n, status: 'ABSENT', evidence: [], note: 'no consent artifact exists in the bundle.' });
    add({ claim: 'A15', attempt: a.n, status: 'ABSENT', evidence: [], note: 'the receipt records a permission tier mask only; there is no cumulative budget, and this is an auth receipt, not a commerce receipt.' });
    add({ claim: 'A16', attempt: a.n, status: 'ABSENT', evidence: [], note: 'nothing in the bundle names a payee, a settlement address, or who controls one.' });
    add({ claim: 'A17', attempt: a.n, status: 'ABSENT', evidence: [], note: 'see B5: simulated credentials, no registry.' });
  }

  // A8b: the replay relation, for the attempt the host labelled a replay.
  const replayAttempt = attempts.find((a) => a.n === 3);
  if (replayAttempt) {
    const first = linked.get(1);
    const third = linked.get(replayAttempt.n);
    const deps = [`A8a@1`, `A8a@${replayAttempt.n}`, `A2@${replayAttempt.n}`];
    if (!first || !third) {
      add({ claim: 'A8b', attempt: replayAttempt.n, status: 'FAILED', evidence: [], inputs: [...deps, 'A1@1', `A1@${replayAttempt.n}`], note: `dependency failed: attempt ${!first ? 1 : replayAttempt.n} is not attributed to a receipt (A1).` });
    } else if (!first.verified || !third.verified) {
      add({ claim: 'A8b', attempt: replayAttempt.n, status: 'FAILED', evidence: [], inputs: deps, note: `dependency failed: receipt line ${!first.verified ? first.line : third.line} did not verify (B1).` });
    } else {
      const same = first.receipt.payload.proof.nonce === third.receipt.payload.proof.nonce;
      const denied = third.receipt.payload.decision.allowed === false;
      add({
        claim: 'A8b',
        attempt: replayAttempt.n,
        status: same && denied ? 'DERIVED' : 'FAILED',
        evidence: [
          { file: RECEIPTS, line: first.line, path: 'payload.proof.nonce' },
          { file: RECEIPTS, line: third.line, path: 'payload.proof.nonce' },
          { file: RECEIPTS, line: third.line, path: 'payload.decision.allowed' },
        ],
        inputs: deps,
        note: same && denied ? 'same signed nonce as attempt 1, and the decision was deny.' : `${same ? 'same nonce' : 'different nonce'}; decision ${denied ? 'deny' : 'allow'}.`,
      });
    }
  }

  // ---- Unattributed receipts: their own payload rows, no attempt ----
  for (const p of parsed) {
    if (!linkedLines.has(p.line)) payloadRows(p, add, undefined, { action });
  }

  return {
    tool: { name: '@bolyra/operator-trial report', version: TRIAL_VERSION, receipts: PACKAGES.receipts, cli: CLI_VERSION },
    generatedAt: (opts.now ?? new Date()).toISOString(),
    bundle: opts.bundleName ?? 'bundle',
    anchors: { ...anchors },
    attempts: attempts.map((a) => a.n),
    unattributedLines,
    findings,
  };
}

function parseSummary(text: string): Summary {
  let s: unknown;
  try {
    s = JSON.parse(text);
  } catch (err) {
    throw new BundleInputError(`summary.json is not JSON: ${(err as Error).message}`);
  }
  if (!s || typeof s !== 'object' || Array.isArray(s)) throw new BundleInputError('summary.json is not an object');
  return s as Summary;
}

function parseJsonOrNull(text: string | undefined): unknown {
  if (typeof text !== 'string') return null;
  try {
    const v = JSON.parse(text);
    return v && typeof v === 'object' ? v : null;
  } catch {
    return null;
  }
}

/** B0 / B1 / B1a per physical line. Blank lines are skipped and not counted. */
function parseReceipts(text: string, signer: string, add: (f: Omit<Finding, 'id' | 'title'>) => Finding): ParsedReceipt[] {
  const out: ParsedReceipt[] = [];
  const raw = text.split('\n');
  for (let i = 0; i < raw.length; i++) {
    const line = i + 1;
    if (raw[i].trim() === '') continue;
    let r: unknown;
    try {
      r = JSON.parse(raw[i]);
    } catch (err) {
      add({ claim: 'B0', receiptLine: line, status: 'FAILED', evidence: [{ file: RECEIPTS, line }], note: `not JSON: ${(err as Error).message}` });
      continue;
    }
    if (!isReceiptShaped(r)) {
      add({ claim: 'B0', receiptLine: line, status: 'FAILED', evidence: [{ file: RECEIPTS, line }], note: 'JSON, but not shaped like a signed receipt (id, payload, signature).' });
      continue;
    }
    const verified = verifyReceipt(r, signer);
    add({
      claim: 'B1',
      receiptLine: line,
      status: verified ? 'DERIVED' : 'FAILED',
      evidence: [
        { file: RECEIPTS, line, path: 'signature.value' },
        { file: RECEIPTS, line, path: 'signature.payloadHash' },
      ],
      inputs: [`verifyReceipt(@bolyra/receipts) with expectedSigner = ${signer}`],
      note: verified ? 'signature recovered to the anchor; payload hash recomputed.' : 'signature-invalid: the signature did not recover to the anchored signer, or the payload hash did not recompute (the payload was altered after signing, or the key differs).',
    });
    out.push({ line, receipt: r, verified, idOk: false });
  }
  // B1a needs the whole log for uniqueness.
  const counts = new Map<string, number>();
  for (const p of out) counts.set(p.receipt.id, (counts.get(p.receipt.id) ?? 0) + 1);
  for (const p of out) {
    const expected = p.receipt.signature.payloadHash.slice(0, 18);
    const consistent = p.receipt.id === expected;
    const unique = counts.get(p.receipt.id) === 1;
    p.idOk = consistent && unique;
    add({
      claim: 'B1a',
      receiptLine: p.line,
      status: p.idOk ? 'DERIVED' : 'FAILED',
      evidence: [
        { file: RECEIPTS, line: p.line, path: 'id' },
        { file: RECEIPTS, line: p.line, path: 'signature.payloadHash' },
      ],
      inputs: ['report-local check: id === signature.payloadHash.slice(0, 18) and unique; not covered by @bolyra/receipts or @bolyra/cli'],
      note: p.idOk
        ? 'consistent with the stored payload hash and unique in the log. Authenticity of the hash itself is B1.'
        : !consistent
          ? `id ${p.receipt.id} does not equal the first 18 characters of signature.payloadHash (${expected}).`
          : `id ${p.receipt.id} appears ${counts.get(p.receipt.id)} times in the log.`,
    });
  }
  return out;
}

function isReceiptShaped(r: unknown): r is SignedReceipt {
  if (!r || typeof r !== 'object') return false;
  const x = r as Record<string, unknown>;
  const sig = x.signature as Record<string, unknown> | undefined;
  const payload = x.payload as Record<string, unknown> | undefined;
  return (
    typeof x.id === 'string' &&
    !!payload && typeof payload === 'object' &&
    !!sig && typeof sig === 'object' && typeof sig.payloadHash === 'string' && typeof sig.value === 'string' && typeof sig.signer === 'string'
  );
}

function lineOfIndex(parsed: ParsedReceipt[], index: number): string {
  return index < 0 ? '(log)' : String(parsed[index]?.line ?? `#${index}`);
}

/** A2, A3, A4b, A4c, A5, A6, A7b, A8a, A9a for one receipt, attributed or not. */
function payloadRows(
  p: ParsedReceipt,
  add: (f: Omit<Finding, 'id' | 'title'>) => Finding,
  attempt: number | undefined,
  ctx: { summaryAttempt?: SummaryAttempt; summaryIndex?: number; action: NonNullable<Summary['action']> },
): void {
  const line = p.line;
  const scope = attempt !== undefined ? { attempt } : { receiptLine: line };
  const ev = (path: string): Evidence[] => [{ file: RECEIPTS, line, path }];
  const failedNote = 'receipt failed signature verification (B1); its payload cannot be read as a signed assertion.';
  const signed = (claim: string, path: string, note: string, extraEv: Evidence[] = []) =>
    add({ claim, ...scope, status: p.verified ? 'SIGNED' : 'FAILED', evidence: [...ev(path), ...extraEv], note: p.verified ? note : failedNote });

  const pl = p.receipt.payload;
  signed('A2', 'payload.decision.allowed', pl.decision.allowed ? 'allow' : 'deny');
  signed('A3', 'payload.decision.reasonCode', `"${pl.decision.reasonCode ?? ''}"`);

  const m = typeof pl.decision.reasonCode === 'string' ? DESCRIPTOR.exec(pl.decision.reasonCode) : null;
  if (!p.verified) {
    add({ claim: 'A4b', ...scope, status: 'FAILED', evidence: ev('payload.decision.reasonCode'), note: failedNote });
    if (attempt !== undefined) add({ claim: 'A4c', ...scope, status: 'FAILED', evidence: [], inputs: [`A4a@${attempt}`, `A4b@${attempt}`], note: failedNote });
  } else if (!m) {
    add({ claim: 'A4b', ...scope, status: 'ABSENT', evidence: [], note: 'the signed reason text carries no " | action=" descriptor.' });
    if (attempt !== undefined) add({ claim: 'A4c', ...scope, status: 'ABSENT', evidence: [], inputs: [`A4a@${attempt}`, `A4b@${attempt}`], note: 'nothing signed to compare against.' });
  } else {
    const [, name, method, host, path] = m;
    add({ claim: 'A4b', ...scope, status: 'DERIVED', evidence: ev('payload.decision.reasonCode'), inputs: ['rule: trailing " | action=<name> <METHOD> <host><path>"'], note: `${name} ${method} ${host}${path}` });
    if (attempt !== undefined) {
      const agree = name === ctx.action.name && method === ctx.action.method && host === ctx.action.host && path === ctx.action.path;
      add({
        claim: 'A4c',
        ...scope,
        status: agree ? 'DERIVED' : 'FAILED',
        evidence: [{ file: SUMMARY, path: 'action' }, ...ev('payload.decision.reasonCode')],
        inputs: [`A4a@${attempt}`, `A4b@${attempt}`],
        note: agree ? 'the unsigned record and the signed descriptor name the same action.' : 'the unsigned record and the signed descriptor disagree.',
      });
    }
  }

  signed('A5', 'payload.subject', `rootDid ${pl.subject.rootDid}; actingDid ${pl.subject.actingDid}; commitments ${pl.subject.credentialCommitment} / ${pl.subject.effectiveCommitment}. Dev DIDs from a simulated credential; these identify a key material commitment, not a person or legal entity.`);

  const stage = ctx.summaryAttempt?.stage;
  const maskNote =
    `permissionBitmask ${pl.decision.permissionBitmask}` +
    (pl.decision.permissionBitmask === '0' && stage === 'verification_failed'
      ? ". This 0 is the gateway's failure default: verification failed before tool policy ran, so it is not evidence that permissions were evaluated."
      : '');
  signed('A6', 'payload.decision.permissionBitmask', maskNote);

  if (attempt === 2) {
    const rm = p.verified && typeof pl.decision.reasonCode === 'string' ? REQUIRED_MASK.exec(pl.decision.reasonCode) : null;
    if (!p.verified) add({ claim: 'A7b', ...scope, status: 'FAILED', evidence: ev('payload.decision.reasonCode'), note: failedNote });
    else if (!rm) add({ claim: 'A7b', ...scope, status: 'ABSENT', evidence: [], note: 'the signed reason text reports no required mask.' });
    else add({ claim: 'A7b', ...scope, status: 'DERIVED', evidence: ev('payload.decision.reasonCode'), inputs: ['rule: "requires permissions <mask>, agent has <mask>" in the signed reason text'], note: `reported required ${rm[1]}, agent ${rm[2]}; this is what the host wrote into the reason, not the enforced configuration.` });
  }

  signed('A8a', 'payload.proof.nonce', `nonce ${pl.proof.nonce}`);
  signed('A9a', 'payload.proof', `humanProofHash ${pl.proof.humanProofHash}; agentProofHash ${pl.proof.agentProofHash}; publicSignalsHash ${pl.proof.publicSignalsHash}. Hashes only; see A9b.`);
}

/** Receipt-backed rows for an attempt whose A1 failed: FAILED, no payload values assigned. */
function unattributedRows(add: (f: Omit<Finding, 'id' | 'title'>) => Finding, attempt: number): void {
  const note = 'this attempt is not attributed to a receipt (A1); no payload value is assigned.';
  const claims = ['A2', 'A3', 'A4b', 'A4c', 'A5', 'A6', 'A8a', 'A9a', ...(attempt === 2 ? ['A7b'] : [])];
  for (const claim of claims) add({ claim, attempt, status: 'FAILED', evidence: [], inputs: [`A1@${attempt}`], note });
}
