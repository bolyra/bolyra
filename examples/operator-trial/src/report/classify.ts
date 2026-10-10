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
  /** Normalized (lower-case hex) so the report and the generated CLI command agree with the verifier's comparison. */
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
  /** 1-based, equal to array index + 1 (validated). */
  n: number;
  index: number;
  credential?: unknown;
  stage?: unknown;
  dispatched?: unknown;
  upstreamStatus?: unknown;
  outcome?: unknown;
  receiptId?: unknown;
}

interface Summary {
  dryRun?: unknown;
  action?: unknown;
  attempts: SummaryAttempt[];
  receiptCount?: unknown;
  headReceiptHash?: unknown;
  note?: unknown;
}

type Add = (f: Omit<Finding, 'id' | 'title'>) => Finding;

const RECEIPTS = 'receipts.jsonl';
const SUMMARY = 'summary.json';
const SIGNER = 'signer.json';
const VERIFY = 'VERIFY.txt';
const DESCRIPTOR = / \| action=([a-z][a-z0-9_-]{0,63}) ([A-Z]+) ([^/\s]+)(\/\S*)$/;
const REQUIRED_MASK = /requires permissions (\S+), agent has (\S+)/;
const ADDRESS = /0x[0-9a-f]{40}(?![0-9a-f])/g;
const PAYLOAD_FAILED = 'receipt failed signature verification (B1: signature-invalid); its payload cannot be read as a signed assertion.';

export function normalizeAnchors(a: Anchors): Anchors {
  const out: Anchors = { signer: a.signer.toLowerCase() };
  if (a.expectCount !== undefined) out.expectCount = a.expectCount;
  if (a.expectHead !== undefined) out.expectHead = a.expectHead.toLowerCase();
  return out;
}

export function classify(files: BundleFiles, rawAnchors: Anchors, opts: { now?: Date; bundleName?: string } = {}): Report {
  const anchors = normalizeAnchors(rawAnchors);
  const findings: Finding[] = [];
  const add: Add = (f) => {
    const id = f.attempt !== undefined ? `${f.claim}@${f.attempt}` : f.receiptLine !== undefined ? `${f.claim}:L${f.receiptLine}` : f.claim;
    const full: Finding = { id, title: CLAIM_TITLES[f.claim] ?? f.claim, ...f };
    findings.push(full);
    return full;
  };

  const summary = parseSummary(files.summaryJson);
  const { parsed, malformedLines, entries } = parseReceipts(files.receiptsJsonl, anchors.signer, add);
  const logNote = malformedLines.length === 0 ? `${entries} receipt line(s)` : `${entries} non-blank line(s), of which ${malformedLines.length} malformed (line ${malformedLines.join(', ')})`;

  // ---- Bundle-level ----
  // The chain is verified over the readable receipts only; a malformed line means the log as a
  // whole cannot be called intact, whatever the readable subset says.
  let chain: ReturnType<typeof verifyReceiptChain>;
  try {
    chain = verifyReceiptChain(parsed.map((p) => p.receipt), { expectedSigner: anchors.signer });
  } catch (err) {
    chain = { ok: false, total: parsed.length, chained: 0, unchained: 0, issues: [{ index: -1, code: 'malformed-receipt', message: `verifier threw: ${(err as Error).message}` }] };
  }
  const chainOk = chain.ok && malformedLines.length === 0;
  // The chain verifier's headHash is the hash of the last CHAINED receipt; an unchained tail is
  // flagged by B2 but never becomes the head, so cite the receipt whose hash was actually compared.
  const lastChained = [...parsed].reverse().find((p) => p.receipt.payload.chain !== undefined);
  const lastReadable = lastChained?.line;
  const headLabel =
    chain.headHash === undefined
      ? '(the readable receipts did not verify as a chain)'
      : `${chain.headHash}, the recomputed hash of the last readable chained receipt (line ${lastReadable})` +
        (malformedLines.length > 0 ? `; malformed line(s) ${malformedLines.join(', ')} are excluded (see B2)` : '');
  const codes = Array.from(new Set(chain.issues.map((i) => i.code)));
  add({
    claim: 'B2',
    status: chainOk ? 'DERIVED' : 'FAILED',
    evidence: [{ file: RECEIPTS }],
    inputs: ['verifyReceiptChain(@bolyra/receipts) with expectedSigner = anchor', `log: ${logNote}`],
    note: chainOk
      ? `${chain.total} receipt(s), ${chain.chained} chained; recomputed head hash ${chain.headHash ?? '(none)'}`
      : (malformedLines.length > 0 ? `malformed line(s) ${malformedLines.join(', ')} (B0) mean the log cannot be verified as one intact chain. ` : '') +
        (chain.issues.length > 0 ? `issues over the readable receipts: ${codes.join(', ')}; ${chain.issues.map((i) => `line ${lineOfIndex(parsed, i.index)}: ${i.message}`).join(' | ')}` : 'the readable receipts chain, but the log is not whole.'),
  });

  if (anchors.expectCount === undefined) {
    add({ claim: 'B3a', status: 'ABSENT', evidence: [], note: '--expect-count was not supplied; tail truncation is not excluded by count.' });
  } else {
    const ok = entries === anchors.expectCount && malformedLines.length === 0;
    add({
      claim: 'B3a',
      status: ok ? 'DERIVED' : 'FAILED',
      evidence: [{ file: RECEIPTS }],
      inputs: [`--expect-count ${anchors.expectCount}`, `log: ${logNote}`],
      note: ok ? 'count matches the supplied checkpoint.' : `count-mismatch: the log has ${logNote}, checkpoint says ${anchors.expectCount}.`,
    });
  }
  if (anchors.expectHead === undefined) {
    add({ claim: 'B3b', status: 'ABSENT', evidence: [], note: '--expect-head was not supplied; tail truncation is not excluded by head hash.' });
  } else {
    const ok = chain.headHash !== undefined && chain.headHash.toLowerCase() === anchors.expectHead;
    add({
      claim: 'B3b',
      status: ok ? 'DERIVED' : 'FAILED',
      evidence: lastReadable !== undefined ? [{ file: RECEIPTS, line: lastReadable }] : [{ file: RECEIPTS }],
      inputs: [`--expect-head ${anchors.expectHead}`, `recomputed: ${headLabel}`],
      note: (ok ? 'the supplied checkpoint equals ' : 'head-hash-mismatch: the supplied checkpoint differs from ') + headLabel + '.',
    });
  }

  // B8a / B8b: the host's own unsigned checkpoints, compared with the log. Never anchors.
  if (typeof summary.receiptCount !== 'number') {
    add({ claim: 'B8a', status: 'ABSENT', evidence: [], note: 'summary.json records no receiptCount.' });
  } else {
    const same = summary.receiptCount === entries && malformedLines.length === 0;
    add({
      claim: 'B8a',
      status: same ? 'OBSERVED' : 'FAILED',
      evidence: [{ file: SUMMARY, path: 'receiptCount' }, { file: RECEIPTS }],
      note: same ? `receiptCount ${summary.receiptCount} (unsigned) equals the number of receipt lines.` : `contradiction: summary.json says ${summary.receiptCount} receipts, the log has ${logNote}.`,
    });
  }
  if (typeof summary.headReceiptHash !== 'string') {
    add({ claim: 'B8b', status: 'ABSENT', evidence: [], note: 'summary.json records no headReceiptHash.' });
  } else {
    const same = chain.headHash !== undefined && summary.headReceiptHash.toLowerCase() === chain.headHash.toLowerCase();
    add({
      claim: 'B8b',
      status: same ? 'OBSERVED' : 'FAILED',
      evidence: [{ file: SUMMARY, path: 'headReceiptHash' }, ...(lastReadable !== undefined ? [{ file: RECEIPTS, line: lastReadable }] : [{ file: RECEIPTS }])],
      note: (same ? 'headReceiptHash (unsigned) equals ' : `contradiction: summary.json names head ${summary.headReceiptHash}, which differs from `) + headLabel + '.',
    });
  }

  // B4 / B4b / B6: signer.json and VERIFY.txt compared against the anchor, never used as one.
  const signerFile = parseJsonOrNull(files.signerJson) as { signer?: unknown; ephemeral?: unknown } | null;
  if (!signerFile) {
    add({ claim: 'B4', status: 'ABSENT', evidence: [], note: 'signer.json is missing or unreadable; nothing to compare against the anchor.' });
    add({ claim: 'B6', status: 'ABSENT', evidence: [], note: 'signer.json is missing or unreadable.' });
  } else {
    const same = typeof signerFile.signer === 'string' && signerFile.signer.toLowerCase() === anchors.signer;
    add({
      claim: 'B4',
      status: same ? 'DERIVED' : 'FAILED',
      evidence: [{ file: SIGNER, path: 'signer' }],
      inputs: [`--signer ${anchors.signer}`],
      note: same ? 'matches the supplied anchor.' : `contradiction: signer.json names ${fmt(signerFile.signer)}, the anchor is ${anchors.signer}.`,
    });
    add({
      claim: 'B6',
      status: signerFile.ephemeral === true ? 'OBSERVED' : 'ABSENT',
      evidence: signerFile.ephemeral === true ? [{ file: SIGNER, path: 'ephemeral' }] : [],
      note: signerFile.ephemeral === true ? 'the host asserts the key was generated for this run; no key-destruction claim follows.' : 'signer.json does not assert an ephemeral key.',
    });
  }
  if (typeof files.verifyTxt !== 'string') {
    add({ claim: 'B4b', status: 'ABSENT', evidence: [], note: 'VERIFY.txt is missing.' });
  } else {
    const mentioned = Array.from(new Set(files.verifyTxt.toLowerCase().match(ADDRESS) ?? []));
    const same = mentioned.length === 1 && mentioned[0] === anchors.signer;
    add({
      claim: 'B4b',
      status: same ? 'OBSERVED' : 'FAILED',
      evidence: [{ file: VERIFY }],
      note: same ? 'VERIFY.txt names the anchored signer (unsigned text; not used as an anchor).' : `contradiction: VERIFY.txt names ${mentioned.length === 0 ? 'no address' : mentioned.join(', ')}, the anchor is ${anchors.signer}.`,
    });
  }
  add({
    claim: 'B5',
    status: 'ABSENT',
    evidence: [],
    note:
      'the bundle does not record whether proofs were verified. Separately: the shipped operator-trial 0.1.0 runs the gateway with devMode: true and static simulated credentials (examples/operator-trial/src/gateway-config.ts); that is a property of the implementation, not authenticated provenance of this bundle.',
  });
  if (typeof summary.dryRun === 'boolean') {
    add({ claim: 'B7', status: 'OBSERVED', evidence: [{ file: SUMMARY, path: 'dryRun' }], note: summary.dryRun ? 'dryRun: true (the host reports the built-in echo endpoint was used).' : 'dryRun: false.' });
  } else {
    add({ claim: 'B7', status: 'ABSENT', evidence: [], note: 'summary.json records no boolean dryRun.' });
  }

  // ---- Attempt linking (A1): one valid receipt per attempt, one attempt per receipt ----
  const attempts = summary.attempts;
  const byId = new Map<string, ParsedReceipt[]>();
  for (const p of parsed) {
    if (!p.idOk) continue;
    byId.set(p.receipt.id, [...(byId.get(p.receipt.id) ?? []), p]);
  }
  const claimedBy = new Map<string, number[]>();
  for (const a of attempts) {
    if (typeof a.receiptId === 'string') claimedBy.set(a.receiptId, [...(claimedBy.get(a.receiptId) ?? []), a.n]);
  }
  const linked = new Map<number, ParsedReceipt>();
  for (const a of attempts) {
    const ev: Evidence[] = [{ file: SUMMARY, path: `attempts[${a.index}].receiptId` }];
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
  const action = actionOf(summary.action);
  for (const a of attempts) {
    const p = linked.get(a.n);
    if (p) payloadRows(p, add, a.n, action);
    else unattributedRows(add, a.n);

    if (action) add({ claim: 'A4a', attempt: a.n, status: 'OBSERVED', evidence: [{ file: SUMMARY, path: 'action' }], note: `${action.name} ${action.method} ${action.host}${action.path}` });
    else add({ claim: 'A4a', attempt: a.n, status: 'ABSENT', evidence: [], note: 'summary.json records no complete action (name, method, host, path).' });
    add({ claim: 'A7a', attempt: a.n, status: 'ABSENT', evidence: [], note: 'the required permission is host configuration; the bundle does not carry it in signed or unsigned form.' });
    add({ claim: 'A9b', attempt: a.n, status: 'ABSENT', evidence: [], note: 'the bundle provides no evidence that any proof was verified; A9a lists hashes only. Separately: the shipped operator-trial 0.1.0 disables proof verification (dev mode; see B5).' });
    if (typeof a.dispatched === 'boolean') {
      add({
        claim: 'A10',
        attempt: a.n,
        status: 'OBSERVED',
        evidence: [{ file: SUMMARY, path: `attempts[${a.index}].dispatched` }],
        note: `dispatched: ${a.dispatched}. 'dispatched' means the host reports invoking fetch; delivery and execution at the endpoint are not proven.`,
      });
    } else {
      add({ claim: 'A10', attempt: a.n, status: 'ABSENT', evidence: [], note: 'summary.json records no boolean dispatched for this attempt.' });
    }
    if (typeof a.upstreamStatus === 'number') {
      add({ claim: 'A11', attempt: a.n, status: 'OBSERVED', evidence: [{ file: SUMMARY, path: `attempts[${a.index}].upstreamStatus` }], note: `upstreamStatus: ${a.upstreamStatus} (as observed by the host).` });
    } else {
      add({
        claim: 'A11',
        attempt: a.n,
        status: 'ABSENT',
        evidence: [],
        note: 'no upstream status was recorded.' + (a.dispatched === true ? ` The host reports dispatching without a status (outcome: ${typeof a.outcome === 'string' ? a.outcome : 'not recorded'}).` : ''),
      });
    }
    add({ claim: 'A12', attempt: a.n, status: 'ABSENT', evidence: [], note: "the bundle holds no ordering evidence. The host's code verifies the persisted receipt before dispatching, but the bundle does not record that." });
    add({ claim: 'A13', attempt: a.n, status: 'ABSENT', evidence: [], note: "never claimed by the trial; an upstream status is the host's observation of a response, not proof of execution." });
    add({ claim: 'A14', attempt: a.n, status: 'ABSENT', evidence: [], note: 'no consent artifact exists in the bundle.' });
    add({ claim: 'A15', attempt: a.n, status: 'ABSENT', evidence: [], note: 'the receipt records a permission tier mask only; there is no cumulative budget, and this is an auth receipt, not a commerce receipt.' });
    add({ claim: 'A16', attempt: a.n, status: 'ABSENT', evidence: [], note: 'nothing in the bundle names a payee, a settlement address, or who controls one.' });
    add({ claim: 'A17', attempt: a.n, status: 'ABSENT', evidence: [], note: 'see B5: simulated credentials, no registry.' });
  }

  // A8b: the replay relation, attempt 3 only (the trial's fixed order).
  if (attempts.some((a) => a.n === 3)) {
    const first = linked.get(1);
    const third = linked.get(3);
    const deps = ['A1@1', 'A1@3', 'A8a@1', 'A8a@3', 'A2@3'];
    if (!first || !third) {
      add({ claim: 'A8b', attempt: 3, status: 'FAILED', evidence: [], inputs: deps, note: `dependency failed: attempt ${!first ? 1 : 3} is not attributed to a receipt (A1).` });
    } else if (!first.verified || !third.verified) {
      add({ claim: 'A8b', attempt: 3, status: 'FAILED', evidence: [], inputs: deps, note: `dependency failed: receipt line ${!first.verified ? first.line : third.line} did not verify (B1: signature-invalid).` });
    } else {
      const same = first.receipt.payload.proof.nonce === third.receipt.payload.proof.nonce;
      const denied = third.receipt.payload.decision.allowed === false;
      add({
        claim: 'A8b',
        attempt: 3,
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
    if (!linkedLines.has(p.line)) payloadRows(p, add, undefined, action);
  }

  return {
    tool: { name: '@bolyra/operator-trial report', version: TRIAL_VERSION, receipts: PACKAGES.receipts, cli: CLI_VERSION },
    generatedAt: (opts.now ?? new Date()).toISOString(),
    bundle: opts.bundleName ?? 'bundle',
    anchors,
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
  if (!isObject(s)) throw new BundleInputError('summary.json is not an object');
  if (!Array.isArray(s.attempts)) throw new BundleInputError('summary.json: attempts is not an array');
  const attempts: SummaryAttempt[] = s.attempts.map((raw, index) => {
    if (!isObject(raw)) throw new BundleInputError(`summary.json: attempts[${index}] is not an object`);
    if (raw.n !== index + 1) throw new BundleInputError(`summary.json: attempts[${index}].n is ${JSON.stringify(raw.n)}, expected ${index + 1}`);
    return { n: index + 1, index, credential: raw.credential, stage: raw.stage, dispatched: raw.dispatched, upstreamStatus: raw.upstreamStatus, outcome: raw.outcome, receiptId: raw.receiptId };
  });
  if (attempts.length === 0) throw new BundleInputError('summary.json: attempts is empty');
  return { dryRun: s.dryRun, action: s.action, attempts, receiptCount: s.receiptCount, headReceiptHash: s.headReceiptHash, note: s.note };
}

function actionOf(a: unknown): { name: string; method: string; host: string; path: string } | null {
  if (!isObject(a)) return null;
  const { name, method, host, path } = a;
  return typeof name === 'string' && typeof method === 'string' && typeof host === 'string' && typeof path === 'string' ? { name, method, host, path } : null;
}

/** Safe rendering of an untrusted value for a note; never calls the value's own toString. */
function fmt(v: unknown): string {
  if (typeof v === 'string') return v;
  try {
    return JSON.stringify(v) ?? String(typeof v);
  } catch {
    return `(unprintable ${typeof v})`;
  }
}

function isObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

function parseJsonOrNull(text: string | undefined): unknown {
  if (typeof text !== 'string') return null;
  try {
    const v = JSON.parse(text);
    return isObject(v) ? v : null;
  } catch {
    return null;
  }
}

/** B0 / B1 / B1a per physical line. Blank lines are skipped and not counted. */
function parseReceipts(text: string, signer: string, add: Add): { parsed: ParsedReceipt[]; malformedLines: number[]; entries: number } {
  const out: ParsedReceipt[] = [];
  const malformedLines: number[] = [];
  let entries = 0;
  const raw = text.split('\n');
  for (let i = 0; i < raw.length; i++) {
    const line = i + 1;
    if (raw[i].trim() === '') continue;
    entries++;
    let r: unknown;
    try {
      r = JSON.parse(raw[i]);
    } catch (err) {
      malformedLines.push(line);
      add({ claim: 'B0', receiptLine: line, status: 'FAILED', evidence: [{ file: RECEIPTS, line }], note: `not JSON: ${(err as Error).message}` });
      continue;
    }
    const shape = receiptShapeProblem(r);
    if (shape) {
      malformedLines.push(line);
      add({ claim: 'B0', receiptLine: line, status: 'FAILED', evidence: [{ file: RECEIPTS, line }], note: `JSON, but not a signed receipt this report can read: ${shape}.` });
      continue;
    }
    const receipt = r as SignedReceipt;
    let verified = false;
    try {
      verified = verifyReceipt(receipt, signer);
    } catch {
      verified = false;
    }
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
    out.push({ line, receipt, verified, idOk: false });
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
  return { parsed: out, malformedLines, entries };
}

/** Every field the report reads must be present with the right type; otherwise the line is B0 FAILED, never dereferenced. */
function receiptShapeProblem(r: unknown): string | null {
  if (!isObject(r)) return 'not an object';
  if (typeof r.id !== 'string') return 'id is not a string';
  const sig = r.signature;
  if (!isObject(sig)) return 'signature is not an object';
  for (const k of ['payloadHash', 'value', 'signer', 'keyId']) if (typeof sig[k] !== 'string') return `signature.${k} is not a string`;
  const pl = r.payload;
  if (!isObject(pl)) return 'payload is not an object';
  const dec = pl.decision;
  if (!isObject(dec)) return 'payload.decision is not an object';
  if (typeof dec.allowed !== 'boolean') return 'payload.decision.allowed is not a boolean';
  if (typeof dec.permissionBitmask !== 'string') return 'payload.decision.permissionBitmask is not a string';
  if (dec.reasonCode !== undefined && typeof dec.reasonCode !== 'string') return 'payload.decision.reasonCode is not a string';
  const sub = pl.subject;
  if (!isObject(sub)) return 'payload.subject is not an object';
  for (const k of ['rootDid', 'actingDid', 'credentialCommitment', 'effectiveCommitment']) if (typeof sub[k] !== 'string') return `payload.subject.${k} is not a string`;
  const proof = pl.proof;
  if (!isObject(proof)) return 'payload.proof is not an object';
  for (const k of ['nonce', 'humanProofHash', 'agentProofHash', 'publicSignalsHash']) if (typeof proof[k] !== 'string') return `payload.proof.${k} is not a string`;
  if (r.receiptHash !== undefined && typeof r.receiptHash !== 'string') return 'receiptHash is not a string';
  if (pl.chain !== undefined) {
    if (!isObject(pl.chain)) return 'payload.chain is not an object';
    if (typeof pl.chain.seq !== 'number' || !Number.isInteger(pl.chain.seq) || pl.chain.seq < 0) return 'payload.chain.seq is not a non-negative integer';
    if (typeof pl.chain.prevReceiptHash !== 'string') return 'payload.chain.prevReceiptHash is not a string';
  }
  return null;
}

function lineOfIndex(parsed: ParsedReceipt[], index: number): string {
  return index < 0 ? '(log)' : String(parsed[index]?.line ?? `#${index}`);
}

/** A2, A3, A4b, A4c, A5, A6, A7b, A8a, A9a for one receipt, attributed or not. */
function payloadRows(p: ParsedReceipt, add: Add, attempt: number | undefined, action: ReturnType<typeof actionOf>): void {
  const line = p.line;
  const scope = attempt !== undefined ? { attempt } : { receiptLine: line };
  const ev = (path: string): Evidence[] => [{ file: RECEIPTS, line, path }];
  const signed = (claim: string, path: string, note: string) =>
    add({ claim, ...scope, status: p.verified ? 'SIGNED' : 'FAILED', evidence: ev(path), note: p.verified ? note : PAYLOAD_FAILED });

  const pl = p.receipt.payload;
  signed('A2', 'payload.decision.allowed', pl.decision.allowed ? 'allow' : 'deny');
  if (typeof pl.decision.reasonCode === 'string') signed('A3', 'payload.decision.reasonCode', `"${pl.decision.reasonCode}"`);
  else if (!p.verified) add({ claim: 'A3', ...scope, status: 'FAILED', evidence: ev('payload.decision.reasonCode'), note: PAYLOAD_FAILED });
  else add({ claim: 'A3', ...scope, status: 'ABSENT', evidence: [], note: 'the signed payload carries no reasonCode.' });

  const m = typeof pl.decision.reasonCode === 'string' ? DESCRIPTOR.exec(pl.decision.reasonCode) : null;
  if (!p.verified) {
    add({ claim: 'A4b', ...scope, status: 'FAILED', evidence: ev('payload.decision.reasonCode'), note: PAYLOAD_FAILED });
    if (attempt !== undefined) add({ claim: 'A4c', ...scope, status: 'FAILED', evidence: [], inputs: [`A4a@${attempt}`, `A4b@${attempt}`], note: PAYLOAD_FAILED });
  } else if (!m) {
    add({ claim: 'A4b', ...scope, status: 'ABSENT', evidence: [], note: 'the signed reason text carries no " | action=" descriptor.' });
    if (attempt !== undefined) add({ claim: 'A4c', ...scope, status: 'ABSENT', evidence: [], inputs: [`A4a@${attempt}`, `A4b@${attempt}`], note: 'nothing signed to compare against.' });
  } else {
    const [, name, method, host, path] = m;
    add({ claim: 'A4b', ...scope, status: 'DERIVED', evidence: ev('payload.decision.reasonCode'), inputs: ['rule: trailing " | action=<name> <METHOD> <host><path>"'], note: `${name} ${method} ${host}${path}` });
    if (attempt !== undefined) {
      if (!action) {
        add({ claim: 'A4c', ...scope, status: 'ABSENT', evidence: ev('payload.decision.reasonCode'), inputs: [`A4a@${attempt}`, `A4b@${attempt}`], note: 'summary.json records no complete action to compare against.' });
      } else {
        const agree = name === action.name && method === action.method && host === action.host && path === action.path;
        add({
          claim: 'A4c',
          ...scope,
          status: agree ? 'DERIVED' : 'FAILED',
          evidence: [{ file: SUMMARY, path: 'action' }, ...ev('payload.decision.reasonCode')],
          inputs: [`A4a@${attempt}`, `A4b@${attempt}`],
          note: agree ? 'the unsigned record and the signed descriptor name the same action.' : 'contradiction: the unsigned record and the signed descriptor disagree.',
        });
      }
    }
  }

  signed('A5', 'payload.subject', `rootDid ${pl.subject.rootDid}; actingDid ${pl.subject.actingDid}; commitments ${pl.subject.credentialCommitment} / ${pl.subject.effectiveCommitment}. Dev DIDs from a simulated credential; these identify a key material commitment, not a person or legal entity.`);

  // A6: the value is signed; the attempt-3 caveat is an implementation fact, stated separately and not controlled by any bundle field.
  let maskNote = `permissionBitmask ${pl.decision.permissionBitmask}.`;
  if (attempt === 3) {
    maskNote +=
      " Implementation note (not from the bundle): in the shipped trial, attempt 3 is the replay; the gateway's failure default for a replay is 0 because verification fails before tool policy runs, so a 0 here is not evidence that permissions were evaluated." +
      (pl.decision.permissionBitmask === '0' ? '' : ' This receipt records a non-zero mask, which the shipped trial would not produce for a replay.');
  }
  signed('A6', 'payload.decision.permissionBitmask', maskNote);

  if (attempt === 2) {
    const rm = p.verified && typeof pl.decision.reasonCode === 'string' ? REQUIRED_MASK.exec(pl.decision.reasonCode) : null;
    if (!p.verified) add({ claim: 'A7b', ...scope, status: 'FAILED', evidence: ev('payload.decision.reasonCode'), note: PAYLOAD_FAILED });
    else if (!rm) add({ claim: 'A7b', ...scope, status: 'ABSENT', evidence: [], note: 'the signed reason text reports no required mask.' });
    else add({ claim: 'A7b', ...scope, status: 'DERIVED', evidence: ev('payload.decision.reasonCode'), inputs: ['rule: "requires permissions <mask>, agent has <mask>" in the signed reason text'], note: `reported required ${rm[1]}, agent ${rm[2]}; this is what the host wrote into the reason, not the enforced configuration.` });
  }

  signed('A8a', 'payload.proof.nonce', `nonce ${pl.proof.nonce}`);
  signed('A9a', 'payload.proof', `humanProofHash ${pl.proof.humanProofHash}; agentProofHash ${pl.proof.agentProofHash}; publicSignalsHash ${pl.proof.publicSignalsHash}. Hashes only; see A9b.`);
}

/** Receipt-backed rows for an attempt whose A1 failed: FAILED, no payload values assigned. */
function unattributedRows(add: Add, attempt: number): void {
  const note = 'this attempt is not attributed to a receipt (A1); no payload value is assigned.';
  const claims = ['A2', 'A3', 'A4b', 'A4c', 'A5', 'A6', 'A8a', 'A9a', ...(attempt === 2 ? ['A7b'] : [])];
  for (const claim of claims) add({ claim, attempt, status: 'FAILED', evidence: [], inputs: [`A1@${attempt}`], note });
}
