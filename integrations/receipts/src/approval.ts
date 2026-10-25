/**
 * Approval-to-execution binding primitive
 * (docs/superpowers/specs/2026-10-25-approval-binding-design.md).
 *
 * Three pieces, all inside the signed payloads:
 *
 * 1. An approval receipt (`bolyra.approval`, scheme `bab1`) binds the reviewed
 *    action — requester, audience, tool, operation id — and a digest of the
 *    exact reviewed arguments, together with who approved it and when.
 * 2. `executeApproved` verifies that receipt immediately before dispatch and
 *    dispatches only the immutable argument snapshot it checked. It is the
 *    only path that dispatches; there is no standalone guard to misuse.
 * 3. An execution observation (`bolyra.execution`, scheme `beo1`) links to the
 *    approval receipt hash, the operation and attempt ids and the digest of the
 *    dispatched snapshot, and verifies offline with
 *    `verifyApprovalExecutionLink`.
 *
 * What this does NOT establish (the README repeats the list): verified human
 * identity because a name was signed; authorization correctness; downstream
 * commitment from dispatch; exactly-once execution; protection against
 * bypassing the hook; log completeness; live vendor integration. The receipt
 * records what the operator asserted was reviewed; it carries the argument
 * digest only, never the arguments.
 *
 * No function here logs, writes files or makes network calls.
 */

import * as secp256k1 from '@noble/secp256k1';
import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import { canonicalize } from './canonical';
import { computeReceiptHash } from './chain';
import { signReceipt, verifyReceipt } from './sign';
import type { ReceiptSignerConfig, SignedReceipt } from './types';


// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/** Domain-separation tag for the arguments digest, terminated by an explicit 0x00. */
export const ARGUMENTS_DIGEST_DST = 'bolyra.approval.arguments/1';
/** Maximum container nesting depth of the argument object (the root object is depth 1). */
export const ARGUMENTS_MAX_DEPTH = 64;
/** Maximum serialized size (UTF-8 bytes) of the argument text and of its canonical form. */
export const ARGUMENTS_MAX_BYTES = 1024 * 1024;

/** Fixed text returned with every link verification result. */
export const LINK_VERIFICATION_STATEMENT =
  'A PASS establishes only that the approval receipt and the execution observation are validly signed ' +
  'by the expected signers and that the observation links to that approval receipt, operation, context ' +
  'and argument digest. It does not establish human review, actual dispatch, consumption, response ' +
  'success, business-state freshness or committed effect.';

const ID_PATTERN = /^[\x21-\x7e]{1,256}$/;
const APPROVER_PATTERN = /^[\x20-\x7e]{1,256}$/;
const RFC3339_MS_Z = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/;
const HEX64 = /^[0-9a-f]{64}$/;
const HEX_0X64 = /^0x[0-9a-f]{64}$/;
const HEX_0X16 = /^0x[0-9a-f]{16}$/;
const ADDRESS_PATTERN = /^0x[0-9a-fA-F]{40}$/;
const SIGNATURE_VALUE_PATTERN = /^0x[0-9a-f]{130}$/;
const PRIVATE_KEY_PATTERN = /^(0x)?[0-9a-fA-F]{64}$/;
const FORBIDDEN_KEYS: ReadonlySet<string> = new Set(['__proto__', 'constructor', 'prototype']);
/** Exclusive upper bound for clock samples: Date.prototype.toISOString must yield a 4-digit year. */
const MAX_TIMESTAMP_MS = Date.UTC(10000, 0, 1);
/** Upper bound for any untrusted value echoed into a diagnostic detail. */
const MAX_DETAIL_CHARS = 120;

// ---------------------------------------------------------------------------
// Types — data model (§4)
// ---------------------------------------------------------------------------

export type JsonPrimitive = string | number | boolean | null;
export type JsonValue = JsonPrimitive | JsonValue[] | { [key: string]: JsonValue };
export type JsonObject = { [key: string]: JsonValue };

export interface ApprovalBinding {
  scheme: 'bab1';
  /** Identity that requested the action, as asserted by the operator. */
  requester: string;
  /** Execution audience: the server / system that will execute. */
  audience: string;
  /** Action / tool name. */
  tool: string;
  /** Operator-assigned, unique per operation. */
  operationId: string;
  /** computeArgumentsDigest() of the reviewed arguments (64 lowercase hex). */
  argumentsDigest: string;
}

export type ApprovalDecision = 'approved' | 'denied';

export type ApprovalValidity = { kind: 'once' } | { kind: 'until'; notAfter: string };

export interface ApprovalAssertion {
  /** Exactly as the approval source asserted it (printable ASCII, 1..256). */
  approver: string;
  /** Provenance label of the approval source. */
  source: string;
  decision: ApprovalDecision;
  /** RFC 3339 UTC with exactly 3-digit milliseconds and a Z suffix. */
  decidedAt: string;
  validity: ApprovalValidity;
  /** External approval-request identifier, verbatim. */
  requestId?: string;
}

export interface ApprovalReceiptPayload {
  v: 1;
  kind: 'bolyra.approval';
  /** Unix seconds. */
  issuedAt: number;
  issuer: string;
  keyId: string;
  binding: ApprovalBinding;
  approval: ApprovalAssertion;
}

export interface ExecutionFields {
  scheme: 'beo1';
  /** computeReceiptHash(approval receipt); verifiers recompute. */
  approvalReceiptHash: string;
  /** Approval envelope id; verifiers re-derive it from payloadHash. */
  approvalReceiptId: string;
  operationId: string;
  /** Operator-assigned per dispatch attempt. */
  attemptId: string;
  requester: string;
  audience: string;
  tool: string;
  /** computeArgumentsDigest() of the dispatched snapshot (same DST). */
  actionDigest: string;
  /** Captured immediately before invoking dispatch. */
  dispatchedAt: string;
  /** What the dispatch promise did — NOT a confirmed effect. */
  outcome: 'returned' | 'threw';
}

export interface ExecutionReceiptPayload {
  v: 1;
  kind: 'bolyra.execution';
  issuedAt: number;
  issuer: string;
  keyId: string;
  execution: ExecutionFields;
}

// ---------------------------------------------------------------------------
// Types — function interfaces (§5)
// ---------------------------------------------------------------------------

export interface ApprovalReceiptInput {
  /** Defaults to 1; any other value throws. */
  v?: 1;
  /** Defaults to 'bolyra.approval'; any other value throws. */
  kind?: 'bolyra.approval';
  /** Unix seconds; defaults to now. */
  issuedAt?: number;
  binding: {
    /** Defaults to 'bab1'; any other value throws. */
    scheme?: 'bab1';
    requester: string;
    audience: string;
    tool: string;
    operationId: string;
  };
  approval: ApprovalAssertion;
  /** The reviewed arguments as JSON text; only their digest enters the receipt. */
  argumentsJson: string;
}

export interface ApprovalContext {
  requester: string;
  audience: string;
  tool: string;
  operationId: string;
}

export interface ConsumeClaim {
  /** Recovered signer address, lowercase. Namespace the store by it. */
  signer: string;
  /** Full payloadHash of the approval receipt — the replay identity. */
  payloadHash: string;
  operationId: string;
}

/**
 * Operator-owned, atomic, durable claim across all executors. Only the literal
 * `true` permits dispatch. The guard cannot know whether the approved operation
 * already produced its effect; business-state checks belong to the operator and
 * must be made atomically with the mutation.
 */
export type ConsumeFn = (claim: ConsumeClaim) => boolean;

export type DispatchFn<R> = (
  snapshot: Readonly<JsonObject>,
  checkedContext: Readonly<ApprovalContext>,
) => R | Promise<R>;

export interface ExecuteApprovedParams {
  receipt: SignedReceipt<ApprovalReceiptPayload>;
  /** Address the approval receipt must recover to. Required, non-empty. */
  expectedSigner: string;
  context: ApprovalContext;
  argumentsJson: string;
  attemptId: string;
  /** Required for `once` receipts. */
  consume?: ConsumeFn;
  /** When present, a `bolyra.execution` observation is signed after settlement. */
  observer?: ReceiptSignerConfig;
  /** Defaults to `() => new Date()`. */
  clock?: () => Date;
}

export type BlockedExecutionCode =
  | 'malformed_input'
  | 'malformed_receipt'
  | 'wrong_kind'
  | 'keyid_mismatch'
  | 'signature_invalid'
  | 'untrusted_signer'
  | 'decision_not_approved'
  | 'future_decision'
  | 'expired'
  | 'context_mismatch'
  | 'arguments_out_of_domain'
  | 'arguments_mismatch'
  | 'consume_required'
  | 'consume_rejected'
  | 'observer_invalid'
  | 'invalid_clock';

export interface BlockedExecution {
  outcome: 'blocked';
  code: BlockedExecutionCode;
  detail: string;
}

export interface ReturnedExecution<R> {
  outcome: 'returned';
  value: R;
  observation?: SignedReceipt<ExecutionReceiptPayload>;
  observationError?: Error;
}

export type ApprovedExecution<R> = BlockedExecution | ReturnedExecution<R>;

/** The dispatch promise rejected (or dispatch threw). Carries the observation when one was signed. */
export class ApprovedExecutionError extends Error {
  readonly cause: unknown;
  readonly observation?: SignedReceipt<ExecutionReceiptPayload>;
  readonly observationError?: Error;

  constructor(
    cause: unknown,
    observation?: SignedReceipt<ExecutionReceiptPayload>,
    observationError?: Error,
  ) {
    super('approved dispatch threw');
    this.name = 'ApprovedExecutionError';
    this.cause = cause;
    if (observation !== undefined) this.observation = observation;
    if (observationError !== undefined) this.observationError = observationError;
  }
}

export type LinkCheckId = 'A1' | 'A2' | 'A3' | 'E1' | 'E2' | 'L1' | 'L2' | 'L3' | 'L4';

export interface LinkCheck {
  id: LinkCheckId;
  status: 'PASS' | 'FAIL';
  detail: string;
}

export interface LinkVerificationResult {
  ok: boolean;
  checks: LinkCheck[];
  statement: string;
}

export interface VerifyLinkParams {
  /** Untrusted input; validated as unknown. */
  approval: unknown;
  /** Untrusted input; validated as unknown. */
  observation: unknown;
  expectedApprovalSigner: string;
  expectedExecutionSigner: string;
}

export type ArgumentsValidation = { ok: true } | { ok: false; detail: string };

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

type Validation = { ok: true } | { ok: false; detail: string };

const OK: Validation = { ok: true };

function fail(detail: string): { ok: false; detail: string } {
  return { ok: false, detail };
}

function utf8(str: string): Uint8Array {
  return new TextEncoder().encode(str);
}

function joinPath(path: string, member: string): string {
  return path === '' ? member : `${path}.${member}`;
}

function isObjectLike(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function truncate(text: string): string {
  return text.length > MAX_DETAIL_CHARS ? text.slice(0, MAX_DETAIL_CHARS - 1) + '…' : text;
}

/**
 * Bounded, non-throwing rendering of an untrusted value for diagnostics. Never
 * invokes user code: no toString/valueOf/toJSON, no template interpolation of
 * symbols or null-prototype objects, no JSON.stringify of bigint or cycles.
 */
function formatUnknown(v: unknown): string {
  try {
    switch (typeof v) {
      case 'string':
        return truncate(JSON.stringify(v));
      case 'number':
      case 'boolean':
        return String(v);
      case 'undefined':
        return 'undefined';
      case 'bigint':
        return `${truncate(v.toString())}n (bigint)`;
      case 'symbol':
        return 'symbol';
      case 'function':
        return 'function';
      default:
        if (v === null) return 'null';
        return Array.isArray(v) ? 'array' : 'object';
    }
  } catch {
    return 'unprintable';
  }
}

/** Bounded, non-throwing message for a caught value (Error-like or anything else). */
/** Property read that never throws (revoked or trapping Proxies, throwing getters). */
function safeRead(target: unknown, key: string): unknown {
  try {
    return (target as Record<string, unknown>)[key];
  } catch {
    return undefined;
  }
}

function errorMessage(e: unknown): string {
  try {
    if (typeof e === 'object' && e !== null) {
      const message = safeRead(e, 'message');
      if (typeof message === 'string') {
        const name = safeRead(e, 'name');
        return truncate(typeof name === 'string' && name.length > 0 ? `${name}: ${message}` : message);
      }
    }
    return `non-Error value thrown: ${formatUnknown(e)}`;
  } catch {
    return 'unprintable error';
  }
}

/** Wraps a caught value into an Error without ever invoking its own conversion methods. */
function toError(e: unknown): Error {
  // `instanceof` runs prototype machinery: a revoked Proxy or a throwing
  // getPrototypeOf trap would throw here and break the settlement contract.
  try {
    if (e instanceof Error) return e;
  } catch {
    // fall through
  }
  return new Error(errorMessage(e));
}

function describe(v: unknown): string {
  return formatUnknown(v);
}

/** Strict RFC 3339 UTC-ms-Z: pattern plus an exact round-trip through Date. */
function parseRfc3339MsZ(value: unknown): number | undefined {
  if (typeof value !== 'string' || !RFC3339_MS_Z.test(value)) return undefined;
  const ms = Date.parse(value);
  if (!Number.isFinite(ms)) return undefined;
  if (new Date(ms).toISOString() !== value) return undefined;
  return ms;
}

/**
 * Closed-schema member check: unknown members are rejected first, then every
 * required member must be present. Presence is `in`, so a member explicitly
 * set to `undefined` is present and is rejected by its type check instead of
 * being silently dropped by JSON serialization.
 */
function checkMembers(
  obj: Record<string, unknown>,
  path: string,
  required: readonly string[],
  optional: readonly string[] = [],
): Validation {
  for (const key of Object.keys(obj)) {
    if (!required.includes(key) && !optional.includes(key)) {
      return fail(`unknown member "${joinPath(path, truncate(key))}" (closed schema)`);
    }
  }
  for (const key of required) {
    if (!(key in obj)) {
      return fail(`missing required member "${joinPath(path, key)}"`);
    }
  }
  return OK;
}

function checkId(obj: Record<string, unknown>, path: string, member: string): Validation {
  const v = obj[member];
  if (typeof v !== 'string' || !ID_PATTERN.test(v)) {
    return fail(
      `member "${joinPath(path, member)}" must be an id: printable ASCII excluding space (0x21..0x7E), 1..256 characters`,
    );
  }
  return OK;
}

function checkNonEmptyString(obj: Record<string, unknown>, path: string, member: string): Validation {
  const v = obj[member];
  if (typeof v !== 'string' || v.length === 0) {
    return fail(`member "${joinPath(path, member)}" must be a non-empty string`);
  }
  return OK;
}

function deepFreeze<T>(value: T): T {
  if (typeof value === 'object' && value !== null && !Object.isFrozen(value)) {
    Object.freeze(value);
    for (const key of Object.getOwnPropertyNames(value)) {
      deepFreeze((value as Record<string, unknown>)[key]);
    }
  }
  return value;
}

// ---------------------------------------------------------------------------
// §4.3 — bab1 argument domain and digest
// ---------------------------------------------------------------------------
//
// Arguments enter ONLY as JSON text. The validator runs on JSON.parse output,
// which can hold nothing but plain objects, dense arrays, strings, finite
// numbers, booleans and null, with own enumerable string-keyed data
// properties: no prototypes to forge, no accessors, no exotic objects, no
// shared references, no cycles. The value-type checks below are defense in
// depth, written with plain property access. JSON.parse collapses duplicate
// keys last-wins ({"a":1,"a":2} binds a:2); the digest binds the parsed
// object, not the text. JSON.parse("-0") IS -0 and is rejected.

type PathStack = Array<string | number>;

const SIZE_CAP_DETAIL = 'serialized size exceeds the 1 MiB cap';

function renderPath(stack: PathStack): string {
  let out = '$';
  for (const part of stack) out += typeof part === 'number' ? `[${part}]` : `.${truncate(part)}`;
  return out;
}

/**
 * Running lower bound of the canonical serialization size (two quotes plus at
 * least one byte per UTF-16 code unit for strings, exact for numbers, keys,
 * literals and punctuation). A lower bound never rejects data whose exact
 * canonical size fits; the exact check follows the walk.
 */
interface ByteCount {
  bytes: number;
}

function charge(count: ByteCount, bytes: number, stack: PathStack): string | undefined {
  count.bytes += bytes;
  return count.bytes > ARGUMENTS_MAX_BYTES ? `${SIZE_CAP_DETAIL} at ${renderPath(stack)}` : undefined;
}

function validateJsonNode(node: unknown, stack: PathStack, depth: number, count: ByteCount): string | undefined {
  switch (typeof node) {
    case 'string':
      return charge(count, node.length + 2, stack);
    case 'boolean':
      return charge(count, node ? 4 : 5, stack);
    case 'number':
      if (!Number.isFinite(node)) return `non-finite number at ${renderPath(stack)}`;
      if (Object.is(node, -0)) return `negative zero at ${renderPath(stack)}`;
      return charge(count, String(node).length, stack);
    case 'object':
      break;
    default:
      // undefined, function, symbol, bigint: unreachable from JSON.parse
      return `unsupported ${typeof node} at ${renderPath(stack)}`;
  }
  if (node === null) return charge(count, 4, stack);
  if (depth > ARGUMENTS_MAX_DEPTH) return `nesting depth exceeds ${ARGUMENTS_MAX_DEPTH} at ${renderPath(stack)}`;
  if (Array.isArray(node)) {
    let problem = charge(count, 2 + Math.max(0, node.length - 1), stack);
    if (problem) return problem;
    for (let i = 0; i < node.length; i++) {
      stack.push(i);
      problem = validateJsonNode(node[i], stack, depth + 1, count);
      stack.pop();
      if (problem) return problem;
    }
    return undefined;
  }
  // Object.keys lists the own "__proto__" property JSON.parse creates.
  const keys = Object.keys(node);
  let problem = charge(count, 2 + Math.max(0, keys.length - 1), stack);
  if (problem) return problem;
  for (const key of keys) {
    if (FORBIDDEN_KEYS.has(key)) return `forbidden key "${key}" at ${renderPath(stack)}`;
    problem = charge(count, key.length + 3, stack);
    if (problem) return problem;
    stack.push(key);
    problem = validateJsonNode((node as Record<string, unknown>)[key], stack, depth + 1, count);
    stack.pop();
    if (problem) return problem;
  }
  return undefined;
}

type AnalyzedArguments =
  | { ok: true; value: JsonObject; canonical: string }
  | { ok: false; detail: string };

/** Parse once (try/catch), validate the parsed tree, canonicalize, apply both size caps. */
function analyzeArgumentsJson(argumentsJson: unknown): AnalyzedArguments {
  if (typeof argumentsJson !== 'string') {
    return fail(`argumentsJson must be a string, got ${describe(argumentsJson)}`);
  }
  if (utf8(argumentsJson).length > ARGUMENTS_MAX_BYTES) {
    return fail('argument text exceeds the 1 MiB size cap');
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(argumentsJson);
  } catch (e) {
    return fail(`invalid JSON: ${errorMessage(e)}`);
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return fail(`arguments must be a JSON object, got ${describe(parsed)}`);
  }
  const problem = validateJsonNode(parsed, [], 1, { bytes: 0 });
  if (problem) return fail(problem);
  const canonical = canonicalize(parsed);
  if (utf8(canonical).length > ARGUMENTS_MAX_BYTES) {
    return fail(`canonical ${SIZE_CAP_DETAIL}`);
  }
  return { ok: true, value: parsed as JsonObject, canonical };
}

/**
 * bab1 domain check for argument JSON text: invalid JSON → ok:false with an
 * "invalid JSON" detail; otherwise the parsed tree must be a non-array object
 * whose values are objects, arrays, strings, finite numbers, booleans or null,
 * with no -0, no `__proto__`/`constructor`/`prototype` key at any depth,
 * nesting depth ≤ 64, text and canonical form ≤ 1 MiB.
 */
export function validateArgumentsJson(argumentsJson: string): ArgumentsValidation {
  const analyzed = analyzeArgumentsJson(argumentsJson);
  return analyzed.ok ? OK : fail(analyzed.detail);
}

function digestCanonical(canonical: string): string {
  const dst = utf8(ARGUMENTS_DIGEST_DST);
  const body = utf8(canonical);
  const input = new Uint8Array(dst.length + 1 + body.length);
  input.set(dst, 0);
  input[dst.length] = 0x00;
  input.set(body, dst.length + 1);
  return bytesToHex(sha256(input));
}

type ParsedArguments =
  | { ok: true; value: Readonly<JsonObject>; digest: string }
  | { ok: false; detail: string };

/** The deep-frozen parsed tree is the snapshot used for both the digest and dispatch. */
function parseArguments(argumentsJson: string): ParsedArguments {
  const analyzed = analyzeArgumentsJson(argumentsJson);
  if (!analyzed.ok) return analyzed;
  return { ok: true, value: deepFreeze(analyzed.value), digest: digestCanonical(analyzed.canonical) };
}

/**
 * argumentsDigest = sha256hex( utf8("bolyra.approval.arguments/1") || 0x00 || utf8(canonicalize(value)) )
 * where `value` is the parsed, bab1-validated argument object. Throws on
 * invalid JSON or out-of-domain values.
 */
export function computeArgumentsDigest(argumentsJson: string): string {
  if (typeof argumentsJson !== 'string') {
    throw new TypeError('computeArgumentsDigest: argumentsJson must be a string');
  }
  const parsed = parseArguments(argumentsJson);
  if (!parsed.ok) {
    throw new Error(`computeArgumentsDigest: ${parsed.detail}`);
  }
  return parsed.digest;
}

// ---------------------------------------------------------------------------
// Payload validators (closed schemas)
// ---------------------------------------------------------------------------

interface ApprovalTimes {
  decidedAtMs: number;
  notAfterMs?: number;
}

function validateApprovalPayloadMembers(payload: Record<string, unknown>, path: string): Validation {
  let r = checkMembers(payload, path, ['v', 'kind', 'issuedAt', 'issuer', 'keyId', 'binding', 'approval']);
  if (!r.ok) return r;
  if (payload.v !== 1) return fail(`member "${joinPath(path, 'v')}" must be 1`);
  if (payload.kind !== 'bolyra.approval') return fail(`member "${joinPath(path, 'kind')}" must be "bolyra.approval"`);
  if (!Number.isSafeInteger(payload.issuedAt) || (payload.issuedAt as number) < 0) {
    return fail(`member "${joinPath(path, 'issuedAt')}" must be a non-negative integer (unix seconds)`);
  }
  r = checkNonEmptyString(payload, path, 'issuer');
  if (!r.ok) return r;
  r = checkNonEmptyString(payload, path, 'keyId');
  if (!r.ok) return r;

  const bindingPath = joinPath(path, 'binding');
  const binding = payload.binding;
  if (!isObjectLike(binding)) return fail(`member "${bindingPath}" must be an object`);
  r = checkMembers(binding, bindingPath, ['scheme', 'requester', 'audience', 'tool', 'operationId', 'argumentsDigest']);
  if (!r.ok) return r;
  if (binding.scheme !== 'bab1') return fail(`member "${joinPath(bindingPath, 'scheme')}" must be "bab1"`);
  for (const member of ['requester', 'audience', 'tool', 'operationId']) {
    r = checkId(binding, bindingPath, member);
    if (!r.ok) return r;
  }
  if (typeof binding.argumentsDigest !== 'string' || !HEX64.test(binding.argumentsDigest)) {
    return fail(`member "${joinPath(bindingPath, 'argumentsDigest')}" must be 64 lowercase hex characters`);
  }

  return validateApprovalAssertion(payload.approval, joinPath(path, 'approval'));
}

function validateApprovalAssertion(approval: unknown, path: string): Validation {
  if (!isObjectLike(approval)) return fail(`member "${path}" must be an object`);
  let r = checkMembers(approval, path, ['approver', 'source', 'decision', 'decidedAt', 'validity'], ['requestId']);
  if (!r.ok) return r;
  if (typeof approval.approver !== 'string' || !APPROVER_PATTERN.test(approval.approver)) {
    return fail(`member "${joinPath(path, 'approver')}" must be printable ASCII (0x20..0x7E), 1..256 characters`);
  }
  r = checkId(approval, path, 'source');
  if (!r.ok) return r;
  if (approval.decision !== 'approved' && approval.decision !== 'denied') {
    return fail(`member "${joinPath(path, 'decision')}" must be "approved" or "denied"`);
  }
  if (parseRfc3339MsZ(approval.decidedAt) === undefined) {
    return fail(`member "${joinPath(path, 'decidedAt')}" must match YYYY-MM-DDTHH:MM:SS.mmmZ exactly (3-digit ms, UTC Z)`);
  }
  const validityPath = joinPath(path, 'validity');
  const validity = approval.validity;
  if (!isObjectLike(validity)) return fail(`member "${validityPath}" must be an object`);
  if (validity.kind === 'once') {
    r = checkMembers(validity, validityPath, ['kind']);
    if (!r.ok) return r;
  } else if (validity.kind === 'until') {
    r = checkMembers(validity, validityPath, ['kind', 'notAfter']);
    if (!r.ok) return r;
    if (parseRfc3339MsZ(validity.notAfter) === undefined) {
      return fail(`member "${joinPath(validityPath, 'notAfter')}" must match YYYY-MM-DDTHH:MM:SS.mmmZ exactly (3-digit ms, UTC Z)`);
    }
  } else {
    return fail(`member "${joinPath(validityPath, 'kind')}" must be "once" or "until"`);
  }
  if ('requestId' in approval) {
    r = checkId(approval, path, 'requestId');
    if (!r.ok) return r;
  }
  return OK;
}

function approvalTimes(payload: ApprovalReceiptPayload): ApprovalTimes {
  const decidedAtMs = parseRfc3339MsZ(payload.approval.decidedAt) as number;
  const validity = payload.approval.validity;
  return validity.kind === 'until'
    ? { decidedAtMs, notAfterMs: parseRfc3339MsZ(validity.notAfter) as number }
    : { decidedAtMs };
}

function validateExecutionPayloadMembers(payload: Record<string, unknown>, path: string): Validation {
  let r = checkMembers(payload, path, ['v', 'kind', 'issuedAt', 'issuer', 'keyId', 'execution']);
  if (!r.ok) return r;
  if (payload.v !== 1) return fail(`member "${joinPath(path, 'v')}" must be 1`);
  if (payload.kind !== 'bolyra.execution') return fail(`member "${joinPath(path, 'kind')}" must be "bolyra.execution"`);
  if (!Number.isSafeInteger(payload.issuedAt) || (payload.issuedAt as number) < 0) {
    return fail(`member "${joinPath(path, 'issuedAt')}" must be a non-negative integer (unix seconds)`);
  }
  r = checkNonEmptyString(payload, path, 'issuer');
  if (!r.ok) return r;
  r = checkNonEmptyString(payload, path, 'keyId');
  if (!r.ok) return r;

  const execPath = joinPath(path, 'execution');
  const exec = payload.execution;
  if (!isObjectLike(exec)) return fail(`member "${execPath}" must be an object`);
  r = checkMembers(exec, execPath, [
    'scheme',
    'approvalReceiptHash',
    'approvalReceiptId',
    'operationId',
    'attemptId',
    'requester',
    'audience',
    'tool',
    'actionDigest',
    'dispatchedAt',
    'outcome',
  ]);
  if (!r.ok) return r;
  if (exec.scheme !== 'beo1') return fail(`member "${joinPath(execPath, 'scheme')}" must be "beo1"`);
  if (typeof exec.approvalReceiptHash !== 'string' || !HEX_0X64.test(exec.approvalReceiptHash)) {
    return fail(`member "${joinPath(execPath, 'approvalReceiptHash')}" must be 0x + 64 lowercase hex characters`);
  }
  if (typeof exec.approvalReceiptId !== 'string' || !HEX_0X16.test(exec.approvalReceiptId)) {
    return fail(`member "${joinPath(execPath, 'approvalReceiptId')}" must be 0x + 16 lowercase hex characters`);
  }
  for (const member of ['operationId', 'attemptId', 'requester', 'audience', 'tool']) {
    r = checkId(exec, execPath, member);
    if (!r.ok) return r;
  }
  if (typeof exec.actionDigest !== 'string' || !HEX64.test(exec.actionDigest)) {
    return fail(`member "${joinPath(execPath, 'actionDigest')}" must be 64 lowercase hex characters`);
  }
  if (parseRfc3339MsZ(exec.dispatchedAt) === undefined) {
    return fail(`member "${joinPath(execPath, 'dispatchedAt')}" must match YYYY-MM-DDTHH:MM:SS.mmmZ exactly (3-digit ms, UTC Z)`);
  }
  if (exec.outcome !== 'returned' && exec.outcome !== 'threw') {
    return fail(`member "${joinPath(execPath, 'outcome')}" must be "returned" or "threw"`);
  }
  return OK;
}

type EnvelopeCode = 'malformed_receipt' | 'wrong_kind' | 'keyid_mismatch';

type EnvelopeValidation<P> =
  | { ok: true; receipt: SignedReceipt<P> }
  | { ok: false; code: EnvelopeCode; detail: string };

/**
 * Structural validation of a signed envelope of one of the new kinds: closed
 * schema at every level, kind, v, scheme, envelope/payload keyId agreement,
 * signature alg and byte lengths, derived id. Signature VALIDITY is a
 * separate step (verifyReceipt).
 */
function validateEnvelope<P>(
  value: unknown,
  kind: 'bolyra.approval' | 'bolyra.execution',
  validatePayload: (payload: Record<string, unknown>, path: string) => Validation,
): EnvelopeValidation<P> {
  const bad = (detail: string): EnvelopeValidation<P> => ({ ok: false, code: 'malformed_receipt', detail });
  if (!isObjectLike(value)) return bad(`receipt must be an object, got ${describe(value)}`);
  let r = checkMembers(value, '', ['id', 'payload', 'signature']);
  if (!r.ok) return bad(r.detail);
  const payload = value.payload;
  if (!isObjectLike(payload)) return bad('member "payload" must be an object');
  if (payload.kind !== kind) {
    return { ok: false, code: 'wrong_kind', detail: `expected payload.kind "${kind}", got ${formatUnknown(payload.kind)}` };
  }
  r = validatePayload(payload, 'payload');
  if (!r.ok) return bad(r.detail);

  const signature = value.signature;
  if (!isObjectLike(signature)) return bad('member "signature" must be an object');
  r = checkMembers(signature, 'signature', ['alg', 'keyId', 'signer', 'payloadHash', 'value']);
  if (!r.ok) return bad(r.detail);
  if (typeof signature.keyId !== 'string') return bad('member "signature.keyId" must be a string');
  if (signature.keyId !== payload.keyId) {
    return {
      ok: false,
      code: 'keyid_mismatch',
      detail: `envelope signature.keyId ${formatUnknown(signature.keyId)} differs from payload.keyId ${formatUnknown(payload.keyId)}`,
    };
  }
  if (signature.alg !== 'ES256K') return bad('member "signature.alg" must be "ES256K"');
  if (typeof signature.signer !== 'string' || !ADDRESS_PATTERN.test(signature.signer)) {
    return bad('member "signature.signer" must be a 20-byte 0x-prefixed hex address');
  }
  if (typeof signature.payloadHash !== 'string' || !HEX_0X64.test(signature.payloadHash)) {
    return bad('member "signature.payloadHash" must be 0x + 64 lowercase hex characters (32 bytes)');
  }
  if (typeof signature.value !== 'string' || !SIGNATURE_VALUE_PATTERN.test(signature.value)) {
    return bad('member "signature.value" must be 0x + 130 lowercase hex characters (65 bytes r||s||v)');
  }
  if (typeof value.id !== 'string' || value.id !== '0x' + signature.payloadHash.slice(2, 18)) {
    return bad('envelope id does not equal the id derived from signature.payloadHash');
  }
  return { ok: true, receipt: value as unknown as SignedReceipt<P> };
}

function validateApprovalEnvelope(value: unknown): EnvelopeValidation<ApprovalReceiptPayload> {
  return validateEnvelope<ApprovalReceiptPayload>(value, 'bolyra.approval', validateApprovalPayloadMembers);
}

function validateExecutionEnvelope(value: unknown): EnvelopeValidation<ExecutionReceiptPayload> {
  return validateEnvelope<ExecutionReceiptPayload>(value, 'bolyra.execution', validateExecutionPayloadMembers);
}

function validateSignerConfig(value: unknown, path: string): Validation {
  if (!isObjectLike(value)) return fail(`${path} must be an object with issuer, keyId and privateKey`);
  let r = checkNonEmptyString(value, path, 'issuer');
  if (!r.ok) return r;
  r = checkNonEmptyString(value, path, 'keyId');
  if (!r.ok) return r;
  const key = value.privateKey;
  if (typeof key !== 'string' || !PRIVATE_KEY_PATTERN.test(key)) {
    return fail(`member "${joinPath(path, 'privateKey')}" must be a 32-byte hex-encoded secp256k1 private key`);
  }
  const clean = key.startsWith('0x') ? key.slice(2) : key;
  if (!secp256k1.utils.isValidPrivateKey(clean)) {
    return fail(`member "${joinPath(path, 'privateKey')}" is not a valid secp256k1 private key`);
  }
  return OK;
}

// ---------------------------------------------------------------------------
// §5.2 — createApprovalReceipt
// ---------------------------------------------------------------------------

/**
 * Validates every member of `input` and the bab1 domain of `argumentsJson`,
 * computes the digest, builds the §4.1 payload and signs it. Throws on any
 * invalid input, naming the first offending member. Provenance (`approver`,
 * `source`, `decidedAt`, `decision`, `validity`) is never defaulted; only the
 * fixed discriminators (`v`, `kind`, `scheme`) and `issuedAt` have defaults.
 */
export function createApprovalReceipt(
  input: ApprovalReceiptInput,
  signerConfig: ReceiptSignerConfig,
): SignedReceipt<ApprovalReceiptPayload> {
  const throwOn = (r: Validation): void => {
    if (!r.ok) throw new Error(`createApprovalReceipt: ${r.detail}`);
  };
  throwOn(validateSignerConfig(signerConfig, 'signerConfig'));
  if (!isObjectLike(input)) throw new Error(`createApprovalReceipt: input must be an object, got ${describe(input)}`);

  throwOn(checkMembers(input, '', ['binding', 'approval', 'argumentsJson'], ['v', 'kind', 'issuedAt']));
  if ('v' in input && input.v !== 1) throwOn(fail('member "v" must be 1'));
  if ('kind' in input && input.kind !== 'bolyra.approval') throwOn(fail('member "kind" must be "bolyra.approval"'));
  let issuedAt: number;
  if ('issuedAt' in input) {
    if (!Number.isSafeInteger(input.issuedAt) || (input.issuedAt as number) < 0) {
      throwOn(fail('member "issuedAt" must be a non-negative integer (unix seconds)'));
    }
    issuedAt = input.issuedAt as number;
  } else {
    issuedAt = Math.floor(Date.now() / 1000);
  }

  const binding = input.binding as unknown;
  if (!isObjectLike(binding)) throwOn(fail('member "binding" must be an object'));
  throwOn(
    checkMembers(binding as Record<string, unknown>, 'binding', ['requester', 'audience', 'tool', 'operationId'], ['scheme']),
  );
  const b = binding as Record<string, unknown>;
  if ('scheme' in b && b.scheme !== 'bab1') throwOn(fail('member "binding.scheme" must be "bab1"'));

  if (typeof input.argumentsJson !== 'string') throwOn(fail('member "argumentsJson" must be a string'));
  const parsed = parseArguments(input.argumentsJson);
  if (!parsed.ok) throwOn(fail(`member "argumentsJson": ${parsed.detail}`));
  const digest = (parsed as { ok: true; digest: string }).digest;

  for (const member of ['requester', 'audience', 'tool', 'operationId']) {
    throwOn(checkId(b, 'binding', member));
  }

  // The approval block is the same closed schema inside the payload; validate
  // the caller's object before copying it member by member.
  throwOn(validateApprovalAssertion(input.approval, 'approval'));
  const a = input.approval;
  const validity: ApprovalValidity =
    a.validity.kind === 'until' ? { kind: 'until', notAfter: a.validity.notAfter } : { kind: 'once' };

  const payload: ApprovalReceiptPayload = {
    v: 1,
    kind: 'bolyra.approval',
    issuedAt,
    issuer: signerConfig.issuer,
    keyId: signerConfig.keyId,
    binding: {
      scheme: 'bab1',
      requester: b.requester as string,
      audience: b.audience as string,
      tool: b.tool as string,
      operationId: b.operationId as string,
      argumentsDigest: digest,
    },
    approval: {
      approver: a.approver,
      source: a.source,
      decision: a.decision,
      decidedAt: a.decidedAt,
      validity,
      ...(a.requestId !== undefined ? { requestId: a.requestId } : {}),
    },
  };

  // The emitter never produces what the verifier would reject.
  throwOn(validateApprovalPayloadMembers(payload as unknown as Record<string, unknown>, ''));
  const signed = signReceipt(payload, signerConfig);
  const envelope = validateApprovalEnvelope(signed);
  if (!envelope.ok) throw new Error(`createApprovalReceipt: produced an invalid envelope: ${envelope.detail}`);
  return signed;
}

// ---------------------------------------------------------------------------
// §5.3 — executeApproved
// ---------------------------------------------------------------------------

function blocked(code: BlockedExecutionCode, detail: string): BlockedExecution {
  return { outcome: 'blocked', code, detail };
}

/**
 * Sample the captured clock: epoch ms via Date.prototype.getTime.call, or
 * undefined when the clock throws, returns a non-Date, an invalid Date, or a
 * time outside the observation timestamp domain (0 <= ms < year 10000, so
 * toISOString yields a 4-digit year and issuedAt is a non-negative integer).
 */
function sampleClock(clock: () => Date): number | undefined {
  try {
    const t = Date.prototype.getTime.call(clock());
    if (typeof t !== 'number' || !Number.isFinite(t)) return undefined;
    if (t < 0 || t >= MAX_TIMESTAMP_MS) return undefined;
    return t;
  } catch {
    return undefined;
  }
}

const INVALID_CLOCK_DETAIL =
  'clock threw, did not return a valid Date, or returned a time outside 1970-01-01T00:00:00.000Z..9999-12-31T23:59:59.999Z';

/** Attach a no-op sink to a thenable so a rejected consume result never surfaces as an unhandled rejection. Never awaits. */
function sinkThenable(v: unknown): boolean {
  try {
    if ((typeof v === 'object' && v !== null) || typeof v === 'function') {
      const then = (v as { then?: unknown }).then;
      if (typeof then === 'function') {
        const noop = (): void => undefined;
        (then as (a: () => void, b: () => void) => unknown).call(v, noop, noop);
        return true;
      }
    }
  } catch {
    return true;
  }
  return false;
}

function temporalCheck(nowMs: number, times: ApprovalTimes, label: string): BlockedExecution | undefined {
  if (times.decidedAtMs > nowMs) {
    return blocked('future_decision', `decidedAt is after the ${label} clock sample`);
  }
  if (times.notAfterMs !== undefined && nowMs >= times.notAfterMs) {
    return blocked('expired', `${label} clock sample is at or after validity.notAfter`);
  }
  return undefined;
}

/**
 * State retained across dispatch for observation signing. Deliberately holds
 * NO callbacks: a callback stored here and invoked as a method would receive
 * this object (observer private key, snapshot, receipt) as `this`. The object
 * is frozen; its members are already deep-frozen or cloned.
 */
interface PreparedDispatch {
  readonly outcome: 'prepared';
  snapshot: Readonly<JsonObject>;
  checkedContext: Readonly<ApprovalContext>;
  receipt: SignedReceipt<ApprovalReceiptPayload>;
  observer: ReceiptSignerConfig | undefined;
  attemptId: string;
  td: number;
  dispatchedAt: string;
}

/**
 * Steps 1–6a of §5.3, fully synchronous: everything that must happen before
 * dispatch, with every caller-controlled read guarded. Any failure here is a
 * typed blocked result; nothing in here may dispatch.
 */
function prepareDispatch(params: ExecuteApprovedParams, dispatch: unknown): BlockedExecution | PreparedDispatch {
  // ----- Step 1: capture and snapshot once, before any other read ---------
  if (!isObjectLike(params)) {
    return blocked('malformed_input', `params must be an object, got ${describe(params)}`);
  }
  let rawReceipt: unknown;
  let rawExpectedSigner: unknown;
  let rawContext: unknown;
  let argumentsJson: unknown;
  let attemptId: unknown;
  let consume: unknown;
  let rawObserver: unknown;
  let rawClock: unknown;
  try {
    rawReceipt = params.receipt;
    rawExpectedSigner = params.expectedSigner;
    rawContext = params.context;
    argumentsJson = params.argumentsJson;
    attemptId = params.attemptId;
    consume = params.consume;
    rawObserver = params.observer;
    rawClock = params.clock;
  } catch (e) {
    return blocked('malformed_input', `reading params threw: ${errorMessage(e)}`);
  }

  if (typeof dispatch !== 'function') return blocked('malformed_input', 'dispatch must be a function');
  if (typeof argumentsJson !== 'string') return blocked('malformed_input', 'argumentsJson must be a string');
  if (typeof attemptId !== 'string' || !ID_PATTERN.test(attemptId)) {
    return blocked('malformed_input', 'attemptId must be an id: printable ASCII excluding space (0x21..0x7E), 1..256 characters');
  }
  if (consume !== undefined && typeof consume !== 'function') {
    return blocked('malformed_input', 'consume must be a function when provided');
  }
  if (rawClock !== undefined && typeof rawClock !== 'function') {
    return blocked('malformed_input', 'clock must be a function when provided');
  }
  if (typeof rawExpectedSigner !== 'string' || rawExpectedSigner.length === 0) {
    return blocked('malformed_input', 'expectedSigner must be a non-empty string');
  }
  const clock: () => Date = rawClock === undefined ? () => new Date() : (rawClock as () => Date);
  const consumeFn = consume as ConsumeFn | undefined;

  let receiptSnapshot: unknown;
  let contextSnapshot: unknown;
  let observerSnapshot: unknown;
  let expectedSigner: string;
  try {
    receiptSnapshot = structuredClone(rawReceipt);
    contextSnapshot = structuredClone(rawContext);
    observerSnapshot = rawObserver === undefined ? undefined : structuredClone(rawObserver);
    expectedSigner = structuredClone(rawExpectedSigner);
  } catch (e) {
    return blocked('malformed_input', `params are not structured-cloneable: ${errorMessage(e)}`);
  }

  if (!isObjectLike(contextSnapshot)) {
    return blocked('malformed_input', `context must be an object, got ${describe(contextSnapshot)}`);
  }
  {
    let r = checkMembers(contextSnapshot, 'context', ['requester', 'audience', 'tool', 'operationId']);
    if (!r.ok) return blocked('malformed_input', r.detail);
    for (const member of ['requester', 'audience', 'tool', 'operationId']) {
      r = checkId(contextSnapshot, 'context', member);
      if (!r.ok) return blocked('malformed_input', r.detail);
    }
  }
  const checkedContext = deepFreeze(contextSnapshot as unknown as ApprovalContext);

  const parsed = parseArguments(argumentsJson);
  if (!parsed.ok) return blocked('arguments_out_of_domain', parsed.detail);
  const snapshot = parsed.value;
  const snapshotDigest = parsed.digest;

  // ----- Step 2: observer preflight, before anything is consumed ----------
  if (observerSnapshot !== undefined) {
    const r = validateSignerConfig(observerSnapshot, 'observer');
    if (!r.ok) return blocked('observer_invalid', r.detail);
  }
  const observer = observerSnapshot as ReceiptSignerConfig | undefined;

  // ----- Step 3: validate the receipt against the snapshots ---------------
  const envelope = validateApprovalEnvelope(receiptSnapshot);
  if (!envelope.ok) return blocked(envelope.code, envelope.detail);
  const receipt = deepFreeze(envelope.receipt);
  if (!verifyReceipt(receipt)) {
    return blocked('signature_invalid', 'ES256K signature does not verify against the payload and claimed signer');
  }
  if (!verifyReceipt(receipt, expectedSigner)) {
    return blocked('untrusted_signer', `receipt signer ${receipt.signature.signer} is not the expected signer`);
  }
  if (receipt.payload.approval.decision !== 'approved') {
    return blocked('decision_not_approved', `approval decision is "${receipt.payload.approval.decision}"`);
  }
  for (const member of ['requester', 'audience', 'tool', 'operationId'] as const) {
    if (receipt.payload.binding[member] !== checkedContext[member]) {
      return blocked('context_mismatch', `binding.${member} does not equal context.${member}`);
    }
  }
  if (receipt.payload.binding.argumentsDigest !== snapshotDigest) {
    return blocked('arguments_mismatch', 'argumentsDigest does not equal the digest of the supplied arguments');
  }
  const times = approvalTimes(receipt.payload);

  // ----- Step 4: first clock sample -----------------------------------------
  const t0 = sampleClock(clock);
  if (t0 === undefined) return blocked('invalid_clock', `${INVALID_CLOCK_DETAIL} (t0)`);
  const t0Problem = temporalCheck(t0, times, 'first');
  if (t0Problem) return t0Problem;

  // ----- Step 5: consumption (once receipts only) ---------------------------
  if (receipt.payload.approval.validity.kind === 'once') {
    if (consumeFn === undefined) {
      return blocked('consume_required', 'a once receipt requires a consume callback');
    }
    const claim: ConsumeClaim = Object.freeze({
      signer: receipt.signature.signer.toLowerCase(),
      payloadHash: receipt.signature.payloadHash,
      operationId: receipt.payload.binding.operationId,
    });
    let decision: unknown;
    try {
      decision = consumeFn(claim);
    } catch (e) {
      return blocked('consume_rejected', `consume threw: ${errorMessage(e)}`);
    }
    if (decision !== true) {
      // A thenable (Promise or foreign) is never awaited and never authorizes;
      // sink its eventual rejection so blocking does not leak an unhandled one.
      const thenable = sinkThenable(decision);
      return blocked(
        'consume_rejected',
        `consume did not return the literal true (got ${thenable ? 'a thenable' : describe(decision)})`,
      );
    }
  }

  // ----- Step 6a: second clock sample -----------------------------------------
  const td = sampleClock(clock);
  if (td === undefined) return blocked('invalid_clock', `${INVALID_CLOCK_DETAIL} (td)`);
  const tdProblem = temporalCheck(td, times, 'second');
  if (tdProblem) return tdProblem;
  const dispatchedAt = new Date(td).toISOString();

  return Object.freeze({
    outcome: 'prepared' as const,
    snapshot,
    checkedContext,
    receipt,
    observer,
    attemptId,
    td,
    dispatchedAt,
  });
}

/**
 * The only path that dispatches. Follows spec §5.3 steps 1–7 in order:
 * snapshot once, preflight the observer, validate the receipt against the
 * snapshots, sample the clock, consume (once receipts), re-check the clock and
 * dispatch the frozen snapshot, then sign the observation.
 *
 * Result contract: any failure before dispatch — including an unexpected
 * exception — resolves to a typed blocked result and dispatch is never called.
 * After dispatch the result is always `returned` or an ApprovedExecutionError
 * rejection carrying the original cause; an observation failure of any kind
 * is reported as `observationError` and never changes the settlement.
 */
export async function executeApproved<R>(
  params: ExecuteApprovedParams,
  dispatch: DispatchFn<R>,
): Promise<ApprovedExecution<R>> {
  // Captured once, as a local: invoked below as a bare function (`this` is
  // undefined), never as a method of any internal object.
  const dispatchFn = dispatch;
  let prepared: PreparedDispatch;
  try {
    const outcome = prepareDispatch(params, dispatchFn);
    if (outcome.outcome === 'blocked') return outcome;
    prepared = outcome;
  } catch (e) {
    // Fail closed: nothing has been dispatched, so a typed block is always correct.
    return blocked('malformed_input', `unexpected failure before dispatch: ${errorMessage(e)}`);
  }

  // ----- Step 6b: dispatch immediately, no await between validation and call --
  let settlement: { outcome: 'returned'; value: R } | { outcome: 'threw'; cause: unknown };
  try {
    const value = await dispatchFn(prepared.snapshot, prepared.checkedContext);
    settlement = { outcome: 'returned', value };
  } catch (cause) {
    settlement = { outcome: 'threw', cause };
  }

  // ----- Step 7: observation (never alters the settlement) --------------------
  let observation: SignedReceipt<ExecutionReceiptPayload> | undefined;
  let observationError: Error | undefined;
  if (prepared.observer !== undefined) {
    try {
      const { receipt, checkedContext, observer } = prepared;
      const payload: ExecutionReceiptPayload = {
        v: 1,
        kind: 'bolyra.execution',
        issuedAt: Math.floor(prepared.td / 1000),
        issuer: observer.issuer,
        keyId: observer.keyId,
        execution: {
          scheme: 'beo1',
          approvalReceiptHash: computeReceiptHash(receipt),
          approvalReceiptId: receipt.id,
          operationId: checkedContext.operationId,
          attemptId: prepared.attemptId,
          requester: checkedContext.requester,
          audience: checkedContext.audience,
          tool: checkedContext.tool,
          actionDigest: digestCanonical(canonicalize(prepared.snapshot)),
          dispatchedAt: prepared.dispatchedAt,
          outcome: settlement.outcome,
        },
      };
      observation = signReceipt(payload, observer);
    } catch (e) {
      observationError = toError(e);
    }
  }

  if (settlement.outcome === 'returned') {
    const result: ReturnedExecution<R> = { outcome: 'returned', value: settlement.value };
    if (observation !== undefined) result.observation = observation;
    if (observationError !== undefined) result.observationError = observationError;
    return result;
  }
  throw new ApprovedExecutionError(settlement.cause, observation, observationError);
}

// ---------------------------------------------------------------------------
// §5.5 — verifyApprovalExecutionLink
// ---------------------------------------------------------------------------

const LINK_CHECK_IDS: readonly LinkCheckId[] = ['A1', 'A2', 'A3', 'E1', 'E2', 'L1', 'L2', 'L3', 'L4'];

/**
 * Offline, pure link verification. Always reports all nine checks; a check
 * whose prerequisite failed is reported FAIL as "not evaluated". Never throws:
 * hostile inputs (cycles, bigint, throwing getters) yield FAIL checks.
 */
export function verifyApprovalExecutionLink(params: VerifyLinkParams): LinkVerificationResult {
  try {
    return verifyLinkChecked(params);
  } catch (e) {
    const detail = `verification aborted: ${errorMessage(e)}`;
    return {
      ok: false,
      checks: LINK_CHECK_IDS.map((id) => ({ id, status: 'FAIL', detail })),
      statement: LINK_VERIFICATION_STATEMENT,
    };
  }
}

function verifyLinkChecked(params: VerifyLinkParams): LinkVerificationResult {
  const checks: LinkCheck[] = [];
  const pass = (id: LinkCheckId, detail: string): void => {
    checks.push({ id, status: 'PASS', detail });
  };
  const failCheck = (id: LinkCheckId, detail: string): void => {
    checks.push({ id, status: 'FAIL', detail });
  };
  const notEvaluated = (id: LinkCheckId, dependsOn: string): void => {
    failCheck(id, `not evaluated: ${dependsOn} failed`);
  };

  let expectedApprovalSigner: unknown;
  let expectedExecutionSigner: unknown;
  let approvalClone: unknown;
  let observationClone: unknown;
  let approvalCloneError: string | undefined;
  let observationCloneError: string | undefined;
  if (!isObjectLike(params)) {
    approvalCloneError = observationCloneError = `params must be an object, got ${describe(params)}`;
  } else {
    try {
      expectedApprovalSigner = params.expectedApprovalSigner;
      expectedExecutionSigner = params.expectedExecutionSigner;
      approvalClone = structuredClone(params.approval);
    } catch (e) {
      approvalCloneError = `approval could not be read or cloned: ${errorMessage(e)}`;
    }
    try {
      observationClone = structuredClone(params.observation);
    } catch (e) {
      observationCloneError = `observation could not be read or cloned: ${errorMessage(e)}`;
    }
  }

  // A1
  let approval: SignedReceipt<ApprovalReceiptPayload> | undefined;
  if (approvalCloneError !== undefined) {
    failCheck('A1', approvalCloneError);
  } else {
    const a = validateApprovalEnvelope(approvalClone);
    if (a.ok) {
      approval = a.receipt;
      pass('A1', 'approval receipt: closed schema, kind, scheme, keyId agreement and derived id hold');
    } else {
      failCheck('A1', `approval receipt ${a.code}: ${a.detail}`);
    }
  }

  // A2
  if (!approval) {
    notEvaluated('A2', 'A1');
  } else if (typeof expectedApprovalSigner !== 'string' || expectedApprovalSigner.length === 0) {
    failCheck('A2', 'expectedApprovalSigner must be a non-empty string');
  } else if (!verifyReceipt(approval)) {
    failCheck('A2', 'approval signature does not verify');
  } else if (!verifyReceipt(approval, expectedApprovalSigner)) {
    failCheck('A2', `approval signer ${approval.signature.signer} is not the expected approval signer`);
  } else {
    pass('A2', `approval signature valid; signer ${approval.signature.signer} is the expected approval signer`);
  }

  // A3
  if (!approval) {
    notEvaluated('A3', 'A1');
  } else if (approval.payload.approval.decision !== 'approved') {
    failCheck('A3', `approval decision is "${approval.payload.approval.decision}"`);
  } else {
    pass('A3', 'approval decision is "approved"');
  }

  // E1
  let observation: SignedReceipt<ExecutionReceiptPayload> | undefined;
  if (observationCloneError !== undefined) {
    failCheck('E1', observationCloneError);
  } else {
    const o = validateExecutionEnvelope(observationClone);
    if (o.ok) {
      observation = o.receipt;
      pass('E1', 'execution observation: closed schema, kind, scheme, keyId agreement and derived id hold');
    } else {
      failCheck('E1', `execution observation ${o.code}: ${o.detail}`);
    }
  }

  // E2
  if (!observation) {
    notEvaluated('E2', 'E1');
  } else if (typeof expectedExecutionSigner !== 'string' || expectedExecutionSigner.length === 0) {
    failCheck('E2', 'expectedExecutionSigner must be a non-empty string');
  } else if (!verifyReceipt(observation)) {
    failCheck('E2', 'observation signature does not verify');
  } else if (!verifyReceipt(observation, expectedExecutionSigner)) {
    failCheck('E2', `observation signer ${observation.signature.signer} is not the expected execution signer`);
  } else {
    pass('E2', `observation signature valid; signer ${observation.signature.signer} is the expected execution signer`);
  }

  // L1–L4
  if (!approval || !observation) {
    const dep = !approval ? 'A1' : 'E1';
    notEvaluated('L1', dep);
    notEvaluated('L2', dep);
    notEvaluated('L3', dep);
    notEvaluated('L4', dep);
  } else {
    const exec = observation.payload.execution;
    const binding = approval.payload.binding;

    const recomputedHash = computeReceiptHash(approval);
    if (exec.approvalReceiptHash !== recomputedHash) {
      failCheck('L1', 'approvalReceiptHash does not equal the recomputed computeReceiptHash(approval)');
    } else if (exec.approvalReceiptId !== approval.id) {
      failCheck('L1', 'approvalReceiptId does not equal the approval receipt id');
    } else {
      pass('L1', 'observation references the approval receipt hash and id');
    }

    const mismatched = (['operationId', 'requester', 'audience', 'tool'] as const).filter(
      (m) => exec[m] !== binding[m],
    );
    if (mismatched.length > 0) {
      failCheck('L2', `context differs between approval and observation: ${mismatched.join(', ')}`);
    } else {
      pass('L2', 'operationId, requester, audience and tool are equal');
    }

    if (exec.actionDigest !== binding.argumentsDigest) {
      failCheck('L3', 'actionDigest does not equal the approved argumentsDigest');
    } else {
      pass('L3', 'actionDigest equals the approved argumentsDigest');
    }

    const times = approvalTimes(approval.payload);
    const dispatchedAtMs = parseRfc3339MsZ(exec.dispatchedAt) as number;
    if (times.decidedAtMs > dispatchedAtMs) {
      failCheck('L4', 'dispatchedAt precedes decidedAt');
    } else if (times.notAfterMs !== undefined && dispatchedAtMs >= times.notAfterMs) {
      failCheck('L4', 'dispatchedAt is at or after validity.notAfter');
    } else {
      pass('L4', 'dispatchedAt is within the approval validity window');
    }
  }

  return {
    ok: checks.every((c) => c.status === 'PASS'),
    checks,
    statement: LINK_VERIFICATION_STATEMENT,
  };
}
