import { sha256 } from '@noble/hashes/sha256';
import { bytesToHex } from '@noble/hashes/utils';
import * as signModule from '../src/sign';
import { signReceipt, verifyReceipt, hashPayload } from '../src/sign';
import { computeReceiptHash } from '../src/chain';
import { canonicalize } from '../src/canonical';
import { createAuthReceipt } from '../src/receipt';
import {
  ARGUMENTS_DIGEST_DST,
  ARGUMENTS_MAX_BYTES,
  ARGUMENTS_MAX_DEPTH,
  ApprovedExecutionError,
  LINK_VERIFICATION_STATEMENT,
  computeArgumentsDigest,
  createApprovalReceipt,
  executeApproved,
  validateArgumentsJson,
  verifyApprovalExecutionLink,
  type ApprovalContext,
  type ApprovalReceiptInput,
  type ApprovalReceiptPayload,
  type ApprovedExecution,
  type BlockedExecution,
  type ConsumeClaim,
  type ExecuteApprovedParams,
  type ExecutionReceiptPayload,
  type LinkCheck,
  type ReturnedExecution,
} from '../src/approval';
import type { AuthReceiptInput, ReceiptSignerConfig, SignedReceipt } from '../src/types';

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);
const OBSERVER_PRIVATE_KEY = '0x' + '02'.repeat(32);
const OTHER_PRIVATE_KEY = '0x' + '03'.repeat(32);

const APPROVER_CONFIG: ReceiptSignerConfig = {
  issuer: 'approval-service.example',
  keyId: 'approval-key-1',
  privateKey: TEST_PRIVATE_KEY,
};

const OBSERVER_CONFIG: ReceiptSignerConfig = {
  issuer: 'executor.example',
  keyId: 'executor-key-1',
  privateKey: OBSERVER_PRIVATE_KEY,
};

const OTHER_CONFIG: ReceiptSignerConfig = {
  issuer: 'someone-else.example',
  keyId: 'other-key-1',
  privateKey: OTHER_PRIVATE_KEY,
};

const DECIDED_AT = '2026-10-25T12:00:00.000Z';
const DECIDED_AT_MS = Date.parse(DECIDED_AT);
const NOT_AFTER = '2026-10-25T12:10:00.000Z';
const NOT_AFTER_MS = Date.parse(NOT_AFTER);
const NOW_MS = DECIDED_AT_MS + 60_000; // one minute after the decision

const ARGS_JSON = '{"orderId":"ord_123","amount":42.5,"currency":"USD"}';
const ARGS_JSON_REORDERED = '{"currency":"USD", "amount":42.5, "orderId":"ord_123"}';
const ARGS_JSON_CHANGED = '{"orderId":"ord_123","amount":4250,"currency":"USD"}';

function makeContext(): ApprovalContext {
  return {
    requester: 'agent:support-bot',
    audience: 'mcp://payments.internal',
    tool: 'refund_order',
    operationId: 'op-0001',
  };
}

function makeInput(overrides: Partial<ApprovalReceiptInput> = {}): ApprovalReceiptInput {
  const ctx = makeContext();
  return {
    issuedAt: Math.floor(DECIDED_AT_MS / 1000),
    binding: {
      scheme: 'bab1',
      requester: ctx.requester,
      audience: ctx.audience,
      tool: ctx.tool,
      operationId: ctx.operationId,
    },
    approval: {
      approver: 'Jane Doe <jane@example.com>',
      source: 'slack:approvals-channel',
      decision: 'approved',
      decidedAt: DECIDED_AT,
      validity: { kind: 'once' },
      requestId: 'req-789',
    },
    argumentsJson: ARGS_JSON,
    ...overrides,
  };
}

function makeReceipt(overrides: Partial<ApprovalReceiptInput> = {}): SignedReceipt<ApprovalReceiptPayload> {
  return createApprovalReceipt(makeInput(overrides), APPROVER_CONFIG);
}

function makeUntilReceipt(): SignedReceipt<ApprovalReceiptPayload> {
  return makeReceipt({
    approval: {
      ...makeInput().approval,
      validity: { kind: 'until', notAfter: NOT_AFTER },
    },
  });
}

function fixedClock(ms: number): () => Date {
  return () => new Date(ms);
}

/** Clock that returns a different sample on each call (first t0, then td, ...). */
function sequenceClock(samples: Array<number | (() => Date)>): () => Date {
  let i = 0;
  return () => {
    const s = samples[Math.min(i, samples.length - 1)];
    i += 1;
    return typeof s === 'function' ? s() : new Date(s);
  };
}

function makeConsumeMap(): { consume: (claim: ConsumeClaim) => boolean; store: Map<string, ConsumeClaim> } {
  const store = new Map<string, ConsumeClaim>();
  return {
    store,
    consume: (claim) => {
      const key = `${claim.signer}|${claim.payloadHash}`;
      if (store.has(key)) return false;
      store.set(key, claim);
      return true;
    },
  };
}

interface Harness {
  params: ExecuteApprovedParams;
  dispatch: jest.Mock;
  store: Map<string, ConsumeClaim>;
}

function makeHarness(
  receipt: SignedReceipt<ApprovalReceiptPayload> = makeReceipt(),
  overrides: Partial<ExecuteApprovedParams> = {},
  dispatchImpl: (...args: unknown[]) => unknown = () => ({ refunded: true }),
): Harness {
  const { consume, store } = makeConsumeMap();
  const dispatch = jest.fn(dispatchImpl);
  const params: ExecuteApprovedParams = {
    receipt,
    expectedSigner: (receipt as { signature?: { signer?: string } } | null)?.signature?.signer ?? '0x' + '01'.repeat(20),
    context: makeContext(),
    argumentsJson: ARGS_JSON,
    attemptId: 'attempt-1',
    consume,
    observer: OBSERVER_CONFIG,
    clock: fixedClock(NOW_MS),
    ...overrides,
  };
  return { params, dispatch, store };
}

async function expectBlocked(
  h: Harness,
  code: BlockedExecution['code'],
): Promise<BlockedExecution> {
  const result = await executeApproved(h.params, h.dispatch);
  expect(result.outcome).toBe('blocked');
  const blocked = result as BlockedExecution;
  expect(blocked.code).toBe(code);
  expect(typeof blocked.detail).toBe('string');
  expect(blocked.detail.length).toBeGreaterThan(0);
  expect(h.dispatch).toHaveBeenCalledTimes(0);
  expect(blocked).not.toHaveProperty('observation');
  return blocked;
}

function asReturned<R>(result: ApprovedExecution<R>): ReturnedExecution<R> {
  expect(result.outcome).toBe('returned');
  return result as ReturnedExecution<R>;
}

function checkById(checks: LinkCheck[], id: LinkCheck['id']): LinkCheck {
  const found = checks.find((c) => c.id === id);
  if (!found) throw new Error(`check ${id} missing`);
  return found;
}

function makeLegacyAuthReceipt(): SignedReceipt {
  const input: AuthReceiptInput = {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2] } },
    agentProof: { proof: { pi_a: [3, 4] } },
    humanPublicSignals: ['111'],
    agentPublicSignals: ['222'],
    bundleVersion: 1,
    nonce: '12345',
  };
  const payload = createAuthReceipt(input, { issuer: 'legacy', keyId: 'approval-key-1', issuedAt: 1 });
  return signReceipt(payload, APPROVER_CONFIG);
}

/** Sign an arbitrary observation payload with the observer key (re-signed negatives). */
function signObservation(
  payload: ExecutionReceiptPayload,
  config: ReceiptSignerConfig = OBSERVER_CONFIG,
): SignedReceipt<ExecutionReceiptPayload> {
  return signReceipt(payload, config);
}

async function produceLinkedPair(): Promise<{
  approval: SignedReceipt<ApprovalReceiptPayload>;
  observation: SignedReceipt<ExecutionReceiptPayload>;
}> {
  const approval = makeReceipt();
  const h = makeHarness(approval);
  const result = asReturned(await executeApproved(h.params, h.dispatch));
  if (!result.observation) throw new Error('expected observation');
  return { approval, observation: result.observation };
}

// ---------------------------------------------------------------------------
// §4.3 / §5.1 — arguments digest
// ---------------------------------------------------------------------------

describe('computeArgumentsDigest — golden canonical bytes and digests', () => {
  // Golden values were computed once with this implementation and pinned.
  // Any change to canonicalization or the DST construction must fail here.
  const GOLDEN: Array<{ name: string; json: string; canonical: string; digest: string }> = [
    {
      // canonicalize() re-inserts sorted keys into an object, so integer-like
      // keys enumerate in ascending numeric order (V8 semantics), then the
      // remaining keys in sorted string order. Pinned as-is: wire compatibility.
      name: 'numeric keys enumerate numerically, then string keys sorted',
      json: '{"10": 1, "9": 2, "a": 3, "1": 4}',
      canonical: '{"1":4,"9":2,"10":1,"a":3}',
      digest: '277d6112d70e421c48ba708e578b567fcbf750669e2ae9ab2b4d4dbfc314ffe9',
    },
    {
      name: 'unicode strings pass through unescaped',
      json: '{"name":"Zoë 🚀 日本","emoji":"\\u00e9"}',
      canonical: '{"emoji":"é","name":"Zoë 🚀 日本"}',
      digest: 'f2bbf65f15af2e814911a21121e2dae3ddbc6eaa9f5d64e369a47a1ffd240127',
    },
    {
      name: 'nested arrays keep order, objects inside are sorted',
      json: '{"z":[[3,[2,[1]]],{"b":false,"a":null}],"a":[]}',
      canonical: '{"a":[],"z":[[3,[2,[1]]],{"a":null,"b":false}]}',
      digest: 'cfc33d4001f8d7022f2ef2629e2c01f5df5521c425b71001d271fad5f0a19c00',
    },
    {
      name: 'numbers with exponents use JS shortest round-trip form',
      json: '{"big":1e21,"small":1.5e-7,"int":1E2,"neg":-2.50,"zero":0}',
      canonical: '{"big":1e+21,"int":100,"neg":-2.5,"small":1.5e-7,"zero":0}',
      digest: '8ba6916b32a901bd9f0f52786040b3e2dfef45b0ffb23e4a218b633c37d44d90',
    },
  ];

  it.each(GOLDEN)('$name', ({ json, canonical, digest }) => {
    expect(canonicalize(JSON.parse(json))).toBe(canonical);
    expect(computeArgumentsDigest(json)).toBe(digest);
  });

  it('digest = sha256( utf8(DST) || 0x00 || utf8(canonical) )', () => {
    expect(ARGUMENTS_DIGEST_DST).toBe('bolyra.approval.arguments/1');
    const canonical = canonicalize(JSON.parse(ARGS_JSON));
    const dst = new TextEncoder().encode(ARGUMENTS_DIGEST_DST);
    const body = new TextEncoder().encode(canonical);
    const input = new Uint8Array(dst.length + 1 + body.length);
    input.set(dst, 0);
    input[dst.length] = 0x00;
    input.set(body, dst.length + 1);
    expect(computeArgumentsDigest(ARGS_JSON)).toBe(bytesToHex(sha256(input)));
    expect(computeArgumentsDigest(ARGS_JSON)).toMatch(/^[0-9a-f]{64}$/);
  });

  it('is independent of whitespace and member order in the JSON text', () => {
    expect(computeArgumentsDigest(ARGS_JSON_REORDERED)).toBe(computeArgumentsDigest(ARGS_JSON));
  });

  it('changes when a value changes', () => {
    expect(computeArgumentsDigest(ARGS_JSON_CHANGED)).not.toBe(computeArgumentsDigest(ARGS_JSON));
  });
});

describe('computeArgumentsDigest — bab1 domain rejections (via JSON text)', () => {
  it.each([
    ['__proto__ at depth', '{"a":{"b":{"__proto__":{"x":1}}}}', /__proto__/],
    ['constructor at depth', '{"a":[{"constructor":1}]}', /constructor/],
    ['prototype at depth', '{"a":{"prototype":1}}', /prototype/],
    ['negative zero at root member', '{"a":-0}', /negative zero/],
    ['negative zero nested in array', '{"a":[1,-0]}', /negative zero/],
    ['root is an array', '[1,2]', /JSON object/],
    ['root is a string', '"x"', /JSON object/],
    ['root is a number', '1', /JSON object/],
    ['root is null', 'null', /JSON object/],
  ])('rejects %s', (_name, json, pattern) => {
    expect(() => computeArgumentsDigest(json)).toThrow(pattern);
  });

  it('rejects invalid JSON', () => {
    expect(() => computeArgumentsDigest('{"a":')).toThrow(/invalid JSON/);
    expect(() => computeArgumentsDigest('')).toThrow(/invalid JSON/);
    expect(() => computeArgumentsDigest('{"a":1} x')).toThrow(/invalid JSON/);
  });

  it('rejects a non-string argument', () => {
    expect(() => computeArgumentsDigest({ a: 1 } as unknown as string)).toThrow(/string/);
    expect(() => computeArgumentsDigest(undefined as unknown as string)).toThrow(/string/);
  });

  it('enforces the nesting depth cap at 64 (root object counts as depth 1)', () => {
    expect(ARGUMENTS_MAX_DEPTH).toBe(64);
    const nest = (n: number) => '{"a":' + '['.repeat(n) + ']'.repeat(n) + '}';
    expect(() => computeArgumentsDigest(nest(63))).not.toThrow(); // depth 64
    expect(() => computeArgumentsDigest(nest(64))).toThrow(/depth/); // depth 65
  });

  it('enforces the 1 MiB serialized size cap', () => {
    expect(ARGUMENTS_MAX_BYTES).toBe(1024 * 1024);
    const overhead = '{"a":""}'.length;
    const under = '{"a":"' + 'x'.repeat(ARGUMENTS_MAX_BYTES - overhead) + '"}';
    expect(Buffer.byteLength(under, 'utf8')).toBe(ARGUMENTS_MAX_BYTES);
    expect(() => computeArgumentsDigest(under)).not.toThrow();
    const over = '{"a":"' + 'x'.repeat(ARGUMENTS_MAX_BYTES - overhead + 1) + '"}';
    expect(() => computeArgumentsDigest(over)).toThrow(/1 MiB|size/);
  });

  it('rejects a canonical form that exceeds the cap even when the text fits', () => {
    // A raw lone surrogate is one 3-byte replacement in UTF-8 but 6 bytes
    // ("\ud800") once JSON.stringify escapes it, so canonical > raw is possible.
    const overhead = '{"a":""}'.length;
    const n = Math.floor((ARGUMENTS_MAX_BYTES - overhead) / 3);
    const text = '{"a":"' + '\ud800'.repeat(n) + '"}';
    expect(Buffer.byteLength(text, 'utf8')).toBeLessThanOrEqual(ARGUMENTS_MAX_BYTES);
    expect(() => computeArgumentsDigest(text)).toThrow(/1 MiB|size/);
  });
});

// ---------------------------------------------------------------------------
// §5.2 — createApprovalReceipt
// ---------------------------------------------------------------------------

describe('createApprovalReceipt', () => {
  it('signs a valid input and the result verifies', () => {
    const receipt = makeReceipt();
    expect(receipt.payload.v).toBe(1);
    expect(receipt.payload.kind).toBe('bolyra.approval');
    expect(receipt.payload.issuer).toBe(APPROVER_CONFIG.issuer);
    expect(receipt.payload.keyId).toBe(APPROVER_CONFIG.keyId);
    expect(receipt.signature.keyId).toBe(receipt.payload.keyId);
    expect(receipt.payload.binding.scheme).toBe('bab1');
    expect(receipt.payload.binding.argumentsDigest).toBe(computeArgumentsDigest(ARGS_JSON));
    expect(receipt.payload.approval.approver).toBe('Jane Doe <jane@example.com>');
    expect(receipt.payload.approval.requestId).toBe('req-789');
    expect(receipt.id).toBe('0x' + receipt.signature.payloadHash.slice(2, 18));
    expect(verifyReceipt(receipt)).toBe(true);
    expect(verifyReceipt(receipt, receipt.signature.signer)).toBe(true);
    expect(hashPayload(receipt.payload)).toBe(receipt.signature.payloadHash);
    expect(Object.keys(receipt).sort()).toEqual(['id', 'payload', 'signature']);
    // The receipt carries the digest only, never the arguments.
    expect(JSON.stringify(receipt)).not.toContain('ord_123');
  });

  it('defaults v, kind and scheme and omits requestId when absent', () => {
    const input = makeInput();
    delete (input.approval as { requestId?: string }).requestId;
    delete (input.binding as { scheme?: string }).scheme;
    const receipt = createApprovalReceipt(input, APPROVER_CONFIG);
    expect(receipt.payload.binding.scheme).toBe('bab1');
    expect(receipt.payload.approval).not.toHaveProperty('requestId');
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('defaults issuedAt to now when omitted', () => {
    const input = makeInput();
    delete input.issuedAt;
    const before = Math.floor(Date.now() / 1000);
    const receipt = createApprovalReceipt(input, APPROVER_CONFIG);
    expect(receipt.payload.issuedAt).toBeGreaterThanOrEqual(before);
  });

  const REQUIRED_PATHS = [
    'binding',
    'binding.requester',
    'binding.audience',
    'binding.tool',
    'binding.operationId',
    'approval',
    'approval.approver',
    'approval.source',
    'approval.decision',
    'approval.decidedAt',
    'approval.validity',
    'approval.validity.kind',
    'argumentsJson',
  ];

  function deletePath(obj: Record<string, unknown>, path: string): void {
    const parts = path.split('.');
    let cur: Record<string, unknown> = obj;
    for (const p of parts.slice(0, -1)) cur = cur[p] as unknown as Record<string, unknown>;
    delete cur[parts[parts.length - 1]];
  }

  it.each(REQUIRED_PATHS)('throws naming the missing member %s', (path) => {
    const input = makeInput() as unknown as Record<string, unknown>;
    deletePath(input, path);
    expect(() => createApprovalReceipt(input as unknown as ApprovalReceiptInput, APPROVER_CONFIG)).toThrow(
      new RegExp(path.replace(/\./g, '\\.')),
    );
  });

  it('throws naming the missing notAfter on an until validity', () => {
    const input = makeInput();
    input.approval.validity = { kind: 'until' } as unknown as ApprovalReceiptInput['approval']['validity'];
    expect(() => createApprovalReceipt(input, APPROVER_CONFIG)).toThrow(/approval\.validity\.notAfter/);
  });

  it.each([
    ['top level', (i: Record<string, unknown>) => (i.extra = 1), /"extra"/],
    ['binding', (i: Record<string, unknown>) => ((i.binding as unknown as Record<string, unknown>).extra = 1), /binding\.extra/],
    ['binding.argumentsDigest supplied by caller', (i: Record<string, unknown>) => ((i.binding as unknown as Record<string, unknown>).argumentsDigest = 'ab'.repeat(32)), /binding\.argumentsDigest/],
    ['approval', (i: Record<string, unknown>) => ((i.approval as unknown as Record<string, unknown>).extra = 1), /approval\.extra/],
    ['validity', (i: Record<string, unknown>) => (((i.approval as unknown as Record<string, unknown>).validity as unknown as Record<string, unknown>).extra = 1), /approval\.validity\.extra/],
    ['validity once with notAfter', (i: Record<string, unknown>) => (((i.approval as unknown as Record<string, unknown>).validity as unknown as Record<string, unknown>).notAfter = NOT_AFTER), /approval\.validity\.notAfter/],
  ])('throws naming an unknown member at %s', (_name, mutate, pattern) => {
    const input = makeInput() as unknown as Record<string, unknown>;
    mutate(input);
    expect(() => createApprovalReceipt(input as unknown as ApprovalReceiptInput, APPROVER_CONFIG)).toThrow(pattern);
  });

  it.each([
    ['requester with a space', (i: ApprovalReceiptInput) => (i.binding.requester = 'agent bot'), /binding\.requester/],
    ['empty tool', (i: ApprovalReceiptInput) => (i.binding.tool = ''), /binding\.tool/],
    ['257-char operationId', (i: ApprovalReceiptInput) => (i.binding.operationId = 'x'.repeat(257)), /binding\.operationId/],
    ['non-ASCII approver', (i: ApprovalReceiptInput) => (i.approval.approver = 'Zoë'), /approval\.approver/],
    ['empty approver', (i: ApprovalReceiptInput) => (i.approval.approver = ''), /approval\.approver/],
    ['source with a space', (i: ApprovalReceiptInput) => (i.approval.source = 'slack channel'), /approval\.source/],
    ['decidedAt without ms', (i: ApprovalReceiptInput) => (i.approval.decidedAt = '2026-10-25T12:00:00Z'), /approval\.decidedAt/],
    ['decidedAt with offset', (i: ApprovalReceiptInput) => (i.approval.decidedAt = '2026-10-25T12:00:00.000+00:00'), /approval\.decidedAt/],
    ['decidedAt impossible date', (i: ApprovalReceiptInput) => (i.approval.decidedAt = '2026-02-30T12:00:00.000Z'), /approval\.decidedAt/],
    ['notAfter invalid', (i: ApprovalReceiptInput) => (i.approval.validity = { kind: 'until', notAfter: 'tomorrow' }), /approval\.validity\.notAfter/],
    ['validity kind unknown', (i: ApprovalReceiptInput) => (i.approval.validity = { kind: 'forever' } as unknown as ApprovalReceiptInput['approval']['validity']), /approval\.validity\.kind/],
    ['requestId non-string', (i: ApprovalReceiptInput) => ((i.approval as unknown as Record<string, unknown>).requestId = 7), /approval\.requestId/],
    ['requestId undefined (present)', (i: ApprovalReceiptInput) => ((i.approval as unknown as Record<string, unknown>).requestId = undefined), /approval\.requestId/],
    ['issuedAt non-integer', (i: ApprovalReceiptInput) => (i.issuedAt = 1.5), /issuedAt/],
    ['argumentsJson invalid JSON', (i: ApprovalReceiptInput) => (i.argumentsJson = '{'), /argumentsJson/],
    ['argumentsJson out of domain', (i: ApprovalReceiptInput) => (i.argumentsJson = '{"__proto__":1}'), /argumentsJson/],
    ['argumentsJson non-string', (i: ApprovalReceiptInput) => ((i as unknown as Record<string, unknown>).argumentsJson = { a: 1 }), /argumentsJson/],
  ])('throws naming the out-of-domain member: %s', (_name, mutate, pattern) => {
    const input = makeInput();
    mutate(input);
    expect(() => createApprovalReceipt(input, APPROVER_CONFIG)).toThrow(pattern);
  });

  it('rejects decision "pending" and anything outside the closed enum', () => {
    for (const decision of ['pending', 'APPROVED', 'yes', '', true, null]) {
      const input = makeInput();
      (input.approval as unknown as Record<string, unknown>).decision = decision;
      expect(() => createApprovalReceipt(input, APPROVER_CONFIG)).toThrow(/approval\.decision/);
    }
  });

  it('signs a denied decision (it is the verifier that refuses it)', () => {
    const input = makeInput();
    input.approval.decision = 'denied';
    const receipt = createApprovalReceipt(input, APPROVER_CONFIG);
    expect(receipt.payload.approval.decision).toBe('denied');
    expect(verifyReceipt(receipt)).toBe(true);
  });

  it('rejects unknown scheme, v and kind', () => {
    const bad = makeInput();
    (bad.binding as unknown as Record<string, unknown>).scheme = 'bab2';
    expect(() => createApprovalReceipt(bad, APPROVER_CONFIG)).toThrow(/binding\.scheme/);
    const badV = makeInput();
    (badV as unknown as Record<string, unknown>).v = 2;
    expect(() => createApprovalReceipt(badV, APPROVER_CONFIG)).toThrow(/"v"/);
    const badKind = makeInput();
    (badKind as unknown as Record<string, unknown>).kind = 'bolyra.auth';
    expect(() => createApprovalReceipt(badKind, APPROVER_CONFIG)).toThrow(/kind/);
  });

  it('rejects a signer config with empty issuer or keyId, or a bad key', () => {
    expect(() => createApprovalReceipt(makeInput(), { ...APPROVER_CONFIG, issuer: '' })).toThrow(/issuer/);
    expect(() => createApprovalReceipt(makeInput(), { ...APPROVER_CONFIG, keyId: '' })).toThrow(/keyId/);
    expect(() => createApprovalReceipt(makeInput(), { ...APPROVER_CONFIG, privateKey: '0x00' })).toThrow(/privateKey/);
  });

  it('rejects non-object input', () => {
    expect(() => createApprovalReceipt(null as unknown as ApprovalReceiptInput, APPROVER_CONFIG)).toThrow();
    expect(() => createApprovalReceipt('x' as unknown as ApprovalReceiptInput, APPROVER_CONFIG)).toThrow();
  });
});

// ---------------------------------------------------------------------------
// §5.3 — executeApproved: blocked cases (zero dispatches every time)
// ---------------------------------------------------------------------------

describe('executeApproved — blocked, zero dispatches', () => {
  it('changed arguments → arguments_mismatch', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: ARGS_JSON_CHANGED });
    await expectBlocked(h, 'arguments_mismatch');
    expect(h.store.size).toBe(0);
  });

  it('reordered (but equal) arguments still match', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: ARGS_JSON_REORDERED });
    asReturned(await executeApproved(h.params, h.dispatch));
    expect(h.dispatch).toHaveBeenCalledTimes(1);
  });

  it.each<[keyof ApprovalContext]>([['requester'], ['audience'], ['tool'], ['operationId']])(
    'changed %s → context_mismatch',
    async (field) => {
      const context = { ...makeContext(), [field]: 'something-else' };
      const h = makeHarness(makeReceipt(), { context });
      const blocked = await expectBlocked(h, 'context_mismatch');
      expect(blocked.detail).toContain(field);
      expect(h.store.size).toBe(0);
    },
  );

  it('denied decision → decision_not_approved', async () => {
    const input = makeInput();
    input.approval.decision = 'denied';
    const h = makeHarness(createApprovalReceipt(input, APPROVER_CONFIG));
    await expectBlocked(h, 'decision_not_approved');
  });

  it('until receipt: t0 == notAfter → expired; t0 == notAfter - 1 ms passes the first check', async () => {
    const atBoundary = makeHarness(makeUntilReceipt(), { clock: fixedClock(NOT_AFTER_MS), consume: undefined });
    await expectBlocked(atBoundary, 'expired');

    const justBefore = makeHarness(makeUntilReceipt(), { clock: fixedClock(NOT_AFTER_MS - 1), consume: undefined });
    asReturned(await executeApproved(justBefore.params, justBefore.dispatch));
    expect(justBefore.dispatch).toHaveBeenCalledTimes(1);
  });

  it('until receipt: past notAfter → expired', async () => {
    const h = makeHarness(makeUntilReceipt(), { clock: fixedClock(NOT_AFTER_MS + 60_000), consume: undefined });
    await expectBlocked(h, 'expired');
  });

  it('future decidedAt → future_decision (t0 == decidedAt is allowed)', async () => {
    const future = makeHarness(makeReceipt(), { clock: fixedClock(DECIDED_AT_MS - 1) });
    await expectBlocked(future, 'future_decision');
    const exact = makeHarness(makeReceipt(), { clock: fixedClock(DECIDED_AT_MS) });
    asReturned(await executeApproved(exact.params, exact.dispatch));
  });

  it('missing consume on a once receipt → consume_required', async () => {
    const h = makeHarness(makeReceipt(), { consume: undefined });
    await expectBlocked(h, 'consume_required');
  });

  it.each<[string, () => unknown]>([
    ['false', () => false],
    ['a string "true"', () => 'true'],
    ['a truthy number', () => 1],
    ['a Promise resolving to true', () => Promise.resolve(true)],
    ['undefined', () => undefined],
  ])('consume returning %s → consume_rejected', async (_name, impl) => {
    const consume = jest.fn(impl) as unknown as (claim: ConsumeClaim) => boolean;
    const h = makeHarness(makeReceipt(), { consume });
    await expectBlocked(h, 'consume_rejected');
    expect(consume).toHaveBeenCalledTimes(1);
  });

  it('consume throwing → consume_rejected', async () => {
    const consume = jest.fn(() => {
      throw new Error('store unavailable');
    });
    const h = makeHarness(makeReceipt(), { consume });
    const blocked = await expectBlocked(h, 'consume_rejected');
    expect(blocked.detail).toContain('store unavailable');
  });

  it('consume is called exactly once with the full payloadHash, lowercase signer and operationId, frozen', async () => {
    const receipt = makeReceipt();
    const claims: ConsumeClaim[] = [];
    const consume = jest.fn((claim: ConsumeClaim) => {
      claims.push(claim);
      return true;
    });
    const h = makeHarness(receipt, { consume });
    asReturned(await executeApproved(h.params, h.dispatch));
    expect(consume).toHaveBeenCalledTimes(1);
    expect(claims[0]).toEqual({
      signer: receipt.signature.signer.toLowerCase(),
      payloadHash: receipt.signature.payloadHash,
      operationId: 'op-0001',
    });
    expect(claims[0].payloadHash).toMatch(/^0x[0-9a-f]{64}$/);
    expect(Object.isFrozen(claims[0])).toBe(true);
  });

  it('concurrent calls sharing one in-memory consume map dispatch exactly once', async () => {
    const receipt = makeReceipt();
    const { consume, store } = makeConsumeMap();
    const dispatch = jest.fn(() => ({ refunded: true }));
    const run = () =>
      executeApproved(
        {
          receipt,
          expectedSigner: receipt.signature.signer,
          context: makeContext(),
          argumentsJson: ARGS_JSON,
          attemptId: 'attempt-concurrent',
          consume,
          observer: OBSERVER_CONFIG,
          clock: fixedClock(NOW_MS),
        },
        dispatch,
      );
    const results = await Promise.all([run(), run(), run(), run(), run()]);
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(results.filter((r) => r.outcome === 'returned')).toHaveLength(1);
    const blocked = results.filter((r) => r.outcome === 'blocked') as BlockedExecution[];
    expect(blocked).toHaveLength(4);
    for (const b of blocked) expect(b.code).toBe('consume_rejected');
    expect(store.size).toBe(1);
  });

  it('re-entrant call from inside dispatch is blocked; exactly one dispatch', async () => {
    const receipt = makeReceipt();
    const { consume, store } = makeConsumeMap();
    let inner: ApprovedExecution<unknown> | undefined;
    let dispatchCount = 0;
    const params: ExecuteApprovedParams = {
      receipt,
      expectedSigner: receipt.signature.signer,
      context: makeContext(),
      argumentsJson: ARGS_JSON,
      attemptId: 'attempt-reentrant',
      consume,
      observer: OBSERVER_CONFIG,
      clock: fixedClock(NOW_MS),
    };
    const dispatch = async (): Promise<string> => {
      dispatchCount += 1;
      inner = await executeApproved(params, dispatch);
      return 'outer';
    };
    const outer = asReturned(await executeApproved(params, dispatch));
    expect(outer.value).toBe('outer');
    expect(dispatchCount).toBe(1);
    expect(inner?.outcome).toBe('blocked');
    expect((inner as BlockedExecution).code).toBe('consume_rejected');
    expect(store.size).toBe(1);
  });

  it('until receipts permit repeats (reconciliation is operator-owned)', async () => {
    const receipt = makeUntilReceipt();
    const h = makeHarness(receipt, { consume: undefined });
    asReturned(await executeApproved(h.params, h.dispatch));
    asReturned(await executeApproved(h.params, h.dispatch));
    expect(h.dispatch).toHaveBeenCalledTimes(2);
  });

  it('wrong expected signer → untrusted_signer', async () => {
    const h = makeHarness(makeReceipt(), { expectedSigner: '0x' + 'ab'.repeat(20) });
    await expectBlocked(h, 'untrusted_signer');
  });

  it('receipt signed by another key → untrusted_signer', async () => {
    const foreign = createApprovalReceipt(makeInput(), OTHER_CONFIG);
    const trusted = makeReceipt();
    const h = makeHarness(foreign, { expectedSigner: trusted.signature.signer });
    await expectBlocked(h, 'untrusted_signer');
  });

  it('expectedSigner is case-insensitive', async () => {
    const receipt = makeReceipt();
    const h = makeHarness(receipt, { expectedSigner: receipt.signature.signer.toUpperCase().replace('0X', '0x') });
    asReturned(await executeApproved(h.params, h.dispatch));
  });

  it('forged envelope id → malformed_receipt', async () => {
    const receipt = makeReceipt();
    const forged = { ...receipt, id: '0x' + '00'.repeat(8) };
    const h = makeHarness(forged);
    await expectBlocked(h, 'malformed_receipt');
  });

  it('tampered payload → signature_invalid', async () => {
    const receipt = makeReceipt();
    const tampered = structuredClone(receipt);
    tampered.payload.approval.approver = 'Mallory';
    const h = makeHarness(tampered);
    await expectBlocked(h, 'signature_invalid');
  });

  it('tampered signature value → signature_invalid', async () => {
    const receipt = makeReceipt();
    const tampered = structuredClone(receipt);
    const v = tampered.signature.value;
    tampered.signature.value = v.slice(0, -2) + (v.endsWith('1b') ? '1c' : '1b');
    const h = makeHarness(tampered);
    await expectBlocked(h, 'signature_invalid');
  });

  it('claimed signer swapped → signature_invalid', async () => {
    const receipt = makeReceipt();
    const tampered = structuredClone(receipt);
    tampered.signature.signer = '0x' + 'ab'.repeat(20);
    const h = makeHarness(tampered, { expectedSigner: tampered.signature.signer });
    await expectBlocked(h, 'signature_invalid');
  });

  it('envelope keyId differing from payload keyId → keyid_mismatch', async () => {
    const receipt = makeReceipt();
    const tampered = structuredClone(receipt);
    tampered.signature.keyId = 'rotated-key';
    const h = makeHarness(tampered);
    await expectBlocked(h, 'keyid_mismatch');
  });

  it('legacy auth receipt → wrong_kind', async () => {
    const legacy = makeLegacyAuthReceipt();
    const h = makeHarness(legacy as unknown as SignedReceipt<ApprovalReceiptPayload>);
    await expectBlocked(h, 'wrong_kind');
  });

  it.each<[string, unknown]>([
    ['null', null],
    ['a string', 'receipt'],
    ['an array', [makeReceipt()]],
    ['an empty object', {}],
    ['missing signature', { id: '0x00', payload: makeReceipt().payload }],
    ['missing payload', { id: '0x00', signature: makeReceipt().signature }],
    ['extra envelope member', { ...makeReceipt(), receiptHash: '0x00' }],
  ])('malformed receipt (%s) → malformed_receipt', async (_name, receipt) => {
    const h = makeHarness(receipt as SignedReceipt<ApprovalReceiptPayload>);
    await expectBlocked(h, 'malformed_receipt');
  });

  it.each<[string, (r: SignedReceipt<ApprovalReceiptPayload>) => void]>([
    ['unknown payload member', (r) => ((r.payload as unknown as Record<string, unknown>).extra = 1)],
    ['unknown binding member', (r) => ((r.payload.binding as unknown as Record<string, unknown>).extra = 1)],
    ['unknown approval member', (r) => ((r.payload.approval as unknown as Record<string, unknown>).extra = 1)],
    ['unknown signature member', (r) => ((r.signature as unknown as Record<string, unknown>).extra = 1)],
    ['wrong v', (r) => ((r.payload as unknown as Record<string, unknown>).v = 2)],
    ['wrong scheme', (r) => ((r.payload.binding as unknown as Record<string, unknown>).scheme = 'bab2')],
    ['wrong alg', (r) => ((r.signature as unknown as Record<string, unknown>).alg = 'ES256')],
    ['short signature value', (r) => (r.signature.value = r.signature.value.slice(0, -2))],
    ['short payloadHash', (r) => (r.signature.payloadHash = r.signature.payloadHash.slice(0, -2))],
    ['decision outside enum', (r) => ((r.payload.approval as unknown as Record<string, unknown>).decision = 'pending')],
    ['argumentsDigest uppercase', (r) => (r.payload.binding.argumentsDigest = r.payload.binding.argumentsDigest.toUpperCase())],
    ['missing binding.tool', (r) => delete (r.payload.binding as Partial<typeof r.payload.binding>).tool],
    ['validity once with notAfter', (r) => ((r.payload.approval.validity as unknown as Record<string, unknown>).notAfter = NOT_AFTER)],
  ])('tampered schema (%s) → malformed_receipt (before signature check)', async (_name, mutate) => {
    const receipt = structuredClone(makeReceipt());
    mutate(receipt);
    const h = makeHarness(receipt);
    await expectBlocked(h, 'malformed_receipt');
  });

  it.each<[string, Partial<ExecuteApprovedParams> | ((p: ExecuteApprovedParams) => void)]>([
    ['non-string argumentsJson', { argumentsJson: { a: 1 } as unknown as string }],
    ['non-string attemptId', { attemptId: 7 as unknown as string }],
    ['attemptId with a space', { attemptId: 'attempt 1' }],
    ['empty attemptId', { attemptId: '' }],
    ['empty expectedSigner', { expectedSigner: '' }],
    ['missing expectedSigner', { expectedSigner: undefined as unknown as string }],
    ['context null', { context: null as unknown as ApprovalContext }],
    ['context missing operationId', (p) => delete (p.context as Partial<ApprovalContext>).operationId],
    ['context with unknown member', (p) => ((p.context as unknown as Record<string, unknown>).extra = 1)],
    ['context member non-id', { context: { ...makeContext(), tool: 'refund order' } }],
    ['consume not a function', { consume: true as unknown as ExecuteApprovedParams['consume'] }],
    ['clock not a function', { clock: Date.now() as unknown as ExecuteApprovedParams['clock'] }],
    ['receipt not cloneable (function inside)', (p) => ((p.receipt as unknown as Record<string, unknown>).fn = () => 1)],
  ])('malformed input (%s) → malformed_input', async (_name, change) => {
    const h = makeHarness(makeReceipt(), typeof change === 'function' ? {} : change);
    if (typeof change === 'function') change(h.params);
    await expectBlocked(h, 'malformed_input');
    expect(h.store.size).toBe(0);
  });

  it('params that are not an object → malformed_input', async () => {
    const dispatch = jest.fn();
    const result = await executeApproved(null as unknown as ExecuteApprovedParams, dispatch);
    expect(result).toMatchObject({ outcome: 'blocked', code: 'malformed_input' });
    expect(dispatch).not.toHaveBeenCalled();
  });

  it('dispatch that is not a function → malformed_input, consume untouched', async () => {
    const h = makeHarness(makeReceipt());
    const result = await executeApproved(h.params, 'nope' as unknown as () => unknown);
    expect(result).toMatchObject({ outcome: 'blocked', code: 'malformed_input' });
    expect(h.store.size).toBe(0);
  });

  it('invalid JSON arguments → arguments_out_of_domain', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: '{' });
    await expectBlocked(h, 'arguments_out_of_domain');
  });

  it('out-of-domain arguments → arguments_out_of_domain', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: '{"a":{"__proto__":1}}' });
    await expectBlocked(h, 'arguments_out_of_domain');
  });

  it.each<[string, unknown]>([
    ['missing privateKey', { issuer: 'x', keyId: 'k' }],
    ['empty issuer', { ...OBSERVER_CONFIG, issuer: '' }],
    ['empty keyId', { ...OBSERVER_CONFIG, keyId: '' }],
    ['short key', { ...OBSERVER_CONFIG, privateKey: '0x0102' }],
    ['non-hex key', { ...OBSERVER_CONFIG, privateKey: '0x' + 'zz'.repeat(32) }],
    ['zero key (off curve)', { ...OBSERVER_CONFIG, privateKey: '0x' + '00'.repeat(32) }],
    ['null observer', null],
    ['string observer', 'observer'],
  ])('invalid observer (%s) → observer_invalid before consumption', async (_name, observer) => {
    const consume = jest.fn(() => true);
    const h = makeHarness(makeReceipt(), { observer: observer as ReceiptSignerConfig, consume });
    await expectBlocked(h, 'observer_invalid');
    expect(consume).not.toHaveBeenCalled();
  });

  it.each<[string, () => Date]>([
    [
      'throws',
      () => {
        throw new Error('no clock');
      },
    ],
    ['returns a number', (() => NOW_MS) as unknown as () => Date],
    ['returns an Invalid Date', () => new Date(NaN)],
    ['returns null', (() => null) as unknown as () => Date],
    ['returns a Date-like object', (() => ({ getTime: () => NOW_MS })) as unknown as () => Date],
  ])('invalid clock (%s) → invalid_clock', async (_name, clock) => {
    const consume = jest.fn(() => true);
    const h = makeHarness(makeReceipt(), { clock, consume });
    await expectBlocked(h, 'invalid_clock');
    expect(consume).not.toHaveBeenCalled();
  });

  it('blocked result carries no observation even when an observer is configured', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: ARGS_JSON_CHANGED });
    const result = await executeApproved(h.params, h.dispatch);
    expect(Object.keys(result).sort()).toEqual(['code', 'detail', 'outcome']);
  });
});

// ---------------------------------------------------------------------------
// §5.3 — executeApproved: success paths
// ---------------------------------------------------------------------------

describe('executeApproved — dispatched', () => {
  it('calls dispatch once with a deep-frozen snapshot and the checked context', async () => {
    const h = makeHarness(makeReceipt(), { argumentsJson: '{"orderId":"ord_123","amount":42.5,"currency":"USD","meta":{"tags":["a","b"]}}' });
    // Receipt must match the richer arguments.
    h.params.receipt = makeReceipt({ argumentsJson: h.params.argumentsJson });
    h.params.expectedSigner = h.params.receipt.signature.signer;
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(result.value).toEqual({ refunded: true });
    expect(h.dispatch).toHaveBeenCalledTimes(1);
    const [snapshot, checked] = h.dispatch.mock.calls[0] as [Record<string, unknown>, ApprovalContext];
    expect(snapshot).toEqual({ orderId: 'ord_123', amount: 42.5, currency: 'USD', meta: { tags: ['a', 'b'] } });
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(snapshot.meta)).toBe(true);
    expect(Object.isFrozen((snapshot.meta as { tags: string[] }).tags)).toBe(true);
    expect(checked).toEqual(makeContext());
    expect(Object.isFrozen(checked)).toBe(true);
    expect(checked).not.toBe(h.params.context);
  });

  it('does not expose observation keys when no observer is configured', async () => {
    const h = makeHarness(makeReceipt(), { observer: undefined });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(result).toEqual({ outcome: 'returned', value: { refunded: true } });
  });

  it('mutating the caller objects during consume and dispatch changes nothing', async () => {
    const receipt = makeReceipt();
    const h = makeHarness(receipt);
    const original = { context: { ...h.params.context }, receiptHash: computeReceiptHash(receipt) };
    const throwingClock = () => {
      throw new Error('swapped clock');
    };
    const consume = jest.fn(() => {
      // Mutate everything the caller owns.
      h.params.context.tool = 'delete_everything';
      h.params.receipt.payload.binding.tool = 'delete_everything';
      h.params.receipt.payload.approval.decision = 'denied';
      h.params.attemptId = 'evil-attempt';
      h.params.argumentsJson = ARGS_JSON_CHANGED;
      h.params.expectedSigner = '0x' + '00'.repeat(20);
      h.params.observer = { ...OBSERVER_CONFIG, privateKey: '0x00' };
      h.params.clock = throwingClock;
      h.params.consume = () => false;
      return true;
    });
    h.params.consume = consume;
    const dispatch = jest.fn((snapshot: Record<string, unknown>, ctx: ApprovalContext) => {
      expect(() => {
        (snapshot as unknown as Record<string, unknown>).amount = 0;
      }).toThrow();
      expect(() => {
        (ctx as unknown as Record<string, unknown>).tool = 'x';
      }).toThrow();
      h.params.context.audience = 'elsewhere';
      return 'done';
    });
    const result = asReturned(await executeApproved(h.params, dispatch));
    expect(result.value).toBe('done');
    expect(dispatch).toHaveBeenCalledTimes(1);
    expect(consume).toHaveBeenCalledTimes(1);
    const obs = result.observation;
    expect(obs).toBeDefined();
    expect(obs!.payload.execution.tool).toBe(original.context.tool);
    expect(obs!.payload.execution.audience).toBe(original.context.audience);
    expect(obs!.payload.execution.attemptId).toBe('attempt-1');
    expect(obs!.payload.execution.dispatchedAt).toBe(new Date(NOW_MS).toISOString());
    expect(verifyReceipt(obs!, obs!.signature.signer)).toBe(true);
    expect(result.observationError).toBeUndefined();
    // The observation links to the original receipt, not the mutated one.
    expect(obs!.payload.execution.approvalReceiptHash).toBe(original.receiptHash);
    expect(computeReceiptHash(receipt)).not.toBe(original.receiptHash); // caller's copy really was mutated
  });

  it('mutating a clock-returned Date during dispatch does not alter the observation', async () => {
    const shared = new Date(NOW_MS);
    const clock = () => shared;
    const dispatch = jest.fn(() => {
      shared.setTime(0);
      return 'ok';
    });
    const h = makeHarness(makeReceipt(), { clock });
    const result = asReturned(await executeApproved(h.params, dispatch));
    expect(result.observation!.payload.execution.dispatchedAt).toBe(new Date(NOW_MS).toISOString());
    expect(result.observation!.payload.issuedAt).toBe(Math.floor(NOW_MS / 1000));
  });

  it('observation signs, verifies and links to the approval', async () => {
    const approval = makeReceipt();
    const h = makeHarness(approval);
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    const obs = result.observation!;
    expect(obs.payload).toEqual({
      v: 1,
      kind: 'bolyra.execution',
      issuedAt: Math.floor(NOW_MS / 1000),
      issuer: OBSERVER_CONFIG.issuer,
      keyId: OBSERVER_CONFIG.keyId,
      execution: {
        scheme: 'beo1',
        approvalReceiptHash: computeReceiptHash(approval),
        approvalReceiptId: approval.id,
        operationId: 'op-0001',
        attemptId: 'attempt-1',
        requester: makeContext().requester,
        audience: makeContext().audience,
        tool: makeContext().tool,
        actionDigest: approval.payload.binding.argumentsDigest,
        dispatchedAt: new Date(NOW_MS).toISOString(),
        outcome: 'returned',
      },
    });
    expect(obs.signature.keyId).toBe(OBSERVER_CONFIG.keyId);
    expect(obs.id).toBe('0x' + obs.signature.payloadHash.slice(2, 18));
    expect(verifyReceipt(obs)).toBe(true);
    expect(hashPayload(obs.payload)).toBe(obs.signature.payloadHash);
    const link = verifyApprovalExecutionLink({
      approval,
      observation: obs,
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: obs.signature.signer,
    });
    expect(link.ok).toBe(true);
    expect(JSON.stringify(obs)).not.toContain('ord_123');
  });

  it('a throwing dispatch rejects with ApprovedExecutionError carrying the threw observation', async () => {
    const cause = new Error('downstream 500');
    const h = makeHarness(makeReceipt(), {}, () => {
      throw cause;
    });
    let caught: unknown;
    try {
      await executeApproved(h.params, h.dispatch);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApprovedExecutionError);
    const err = caught as ApprovedExecutionError;
    expect(err.name).toBe('ApprovedExecutionError');
    expect(err.cause).toBe(cause);
    expect(err.observation!.payload.execution.outcome).toBe('threw');
    expect(verifyReceipt(err.observation!)).toBe(true);
    expect(err.observationError).toBeUndefined();
    expect(h.dispatch).toHaveBeenCalledTimes(1);
  });

  it('an async dispatch that rejects is also "threw"', async () => {
    const h = makeHarness(makeReceipt(), {}, () => Promise.reject(new Error('rejected')));
    await expect(executeApproved(h.params, h.dispatch)).rejects.toBeInstanceOf(ApprovedExecutionError);
    expect(h.dispatch).toHaveBeenCalledTimes(1);
  });

  it('a dispatch returning a business error value is "returned" (values are not interpreted)', async () => {
    const h = makeHarness(makeReceipt(), {}, () => ({ ok: false, error: 'insufficient_funds' }));
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(result.value).toEqual({ ok: false, error: 'insufficient_funds' });
    expect(result.observation!.payload.execution.outcome).toBe('returned');
  });

  it('a failing observer at signing time yields observationError, never blocked (returned)', async () => {
    const h = makeHarness(makeReceipt());
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw new Error('HSM offline');
    });
    try {
      const result = asReturned(await executeApproved(h.params, h.dispatch));
      expect(result.value).toEqual({ refunded: true });
      expect(result.observation).toBeUndefined();
      expect(result.observationError).toBeInstanceOf(Error);
      expect(result.observationError!.message).toBe('HSM offline');
      expect(h.dispatch).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('a failing observer at signing time yields observationError on the threw path too', async () => {
    const h = makeHarness(makeReceipt(), {}, () => {
      throw new Error('boom');
    });
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw new Error('HSM offline');
    });
    try {
      let caught: unknown;
      try {
        await executeApproved(h.params, h.dispatch);
      } catch (e) {
        caught = e;
      }
      const err = caught as ApprovedExecutionError;
      expect(err).toBeInstanceOf(ApprovedExecutionError);
      expect((err.cause as Error).message).toBe('boom');
      expect(err.observation).toBeUndefined();
      expect(err.observationError!.message).toBe('HSM offline');
      expect(h.dispatch).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('default clock (real time) dispatches a freshly decided once receipt', async () => {
    const now = new Date();
    const decidedAt = new Date(now.getTime() - 1000).toISOString();
    const receipt = makeReceipt({ approval: { ...makeInput().approval, decidedAt } });
    const h = makeHarness(receipt, { clock: undefined });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(Date.parse(result.observation!.payload.execution.dispatchedAt)).toBeGreaterThanOrEqual(now.getTime());
  });
});

// ---------------------------------------------------------------------------
// §5.3 step 6 — second clock sample (td) boundaries
// ---------------------------------------------------------------------------

describe('executeApproved — second clock sample', () => {
  it('td throws → invalid_clock, zero dispatches, claim stays consumed', async () => {
    const clock = sequenceClock([
      NOW_MS,
      () => {
        throw new Error('clock died');
      },
    ]);
    const h = makeHarness(makeReceipt(), { clock });
    await expectBlocked(h, 'invalid_clock');
    expect(h.store.size).toBe(1); // consumed-then-blocked is never released here
  });

  it('td invalid Date → invalid_clock', async () => {
    const h = makeHarness(makeReceipt(), { clock: sequenceClock([NOW_MS, () => new Date(NaN)]) });
    await expectBlocked(h, 'invalid_clock');
  });

  it('td precedes decidedAt → future_decision', async () => {
    const h = makeHarness(makeReceipt(), { clock: sequenceClock([NOW_MS, DECIDED_AT_MS - 1]) });
    await expectBlocked(h, 'future_decision');
  });

  it('td equals notAfter → expired', async () => {
    const h = makeHarness(makeUntilReceipt(), {
      consume: undefined,
      clock: sequenceClock([NOT_AFTER_MS - 1, NOT_AFTER_MS]),
    });
    await expectBlocked(h, 'expired');
  });

  it('dispatchedAt comes from td, not t0', async () => {
    const h = makeHarness(makeReceipt(), { clock: sequenceClock([NOW_MS, NOW_MS + 5]) });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(result.observation!.payload.execution.dispatchedAt).toBe(new Date(NOW_MS + 5).toISOString());
  });

  it('mutating params during consumption does not replace captured callbacks or attemptId', async () => {
    const h = makeHarness(makeReceipt());
    const realDispatch = h.dispatch;
    const consume = jest.fn(() => {
      h.params.clock = () => {
        throw new Error('replaced clock');
      };
      h.params.attemptId = 'replaced';
      h.params.consume = () => {
        throw new Error('replaced consume');
      };
      return true;
    });
    h.params.consume = consume;
    const result = asReturned(await executeApproved(h.params, realDispatch));
    expect(realDispatch).toHaveBeenCalledTimes(1);
    expect(result.observation!.payload.execution.attemptId).toBe('attempt-1');
    expect(result.observation!.payload.execution.dispatchedAt).toBe(new Date(NOW_MS).toISOString());
  });
});

// ---------------------------------------------------------------------------
// §5.5 — verifyApprovalExecutionLink
// ---------------------------------------------------------------------------

describe('verifyApprovalExecutionLink', () => {
  const ALL_IDS: LinkCheck['id'][] = ['A1', 'A2', 'A3', 'E1', 'E2', 'L1', 'L2', 'L3', 'L4'];

  it('full PASS with the fixed statement', async () => {
    const { approval, observation } = await produceLinkedPair();
    const result = verifyApprovalExecutionLink({
      approval,
      observation,
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: observation.signature.signer,
    });
    expect(result.ok).toBe(true);
    expect(result.checks.map((c) => c.id)).toEqual(ALL_IDS);
    for (const c of result.checks) expect(c.status).toBe('PASS');
    expect(result.statement).toBe(LINK_VERIFICATION_STATEMENT);
    expect(result.statement).toMatch(/does not establish/);
    expect(result.statement).toMatch(/human review/);
    expect(result.statement).toMatch(/committed effect/);
  });

  it('is pure: does not mutate its inputs', async () => {
    const { approval, observation } = await produceLinkedPair();
    const a = JSON.stringify(approval);
    const o = JSON.stringify(observation);
    verifyApprovalExecutionLink({
      approval,
      observation,
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: observation.signature.signer,
    });
    expect(JSON.stringify(approval)).toBe(a);
    expect(JSON.stringify(observation)).toBe(o);
  });

  it('tampered fields fail the matching check', async () => {
    const { approval, observation } = await produceLinkedPair();
    const base = {
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: observation.signature.signer,
    };
    const run = (a: unknown, o: unknown, extra: Partial<typeof base> = {}) =>
      verifyApprovalExecutionLink({ approval: a, observation: o, ...base, ...extra });

    // A1: forged approval id
    let r = run({ ...approval, id: '0x' + '11'.repeat(8) }, observation);
    expect(r.ok).toBe(false);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');

    // A1: approval kind wrong / legacy receipt
    r = run(makeLegacyAuthReceipt(), observation);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');
    expect(checkById(r.checks, 'A1').detail).toMatch(/kind/);

    // A1: keyId disagreement
    const keyTampered = structuredClone(approval);
    keyTampered.signature.keyId = 'other';
    r = run(keyTampered, observation);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');
    expect(checkById(r.checks, 'A1').detail).toMatch(/keyId/);

    // A2: tampered approval payload (signature breaks)
    const payloadTampered = structuredClone(approval);
    payloadTampered.payload.binding.tool = 'other_tool';
    r = run(payloadTampered, observation);
    expect(checkById(r.checks, 'A1').status).toBe('PASS');
    expect(checkById(r.checks, 'A2').status).toBe('FAIL');

    // A2: wrong expected approval signer
    r = run(approval, observation, { expectedApprovalSigner: '0x' + 'ab'.repeat(20) });
    expect(checkById(r.checks, 'A2').status).toBe('FAIL');
    expect(checkById(r.checks, 'A2').detail).toMatch(/signer/);

    // A2: empty expected approval signer
    r = run(approval, observation, { expectedApprovalSigner: '' });
    expect(checkById(r.checks, 'A2').status).toBe('FAIL');

    // E1: observation kind wrong
    const kindTampered = structuredClone(observation);
    (kindTampered.payload as unknown as Record<string, unknown>).kind = 'bolyra.approval';
    r = run(approval, kindTampered);
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');

    // E1: observation extra member
    const extraTampered = structuredClone(observation);
    (extraTampered.payload.execution as unknown as Record<string, unknown>).responseDigest = 'ab'.repeat(32);
    r = run(approval, extraTampered);
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');

    // E1: forged observation id
    r = run(approval, { ...observation, id: '0x' + '22'.repeat(8) });
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');

    // E2: tampered observation payload
    const obsTampered = structuredClone(observation);
    obsTampered.payload.execution.actionDigest = 'ff'.repeat(32);
    r = run(approval, obsTampered);
    expect(checkById(r.checks, 'E1').status).toBe('PASS');
    expect(checkById(r.checks, 'E2').status).toBe('FAIL');
    expect(checkById(r.checks, 'L3').status).toBe('FAIL');

    // E2: wrong / empty expected execution signer
    r = run(approval, observation, { expectedExecutionSigner: approval.signature.signer });
    expect(checkById(r.checks, 'E2').status).toBe('FAIL');
    r = run(approval, observation, { expectedExecutionSigner: '' });
    expect(checkById(r.checks, 'E2').status).toBe('FAIL');

    // Non-object inputs fail A1 / E1 without throwing.
    r = run(null, observation);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');
    r = run(approval, 'nope');
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');
    r = run(approval, { ...observation, fn: () => 1 });
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');
  });

  it('A3 fails for a validly signed denied approval', async () => {
    const { observation } = await produceLinkedPair();
    const input = makeInput();
    input.approval.decision = 'denied';
    const denied = createApprovalReceipt(input, APPROVER_CONFIG);
    const r = verifyApprovalExecutionLink({
      approval: denied,
      observation,
      expectedApprovalSigner: denied.signature.signer,
      expectedExecutionSigner: observation.signature.signer,
    });
    expect(r.ok).toBe(false);
    expect(checkById(r.checks, 'A1').status).toBe('PASS');
    expect(checkById(r.checks, 'A2').status).toBe('PASS');
    expect(checkById(r.checks, 'A3').status).toBe('FAIL');
  });

  describe('re-signed semantic negatives for L1–L4', () => {
    async function base() {
      const { approval, observation } = await produceLinkedPair();
      const expected = {
        expectedApprovalSigner: approval.signature.signer,
        expectedExecutionSigner: observation.signature.signer,
      };
      const resign = (mutate: (p: ExecutionReceiptPayload) => void) => {
        const payload = structuredClone(observation.payload);
        mutate(payload);
        return signObservation(payload);
      };
      return { approval, observation, expected, resign };
    }

    function expectOnlyFail(result: ReturnType<typeof verifyApprovalExecutionLink>, failing: LinkCheck['id'][]) {
      expect(result.ok).toBe(false);
      for (const c of result.checks) {
        expect(`${c.id}:${c.status}`).toBe(`${c.id}:${failing.includes(c.id) ? 'FAIL' : 'PASS'}`);
      }
    }

    it('L1: approvalReceiptHash differs', async () => {
      const { approval, expected, resign } = await base();
      const obs = resign((p) => (p.execution.approvalReceiptHash = '0x' + 'ab'.repeat(32)));
      expect(verifyReceipt(obs)).toBe(true);
      expectOnlyFail(verifyApprovalExecutionLink({ approval, observation: obs, ...expected }), ['L1']);
    });

    it('L1: approvalReceiptId differs', async () => {
      const { approval, expected, resign } = await base();
      const obs = resign((p) => (p.execution.approvalReceiptId = '0x' + 'ab'.repeat(8)));
      expectOnlyFail(verifyApprovalExecutionLink({ approval, observation: obs, ...expected }), ['L1']);
    });

    it('L1: observation links to a different (validly signed) approval', async () => {
      const { expected, observation } = await base();
      const other = makeReceipt({ binding: { ...makeInput().binding, operationId: 'op-0002' } });
      const r = verifyApprovalExecutionLink({ approval: other, observation, ...expected });
      expect(checkById(r.checks, 'L1').status).toBe('FAIL');
      expect(checkById(r.checks, 'L2').status).toBe('FAIL');
      expect(r.ok).toBe(false);
    });

    it.each<[keyof ExecutionReceiptPayload['execution']]>([['operationId'], ['requester'], ['audience'], ['tool']])(
      'L2: %s differs',
      async (field) => {
        const { approval, expected, resign } = await base();
        const obs = resign((p) => ((p.execution as unknown as Record<string, unknown>)[field] = 'different'));
        const r = verifyApprovalExecutionLink({ approval, observation: obs, ...expected });
        expectOnlyFail(r, ['L2']);
        expect(checkById(r.checks, 'L2').detail).toContain(field);
      },
    );

    it('L3: actionDigest differs (valid signature, different digest)', async () => {
      const { approval, expected, resign } = await base();
      const obs = resign((p) => (p.execution.actionDigest = computeArgumentsDigest(ARGS_JSON_CHANGED)));
      expect(verifyReceipt(obs, expected.expectedExecutionSigner)).toBe(true);
      expectOnlyFail(verifyApprovalExecutionLink({ approval, observation: obs, ...expected }), ['L3']);
    });

    it('L4: dispatchedAt precedes decidedAt', async () => {
      const { approval, expected, resign } = await base();
      const obs = resign((p) => (p.execution.dispatchedAt = new Date(DECIDED_AT_MS - 1).toISOString()));
      expectOnlyFail(verifyApprovalExecutionLink({ approval, observation: obs, ...expected }), ['L4']);
    });

    it('L4: dispatchedAt == decidedAt passes', async () => {
      const { approval, expected, resign } = await base();
      const obs = resign((p) => (p.execution.dispatchedAt = DECIDED_AT));
      expect(verifyApprovalExecutionLink({ approval, observation: obs, ...expected }).ok).toBe(true);
    });

    it('L4: until — dispatchedAt == notAfter fails, notAfter - 1 ms passes', async () => {
      const approval = makeUntilReceipt();
      const h = makeHarness(approval, { consume: undefined, clock: fixedClock(NOT_AFTER_MS - 1) });
      const result = asReturned(await executeApproved(h.params, h.dispatch));
      const observation = result.observation!;
      const expected = {
        expectedApprovalSigner: approval.signature.signer,
        expectedExecutionSigner: observation.signature.signer,
      };
      expect(verifyApprovalExecutionLink({ approval, observation, ...expected }).ok).toBe(true);
      const payload = structuredClone(observation.payload);
      payload.execution.dispatchedAt = NOT_AFTER;
      const late = signObservation(payload);
      expectOnlyFail(verifyApprovalExecutionLink({ approval, observation: late, ...expected }), ['L4']);
    });

    it('a blocked execution produces no observation (the L3 negative above is separately signed)', async () => {
      const h = makeHarness(makeReceipt(), { argumentsJson: ARGS_JSON_CHANGED });
      const result = await executeApproved(h.params, h.dispatch);
      expect(result.outcome).toBe('blocked');
      expect(result).not.toHaveProperty('observation');
    });
  });
});

// ---------------------------------------------------------------------------
// Legacy overloads keep runtime bytes identical
// ---------------------------------------------------------------------------

describe('legacy overloads', () => {
  it('legacy receipts hash and verify unchanged; approval receipts take the second overload', () => {
    const legacy = makeLegacyAuthReceipt();
    expect(hashPayload(legacy.payload)).toBe(legacy.signature.payloadHash);
    expect(verifyReceipt(legacy)).toBe(true);
    expect(computeReceiptHash(legacy)).toMatch(/^0x[0-9a-f]{64}$/);
    const approval = makeReceipt();
    expect(computeReceiptHash(approval)).toBe(
      '0x' + bytesToHex(require('@noble/hashes/sha3').keccak_256(new TextEncoder().encode(canonicalize({ payload: approval.payload, signature: approval.signature })))),
    );
  });
});

// ---------------------------------------------------------------------------
// Codex review R1 regressions
// ---------------------------------------------------------------------------

async function settleUnhandled(): Promise<void> {
  await new Promise((resolve) => setImmediate(resolve));
  await new Promise((resolve) => setImmediate(resolve));
}

describe('R1-1 result contract holds for hostile inputs (never throws out of band)', () => {
  it('payload.kind = 1n → wrong_kind, no TypeError', async () => {
    const receipt = structuredClone(makeReceipt());
    (receipt.payload as unknown as Record<string, unknown>).kind = 1n;
    const h = makeHarness(receipt);
    const blocked = await expectBlocked(h, 'wrong_kind');
    expect(blocked.detail).toContain('bigint');
  });

  it('cyclic receipt → blocked, no throw', async () => {
    const cyclicKind = structuredClone(makeReceipt());
    (cyclicKind.payload as unknown as Record<string, unknown>).kind = cyclicKind;
    await expectBlocked(makeHarness(cyclicKind), 'wrong_kind');

    const cyclicMember = structuredClone(makeReceipt());
    (cyclicMember.payload.binding as unknown as Record<string, unknown>).loop = cyclicMember;
    await expectBlocked(makeHarness(cyclicMember), 'malformed_receipt');

    const cyclicKeyId = structuredClone(makeReceipt());
    (cyclicKeyId.signature as unknown as Record<string, unknown>).keyId = cyclicKeyId;
    await expectBlocked(makeHarness(cyclicKeyId), 'malformed_receipt');
  });

  it('bigint / symbol / null-prototype values in the receipt → blocked, no throw', async () => {
    for (const poison of [1n, Symbol('s'), Object.create(null), { toString: () => { throw new Error('x'); } }]) {
      const receipt = structuredClone(makeReceipt()) as unknown as Record<string, unknown>;
      (receipt.signature as Record<string, unknown>).keyId = poison;
      const h = makeHarness(receipt as unknown as SignedReceipt<ApprovalReceiptPayload>);
      const result = await executeApproved(h.params, h.dispatch);
      expect(result.outcome).toBe('blocked');
      expect(h.dispatch).not.toHaveBeenCalled();
    }
  });

  it.each(['receipt', 'expectedSigner', 'context', 'argumentsJson', 'attemptId', 'consume', 'observer', 'clock'])(
    'throwing getter on params.%s → malformed_input',
    async (member) => {
      const h = makeHarness(makeReceipt());
      Object.defineProperty(h.params, member, {
        get() {
          throw new Error('getter boom');
        },
        enumerable: true,
      });
      const blocked = await expectBlocked(h, 'malformed_input');
      expect(blocked.detail).toContain('getter boom');
      expect(h.store.size).toBe(0);
    },
  );

  it('params getter throwing a null-prototype object → malformed_input', async () => {
    const h = makeHarness(makeReceipt());
    Object.defineProperty(h.params, 'receipt', {
      get() {
        throw Object.create(null);
      },
    });
    await expectBlocked(h, 'malformed_input');
  });

  it('consume throwing a null-prototype object → consume_rejected', async () => {
    const consume = jest.fn(() => {
      throw Object.create(null);
    });
    const h = makeHarness(makeReceipt(), { consume });
    await expectBlocked(h, 'consume_rejected');
  });

  it('consume throwing a symbol / bigint → consume_rejected', async () => {
    for (const poison of [Symbol('s'), 1n]) {
      const h = makeHarness(makeReceipt(), {
        consume: () => {
          throw poison;
        },
      });
      await expectBlocked(h, 'consume_rejected');
    }
  });

  it('observer throwing a non-Error after dispatch (returned path) → returned + observationError', async () => {
    const h = makeHarness(makeReceipt());
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw Object.create(null);
    });
    try {
      const result = asReturned(await executeApproved(h.params, h.dispatch));
      expect(result.value).toEqual({ refunded: true });
      expect(result.observation).toBeUndefined();
      expect(result.observationError).toBeInstanceOf(Error);
      expect(h.dispatch).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('observer throwing a non-Error after dispatch (threw path) → ApprovedExecutionError with original cause', async () => {
    const cause = new Error('downstream failed');
    const h = makeHarness(makeReceipt(), {}, () => {
      throw cause;
    });
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw Object.create(null);
    });
    try {
      let caught: unknown;
      try {
        await executeApproved(h.params, h.dispatch);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ApprovedExecutionError);
      const err = caught as ApprovedExecutionError;
      expect(err.cause).toBe(cause);
      expect(err.observation).toBeUndefined();
      expect(err.observationError).toBeInstanceOf(Error);
      expect(h.dispatch).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it('dispatch throwing a null-prototype object / bigint is preserved verbatim as cause', async () => {
    for (const poison of [Object.create(null), 1n, Symbol('s')]) {
      const h = makeHarness(makeReceipt(), {}, () => {
        throw poison;
      });
      let caught: unknown;
      try {
        await executeApproved(h.params, h.dispatch);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ApprovedExecutionError);
      expect((caught as ApprovedExecutionError).cause).toBe(poison);
      expect((caught as ApprovedExecutionError).observation!.payload.execution.outcome).toBe('threw');
    }
  });

  it('verifyApprovalExecutionLink on cyclic / bigint / hostile inputs returns FAIL checks, never throws', async () => {
    const { approval, observation } = await produceLinkedPair();
    const expected = {
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: observation.signature.signer,
    };
    const cyclicApproval = structuredClone(approval);
    (cyclicApproval.payload as unknown as Record<string, unknown>).kind = cyclicApproval;
    let r = verifyApprovalExecutionLink({ approval: cyclicApproval, observation, ...expected });
    expect(r.ok).toBe(false);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');
    expect(checkById(r.checks, 'E1').status).toBe('PASS');

    const bigintObs = structuredClone(observation);
    (bigintObs.payload as unknown as Record<string, unknown>).kind = 1n;
    r = verifyApprovalExecutionLink({ approval, observation: bigintObs, ...expected });
    expect(checkById(r.checks, 'A1').status).toBe('PASS');
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');
    expect(checkById(r.checks, 'E1').detail).toContain('bigint');

    const hostileKeyId = structuredClone(observation);
    (hostileKeyId.signature as unknown as Record<string, unknown>).keyId = Object.create(null);
    r = verifyApprovalExecutionLink({ approval, observation: hostileKeyId, ...expected });
    expect(checkById(r.checks, 'E1').status).toBe('FAIL');

    const throwingParams = {} as Parameters<typeof verifyApprovalExecutionLink>[0];
    Object.defineProperty(throwingParams, 'approval', {
      get() {
        throw new Error('getter boom');
      },
    });
    r = verifyApprovalExecutionLink(throwingParams);
    expect(r.ok).toBe(false);
    expect(r.checks).toHaveLength(9);
    expect(checkById(r.checks, 'A1').status).toBe('FAIL');

    r = verifyApprovalExecutionLink(null as unknown as Parameters<typeof verifyApprovalExecutionLink>[0]);
    expect(r.ok).toBe(false);
    expect(r.checks).toHaveLength(9);
  });
});

describe('R1-2 rejected consume thenables are sunk, never awaited, never authorize', () => {
  async function withUnhandledCapture<T>(fn: () => Promise<T>): Promise<{ result: T; unhandled: unknown[] }> {
    const unhandled: unknown[] = [];
    const listener = (reason: unknown) => {
      unhandled.push(reason);
    };
    const previous = process.listeners('unhandledRejection');
    for (const l of previous) process.removeListener('unhandledRejection', l as (...args: unknown[]) => void);
    process.on('unhandledRejection', listener);
    try {
      const result = await fn();
      await settleUnhandled();
      return { result, unhandled };
    } finally {
      process.removeListener('unhandledRejection', listener);
      for (const l of previous) process.on('unhandledRejection', l as (...args: unknown[]) => void);
    }
  }

  it('consume returning a rejected Promise → consume_rejected, zero dispatches, no unhandledRejection', async () => {
    const h = makeHarness(makeReceipt(), { consume: () => Promise.reject(new Error('store down')) as unknown as boolean });
    const { result, unhandled } = await withUnhandledCapture(() => executeApproved(h.params, h.dispatch));
    expect(result).toMatchObject({ outcome: 'blocked', code: 'consume_rejected' });
    expect(h.dispatch).not.toHaveBeenCalled();
    expect(unhandled).toEqual([]);
  });

  it('consume returning a resolved Promise<true> → consume_rejected, zero dispatches', async () => {
    const h = makeHarness(makeReceipt(), { consume: () => Promise.resolve(true) as unknown as boolean });
    const { result, unhandled } = await withUnhandledCapture(() => executeApproved(h.params, h.dispatch));
    expect(result).toMatchObject({ outcome: 'blocked', code: 'consume_rejected' });
    expect(h.dispatch).not.toHaveBeenCalled();
    expect(unhandled).toEqual([]);
  });

  it('consume returning a foreign thenable whose then throws → consume_rejected, no throw', async () => {
    const thenable = {
      then() {
        throw new Error('hostile then');
      },
    };
    const h = makeHarness(makeReceipt(), { consume: () => thenable as unknown as boolean });
    const result = await executeApproved(h.params, h.dispatch);
    expect(result).toMatchObject({ outcome: 'blocked', code: 'consume_rejected' });
    expect(h.dispatch).not.toHaveBeenCalled();
  });

  it('consume returning a thenable that later resolves true never dispatches', async () => {
    let resolveLater: ((v: boolean) => void) | undefined;
    const pending = new Promise<boolean>((resolve) => {
      resolveLater = resolve;
    });
    const h = makeHarness(makeReceipt(), { consume: () => pending as unknown as boolean });
    const result = await executeApproved(h.params, h.dispatch);
    expect(result).toMatchObject({ outcome: 'blocked', code: 'consume_rejected' });
    resolveLater!(true);
    await settleUnhandled();
    expect(h.dispatch).not.toHaveBeenCalled();
  });
});

describe('R1-5 non-callable toJSON members are valid bab1 data', () => {
  it('digests {"toJSON":1} and nested non-callable toJSON fields', () => {
    expect(computeArgumentsDigest('{"toJSON":1}')).toMatch(/^[0-9a-f]{64}$/);
    expect(computeArgumentsDigest('{"toJSON":1}')).toBe(computeArgumentsDigest('{ "toJSON" : 1 }'));
    expect(computeArgumentsDigest('{"a":{"toJSON":{"b":[1,"x"]}}}')).toMatch(/^[0-9a-f]{64}$/);
    expect(computeArgumentsDigest('{"toJSON":null}')).not.toBe(computeArgumentsDigest('{"toJSON":1}'));
    expect(validateArgumentsJson('{"toJSON":"string"}')).toEqual({ ok: true });
    expect(validateArgumentsJson('{"a":[{"toJSON":{"toJSON":false}}]}')).toEqual({ ok: true });
  });

  it('executes an approval whose arguments carry a toJSON field', async () => {
    const argumentsJson = '{"orderId":"ord_1","toJSON":{"note":"legit"}}';
    const receipt = makeReceipt({ argumentsJson });
    const h = makeHarness(receipt, { argumentsJson });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    expect(h.dispatch).toHaveBeenCalledTimes(1);
    const [snapshot] = h.dispatch.mock.calls[0] as [Record<string, unknown>];
    expect(snapshot).toEqual({ orderId: 'ord_1', toJSON: { note: 'legit' } });
    expect(result.observation!.payload.execution.actionDigest).toBe(computeArgumentsDigest(argumentsJson));
    expect(verifyReceipt(result.observation!)).toBe(true);
  });
});

describe('R1-6 clock samples must fit the observation timestamp domain', () => {
  const YEAR_10000 = Date.UTC(10000, 0, 1);
  const LAST_VALID = YEAR_10000 - 1;

  it('t0 beyond year 9999 → invalid_clock before consumption', async () => {
    const consume = jest.fn(() => true);
    const h = makeHarness(makeReceipt(), { clock: () => new Date('+010000-01-01T00:00:00.000Z'), consume });
    await expectBlocked(h, 'invalid_clock');
    expect(consume).not.toHaveBeenCalled();
    const h2 = makeHarness(makeReceipt(), { clock: fixedClock(YEAR_10000), consume });
    await expectBlocked(h2, 'invalid_clock');
    expect(consume).not.toHaveBeenCalled();
  });

  it('td beyond year 9999 → invalid_clock, zero dispatches (claim consumed)', async () => {
    const h = makeHarness(makeReceipt(), { clock: sequenceClock([NOW_MS, YEAR_10000]) });
    await expectBlocked(h, 'invalid_clock');
    expect(h.store.size).toBe(1);
  });

  it('negative epoch samples → invalid_clock at either position', async () => {
    const consume = jest.fn(() => true);
    const h = makeHarness(makeReceipt(), { clock: fixedClock(-1), consume });
    await expectBlocked(h, 'invalid_clock');
    expect(consume).not.toHaveBeenCalled();
    const h2 = makeHarness(makeReceipt(), { clock: sequenceClock([NOW_MS, -1]) });
    await expectBlocked(h2, 'invalid_clock');
  });

  it('the last valid millisecond of year 9999 dispatches and the observation passes E1 and the link', async () => {
    const approval = makeReceipt();
    const h = makeHarness(approval, { clock: fixedClock(LAST_VALID) });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    const obs = result.observation!;
    expect(obs.payload.execution.dispatchedAt).toBe('9999-12-31T23:59:59.999Z');
    expect(obs.payload.issuedAt).toBe(Math.floor(LAST_VALID / 1000));
    const link = verifyApprovalExecutionLink({
      approval,
      observation: obs,
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: obs.signature.signer,
    });
    expect(checkById(link.checks, 'E1').status).toBe('PASS');
    expect(link.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Codex review R2 regressions
// ---------------------------------------------------------------------------

describe('R2-1 dispatch is invoked as a bare function with no access to retained state', () => {
  it('this is undefined inside dispatch; retained snapshot/receipt/observer cannot be reached or replaced', async () => {
    const approval = makeReceipt();
    const other = makeReceipt({
      binding: { ...makeInput().binding, operationId: 'op-other' },
      argumentsJson: ARGS_JSON_CHANGED,
    });
    const originalDigest = approval.payload.binding.argumentsDigest;
    let seenThis: unknown = 'unset';
    let leakedKey: unknown = 'unset';
    let leakedSnapshot: unknown = 'unset';
    let leakedReceipt: unknown = 'unset';
    const dispatch = jest.fn(function dispatch(this: unknown) {
      seenThis = this;
      if (this !== undefined && this !== null) {
        const state = this as Record<string, unknown>;
        try {
          leakedKey = (state.observer as { privateKey?: unknown } | undefined)?.privateKey;
          leakedSnapshot = state.snapshot;
          leakedReceipt = state.receipt;
          state.snapshot = { orderId: 'ord_123', amount: 999, currency: 'USD' };
          state.receipt = other;
          state.attemptId = 'forged';
          state.observer = OBSERVER_CONFIG;
        } catch {
          // frozen or unreachable: both acceptable
        }
      }
      return 'ok';
    });
    const h = makeHarness(approval);
    const result = asReturned(await executeApproved(h.params, dispatch));
    expect(seenThis).toBeUndefined();
    expect(leakedKey).toBe('unset');
    expect(leakedSnapshot).toBe('unset');
    expect(leakedReceipt).toBe('unset');
    const obs = result.observation!;
    expect(obs.payload.execution.actionDigest).toBe(originalDigest);
    expect(obs.payload.execution.approvalReceiptHash).toBe(computeReceiptHash(approval));
    expect(obs.payload.execution.attemptId).toBe('attempt-1');
    expect(JSON.stringify(obs)).not.toContain(OBSERVER_PRIVATE_KEY.slice(2));
    expect(
      verifyApprovalExecutionLink({
        approval,
        observation: obs,
        expectedApprovalSigner: approval.signature.signer,
        expectedExecutionSigner: obs.signature.signer,
      }).ok,
    ).toBe(true);
    expect(
      verifyApprovalExecutionLink({
        approval: other,
        observation: obs,
        expectedApprovalSigner: other.signature.signer,
        expectedExecutionSigner: obs.signature.signer,
      }).ok,
    ).toBe(false);
  });

  it('consume and clock are also invoked with this undefined', async () => {
    let consumeThis: unknown = 'unset';
    let clockThis: unknown = 'unset';
    const h = makeHarness(makeReceipt(), {
      consume: function consume(this: unknown) {
        consumeThis = this;
        return true;
      },
      clock: function clock(this: unknown) {
        clockThis = this;
        return new Date(NOW_MS);
      },
    });
    asReturned(await executeApproved(h.params, h.dispatch));
    expect(consumeThis).toBeUndefined();
    expect(clockThis).toBeUndefined();
  });
});

describe('R2-2 observer throwing a hostile Proxy never breaks the settlement contract', () => {
  function revokedProxy(): unknown {
    const { proxy, revoke } = Proxy.revocable(new Error('x'), {});
    revoke();
    return proxy;
  }
  function throwingProtoProxy(): unknown {
    return new Proxy(
      {},
      {
        getPrototypeOf() {
          throw new Error('trap');
        },
        get() {
          throw new Error('trap');
        },
      },
    );
  }

  it.each<[string, () => unknown]>([
    ['revoked Proxy', revokedProxy],
    ['Proxy with throwing getPrototypeOf/get traps', throwingProtoProxy],
  ])('%s thrown by the observer: returned path keeps the value', async (_name, make) => {
    const h = makeHarness(makeReceipt());
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw make();
    });
    try {
      const result = asReturned(await executeApproved(h.params, h.dispatch));
      expect(result.value).toEqual({ refunded: true });
      expect(result.observation).toBeUndefined();
      expect(result.observationError).toBeInstanceOf(Error);
      expect(h.dispatch).toHaveBeenCalledTimes(1);
    } finally {
      spy.mockRestore();
    }
  });

  it.each<[string, () => unknown]>([
    ['revoked Proxy', revokedProxy],
    ['Proxy with throwing getPrototypeOf/get traps', throwingProtoProxy],
  ])('%s thrown by the observer: threw path keeps the original cause', async (_name, make) => {
    const cause = new Error('downstream failed');
    const h = makeHarness(makeReceipt(), {}, () => {
      throw cause;
    });
    const spy = jest.spyOn(signModule, 'signReceipt').mockImplementation(() => {
      throw make();
    });
    try {
      let caught: unknown;
      try {
        await executeApproved(h.params, h.dispatch);
      } catch (e) {
        caught = e;
      }
      expect(caught).toBeInstanceOf(ApprovedExecutionError);
      const err = caught as ApprovedExecutionError;
      expect(err.cause).toBe(cause);
      expect(err.observation).toBeUndefined();
      expect(err.observationError).toBeInstanceOf(Error);
    } finally {
      spy.mockRestore();
    }
  });

  it('a hostile Proxy thrown by dispatch is preserved as the cause', async () => {
    const poison = revokedProxy();
    const h = makeHarness(makeReceipt(), {}, () => {
      throw poison;
    });
    let caught: unknown;
    try {
      await executeApproved(h.params, h.dispatch);
    } catch (e) {
      caught = e;
    }
    expect(caught).toBeInstanceOf(ApprovedExecutionError);
    expect((caught as ApprovedExecutionError).cause).toBe(poison);
    expect((caught as ApprovedExecutionError).observation!.payload.execution.outcome).toBe('threw');
  });

  it('a hostile Proxy thrown by consume or a params getter still blocks', async () => {
    const h1 = makeHarness(makeReceipt(), {
      consume: () => {
        throw revokedProxy();
      },
    });
    await expectBlocked(h1, 'consume_rejected');
    const h2 = makeHarness(makeReceipt());
    Object.defineProperty(h2.params, 'receipt', {
      get() {
        throw throwingProtoProxy();
      },
    });
    await expectBlocked(h2, 'malformed_input');
  });
});




// ---------------------------------------------------------------------------
// validateArgumentsJson — arguments enter only as JSON text (Codex R5 contract)
// ---------------------------------------------------------------------------

describe('validateArgumentsJson', () => {
  it('accepts valid bab1 JSON text and rejects a non-string without throwing', () => {
    expect(validateArgumentsJson(ARGS_JSON)).toEqual({ ok: true });
    for (const bad of [undefined, null, 1, { a: 1 }, ['{}']]) {
      const result = validateArgumentsJson(bad as unknown as string);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.detail).toMatch(/string/);
    }
  });

  it('reports invalid JSON with the fixed detail prefix', () => {
    for (const text of ['', '{', '{"a":1} x', "{'a':1}", 'undefined', '{"a":NaN}', '{"a":Infinity}']) {
      const result = validateArgumentsJson(text);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.detail).toMatch(/^invalid JSON/);
    }
  });

  it('rejects negative zero in every spelling, at root members, nested and in arrays', () => {
    for (const zero of ['-0', '-0.0', '-0e0', '-0E0', '-0.0e+0']) {
      for (const text of [`{"a":${zero}}`, `{"a":{"b":${zero}}}`, `{"a":[1,${zero}]}`, `{"a":[[${zero}]]}`]) {
        const result = validateArgumentsJson(text);
        expect(`${text}:${result.ok}`).toBe(`${text}:false`);
        if (!result.ok) expect(result.detail).toMatch(/negative zero/);
      }
    }
    expect(validateArgumentsJson('{"a":0}')).toEqual({ ok: true });
    expect(validateArgumentsJson('{"a":0.0}')).toEqual({ ok: true });
    expect(JSON.parse('-0')).toBe(-0); // the hazard this guards
  });

  it('rejects __proto__, constructor and prototype keys at root and at depth (JSON.parse makes them own properties)', () => {
    const own = JSON.parse('{"__proto__":{"amount":999}}') as Record<string, unknown>;
    expect(Object.keys(own)).toEqual(['__proto__']); // own, not the prototype setter
    for (const text of [
      '{"__proto__":{"amount":999}}',
      '{"a":{"__proto__":1}}',
      '{"a":[{"b":{"__proto__":{}}}]}',
      '{"constructor":1}',
      '{"a":{"constructor":{"prototype":1}}}',
      '{"a":[[{"prototype":null}]]}',
    ]) {
      const result = validateArgumentsJson(text);
      expect(`${text}:${result.ok}`).toBe(`${text}:false`);
      if (!result.ok) expect(result.detail).toMatch(/__proto__|constructor|prototype/);
    }
    expect(() => computeArgumentsDigest('{"__proto__":{"amount":999}}')).toThrow(/__proto__/);
  });

  it('rejects a root that is not an object', () => {
    for (const text of ['[{"a":1}]', '"x"', '1', 'true', 'null']) {
      const result = validateArgumentsJson(text);
      expect(result.ok).toBe(false);
      if (!result.ok) expect(result.detail).toMatch(/JSON object/);
    }
  });

  it('duplicate keys collapse last-wins (documented): {"a":1,"a":2} binds a:2', async () => {
    expect(validateArgumentsJson('{"a":1,"a":2}')).toEqual({ ok: true });
    expect(computeArgumentsDigest('{"a":1,"a":2}')).toBe(computeArgumentsDigest('{"a":2}'));
    expect(computeArgumentsDigest('{"a":1,"a":2}')).not.toBe(computeArgumentsDigest('{"a":1}'));
    const receipt = makeReceipt({ argumentsJson: '{"a":2}' });
    const h = makeHarness(receipt, { argumentsJson: '{"a":1,"a":2}' });
    asReturned(await executeApproved(h.params, h.dispatch));
    expect(h.dispatch).toHaveBeenCalledTimes(1);
    const [snapshot] = h.dispatch.mock.calls[0] as [Record<string, unknown>];
    expect(snapshot).toEqual({ a: 2 });
    expect(Object.isFrozen(snapshot)).toBe(true);
  });

  it('enforces the depth cap and both size caps through JSON text', () => {
    const nest = (n: number) => '{"a":' + '['.repeat(n) + ']'.repeat(n) + '}';
    expect(validateArgumentsJson(nest(63))).toEqual({ ok: true });
    const deep = validateArgumentsJson(nest(64));
    expect(deep.ok).toBe(false);
    if (!deep.ok) expect(deep.detail).toMatch(/depth/);
    const overhead = '{"a":""}'.length;
    const under = '{"a":"' + 'x'.repeat(ARGUMENTS_MAX_BYTES - overhead) + '"}';
    expect(validateArgumentsJson(under)).toEqual({ ok: true });
    const over = '{"a":"' + 'x'.repeat(ARGUMENTS_MAX_BYTES - overhead + 1) + '"}';
    const big = validateArgumentsJson(over);
    expect(big.ok).toBe(false);
    if (!big.ok) expect(big.detail).toMatch(/1 MiB|size/);
    // Escapes shrink on canonicalization; the exact canonical check still passes.
    const escaped = '{"a":"' + '\\u0041'.repeat(Math.floor((ARGUMENTS_MAX_BYTES - overhead) / 6)) + '"}';
    expect(validateArgumentsJson(escaped)).toEqual({ ok: true });
  });

  it('the snapshot dispatched is the frozen parsed tree and matches the digested canonical form', async () => {
    const argumentsJson = '{"z":[1,{"b":null}],"a":"ü","n":1e21}';
    const receipt = makeReceipt({ argumentsJson });
    const h = makeHarness(receipt, { argumentsJson: ' { "n" : 1e21 , "a" : "ü" , "z" : [ 1 , { "b" : null } ] } ' });
    const result = asReturned(await executeApproved(h.params, h.dispatch));
    const [snapshot] = h.dispatch.mock.calls[0] as [Record<string, unknown>];
    expect(snapshot).toEqual({ z: [1, { b: null }], a: 'ü', n: 1e21 });
    expect(Object.isFrozen((snapshot.z as unknown[])[1])).toBe(true);
    expect(canonicalize(snapshot)).toBe(canonicalize(JSON.parse(argumentsJson)));
    expect(result.observation!.payload.execution.actionDigest).toBe(computeArgumentsDigest(argumentsJson));
  });
});
