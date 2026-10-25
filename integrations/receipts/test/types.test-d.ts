/**
 * Compile-time assertions only — no runtime test. Type-checked by
 * `tsc -p tsconfig.test.json` (npm run typecheck); Jest's testMatch
 * (**\/test/**\/*.test.ts) does not pick up the `.test-d.ts` suffix.
 *
 * Guards the legacy surface after SignedReceipt became generic and the
 * sign/verify/hash functions gained overloads: every pre-existing call site
 * written WITHOUT type arguments must keep type-checking with the legacy
 * ReceiptPayload shape.
 */
import { signReceipt, verifyReceipt, hashPayload } from '../src/sign';
import { ReceiptChain, computeReceiptHash, verifyReceiptChain } from '../src/chain';
import { verifyInstanceBinding } from '../src/instance';
import { createApprovalReceipt, executeApproved } from '../src/approval';
import type { ApprovalReceiptPayload, ExecutionReceiptPayload, ReturnedExecution } from '../src/approval';
import type { ReceiptPayload, ReceiptSignerConfig, SignedReceipt } from '../src/types';

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Expect<T extends true> = T;

declare const payload: ReceiptPayload;
declare const config: ReceiptSignerConfig;
declare const expectedSigner: string;

// --- legacy call sites, no type arguments -----------------------------------

const signed = signReceipt(payload, config);
export type _SignReturnsLegacy = Expect<Equal<typeof signed, SignedReceipt>>;
export type _LegacyDefaultIsReceiptPayload = Expect<Equal<SignedReceipt, SignedReceipt<ReceiptPayload>>>;

const legacyTyped: SignedReceipt = signed;
const payloadOut: ReceiptPayload = legacyTyped.payload;
const kind: 'bolyra.auth' | 'bolyra.commerce' = payloadOut.kind;

const verified: boolean = verifyReceipt(signed);
const verifiedWithSigner: boolean = verifyReceipt(signed, expectedSigner);
const hashed: string = hashPayload(payload);
const receiptHash: string = computeReceiptHash(signed);

// Conditional-type inference on the overloaded functions stays legacy.
export type _ReturnTypeStaysLegacy = Expect<Equal<ReturnType<typeof signReceipt>, SignedReceipt>>;
export type _VerifyParamStaysLegacy = Expect<Equal<Parameters<typeof verifyReceipt>[0], SignedReceipt>>;
export type _HashParamStaysLegacy = Expect<Equal<Parameters<typeof hashPayload>[0], ReceiptPayload>>;
export type _ChainHashParamStaysLegacy = Expect<Equal<Parameters<typeof computeReceiptHash>[0], SignedReceipt>>;
declare const inferred: ReturnType<typeof signReceipt>;
const inferredAsLegacy: SignedReceipt = inferred;

// Chain usage.
const chain = new ReceiptChain();
const chained = chain.sign(payload, config);
const chainedTyped: SignedReceipt = chained;
const chainResult = verifyReceiptChain([signed, chained], { expectedSigner });
const chainOk: boolean = chainResult.ok;
const instance = verifyInstanceBinding(signed);
const instanceOk: boolean = instance.ok;

// --- new kinds take the second overload ---------------------------------------

declare const approvalInput: Parameters<typeof createApprovalReceipt>[0];
const approval = createApprovalReceipt(approvalInput, config);
export type _ApprovalIsTyped = Expect<Equal<typeof approval, SignedReceipt<ApprovalReceiptPayload>>>;
declare const approvalPayload: ApprovalReceiptPayload;
declare const executionPayload: ExecutionReceiptPayload;
const signedApproval = signReceipt(approvalPayload, config);
export type _SignApprovalTyped = Expect<Equal<typeof signedApproval, SignedReceipt<ApprovalReceiptPayload>>>;
const signedExecution = signReceipt(executionPayload, config);
export type _SignExecutionTyped = Expect<Equal<typeof signedExecution, SignedReceipt<ExecutionReceiptPayload>>>;
const approvalVerified: boolean = verifyReceipt(approval, expectedSigner);
const approvalHash: string = computeReceiptHash(approval);
const approvalPayloadHash: string = hashPayload(approval.payload);

// A legacy receipt is NOT accepted where an approval receipt is required.
// @ts-expect-error legacy SignedReceipt is not SignedReceipt<ApprovalReceiptPayload>
const notApproval: SignedReceipt<ApprovalReceiptPayload> = signed;

// executeApproved infers R from dispatch.
declare const execParams: Parameters<typeof executeApproved>[0];
async function _infersR(): Promise<void> {
  const result = await executeApproved(execParams, async () => ({ refunded: true as const }));
  if (result.outcome === 'returned') {
    const r: ReturnedExecution<{ refunded: true }> = result;
    const refunded: true = r.value.refunded;
    void refunded;
  }
}

void [kind, verified, verifiedWithSigner, hashed, receiptHash, inferredAsLegacy, chainedTyped, chainOk];
void [instanceOk, approvalVerified, approvalHash, approvalPayloadHash, notApproval, _infersR];
export {};
