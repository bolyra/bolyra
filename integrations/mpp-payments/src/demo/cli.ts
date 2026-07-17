#!/usr/bin/env node
/**
 * `npx @bolyra/mpp demo` — the two-minute, zero-setup first impression.
 *
 * Runs the full mandate flow in-process: an operator issues a small-tier
 * spend mandate with the package's own `issueMandate`, an agent presents it
 * to a route gated by `bolyraGate`, a $25 spend allows, a $500 spend denies
 * with the RFC 9457 problem body, a mandate-less request denies, and the
 * signed authorization receipt is verified. No network, no wallet, no
 * browser, nothing else to install.
 *
 * HONESTY LABEL — what is real and what is a stub. Everything on the
 * VERIFICATION path is the real shipped code: `issueMandate` (operator
 * EdDSA-Poseidon binding signature), `bolyraGate` (classical verify:
 * trusted-operator gate, audience binding, tier/capability subset, scope
 * anchoring, strict expiry), the RFC 9457 denial bodies, and the ES256K
 * hash-chained receipts verified with `@bolyra/receipts`. Only the ROUTE is
 * a stub: a minimal in-process stand-in for an mppx payment method (the gate
 * wraps `Method.Server` structurally, so no mppx import is needed). The stub
 * mimics mppx's call order — preflight → 402 challenge → credential retry →
 * preflight → verify → receipt — but settles nothing. For the same flow
 * against real mppx, see examples/mandate-demo.
 */

import { verifyReceipt, verifyReceiptChain, type SignedReceipt } from '@bolyra/receipts';
import {
  bolyraGate,
  BOLYRA_AUTHORIZATION_HEADER,
  issueMandate,
  type MppxServerMethodLike,
} from '../index';

const OPERATOR_PRIVATE_KEY = 42n; // demo only — never a real key
const AUDIENCE = 'api.merchant.example';
const MODEL = 'opus-4.1';
const AGENT = 'shopper-bot';
const STUB_PAYMENT_TOKEN = 'stub-demo-payment-token';

/** One narrated line sink; the CLI uses console.log, the smoke test captures. */
export type WriteLine = (line: string) => void;

/**
 * Run the full narrated demo. Exported so the smoke test can execute it
 * programmatically; throws if any step lands on an unexpected outcome.
 */
export async function runDemo(write: WriteLine = console.log): Promise<void> {
  const startedAt = Date.now();

  write('@bolyra/mpp demo — MPP moves the money; Bolyra proves the mandate.');
  write('');
  write('Everything on the verification path below is the real shipped code');
  write('(issueMandate → bolyraGate classical verify → signed receipts). Only the');
  write('route is a stub standing in for an mppx payment method — no network, no');
  write('wallet, nothing else to install.');
  write('');

  // ── [1/6] OPERATOR issues a spend mandate ─────────────────────────────────
  const expiry = Math.floor(Date.now() / 1000) + 60 * 60;
  const mandate = await issueMandate({
    operatorPrivateKey: OPERATOR_PRIVATE_KEY,
    agentName: AGENT,
    audience: AUDIENCE,
    model: MODEL,
    tier: 'small', // < $100, nothing more
    expiry,
  });
  write(`[1/6] OPERATOR issues a spend mandate (issueMandate, in-process).`);
  write(`      tier=${mandate.tier} (< $100)  agent=${mandate.agentName}  audience=${mandate.audience}  expires=+1h`);
  write('      why: the operator’s EdDSA-Poseidon signature binds agent, audience,');
  write('      tier capabilities, and expiry into one tamper-evident mandate.');
  write('');

  // ── [2/6] SERVER gates a stub mppx-shaped route with bolyraGate ──────────
  let stubPaymentRuns = 0;
  const stubCharge: MppxServerMethodLike = {
    name: 'stub',
    intent: 'charge',
    async verify() {
      stubPaymentRuns += 1;
      return {
        method: 'stub',
        reference: `stub-tx-${stubPaymentRuns}`,
        status: 'success',
        timestamp: new Date().toISOString(),
      };
    },
  };

  const receipts: SignedReceipt[] = [];
  const gated = bolyraGate(stubCharge, {
    audience: AUDIENCE,
    model: MODEL,
    verifier: {
      kind: 'classical',
      trustedOperators: [mandate.operatorPublicKey],
    },
    onReceipt: (receipt) => receipts.push(receipt),
  });

  write('[2/6] SERVER wraps a stub payment route with bolyraGate (the real gate).');
  write('      why: bolyraGate composes into the method’s preflight hook, so the');
  write('      mandate is verified BEFORE any challenge or payment logic runs. The');
  write('      stub only stands in for the mppx transport; the gate code is real.');
  write('');

  /**
   * The stub transport: one HTTP exchange the way mppx drives a gated method.
   * The (wrapped) preflight runs first; a returned Response fully handles the
   * request (that is a gate denial). Otherwise a credential-less request gets
   * the minimal 402 stub challenge, and a credential-bearing one reaches the
   * (wrapped) verify, which attaches the bolyraAuthorization receipt field.
   */
  async function handleOnce(request: Request, amount: string): Promise<Response> {
    const capturedRequest = {}; // mppx's per-request snapshot token
    const credential = request.headers.get('authorization');
    const preflight = await gated.preflight?.({
      capturedRequest,
      credential,
      input: request,
      options: { amount },
    });
    if (preflight instanceof Response) return preflight; // gate denial
    if (credential !== `Stub ${STUB_PAYMENT_TOKEN}`) {
      return Response.json({ stub: 'payment challenge' }, { status: 402 });
    }
    const receipt = await gated.verify({ envelope: { capturedRequest } });
    return Response.json(
      { data: 'paid content', receipt },
      { status: 200, headers: { 'stub-payment-receipt': 'attached' } },
    );
  }

  /** The agent's 402 flow: call, and on a stub challenge retry with payment. */
  async function payAndCall(path: string, amount: string, presentation?: string): Promise<Response> {
    const headers: Record<string, string> = {};
    if (presentation !== undefined) headers[BOLYRA_AUTHORIZATION_HEADER] = presentation;
    const first = await handleOnce(new Request(`https://${AUDIENCE}${path}`, { headers }), amount);
    if (first.status !== 402) return first;
    return handleOnce(
      new Request(`https://${AUDIENCE}${path}`, {
        headers: { ...headers, authorization: `Stub ${STUB_PAYMENT_TOKEN}` },
      }),
      amount,
    );
  }

  async function problemLine(response: Response): Promise<string[]> {
    const contentType = response.headers.get('content-type') ?? '';
    const body = (await response.json()) as Record<string, unknown>;
    return [
      `      problem body (RFC 9457, ${contentType}):`,
      ...JSON.stringify(body, null, 2)
        .split('\n')
        .map((l) => `        ${l}`),
    ];
  }

  // ── [3/6] $25 with the mandate → ALLOW ───────────────────────────────────
  const allowed = await payAndCall('/api/report', '25', mandate.presentation);
  if (allowed.status !== 200) throw new Error(`expected 200 for $25, got ${allowed.status}`);
  write('[3/6] AGENT calls GET /api/report ($25) with the mandate → HTTP 200 ALLOW.');
  write('      why: $25 maps to tier "small" — within the delegated mandate, for the');
  write('      audience it was signed for, before expiry. The (stub) payment then ran');
  write('      and its receipt carries the bolyraAuthorization extension field.');
  write('');

  // ── [4/6] $500 with the SAME mandate → DENY before payment ───────────────
  const paymentRunsBefore = stubPaymentRuns;
  const overTier = await payAndCall('/api/bulk-export', '500', mandate.presentation);
  if (overTier.status !== 403) throw new Error(`expected 403 for $500, got ${overTier.status}`);
  const overTierDelta = stubPaymentRuns - paymentRunsBefore;
  write('[4/6] AGENT calls GET /api/bulk-export ($500) with the SAME mandate → HTTP 403 DENY.');
  for (const line of await problemLine(overTier)) write(line);
  write(`      why: $500 requires tier "medium"; the mandate only delegates "small".`);
  write(`      Denied BEFORE payment: no 402 challenge was issued, and the`);
  write(`      stub payment method ran ${overTierDelta} times for this request.`);
  write('');

  // ── [5/6] No mandate at all → DENY ───────────────────────────────────────
  const noMandate = await payAndCall('/api/report', '25');
  if (noMandate.status !== 401) throw new Error(`expected 401 without mandate, got ${noMandate.status}`);
  write('[5/6] AGENT calls GET /api/report ($25) with NO mandate → HTTP 401 DENY.');
  for (const line of await problemLine(noMandate)) write(line);
  write('      why: no x-bolyra-authorization header was presented — the gate fails');
  write('      closed and unauthorized agents never even see a 402 challenge.');
  write('');

  // ── [6/6] Verify the signed authorization receipts ───────────────────────
  // Expected: 2 allows for the $25 call (challenge leg + payment leg), then
  // the $500 deny and the no-mandate deny — 4 receipts, one hash chain.
  if (receipts.length !== 4) {
    throw new Error(`expected 4 signed receipts (2 allow, 2 deny), got ${receipts.length}`);
  }
  const allowReceipt = [...receipts].reverse().find((r) => r.payload.decision.allowed);
  if (allowReceipt === undefined) throw new Error('no allow receipt was signed');
  const everySignatureOk = receipts.every((r) => verifyReceipt(r, r.signature.signer));
  const chain = verifyReceiptChain(receipts, { expectedCount: receipts.length });
  const verified = everySignatureOk && chain.ok;
  write('[6/6] Every gate decision (allow AND deny) got a signed authorization receipt.');
  write(
    `      ${receipts.length} ES256K receipts (${receipts.filter((r) => r.payload.decision.allowed).length} allow, ` +
      `${receipts.filter((r) => !r.payload.decision.allowed).length} deny), one hash chain. The $25 allow receipt:`,
  );
  write(
    `        seq=${allowReceipt.payload.chain?.seq}  allowed=${allowReceipt.payload.decision.allowed}` +
      `  amountUsd=$${allowReceipt.payload.commerce?.amount}  merchant=${allowReceipt.payload.commerce?.merchant}`,
  );
  write(`        signer=${allowReceipt.signature.signer}`);
  write(`        payloadHash=${allowReceipt.signature.payloadHash}`);
  write(
    `      signature verified: ${verified} — all ${receipts.length} receipt signatures` +
      ` (verifyReceipt) and the hash chain (verifyReceiptChain, @bolyra/receipts)`,
  );
  if (!verified) {
    throw new Error(
      `receipt verification failed (signatures ok: ${everySignatureOk}, chain ok: ${chain.ok})`,
    );
  }
  write('');

  const seconds = ((Date.now() - startedAt) / 1000).toFixed(1);
  write(`Done in ${seconds}s — real verification, stub transport.`);
  write('Deeper path: the README Quickstart wires bolyraGate into a real mppx server.');
}

function usage(write: WriteLine): void {
  write('Usage: npx @bolyra/mpp demo');
  write('');
  write('Runs the self-contained @bolyra/mpp mandate demo: issue a spend mandate,');
  write('gate a stub route with bolyraGate, watch a $25 spend allow, a $500 spend');
  write('deny (RFC 9457), a mandate-less request deny, and verify the signed');
  write('authorization receipt. No network, no wallet, no setup.');
}

/* istanbul ignore next — exercised via the packed-tarball npx run */
if (require.main === module) {
  const command = process.argv[2];
  if (command === 'demo') {
    runDemo().catch((err) => {
      console.error(err instanceof Error ? err.message : err);
      process.exit(1);
    });
  } else if (command === undefined || command === '--help' || command === '-h') {
    usage(console.log);
    process.exit(command === undefined ? 1 : 0);
  } else {
    console.error(`unknown command "${command}"`);
    usage(console.error);
    process.exit(1);
  }
}
