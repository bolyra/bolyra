/**
 * Approval-to-execution binding — runnable example.
 *
 *   npx tsx examples/approval-binding.ts
 *
 * A refund tool. An approval source signs a receipt binding the reviewed
 * arguments { orderId, amount }; the executor dispatches ONLY when the live
 * arguments digest to the same value, and signs an execution observation that
 * links back to the approval receipt. A changed amount is blocked with zero
 * dispatches and no observation. Offline link verification PASSes for the
 * matched case.
 *
 * SYNTHETIC: every key below is derived from a fixed test private key. Nothing
 * here is a real approver, executor or credential.
 */
import {
  createApprovalReceipt,
  executeApproved,
  verifyApprovalExecutionLink,
  type ApprovalContext,
  type ApprovedExecution,
  type ConsumeClaim,
  type LinkCheck,
} from '../src';
import type { ReceiptSignerConfig } from '../src';

const SYNTHETIC_APPROVER: ReceiptSignerConfig = {
  issuer: 'approvals.synthetic.example',
  keyId: 'synthetic-approver-key-1',
  privateKey: '0x' + '01'.repeat(32), // SYNTHETIC test key
};

const SYNTHETIC_EXECUTOR: ReceiptSignerConfig = {
  issuer: 'executor.synthetic.example',
  keyId: 'synthetic-executor-key-1',
  privateKey: '0x' + '02'.repeat(32), // SYNTHETIC test key
};

const CONTEXT: ApprovalContext = {
  requester: 'agent:support-assistant',
  audience: 'mcp://payments.synthetic.example',
  tool: 'refund_order',
  operationId: 'op-2026-10-25-0001',
};

const REVIEWED_ARGUMENTS = JSON.stringify({ orderId: 'ord_8a21', amount: 42.5 });
const CHANGED_ARGUMENTS = JSON.stringify({ orderId: 'ord_8a21', amount: 4250 });

const DECIDED_AT = '2026-10-25T14:00:00.000Z';
const CLOCK_NOW = new Date('2026-10-25T14:00:30.000Z');

export interface ExampleOutcome {
  outcome: ApprovedExecution<unknown>['outcome'];
  code?: string;
  dispatchCount: number;
  /** Operator-visible result value when dispatched. */
  value?: unknown;
  /** Whether an execution observation was signed. */
  observation: boolean;
  /** Offline link verification result (matched case only). */
  link?: { ok: boolean; checks: LinkCheck[] };
}

export interface ExampleResult {
  matched: ExampleOutcome;
  changed: ExampleOutcome;
}

/** In-memory replay store: operators use a durable, atomic store namespaced by signer. */
function makeConsumeStore(): (claim: ConsumeClaim) => boolean {
  const seen = new Set<string>();
  return (claim) => {
    const key = `${claim.signer}|${claim.payloadHash}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  };
}

export async function runExample(): Promise<ExampleResult> {
  // 1. The approval source signs what was reviewed: context + argument digest.
  const approval = createApprovalReceipt(
    {
      binding: { ...CONTEXT },
      approval: {
        approver: 'Synthetic Approver <approver@synthetic.example>',
        source: 'synthetic:approval-queue',
        decision: 'approved',
        decidedAt: DECIDED_AT,
        validity: { kind: 'once' },
        requestId: 'apr-0001',
      },
      argumentsJson: REVIEWED_ARGUMENTS,
    },
    SYNTHETIC_APPROVER,
  );

  // 2. The executor dispatches only through executeApproved.
  const consume = makeConsumeStore();
  let dispatchCount = 0;
  const refundTool = async (snapshot: Readonly<Record<string, unknown>>) => {
    dispatchCount += 1;
    return { refundId: 'rf_0001', orderId: snapshot.orderId, amount: snapshot.amount };
  };

  const matchedResult = await executeApproved(
    {
      receipt: approval,
      expectedSigner: approval.signature.signer,
      context: { ...CONTEXT },
      argumentsJson: REVIEWED_ARGUMENTS,
      attemptId: 'attempt-1',
      consume,
      observer: SYNTHETIC_EXECUTOR,
      clock: () => new Date(CLOCK_NOW.getTime()),
    },
    refundTool,
  );
  const matchedDispatches = dispatchCount;

  // 3. Offline: anyone with the two receipts and the expected signers can verify the link.
  let link: ExampleOutcome['link'];
  if (matchedResult.outcome === 'returned' && matchedResult.observation) {
    const verification = verifyApprovalExecutionLink({
      approval,
      observation: matchedResult.observation,
      expectedApprovalSigner: approval.signature.signer,
      expectedExecutionSigner: matchedResult.observation.signature.signer,
    });
    link = { ok: verification.ok, checks: verification.checks };
  }

  // 4. Same receipt, changed amount: blocked before dispatch, nothing observed.
  const changedApproval = createApprovalReceipt(
    {
      binding: { ...CONTEXT, operationId: 'op-2026-10-25-0002' },
      approval: {
        approver: 'Synthetic Approver <approver@synthetic.example>',
        source: 'synthetic:approval-queue',
        decision: 'approved',
        decidedAt: DECIDED_AT,
        validity: { kind: 'once' },
      },
      argumentsJson: REVIEWED_ARGUMENTS,
    },
    SYNTHETIC_APPROVER,
  );
  const before = dispatchCount;
  const changedResult = await executeApproved(
    {
      receipt: changedApproval,
      expectedSigner: changedApproval.signature.signer,
      context: { ...CONTEXT, operationId: 'op-2026-10-25-0002' },
      argumentsJson: CHANGED_ARGUMENTS,
      attemptId: 'attempt-1',
      consume,
      observer: SYNTHETIC_EXECUTOR,
      clock: () => new Date(CLOCK_NOW.getTime()),
    },
    refundTool,
  );

  return {
    matched: {
      outcome: matchedResult.outcome,
      dispatchCount: matchedDispatches,
      value: matchedResult.outcome === 'returned' ? matchedResult.value : undefined,
      observation: matchedResult.outcome === 'returned' && matchedResult.observation !== undefined,
      link,
    },
    changed: {
      outcome: changedResult.outcome,
      code: changedResult.outcome === 'blocked' ? changedResult.code : undefined,
      dispatchCount: dispatchCount - before,
      observation: 'observation' in changedResult && changedResult.observation !== undefined,
    },
  };
}

function printTable(result: ExampleResult): void {
  const rows: Array<[string, string, string, string, string]> = [
    ['case', 'outcome', 'dispatches', 'observation', 'link'],
    [
      'matched {orderId, amount}',
      result.matched.outcome,
      String(result.matched.dispatchCount),
      result.matched.observation ? 'signed' : 'none',
      result.matched.link ? (result.matched.link.ok ? 'PASS (9/9)' : 'FAIL') : 'n/a',
    ],
    [
      'changed amount',
      `${result.changed.outcome} (${result.changed.code})`,
      String(result.changed.dispatchCount),
      result.changed.observation ? 'signed' : 'none',
      'n/a',
    ],
  ];
  const widths = rows[0].map((_, i) => Math.max(...rows.map((r) => r[i].length)));
  const line = (r: string[]) => r.map((c, i) => c.padEnd(widths[i])).join('  ');
  console.log('SYNTHETIC keys only — approval-to-execution binding example');
  console.log(line(rows[0]));
  console.log(widths.map((w) => '-'.repeat(w)).join('  '));
  for (const r of rows.slice(1)) console.log(line(r));
}

if (require.main === module) {
  runExample()
    .then((result) => {
      printTable(result);
      const ok =
        result.matched.outcome === 'returned' &&
        result.matched.dispatchCount === 1 &&
        result.matched.link?.ok === true &&
        result.changed.outcome === 'blocked' &&
        result.changed.dispatchCount === 0 &&
        result.changed.observation === false;
      process.exitCode = ok ? 0 : 1;
    })
    .catch((err) => {
      console.error(err);
      process.exitCode = 1;
    });
}
