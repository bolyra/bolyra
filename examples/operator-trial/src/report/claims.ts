/**
 * The fixed claim list (spec §5). Titles are what the reviewer reads; the
 * classifier fills status, evidence and notes. Changing a title here changes
 * the report; adding a claim requires a test in report.classify.test.ts.
 */

export type Status = 'SIGNED' | 'OBSERVED' | 'DERIVED' | 'ABSENT' | 'FAILED';

export const STATUS_LEGEND: Record<Status, string> = {
  SIGNED:
    'An authenticated signer assertion, not independently established truth: the value is inside a receipt payload whose ES256K signature recovered to the anchored signer and whose payload hash recomputed.',
  OBSERVED: 'An unsigned host assertion: recorded by the trial host, signed by nothing.',
  DERIVED:
    'A conclusion this report computes from SIGNED or OBSERVED values, reviewer anchors, or a named check; the row names its inputs and the rule.',
  ABSENT: 'No supporting evidence for this claim in the bundle. The row says what would be needed.',
  FAILED: 'Evidence is present and a named check on it failed, or two sources contradict.',
};

export const ANCHORS_WORDING =
  'Values were supplied through command-line flags. Their independence from this bundle is unknown. ' +
  'Copying signer/count/head from bundle files establishes consistency with those supplied values; it does not ' +
  'establish signer identity or independently establish completeness. External assurance requires a separately ' +
  'trusted signer reference and checkpoint.';

export const DEV_MODE_DISCLOSURE =
  'The shipped operator-trial 0.1.0 runs the gateway with devMode: true and static simulated credentials ' +
  '(examples/operator-trial/src/gateway-config.ts), signs receipts with an ephemeral key, and verifies no ' +
  'zero-knowledge proof. This is a property of the implementation that produced bundles of this shape; ' +
  'it is not something this bundle proves about itself.';

export const TAMPER_INSTRUCTION =
  'Change payload.decision.allowed in any receipt line without re-signing and re-run the command: expect ' +
  'FAIL line <n>: [signature-invalid] for that line, possibly with additional chain failures. The id check in ' +
  "this report (B1a) is not part of the CLI's output.";

export const CLAIM_TITLES: Record<string, string> = {
  B0: 'Receipt line parses as a signed receipt',
  B1: "Receipt's signature recovers to the anchored signer and its payload hash recomputes",
  B1a: "Receipt's id equals the first 18 characters of its stored payload hash and is unique in the log",
  B2: 'Receipts form one intact hash chain (genesis, seq, prevReceiptHash, stored receiptHash)',
  B3a: 'Receipt count matches the supplied count checkpoint',
  B3b: 'Head hash matches the supplied head checkpoint',
  B4: 'Signer in signer.json equals the supplied signer anchor',
  B4b: 'VERIFY.txt names the anchored signer (compared, never used as an anchor)',
  B5: 'Proof verification mode',
  B6: 'Host reports an ephemeral signer',
  B7: 'Host-reported dry-run flag',
  B8a: "Host's unsigned receiptCount equals the number of receipt lines",
  B8b: "Host's unsigned headReceiptHash equals the recomputed head of the log",
  A1: "The summary's receipt id names exactly one valid receipt in the log",
  A2: 'Decision (allow / deny)',
  A3: 'Decision reason text',
  A4a: 'Action name, method, host, path as the host recorded them',
  A4b: 'Action descriptor parsed from the signed reason text (operator-trial convention, not a receipt schema field)',
  A4c: 'Recorded action and signed action descriptor agree',
  A5: 'Signer-asserted simulated subject identifiers; subject authentication is not established',
  A6: 'Recorded permission bitmask',
  A7a: 'Permission the host configured as required',
  A7b: 'Required mask as reported in the denial text (reported, not the enforced configuration)',
  A8a: 'Nonce',
  A8b: "Attempt presented attempt 1's nonce and was denied",
  A9a: 'Proof hashes',
  A9b: 'Human and agent proofs were verified',
  A10: 'Host reports invoking fetch toward the endpoint; delivery and execution unproven',
  A11: 'Upstream HTTP status',
  A12: 'Decision was signed before dispatch',
  A13: 'The endpoint executed the action',
  A14: 'A human consented to this action',
  A15: 'A mandate or spend limit bounded this action',
  A16: 'Who receives funds or controls a settlement address',
  A17: 'Production credentials or registry were used',
};
