/**
 * Standalone audit verification — run any time after `npm run demo`:
 *
 *   npm run verify
 *
 * Reads audit/audit-log.jsonl + audit/signer.json and verifies every receipt
 * with @bolyra/receipts. The gateway does not need to be running: the JSONL
 * file and the signer address are all an auditor needs.
 *
 * Exits non-zero if any receipt fails verification or any tampered variant
 * unexpectedly passes.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { readAuditLog, verifyAuditLog, verifyAuditChain, tamperChecks, logTamperChecks } from './audit';
import { pkgRoot } from './paths';

const ROOT = pkgRoot(__dirname);
const AUDIT_DIR = path.join(ROOT, 'audit');
const LOG_PATH = path.join(AUDIT_DIR, 'audit-log.jsonl');
const SIGNER_PATH = path.join(AUDIT_DIR, 'signer.json');

function main(): void {
  if (!fs.existsSync(LOG_PATH) || !fs.existsSync(SIGNER_PATH)) {
    console.error('No audit log found. Run `npm run demo` first.');
    process.exit(1);
  }

  const signerInfo = JSON.parse(fs.readFileSync(SIGNER_PATH, 'utf8')) as { signer: string };
  const receipts = readAuditLog(LOG_PATH);
  console.log(`Verifying ${receipts.length} receipts from ${path.relative(process.cwd(), LOG_PATH)}`);
  console.log(`Pinned signer: ${signerInfo.signer}\n`);

  let failures = 0;
  for (const { receipt, valid } of verifyAuditLog(receipts, signerInfo.signer)) {
    const { decision } = receipt.payload;
    console.log(
      `  ${receipt.id}  ${decision.allowed ? 'allow' : 'deny '}  ${valid ? 'VALID' : 'INVALID'}  ${decision.reasonCode ?? ''}`,
    );
    if (!valid) failures++;
  }

  console.log('\nChain check (whole-log integrity — seq + prevReceiptHash links):');
  const chainResult = verifyAuditChain(receipts, signerInfo.signer);
  if (chainResult.ok) {
    console.log(`  chain intact: ${chainResult.chained} receipts, head ${chainResult.headHash}`);
    console.log('  note: tail truncation is not detectable from the log alone — pin the head');
    console.log('  hash above and re-check with `bolyra receipt verify-chain --expect-head`.');
  } else {
    for (const issue of chainResult.issues) {
      console.log(`  line ${issue.index + 1}: [${issue.code}] ${issue.message}`);
    }
    failures += chainResult.issues.length;
  }

  console.log('\nTamper checks (mutated copies must NOT verify):');
  const sample = receipts.find((r) => !r.payload.decision.allowed) ?? receipts[0];
  if (sample) {
    const other = receipts.find((r) => r.id !== sample.id);
    for (const check of tamperChecks(sample, other)) {
      const ok = !check.stillVerifies;
      console.log(`  ${check.description} -> ${ok ? 'rejected (good)' : 'ACCEPTED (bug!)'}`);
      if (!ok) failures++;
    }
  }

  console.log('\nLog tamper checks (deleted/reordered lines must break the chain):');
  for (const check of logTamperChecks(receipts)) {
    const ok = !check.chainStillVerifies;
    console.log(`  ${check.description} -> ${ok ? 'chain broken (good)' : 'chain STILL VERIFIES (bug!)'}`);
    if (!ok) failures++;
  }

  if (failures > 0) {
    console.error(`\n${failures} verification failure(s) — audit log is not trustworthy.`);
    process.exit(1);
  }
  console.log(`\nAll ${receipts.length} receipts verified. Audit log is intact.`);
}

main();
