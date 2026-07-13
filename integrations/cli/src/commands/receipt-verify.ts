/**
 * bolyra receipt verify <file> — Verify a signed audit receipt.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';
import { verifyReceipt, hashPayload } from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';
import { fetchAcceptedSigners } from './signer-discovery-fetch';

const HELP = `bolyra receipt verify <file> — Verify a signed audit receipt

Arguments:
  <file>              Path to receipt JSON file

Flags:
  --stdin             Read receipt from stdin instead of file
  --signer <address>  Expected signer address (optional)
  --signer-from <url> Accept signers from a Receipt Signer Discovery v1
                      document (/.well-known/bolyra-signers.json). Fail-closed
                      on any fetch/schema error. With --signer too, both must
                      agree (the address must be listed in the document)
  --max-age <seconds> Maximum receipt age in seconds (default: 86400)
  --help              Show this help
`;

export async function run(args: string[]): Promise<void> {
  const { values, positionals } = parseArgs({
    args,
    options: {
      stdin: { type: 'boolean', default: false },
      signer: { type: 'string' },
      'signer-from': { type: 'string' },
      'max-age': { type: 'string', default: '86400' },
      help: { type: 'boolean', default: false },
    },
    allowPositionals: true,
    strict: true,
  });

  if (values.help) {
    console.log(HELP);
    return;
  }

  let receiptJson: string;

  if (values.stdin) {
    // Read from stdin
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) {
      chunks.push(chunk as Buffer);
    }
    receiptJson = Buffer.concat(chunks).toString('utf-8');
  } else if (positionals.length > 0) {
    const filePath = positionals[0];
    if (!fs.existsSync(filePath)) {
      console.error(`Error: file not found: ${filePath}`);
      process.exitCode = 1;
      return;
    }
    receiptJson = fs.readFileSync(filePath, 'utf-8');
  } else {
    console.error('Error: provide a receipt file path or use --stdin');
    process.exitCode = 2;
    return;
  }

  let receipt: SignedReceipt;
  try {
    receipt = JSON.parse(receiptJson) as SignedReceipt;
  } catch {
    console.error('Error: invalid JSON in receipt');
    process.exitCode = 1;
    return;
  }

  const maxAge = parseInt(values['max-age'] ?? '86400', 10);

  try {
    const valid = verifyReceipt(receipt);

    if (!valid) {
      console.error('FAIL: receipt signature invalid');
      process.exitCode = 1;
      return;
    }

    // Check signer if specified. SignedReceipt carries the recovered signer
    // address at signature.signer (addresses are lowercase hex; compare
    // case-insensitively so checksummed input still matches).
    const receiptSigner = receipt.signature?.signer;

    // Signer discovery (spec/receipt-signer-discovery-v1.md): fetch failures
    // and schema violations are verification failures, never "no restriction".
    // Checked against undefined, not truthiness: `--signer-from=` (empty
    // value) must fail closed via URL validation, not silently skip discovery.
    if (values['signer-from'] !== undefined) {
      let accepted: Set<string>;
      try {
        accepted = await fetchAcceptedSigners(values['signer-from']);
      } catch (err) {
        console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
        process.exitCode = 1;
        return;
      }
      if (values.signer && !accepted.has(values.signer.toLowerCase())) {
        console.error(
          `FAIL: --signer and --signer-from do not agree: ${values.signer} is not listed in the discovery document`,
        );
        process.exitCode = 1;
        return;
      }
      if (!values.signer && (!receiptSigner || !accepted.has(receiptSigner.toLowerCase()))) {
        console.error(
          `FAIL: signer ${receiptSigner ?? 'unknown'} is not listed in the discovery document (unknown signer)`,
        );
        process.exitCode = 1;
        return;
      }
    }

    if (values.signer && receiptSigner?.toLowerCase() !== values.signer.toLowerCase()) {
      console.error(`FAIL: signer mismatch`);
      console.error(`  Expected: ${values.signer}`);
      console.error(`  Got:      ${receiptSigner ?? 'unknown'}`);
      process.exitCode = 1;
      return;
    }

    // Check age — ReceiptPayload.issuedAt is Unix SECONDS.
    const issuedAt = receipt.payload?.issuedAt;
    if (typeof issuedAt === 'number') {
      const ageSeconds = Math.floor(Date.now() / 1000) - issuedAt;
      if (ageSeconds > maxAge) {
        console.error(`FAIL: receipt too old (${ageSeconds}s > ${maxAge}s max)`);
        process.exitCode = 1;
        return;
      }
    }

    console.log('PASS: receipt signature valid');
    if (receiptSigner) console.log(`  Signer: ${receiptSigner}`);
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}
