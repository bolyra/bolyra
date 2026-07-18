#!/usr/bin/env node
/**
 * export-receipts.mjs — collect a pilot's signed receipts into one JSONL
 * audit export that the partner verifies independently with the EXISTING
 * tooling: `bolyra receipt verify-chain` (@bolyra/cli). No new evidence
 * format — every line is an unmodified @bolyra/receipts SignedReceipt.
 *
 * Exactly ONE source per run (mixing chained and unchained receipts in one
 * file breaks chain verification — export per source instead):
 *
 *   --gateway-dir <dir>   @bolyra/gateway file output (receipts.output=file):
 *                         day-rotated subdirs of one pretty-printed
 *                         SignedReceipt JSON per file. Hash-chained per
 *                         gateway instance.
 *   --jsonl <file>        an existing NDJSON receipt log (e.g.
 *                         `bolyra run --receipt-file …`, or gateway stdout
 *                         mode captured to a file). Normalized + validated.
 *   --headers <file>      hosted-verify capture: one base64url
 *                         X-Bolyra-Receipt header value per line. These
 *                         receipts are signed but NOT hash-chained (the
 *                         Worker is stateless).
 *
 *   --out <file>          output JSONL (required; refuses to overwrite
 *                         unless --force)
 *
 * Prints the receipt count, head receiptHash (chained sources), and the
 * exact `bolyra receipt verify-chain` command to (1) run yourself before
 * sending and (2) hand to the partner. Pin the printed count/head — that is
 * the only defense against tail truncation (see receipt verify-chain --help).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parseArgs } from 'node:util';
import { createRequire } from 'node:module';
import { createHash } from 'node:crypto';
import { fileURLToPath } from 'node:url';

function die(msg) {
  console.error(`ERROR: ${msg}`);
  process.exit(1);
}

// The export is PRE-VERIFIED with the real @bolyra/receipts verifyReceiptChain
// before anything is written — an export that would fail the partner's
// verify-chain run must never leave this script. Resolve the package from the
// repo (workspace dist or an installed copy); fail closed if unavailable.
function loadReceiptsPkg() {
  const here = path.dirname(fileURLToPath(import.meta.url));
  const require_ = createRequire(import.meta.url);
  const candidates = [
    path.join(here, '../../integrations/receipts/dist/index.js'),
    path.join(here, '../../integrations/hosted-verify/node_modules/@bolyra/receipts/dist/index.js'),
    path.join(here, '../../integrations/cli/node_modules/@bolyra/receipts/dist/index.js'),
  ];
  for (const c of candidates) {
    if (fs.existsSync(c)) return require_(c);
  }
  try {
    return require_('@bolyra/receipts');
  } catch {
    die(
      '@bolyra/receipts not found — build it first (cd integrations/receipts && npm install && npm run build). ' +
        'Refusing to emit an unverified audit export.',
    );
  }
}

let args;
try {
  args = parseArgs({
    options: {
      'gateway-dir': { type: 'string' },
      jsonl: { type: 'string' },
      headers: { type: 'string' },
      out: { type: 'string' },
      signer: { type: 'string' },
      force: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
    },
    strict: true,
  }).values;
} catch (err) {
  die(err instanceof Error ? err.message : String(err));
}

if (args.help) {
  console.log(
    'usage: node pilot/scripts/export-receipts.mjs (--gateway-dir <dir> | --jsonl <file> | --headers <file>) --out <file> [--signer <addr>] [--force]',
  );
  console.log(
    '  --signer <addr>  expected receipt-signer address (from the pilot policy record).' +
      ' Every signature must recover to it. Without it, signer identity is taken' +
      ' from the log itself and only single-signer exports are allowed.',
  );
  process.exit(0);
}

const sources = ['gateway-dir', 'jsonl', 'headers'].filter((k) => args[k] !== undefined);
if (sources.length !== 1) {
  die('provide exactly one of --gateway-dir, --jsonl, --headers (one source per export — do not mix chained and unchained receipts in one file)');
}
if (!args.out) die('--out <file> is required');
if (fs.existsSync(args.out) && !args.force) {
  die(`${args.out} already exists (pass --force to overwrite)`);
}

/** Fail-closed structural check: this must LOOK like a SignedReceipt. */
function assertSignedReceipt(r, where) {
  const ok =
    typeof r === 'object' &&
    r !== null &&
    typeof r.payload === 'object' &&
    r.payload !== null &&
    typeof r.signature === 'object' &&
    r.signature !== null &&
    typeof r.signature.value === 'string' &&
    typeof r.signature.signer === 'string';
  if (!ok) {
    die(
      `${where}: not a signed receipt (missing payload/signature). ` +
        'Unsigned or foreign records cannot go in the audit export.',
    );
  }
}

function readJsonFile(file) {
  let parsed;
  try {
    parsed = JSON.parse(fs.readFileSync(file, 'utf8'));
  } catch (err) {
    die(`${file}: invalid JSON (${err instanceof Error ? err.message : err})`);
  }
  assertSignedReceipt(parsed, file);
  return parsed;
}

function collectGatewayDir(dir) {
  if (!fs.existsSync(dir) || !fs.statSync(dir).isDirectory()) {
    die(`--gateway-dir ${dir}: not a directory`);
  }
  const receipts = [];
  const walk = (d) => {
    for (const entry of fs.readdirSync(d, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const p = path.join(d, entry.name);
      if (entry.isDirectory()) walk(p);
      else if (entry.isFile() && entry.name.endsWith('.json')) receipts.push(readJsonFile(p));
    }
  };
  walk(dir);
  return receipts;
}

function collectJsonl(file) {
  if (!fs.existsSync(file)) die(`--jsonl ${file}: file not found`);
  const receipts = [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (line.trim() === '') return;
    let parsed;
    try {
      parsed = JSON.parse(line);
    } catch {
      die(`${file}:${i + 1}: invalid JSON line`);
    }
    assertSignedReceipt(parsed, `${file}:${i + 1}`);
    receipts.push(parsed);
  });
  return receipts;
}

function collectHeaders(file) {
  if (!fs.existsSync(file)) die(`--headers ${file}: file not found`);
  const receipts = [];
  const lines = fs.readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    const value = line.trim();
    if (value === '') return;
    let json;
    try {
      json = Buffer.from(value, 'base64url').toString('utf8');
    } catch {
      die(`${file}:${i + 1}: not base64url`);
    }
    let parsed;
    try {
      parsed = JSON.parse(json);
    } catch {
      die(`${file}:${i + 1}: base64url payload is not JSON — is this really an X-Bolyra-Receipt value?`);
    }
    assertSignedReceipt(parsed, `${file}:${i + 1}`);
    receipts.push(parsed);
  });
  return receipts;
}

let receipts;
if (args['gateway-dir']) receipts = collectGatewayDir(args['gateway-dir']);
else if (args.jsonl) receipts = collectJsonl(args.jsonl);
else receipts = collectHeaders(args.headers);

if (receipts.length === 0) die('no receipts found — nothing to export');

// Chained sources are ordered by chain seq; unchained by issuedAt. A mix, or
// duplicate seqs (two gateway instances = two chains), cannot form one
// verifiable log — fail with guidance instead of emitting a file that fails
// verify-chain later.
const chained = receipts.filter((r) => r.payload.chain !== undefined);
if (chained.length > 0 && chained.length < receipts.length) {
  die(
    `mixed chained (${chained.length}) and unchained (${receipts.length - chained.length}) receipts — export each source separately (one JSONL per source)`,
  );
}
const isChained = chained.length === receipts.length && receipts.length > 0 && chained.length > 0;

if (isChained) {
  receipts.sort((a, b) => a.payload.chain.seq - b.payload.chain.seq);
  const seqs = new Set();
  for (const r of receipts) {
    if (seqs.has(r.payload.chain.seq)) {
      die(
        `duplicate chain seq ${r.payload.chain.seq} — receipts from more than one chain (e.g. two gateway instances / restarts) are mixed. Export one chain per JSONL: split the source by signer/instance and re-run.`,
      );
    }
    seqs.add(r.payload.chain.seq);
  }
} else {
  receipts.sort((a, b) => (a.payload.issuedAt ?? 0) - (b.payload.issuedAt ?? 0));
}

// Pre-verify with the REAL verifier before writing: every signature, and for
// chained sources the full chain (genesis sentinel, seq contiguity,
// prevReceiptHash links) — seq uniqueness above is only a fast-fail; this is
// the authoritative check. The head hash comes from the verifier's own
// recomputation, never from the receipts' convenience field.
const { verifyReceiptChain } = loadReceiptsPkg();
const result = verifyReceiptChain(receipts, {
  allowUnchained: !isChained,
  expectedSigner: args.signer,
});
if (!result.ok) {
  for (const issue of result.issues) {
    console.error(`  FAIL receipt ${issue.index}: [${issue.code}] ${issue.message}`);
  }
  die('receipts do not form a valid export (see issues above) — nothing written. Fix the source (e.g. split per chain/instance, or check --signer against the policy record) and re-run.');
}

// Signer identity: with --signer, verifyReceiptChain proved every signature
// recovers to the expected address. Without it, signatures are only
// self-consistent — the signer comes from the log itself, so refuse mixed
// signers (a single pilot export has exactly one) and say the check is weaker.
const signers = [...new Set(receipts.map((r) => r.signature.signer))];
if (!args.signer && signers.length > 1) {
  die(
    `receipts carry ${signers.length} different signers (${signers.join(', ')}) — a single pilot export must have one. ` +
      'Split the source per signer, or pass --signer <addr> (from the policy record) to enforce the expected one.',
  );
}

const body = receipts.map((r) => JSON.stringify(r)).join('\n') + '\n';
fs.writeFileSync(args.out, body);
const digest = createHash('sha256').update(body).digest('hex');

const head = result.headHash;

console.log(
  `wrote ${receipts.length} receipt(s) -> ${args.out} (pre-verified: signatures${isChained ? ' + chain' : ''}${args.signer ? ' + signer' : ''} OK)`,
);
console.log(`  chained: ${isChained ? 'yes (hash-chained log)' : 'no (independently signed receipts)'}`);
if (args.signer) {
  console.log(`  signer: ${args.signer} (enforced — every signature recovers to it)`);
} else {
  console.log(`  signer: ${signers[0]} (taken from the log itself, NOT enforced — pass --signer from the policy record to enforce)`);
}
if (isChained && head) console.log(`  head receiptHash (recomputed): ${head}`);
console.log(`  sha256(${path.basename(args.out)}): ${digest}`);

console.log('\nVerify (run this yourself BEFORE sending, then give the partner the same command):');
// Single signer guaranteed here: multi-signer dies above unless --signer was
// given, in which case every signature already recovered to it.
const signerFlag = ` --signer ${args.signer ?? signers[0]}`;
if (isChained) {
  console.log(
    `  bolyra receipt verify-chain ${args.out}${signerFlag} --expect-count ${receipts.length}` +
      (head ? ` --expect-head ${head}` : ''),
  );
  console.log('\nPin the count and head hash somewhere the partner can check them');
  console.log('independently (e.g. the pilot status email) — tail truncation is not');
  console.log('detectable from the log alone.');
} else {
  console.log(
    `  bolyra receipt verify-chain ${args.out} --allow-unchained${signerFlag} --expect-count ${receipts.length}`,
  );
  console.log('\nNote: hosted-verify receipts are signed per response but NOT hash-chained');
  console.log('(stateless Worker). verify-chain proves every signature is valid, and');
  console.log('--expect-count catches count changes ONLY — it does not catch reordering');
  console.log('or same-count substitution with other validly signed receipts. Pin the');
  console.log('sha256 digest above alongside the count: it fixes the exact file contents.');
}
