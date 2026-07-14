/**
 * Reference receipts CONSUMER — what an indexer or counterparty-risk scoring
 * system does with Bolyra receipt logs:
 *
 *   1. VERIFY FIRST, fail closed: signer set from a Receipt Signer Discovery
 *      v1 document (spec/receipt-signer-discovery-v1.md), every signature +
 *      the hash chain via verifyReceiptChain, count/head pinned externally.
 *      Unverified logs contribute NOTHING to scoring.
 *   2. Extract per-actor features from the verified receipts — the
 *      "receipts as pre-call scoring input" consumption model.
 *
 * Everything here uses the PUBLISHED @bolyra/receipts (0.9.0) — no local
 * source, no private APIs. Run against the committed corpus:
 *
 *   npm run score -- ../receipt-scoring-kit/corpus/receipts.jsonl \
 *     --signers ../receipt-scoring-kit/corpus/bolyra-signers.json \
 *     --expect-count 8 --expect-head 0x8150...
 *
 * (--signers accepts a local file or an https URL; https fetching mirrors the
 * CLI's rules: no plain http except loopback, no redirects.)
 */
import * as fs from 'fs';
import { parseArgs } from 'node:util';
import {
  parseSignerDiscovery,
  acceptedSigners,
  verifyReceiptChain,
} from '@bolyra/receipts';
import type { SignedReceipt } from '@bolyra/receipts';

// ---------------------------------------------------------------- features

/** Per-actor scoring features — the columns a risk engine would ingest. */
export interface ActorFeatures {
  actor: string; // credentialCommitment (stable aggregation key)
  issuer: string;
  totalActions: number;
  allowed: number;
  denied: number;
  denyRate: number; // denied / totalActions
  denyReasons: Record<string, number>; // reason-code prefix histogram
  maxFinancialTier: 'none' | 'FINANCIAL_SMALL' | 'FINANCIAL_MEDIUM' | 'FINANCIAL_UNLIMITED';
  maxDelegationDepth: number;
  commerceVolumeAllowed: Record<string, number>; // currency -> summed allowed amounts
  commerceDenied: number;
  firstSeen: number; // unix seconds
  lastSeen: number;
}

const TIER_BITS: Array<[bigint, ActorFeatures['maxFinancialTier']]> = [
  [1n << 4n, 'FINANCIAL_UNLIMITED'],
  [1n << 3n, 'FINANCIAL_MEDIUM'],
  [1n << 2n, 'FINANCIAL_SMALL'],
];

function financialTier(bitmaskDecimal: string): ActorFeatures['maxFinancialTier'] {
  let mask: bigint;
  try {
    mask = BigInt(bitmaskDecimal);
  } catch {
    return 'none';
  }
  for (const [bit, tier] of TIER_BITS) {
    if ((mask & bit) !== 0n) return tier;
  }
  return 'none';
}

const TIER_ORDER = ['none', 'FINANCIAL_SMALL', 'FINANCIAL_MEDIUM', 'FINANCIAL_UNLIMITED'];

/** Stable histogram key: the reason-code prefix before the first ':'. */
function reasonKey(reasonCode: string): string {
  return reasonCode.split(':')[0].trim();
}

/** Extract per-actor features from VERIFIED receipts. Pure — no I/O. */
export function extractFeatures(receipts: SignedReceipt[]): ActorFeatures[] {
  const byActor = new Map<string, ActorFeatures>();
  for (const r of receipts) {
    const p = r.payload;
    const actor = p.subject.credentialCommitment;
    let f = byActor.get(actor);
    if (!f) {
      f = {
        actor,
        issuer: p.issuer,
        totalActions: 0,
        allowed: 0,
        denied: 0,
        denyRate: 0,
        denyReasons: {},
        maxFinancialTier: 'none',
        maxDelegationDepth: 0,
        commerceVolumeAllowed: {},
        commerceDenied: 0,
        firstSeen: p.issuedAt,
        lastSeen: p.issuedAt,
      };
      byActor.set(actor, f);
    }
    f.totalActions++;
    if (p.decision.allowed) f.allowed++;
    else {
      f.denied++;
      if (p.decision.reasonCode) {
        const key = reasonKey(p.decision.reasonCode);
        f.denyReasons[key] = (f.denyReasons[key] ?? 0) + 1;
      }
    }
    const tier = financialTier(p.decision.permissionBitmask);
    if (TIER_ORDER.indexOf(tier) > TIER_ORDER.indexOf(f.maxFinancialTier)) {
      f.maxFinancialTier = tier;
    }
    if (p.decision.chainDepth > f.maxDelegationDepth) f.maxDelegationDepth = p.decision.chainDepth;
    if (p.kind === 'bolyra.commerce' && p.commerce) {
      if (p.decision.allowed) {
        f.commerceVolumeAllowed[p.commerce.currency] =
          (f.commerceVolumeAllowed[p.commerce.currency] ?? 0) + p.commerce.amount;
      } else {
        f.commerceDenied++;
      }
    }
    if (p.issuedAt < f.firstSeen) f.firstSeen = p.issuedAt;
    if (p.issuedAt > f.lastSeen) f.lastSeen = p.issuedAt;
  }
  for (const f of byActor.values()) {
    f.denyRate = f.totalActions === 0 ? 0 : Number((f.denied / f.totalActions).toFixed(4));
  }
  return [...byActor.values()].sort((a, b) => a.actor.localeCompare(b.actor));
}

// ------------------------------------------------------------ verification

const LOOPBACK = new Set(['127.0.0.1', 'localhost', '[::1]', '::1']);

/** Load a discovery doc from a local path or an https URL (CLI's rules). */
export async function loadAcceptedSigners(source: string): Promise<Set<string>> {
  let raw: string;
  if (/^https?:\/\//.test(source)) {
    const url = new URL(source);
    if (url.protocol !== 'https:' && !(url.protocol === 'http:' && LOOPBACK.has(url.hostname))) {
      throw new Error('discovery URL must be https (plain http only for loopback)');
    }
    const res = await fetch(url, { signal: AbortSignal.timeout(10_000), redirect: 'error' });
    if (!res.ok) throw new Error(`discovery fetch failed: HTTP ${res.status}`);
    raw = await res.text();
  } else {
    raw = fs.readFileSync(source, 'utf8');
  }
  return acceptedSigners(parseSignerDiscovery(JSON.parse(raw)));
}

export interface VerifyAndScoreOptions {
  signersSource: string;
  /** REQUIRED: externally pinned receipt count — the tail-truncation guard. */
  expectCount: number;
  /** REQUIRED: externally pinned head receiptHash — the tail-truncation guard. */
  expectHead: string;
}

/**
 * The whole consumer pipeline: verify (fail closed) then extract features.
 * Throws on ANY verification failure — an unverified log scores nothing.
 */
export async function verifyAndScore(
  logPath: string,
  options: VerifyAndScoreOptions,
): Promise<ActorFeatures[]> {
  // Fail closed on missing pins: without an external count + head, a tail-
  // truncated log is internally consistent and would score. No optional mode.
  if (!Number.isInteger(options.expectCount) || typeof options.expectHead !== 'string' || options.expectHead === '') {
    throw new Error('expectCount and expectHead are required — scoring without externally pinned count/head would accept tail-truncated logs');
  }
  const accepted = await loadAcceptedSigners(options.signersSource);

  const receipts: SignedReceipt[] = fs
    .readFileSync(logPath, 'utf8')
    .split('\n')
    .filter((l) => l.trim() !== '')
    .map((l) => JSON.parse(l));

  const result = verifyReceiptChain(receipts, {
    expectedCount: options.expectCount,
    expectedHeadHash: options.expectHead,
  });
  if (!result.ok) {
    throw new Error(
      `receipt log failed verification — scoring aborted: ${result.issues
        .map((i) => `[${i.code}] ${i.message}`)
        .join('; ')}`,
    );
  }
  for (const r of receipts) {
    const signer = r.signature?.signer;
    if (typeof signer !== 'string' || !accepted.has(signer.toLowerCase())) {
      throw new Error(
        `receipt ${r.id} signed by ${signer ?? 'unknown'} — not in the discovery document; scoring aborted`,
      );
    }
  }

  return extractFeatures(receipts);
}

// ------------------------------------------------------------------- CLI

function renderTable(features: ActorFeatures[]): string {
  const lines = [
    '| actor (credentialCommitment) | actions | allow | deny | deny rate | top deny reason | max tier | max depth | commerce allowed | first→last |',
    '|---|---|---|---|---|---|---|---|---|---|',
  ];
  for (const f of features) {
    const topReason =
      Object.entries(f.denyReasons).sort((a, b) => b[1] - a[1])[0]?.[0] ?? '-';
    const volume =
      Object.entries(f.commerceVolumeAllowed)
        .map(([c, v]) => `${v} ${c}`)
        .join(', ') || '-';
    lines.push(
      `| ${f.actor} | ${f.totalActions} | ${f.allowed} | ${f.denied} | ${f.denyRate} | ${topReason} | ${f.maxFinancialTier} | ${f.maxDelegationDepth} | ${volume} | ${f.firstSeen}→${f.lastSeen} |`,
    );
  }
  return lines.join('\n');
}

async function main(): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: process.argv.slice(2),
      options: {
        signers: { type: 'string' },
        'expect-count': { type: 'string' },
        'expect-head': { type: 'string' },
        json: { type: 'boolean', default: false },
      },
      allowPositionals: true,
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 2;
    return;
  }
  const { values, positionals } = parsed;
  const logPath = positionals[0];
  const signersSource = values.signers;
  if (!logPath || !signersSource) {
    console.error(
      'usage: score <receipts.jsonl> --signers <file-or-https-url> --expect-count <n> --expect-head <0x...> [--json]',
    );
    process.exitCode = 2;
    return;
  }
  const expectCountRaw = values['expect-count'];
  const expectHead = values['expect-head'];
  if (expectCountRaw === undefined || !/^\d+$/.test(expectCountRaw) || expectHead === undefined) {
    console.error('--expect-count <n> and --expect-head <hash> are required (tail-truncation guard)');
    process.exitCode = 2;
    return;
  }
  try {
    const features = await verifyAndScore(logPath, {
      signersSource,
      expectCount: parseInt(expectCountRaw, 10),
      expectHead,
    });
    console.log(values.json ? JSON.stringify(features, null, 2) : renderTable(features));
  } catch (err) {
    console.error(`FAIL: ${err instanceof Error ? err.message : String(err)}`);
    process.exitCode = 1;
  }
}

if (require.main === module) {
  void main();
}
