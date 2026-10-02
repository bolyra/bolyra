#!/usr/bin/env node
/**
 * Playground usage report from CloudFront standard access logs.
 *
 *   node tools/usage-report.mjs --since 2026-10-02            # syncs logs from S3 into a temp dir
 *   node tools/usage-report.mjs --since 2026-10-02 --logs DIR # reads *.gz already on disk
 *
 * Counts allowlisted `GET /e?v=1&ev=<name>` beacons per day (raw and heuristic-filtered),
 * plus /playground page loads. Never prints addresses. Read-only on S3; logs stay in a temp dir.
 * Counts are first occurrences per page load, not executions; addresses are not people; not
 * evidence of demand.
 */
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import zlib from 'node:zlib';
import { spawnSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { EVENTS } from '../src/core/usage.js';

const ALLOWED = new Set(EVENTS);
const BOT_UA = /curl|wget|python|Go-http|[Bb]ot|crawl|spider|HeadlessChrome|Playwright|node-fetch|axios|undici|Scrapy|census-probe|Dataprovider|amazon-Quick/;
const SCANNER_PATH = /^\/(\.env|\.git|index\.php|wp-|xmlrpc|\.aws|phpinfo|admin|config\.|\.ssh)/;

export function summarize(lines, { since = '0000-00-00' } = {}) {
  const rows = [];
  for (const l of lines) { if (!l || l.startsWith('#')) continue; const f = l.split('\t'); if (f.length < 12) continue; rows.push({ date: f[0], ip: f[4], stem: f[7], ua: f[10], query: f[11] }); }
  const scanners = new Set(rows.filter((r) => SCANNER_PATH.test(r.stem)).map((r) => r.ip));
  const days = {};
  const day = (d) => (days[d] ??= { raw: {}, filtered: {}, rejected: 0, probes: 0, loads: { raw: 0, filtered: 0 } });
  for (const r of rows) {
    if (r.date < since) continue;
    const human = !BOT_UA.test(r.ua) && !scanners.has(r.ip);
    if (r.stem === '/playground' || r.stem === '/playground.html') { const d = day(r.date); d.loads.raw++; if (human) d.loads.filtered++; continue; }
    if (r.stem !== '/e') continue;
    const d = day(r.date);
    if (r.query === '-' || r.query === '') { d.probes++; continue; }
    const q = new URLSearchParams(r.query); const keys = [...q.keys()];
    const ev = q.get('ev');
    if (keys.length !== 2 || keys[0] !== 'v' || keys[1] !== 'ev' || q.get('v') !== '1' || !ALLOWED.has(ev)) { d.rejected++; continue; }
    d.raw[ev] = (d.raw[ev] ?? 0) + 1;
    if (human) d.filtered[ev] = (d.filtered[ev] ?? 0) + 1;
  }
  const sorted = Object.fromEntries(Object.keys(days).sort().map((k) => [k, days[k]]));
  return { since, days: sorted };
}

/** Every calendar month (YYYY-MM) from `since` through `until`, inclusive. */
export function monthsBetween(since, until) {
  let [y, m] = since.slice(0, 7).split('-').map(Number);
  const [ey, em] = until.slice(0, 7).split('-').map(Number);
  const out = [];
  while (y < ey || (y === ey && m <= em)) { out.push(`${y}-${String(m).padStart(2, '0')}`); m += 1; if (m === 13) { m = 1; y += 1; } }
  return out;
}

export function formatReport(s) {
  const out = [`Playground usage since ${s.since} (CloudFront access logs)`, ''];
  for (const [date, d] of Object.entries(s.days)) {
    out.push(`${date}  page loads: ${d.loads.raw} raw / ${d.loads.filtered} filtered   rejected beacons: ${d.rejected}   endpoint probes: ${d.probes}`);
    const evs = EVENTS.filter((e) => d.raw[e]);
    if (evs.length === 0) out.push('    (no usage events)');
    for (const e of evs) out.push(`    ${e.padEnd(18)} ${String(d.raw[e]).padStart(4)} raw  ${String(d.filtered[e] ?? 0).padStart(4)} filtered`);
  }
  out.push('', 'Counts are first occurrences per page load, not executions. Addresses are not people;',
    'filtering is heuristic (bot user agents, addresses that probed scanner paths). Events can be forged.',
    'These counts are not evidence of demand.');
  return out.join('\n');
}

function readLogs(dir) {
  const lines = [];
  for (const f of fs.readdirSync(dir)) {
    if (!f.endsWith('.gz')) continue;
    lines.push(...zlib.gunzipSync(fs.readFileSync(path.join(dir, f))).toString('utf8').split('\n'));
  }
  return lines;
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const args = process.argv.slice(2);
  const opt = (n) => { const i = args.indexOf(n); return i === -1 ? undefined : args[i + 1]; };
  const since = opt('--since') ?? new Date(Date.now() - 7 * 864e5).toISOString().slice(0, 10);
  let dir = opt('--logs');
  if (!dir) {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pg-usage-'));
    const months = monthsBetween(since, new Date().toISOString().slice(0, 10));
    for (const m of months) {
      const r = spawnSync('aws', ['s3', 'sync', 's3://bolyra-ai-cloudfront-logs/cf-logs/', dir, '--exclude', '*', '--include', `E28JZX72HEYVTP.${m}-*`, '--quiet'], { stdio: 'inherit' });
      if (r.status !== 0) { console.error('aws s3 sync failed'); process.exit(1); }
    }
  }
  console.log(formatReport(summarize(readLogs(dir), { since })));
}
