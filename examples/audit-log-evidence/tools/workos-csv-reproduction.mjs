#!/usr/bin/env node
/**
 * Reproduction: do the packet's metadata values survive a WorkOS Audit Logs CSV export losslessly?
 *
 * STAGING ONLY. Reads the API key from the file named by WORKOS_STAGING_KEY_FILE (never from argv).
 * Emits exactly the two fixture events into a fresh staging organization, creates an export over their
 * time range, downloads the CSV, and compares action_digest / receipt_id / receipt_hash / signer exactly.
 * Writes a sanitized result (no key, no download URL) to tools/workos-csv-reproduction.result.json.
 *
 *   WORKOS_STAGING_KEY_FILE=~/.secrets/workos-staging.key node tools/workos-csv-reproduction.mjs
 */
import { readFileSync, writeFileSync } from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

function fail(msg) { console.error('FAIL: ' + msg); process.exit(2); }
const here = path.dirname(fileURLToPath(import.meta.url));
const fixtures = path.join(here, '..', 'fixtures');
const API = 'https://api.workos.com';

const keyFile = process.env.WORKOS_STAGING_KEY_FILE;
if (!keyFile) fail('set WORKOS_STAGING_KEY_FILE to the path of a file holding the STAGING API key');
let apiKey = '';
try { apiKey = readFileSync(keyFile.replace(/^~/, process.env.HOME ?? ''), 'utf8').trim(); } catch (e) { fail(`cannot read key file: ${e.message}`); }
if (!/^sk_test_/.test(apiKey)) fail('refusing: the key does not look like a staging key (expected sk_test_… prefix). Production is never used.');

const events = readFileSync(path.join(fixtures, 'export.jsonl'), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
if (events.length !== 2) fail('expected exactly two fixture events');
const TRACKED = ['action_digest', 'receipt_id', 'receipt_hash', 'signer'];

async function api(method, route, body, extraHeaders = {}) {
  const res = await fetch(API + route, {
    method,
    headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json', ...extraHeaders },
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  const text = await res.text();
  let json;
  try { json = text ? JSON.parse(text) : {}; } catch { json = { raw: text.slice(0, 500) }; }
  return { status: res.status, json };
}

const log = (m) => console.log(m);
const result = { ran_at: new Date().toISOString(), environment: 'staging', transport_notes: ['actor.metadata: {} added in transit (schema requires the key)', 'event schemas registered via POST /audit_logs/actions/{action}/schemas because unconfigured actions are rejected with invalid_audit_log'], steps: [], comparison: null, verdict: null };
const step = (name, detail) => { result.steps.push({ name, ...detail }); log(`${name}: ${JSON.stringify(detail)}`); };

// 1. organization
const orgName = `bolyra-audit-log-evidence ${new Date().toISOString().slice(0, 19)}`;
let r = await api('POST', '/organizations', { name: orgName });
if (r.status >= 300) fail(`create organization → ${r.status} ${JSON.stringify(r.json).slice(0, 300)}`);
const orgId = r.json.id;
step('organization_created', { status: r.status, organization_id: orgId });

// 2. events (create schemas on demand if the API rejects an unregistered action)
for (const ev of events) {
  // The registered schema makes actor.metadata required; the fixture rows carry none, so an empty object is added in transit (recorded in the result).
  const body = { organization_id: orgId, event: { action: ev.action, version: ev.version, occurred_at: ev.occurred_at, actor: { ...ev.actor, metadata: {} }, targets: ev.targets, context: ev.context, metadata: ev.metadata } };
  r = await api('POST', '/audit_logs/events', body, { 'Idempotency-Key': randomUUID() });
  if (r.status >= 300 && (r.json?.code === 'invalid_audit_log' || /not been configured|action|schema/i.test(JSON.stringify(r.json)))) {
    const schema = {
      actor: { metadata: { type: 'object', properties: {} } },
      targets: [...new Set(ev.targets.map((t) => t.type))].map((type) => ({ type })),
      metadata: { type: 'object', properties: Object.fromEntries(Object.keys(ev.metadata).map((k) => [k, { type: 'string' }])) },
    };
    const s = await api('POST', `/audit_logs/actions/${encodeURIComponent(ev.action)}/schemas`, schema);
    step('schema_created', { action: ev.action, status: s.status, error: s.status >= 300 ? JSON.stringify(s.json).slice(0, 300) : undefined });
    r = await api('POST', '/audit_logs/events', body, { 'Idempotency-Key': randomUUID() });
  }
  step('event_emitted', { action: ev.action, status: r.status, error: r.status >= 300 ? JSON.stringify(r.json).slice(0, 300) : undefined });
  if (r.status >= 300) fail(`event ${ev.action} rejected`);
}

// 3. export over the fixture range
const times = events.map((e) => Date.parse(e.occurred_at));
r = await api('POST', '/audit_logs/exports', {
  organization_id: orgId,
  range_start: new Date(Math.min(...times) - 60_000).toISOString(),
  range_end: new Date(Math.max(...times) + 60_000).toISOString(),
});
if (r.status >= 300) fail(`create export → ${r.status} ${JSON.stringify(r.json).slice(0, 300)}`);
let exp = r.json;
step('export_created', { status: r.status, export_id: exp.id, state: exp.state });
const deadline = Date.now() + 5 * 60_000;
while (exp.state !== 'ready') {
  if (Date.now() > deadline) fail('export did not become ready within 5 minutes');
  if (exp.state === 'error') fail('export state error');
  await new Promise((res) => setTimeout(res, 5000));
  exp = (await api('GET', `/audit_logs/exports/${encodeURIComponent(exp.id)}`)).json;
}
step('export_ready', { state: exp.state, has_url: typeof exp.url === 'string' });

// 4. download + parse (RFC 4180-ish parser: quotes, doubled quotes, embedded newlines)
const csv = await (await fetch(exp.url)).text();
function parseCsv(text) {
  const rows = []; let row = []; let field = ''; let q = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (q) { if (c === '"') { if (text[i + 1] === '"') { field += '"'; i++; } else q = false; } else field += c; }
    else if (c === '"') q = true;
    else if (c === ',') { row.push(field); field = ''; }
    else if (c === '\n') { row.push(field); rows.push(row); row = []; field = ''; }
    else if (c !== '\r') field += c;
  }
  if (field !== '' || row.length) { row.push(field); rows.push(row); }
  return rows;
}
const rows = parseCsv(csv);
const header = rows[0] ?? [];
const records = rows.slice(1).filter((r) => r.length === header.length).map((r) => Object.fromEntries(header.map((h, i) => [h, r[i]])));
step('csv_parsed', { columns: header, row_count: records.length, bytes: csv.length });

// 5. compare: find each event's row by action; locate the tracked values wherever they appear
const comparison = [];
for (const ev of events) {
  const candidates = records.filter((rec) => Object.values(rec).some((v) => v === ev.action));
  const rec = candidates[0];
  const per = { action: ev.action, matched_row: !!rec, values: {} };
  for (const k of TRACKED) {
    if (!(k in ev.metadata)) continue;
    const want = ev.metadata[k];
    let found = null;
    if (rec) {
      for (const [col, val] of Object.entries(rec)) {
        if (val === want) { found = { column: col, form: 'exact_cell' }; break; }
        if (typeof val === 'string' && val.includes(want)) {
          let form = 'substring';
          try { const j = JSON.parse(val); if (j && typeof j === 'object' && j[k] === want) form = 'json_object_cell'; } catch {}
          found = { column: col, form }; break;
        }
      }
    }
    per.values[k] = { expected_length: want.length, found };
  }
  comparison.push(per);
}
result.comparison = comparison;
const allExact = comparison.every((c) => c.matched_row && Object.values(c.values).every((v) => v.found && (v.found.form === 'exact_cell' || v.found.form === 'json_object_cell')));
const anyMissing = comparison.some((c) => !c.matched_row || Object.values(c.values).some((v) => !v.found));
result.verdict = allExact ? 'lossless: every tracked value recovered exactly (as its own cell or as a JSON object field)' : anyMissing ? 'lossy or missing: at least one tracked value could not be recovered from the CSV' : 'recoverable only by substring: representation is ambiguous';
log('\nVERDICT: ' + result.verdict);
writeFileSync(path.join(here, 'workos-csv-reproduction.result.json'), JSON.stringify(result, null, 2) + '\n');
log('result written (sanitized; no key, no URL): tools/workos-csv-reproduction.result.json');
