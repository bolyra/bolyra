#!/usr/bin/env node
/**
 * Reproduction: do the packet's metadata values survive a WorkOS Audit Logs CSV export losslessly?
 *
 * STAGING ONLY. Use a dedicated staging environment: audit-log actions and schemas are scoped to the
 * environment, so a fresh organization does not isolate them. Reads the API key from the file named by
 * WORKOS_STAGING_KEY_FILE (never from argv).
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
  try { json = text ? JSON.parse(text) : {}; } catch { json = {}; }
  return { status: res.status, json };
}

const log = (m) => console.log(m);
const result = { ran_at: new Date().toISOString(), environment: 'staging', transport_notes: ['actor.metadata: {} added in transit (schema requires the key)', 'event schemas registered via POST /audit_logs/actions/{action}/schemas because unconfigured actions are rejected with invalid_audit_log'], steps: [], comparison: null, verdict: null };
const step = (name, detail) => { result.steps.push({ name, ...detail }); log(`${name}: ${JSON.stringify(detail)}`); };
// Allowlisted diagnostics only: HTTP status and the API's error code; never raw response bodies.
const diag = (r) => ({ status: r.status, ...(r.status >= 300 && typeof r.json?.code === 'string' ? { code: r.json.code } : {}) });
const UNCONFIGURED = /has not been configured in this environment/;

// 1. organization
const orgName = `bolyra-audit-log-evidence ${new Date().toISOString().slice(0, 19)}`;
let r = await api('POST', '/organizations', { name: orgName });
if (r.status >= 300) fail(`create organization → ${r.status} ${r.json?.code ?? ''}`);
const orgId = r.json.id;
step('organization_created', { status: r.status, organization_id: orgId });

// 2. events (create schemas on demand if the API rejects an unregistered action)
for (const ev of events) {
  // The registered schema makes actor.metadata required; the fixture rows carry none, so an empty object is added in transit (recorded in the result).
  const body = { organization_id: orgId, event: { action: ev.action, version: ev.version, occurred_at: ev.occurred_at, actor: { ...ev.actor, metadata: {} }, targets: ev.targets, context: ev.context, metadata: ev.metadata } };
  r = await api('POST', '/audit_logs/events', body, { 'Idempotency-Key': randomUUID() });
  if (r.status >= 300 && r.json?.code === 'invalid_audit_log' && UNCONFIGURED.test(String(r.json?.message ?? ''))) {
    const schema = {
      actor: { metadata: { type: 'object', properties: {} } },
      targets: [...new Set(ev.targets.map((t) => t.type))].map((type) => ({ type })),
      metadata: { type: 'object', properties: Object.fromEntries(Object.keys(ev.metadata).map((k) => [k, { type: 'string' }])) },
    };
    const s = await api('POST', `/audit_logs/actions/${encodeURIComponent(ev.action)}/schemas`, schema);
    step('schema_registered', { action: ev.action, ...diag(s) });
    if (s.status >= 300) fail(`schema registration for ${ev.action} failed (${s.status})`);
    r = await api('POST', '/audit_logs/events', body, { 'Idempotency-Key': randomUUID() });
  }
  step('event_emitted', { action: ev.action, ...diag(r) });
  if (r.status >= 300) fail(`event ${ev.action} rejected (${r.status} ${r.json?.code ?? ''})`);
}

// 3. export over the fixture range
const times = events.map((e) => Date.parse(e.occurred_at));
r = await api('POST', '/audit_logs/exports', {
  organization_id: orgId,
  range_start: new Date(Math.min(...times) - 60_000).toISOString(),
  range_end: new Date(Math.max(...times) + 60_000).toISOString(),
});
if (r.status >= 300) fail(`create export → ${r.status} ${r.json?.code ?? ''}`);
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

// 5. compare: match each event's row by its action column; parse the metadata JSON cell; compare each
// expected field directly. Every expected field must be present in the fixture AND recovered exactly.
const comparison = [];
for (const ev of events) {
  const expectedFields = TRACKED.filter((k) => k in ev.metadata);
  const rowsForAction = records.filter((rec) => rec.action === ev.action);
  const rec = rowsForAction.length === 1 ? rowsForAction[0] : undefined;
  let parsed = null;
  if (rec && typeof rec.metadata === 'string') { try { parsed = JSON.parse(rec.metadata); } catch { parsed = null; } }
  const per = { action: ev.action, rows_with_action: rowsForAction.length, metadata_cell_is_json_object: !!parsed && typeof parsed === 'object', expected_fields: expectedFields, values: {} };
  for (const k of expectedFields) {
    const want = ev.metadata[k];
    const got = parsed && typeof parsed === 'object' ? parsed[k] : undefined;
    per.values[k] = { expected_length: want.length, recovered_exactly: got === want, recovered_type: typeof got };
  }
  comparison.push(per);
}
result.comparison = comparison;
const total = comparison.reduce((n, c) => n + c.expected_fields.length, 0);
const exact = comparison.reduce((n, c) => n + Object.values(c.values).filter((v) => v.recovered_exactly).length, 0);
const allExact = comparison.every((c) => c.rows_with_action === 1 && c.metadata_cell_is_json_object) && exact === total;
result.verdict = allExact
  ? `lossless for the ${total} tested string occurrences in this run: each recovered exactly from the metadata JSON cell`
  : `not lossless: ${exact} of ${total} tested string occurrences recovered exactly`;
log('\nVERDICT: ' + result.verdict);
writeFileSync(path.join(here, 'workos-csv-reproduction.result.json'), JSON.stringify(result, null, 2) + '\n');
log('result written (sanitized; no key, no URL): tools/workos-csv-reproduction.result.json');
