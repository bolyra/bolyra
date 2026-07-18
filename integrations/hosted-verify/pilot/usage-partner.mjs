#!/usr/bin/env node
/**
 * Per-partner usage report for the hosted verify preview — a pilot-scoped
 * sibling of ../scripts/usage.mjs, over the SAME Analytics Engine dataset
 * (bolyra_hosted_verify_usage). One partner label, counts only.
 *
 *   CF_API_TOKEN=$(security find-generic-password -s bolyra-hosted-verify -a cf-analytics-token -w) \
 *     node pilot/usage-partner.mjs <label> [days]
 *
 * Token scope: Account → Account Analytics → Read (nothing else).
 * Optional env overrides: CF_ACCOUNT_ID, USAGE_DATASET.
 *
 * Prints, for ONE partner token label over the window (default 7 days):
 * request counts by route, verdict breakdown (allow/deny/error), deny codes,
 * transport error codes, HTTP status codes, and p50/p95 verify latency.
 * The dataset stores labels and counts only — never tokens, bodies, proofs,
 * credentials, or IPs (see ../README.md "Observability").
 */

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID ?? 'f3bcaec9510eb064bb9028b448bb5e38';
const DATASET = process.env.USAGE_DATASET ?? 'bolyra_hosted_verify_usage';
const TOKEN = process.env.CF_API_TOKEN;

// DATASET is interpolated into SQL as an identifier — constrain it like one.
if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(DATASET)) {
  console.error('USAGE_DATASET must be a valid identifier ([A-Za-z_][A-Za-z0-9_]*).');
  process.exit(1);
}

const [label, daysArg] = process.argv.slice(2);

if (!TOKEN) {
  console.error('CF_API_TOKEN is required (scope: Account → Account Analytics → Read).');
  process.exit(1);
}
// The label is embedded in SQL — restrict it to the same charset
// partner-token.sh enforces, so no quoting tricks are possible.
if (!label || !/^[a-z0-9][a-z0-9_-]{0,31}$/.test(label)) {
  console.error('usage: node pilot/usage-partner.mjs <label> [days]');
  console.error('  <label> must match ^[a-z0-9][a-z0-9_-]{0,31}$ (e.g. theseus)');
  process.exit(1);
}
const days = daysArg === undefined ? 7 : Number(daysArg);
if (!Number.isInteger(days) || days < 1 || days > 90) {
  console.error('[days] must be an integer 1..90');
  process.exit(1);
}

// Row schema (see ../README.md "Observability"):
//   blob1 route · blob2 partner label · blob3 verdict · blob4 code
//   blob5 proof kind · blob6 request id · double1 latency_ms · double2 status
const SQL_API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`;
const WINDOW = `timestamp > NOW() - INTERVAL '${days}' DAY`;
const PARTNER = `blob2 = '${label}'`;

async function sql(query) {
  const res = await fetch(SQL_API, {
    method: 'POST',
    headers: { authorization: `Bearer ${TOKEN}` },
    body: query,
  });
  if (!res.ok) {
    throw new Error(`Analytics Engine SQL API ${res.status}: ${await res.text()}`);
  }
  const { data } = await res.json();
  return data;
}

function section(title, rows) {
  console.log(`\n=== ${title} ===`);
  if (rows.length === 0) {
    console.log('(no data)');
  } else {
    console.table(rows);
  }
}

const requestsByRoute = `
  SELECT blob1 AS route, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER}
  GROUP BY route
  ORDER BY requests DESC
  FORMAT JSON`;

const verdictBreakdown = `
  SELECT blob3 AS verdict, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER}
  GROUP BY verdict
  ORDER BY requests DESC
  FORMAT JSON`;

const denyCodes = `
  SELECT blob4 AS code, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER} AND blob3 = 'deny'
  GROUP BY code
  ORDER BY requests DESC
  FORMAT JSON`;

const errorCodes = `
  SELECT blob4 AS code, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER} AND blob3 = 'error'
  GROUP BY code
  ORDER BY requests DESC
  FORMAT JSON`;

const httpStatus = `
  SELECT double2 AS status, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER}
  GROUP BY status
  ORDER BY requests DESC
  FORMAT JSON`;

const latency = `
  SELECT
    quantileExactWeighted(0.5)(double1, _sample_interval) AS p50_ms,
    quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
    sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE ${WINDOW} AND ${PARTNER} AND blob1 = '/v1/verify'
  FORMAT JSON`;

try {
  console.log(`Partner: ${label} — last ${days} day(s) — dataset ${DATASET}`);
  section('Requests by route', await sql(requestsByRoute));
  section('Verdict breakdown (allow/deny/error)', await sql(verdictBreakdown));
  section('Deny codes (spec §9)', await sql(denyCodes));
  section('Transport error codes (401/404/405)', await sql(errorCodes));
  section('HTTP status codes', await sql(httpStatus));
  section('Verify latency p50/p95 (ms)', await sql(latency));
} catch (err) {
  console.error(String(err instanceof Error ? err.message : err));
  process.exit(1);
}
