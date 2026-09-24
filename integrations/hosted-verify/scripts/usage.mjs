#!/usr/bin/env node
/**
 * Usage report for the hosted verify preview, from Workers Analytics Engine.
 *
 *   CF_API_TOKEN=<token> node scripts/usage.mjs
 *
 * Token scope (create at dash.cloudflare.com → My Profile → API Tokens):
 *   Account → Account Analytics → Read      — nothing else is needed.
 *
 * Optional env overrides:
 *   CF_ACCOUNT_ID   (default: the bolyra founder account)
 *   USAGE_DATASET   (default: bolyra_hosted_verify_usage)
 *
 * Prints: last 24h/7d requests by tenant label (<org_id>:<role>), verdict breakdown,
 * top deny codes, and p50/p95 verify latency — all from the one-row-per-
 * request data points the Worker writes (labels only; never tokens, bodies,
 * proofs, credentials, or IPs).
 */

const ACCOUNT_ID = process.env.CF_ACCOUNT_ID ?? 'f3bcaec9510eb064bb9028b448bb5e38';
const DATASET = process.env.USAGE_DATASET ?? 'bolyra_hosted_verify_usage';
const TOKEN = process.env.CF_API_TOKEN;

if (!TOKEN) {
  console.error('CF_API_TOKEN is required (scope: Account → Account Analytics → Read).');
  process.exit(1);
}

// Row schema (see README "Observability"):
//   blob1 route · blob2 tenant label (org_id:role) · blob3 verdict · blob4 code
//   blob5 proof kind · blob6 request id (server UUID) · blob7 cf-ray (or empty)
//   double1 latency_ms · double2 status
const SQL_API = `https://api.cloudflare.com/client/v4/accounts/${ACCOUNT_ID}/analytics_engine/sql`;

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

const requestsByTenant = (interval) => `
  SELECT blob2 AS tenant, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE timestamp > NOW() - INTERVAL ${interval}
  GROUP BY tenant
  ORDER BY requests DESC
  FORMAT JSON`;

const verdictBreakdown = `
  SELECT blob2 AS tenant, blob3 AS verdict, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE timestamp > NOW() - INTERVAL '7' DAY
  GROUP BY tenant, verdict
  ORDER BY tenant, requests DESC
  FORMAT JSON`;

const topDenyCodes = `
  SELECT blob4 AS code, sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob3 = 'deny'
  GROUP BY code
  ORDER BY requests DESC
  LIMIT 10
  FORMAT JSON`;

const latency = `
  SELECT
    blob2 AS tenant,
    quantileExactWeighted(0.5)(double1, _sample_interval) AS p50_ms,
    quantileExactWeighted(0.95)(double1, _sample_interval) AS p95_ms,
    sum(_sample_interval) AS requests
  FROM ${DATASET}
  WHERE timestamp > NOW() - INTERVAL '7' DAY AND blob1 = '/v1/verify'
  GROUP BY tenant
  ORDER BY tenant
  FORMAT JSON`;

try {
  section('Requests by tenant — last 24h', await sql(requestsByTenant("'1' DAY")));
  section('Requests by tenant — last 7d', await sql(requestsByTenant("'7' DAY")));
  section('Verdict breakdown by tenant — last 7d', await sql(verdictBreakdown));
  section('Top deny codes — last 7d', await sql(topDenyCodes));
  section('Verify latency (p50/p95 ms) by tenant — last 7d', await sql(latency));
} catch (err) {
  console.error(String(err instanceof Error ? err.message : err));
  process.exit(1);
}
