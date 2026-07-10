/**
 * Verified agent actions — end-to-end demo.
 *
 *   npm run demo
 *
 * Story:
 *   Scene 1  support agent (READ|WRITE) refunds a customer   -> ALLOWED
 *   Scene 2  reporting agent (READ only) tries the same      -> DENIED
 *   Scene 3  reporting agent reads the ledger                -> ALLOWED
 *   Scene 4  attacker replays scene 1's proof bundle         -> REJECTED
 *   Scene 5  forged bundle claims permissions it wasn't granted -> REJECTED
 *   Audit    every decision is an ES256K-signed receipt in a JSONL log;
 *            each receipt verifies independently and any edit breaks it.
 */

import * as path from 'node:path';
import type * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import { loadConfig } from '@bolyra/gateway';
import { createDemoAgent, buildDevBundle, fmtMask, READ_DATA, WRITE_DATA } from './agents';
import type { DemoAgent } from './agents';
import { AuditLog, readAuditLog, verifyAuditLog, tamperChecks } from './audit';
import { createVerifiedActionsHost } from './gateway-host';
import { pkgRoot } from './paths';
import { createUpstreamServer } from './upstream';

const ROOT = pkgRoot(__dirname);
const useColor = process.stdout.isTTY && !process.env.NO_COLOR;
const green = (s: string) => (useColor ? `\x1b[32m${s}\x1b[0m` : s);
const red = (s: string) => (useColor ? `\x1b[31m${s}\x1b[0m` : s);
const dim = (s: string) => (useColor ? `\x1b[2m${s}\x1b[0m` : s);
const bold = (s: string) => (useColor ? `\x1b[1m${s}\x1b[0m` : s);

function section(title: string): void {
  console.log('\n' + bold('=== ' + title + ' ==='));
}

let rpcId = 0;

interface CallResult {
  status: number;
  body: { result?: { content?: Array<{ text?: string }> }; error?: { message?: string } };
  /** The Authorization header used — kept so the replay scene can reuse it. */
  authHeader: string;
}

async function callTool(
  hostUrl: string,
  agent: DemoAgent,
  tool: string,
  args: Record<string, unknown>,
  reuseAuthHeader?: string,
): Promise<CallResult> {
  const authHeader = reuseAuthHeader ?? buildDevBundle(agent).header;
  const res = await fetch(hostUrl, {
    method: 'POST',
    headers: { 'content-type': 'application/json', authorization: authHeader },
    body: JSON.stringify({
      jsonrpc: '2.0',
      id: ++rpcId,
      method: 'tools/call',
      params: { name: tool, arguments: args },
    }),
  });
  return { status: res.status, body: (await res.json()) as CallResult['body'], authHeader };
}

function printClientResult(result: CallResult): void {
  if (result.status === 200) {
    const text = result.body.result?.content?.[0]?.text ?? JSON.stringify(result.body.result);
    console.log(`  client:  HTTP 200 ${green('->')} ${text}`);
  } else {
    console.log(`  client:  HTTP ${result.status} ${red('->')} ${result.body.error?.message ?? 'error'}`);
  }
}

function listen(server: http.Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve((server.address() as AddressInfo).port));
  });
}

async function main(): Promise<void> {
  console.log(bold('Bolyra — verified agent actions'));
  console.log(dim('Every MCP tool call is checked against the agent\'s credential and'));
  console.log(dim('receipted with an ES256K signature — allows AND denies.'));

  section('Setup');

  // 1. The MCP server being protected (a mock payments server).
  const upstream = createUpstreamServer({ log: (l) => console.log(dim(`  upstream: ${l}`)) });
  const upstreamPort = await listen(upstream);
  console.log(`  upstream payments MCP server on 127.0.0.1:${upstreamPort} (tools: read_ledger, refund_customer)`);

  // 2. Gateway config — gateway.yaml parsed by @bolyra/gateway's own loadConfig.
  const config = loadConfig({
    config: path.join(ROOT, 'gateway.yaml'),
    target: `http://127.0.0.1:${upstreamPort}/mcp`,
  });
  console.log(`  policy (gateway.yaml): read_ledger requires READ_DATA (1b), refund_customer requires WRITE_DATA (10b)`);
  console.log(`  dev mode: ${config.devMode} ${dim('(mock proofs + registry stand-in — production uses real Groth16 + resolveCredential)')}`);

  // 3. Two agents with different credentials, registered with the gateway.
  //    In production the registry is resolveCredential + the proof's
  //    scopeCommitment binding; in dev mode the host checks claims against
  //    this map so a forged permission mask still gets caught (scene 5).
  const supportAgent = createDemoAgent('support-agent', READ_DATA | WRITE_DATA);
  const reportingAgent = createDemoAgent('reporting-agent', READ_DATA);
  const credentials = new Map<string, bigint>([
    [supportAgent.commitment.toString(), supportAgent.permissionBitmask],
    [reportingAgent.commitment.toString(), reportingAgent.permissionBitmask],
  ]);
  console.log(`  agents: support-agent ${fmtMask(supportAgent.permissionBitmask)} (READ|WRITE), reporting-agent ${fmtMask(reportingAgent.permissionBitmask)} (READ only)`);

  // 4. Signed audit log + gateway host.
  const audit = new AuditLog(path.join(ROOT, 'audit'));
  console.log(`  audit log: ${path.relative(ROOT, audit.logPath)} — signer ${audit.signerInfo.signer} (ES256K)`);
  const host = createVerifiedActionsHost({ config, audit, credentials, log: (l) => console.log(dim(`  gateway:  ${l}`)) });
  const hostPort = await listen(host);
  const hostUrl = `http://127.0.0.1:${hostPort}/mcp`;
  console.log(`  Bolyra gateway host on 127.0.0.1:${hostPort} -> forwards verified calls upstream`);

  section('Scene 1 — support-agent refunds a customer (has WRITE_DATA)');
  const scene1 = await callTool(hostUrl, supportAgent, 'refund_customer', {
    customer_id: 'cus_4821',
    amount_usd: 42.0,
  });
  printClientResult(scene1);

  section('Scene 2 — reporting-agent tries the same refund (READ only)');
  const scene2 = await callTool(hostUrl, reportingAgent, 'refund_customer', {
    customer_id: 'cus_4821',
    amount_usd: 42.0,
  });
  printClientResult(scene2);

  section('Scene 3 — reporting-agent reads the ledger (in scope)');
  const scene3 = await callTool(hostUrl, reportingAgent, 'read_ledger', { customer_id: 'cus_4821' });
  printClientResult(scene3);
  console.log(dim('  per-action authority: the same agent that was denied a write is allowed a read.'));

  section('Scene 4 — attacker replays scene 1\'s proof bundle');
  const scene4 = await callTool(hostUrl, supportAgent, 'refund_customer', {
    customer_id: 'cus_9999',
    amount_usd: 9_999.0,
  }, scene1.authHeader);
  printClientResult(scene4);

  section('Scene 5 — forged bundle: reporting-agent claims READ|WRITE it was never granted');
  const forgedAgent = { ...reportingAgent, permissionBitmask: READ_DATA | WRITE_DATA };
  const scene5 = await callTool(hostUrl, forgedAgent, 'refund_customer', {
    customer_id: 'cus_4821',
    amount_usd: 42.0,
  });
  printClientResult(scene5);
  console.log(dim('  dev mode catches this against the registered credential; in production the'));
  console.log(dim('  Groth16 proof binds permissions cryptographically — a forged mask cannot prove.'));

  section('Audit — every decision left a signed receipt');
  const receipts = readAuditLog(audit.logPath);
  console.log(`  ${receipts.length} receipts in ${path.relative(ROOT, audit.logPath)}:\n`);
  console.log(dim('  #  id                  decision  score  agent                        reason'));
  receipts.forEach((r, i) => {
    const decision = r.payload.decision.allowed ? green('allow   ') : red('deny    ');
    const agent = r.payload.subject.actingDid.slice(0, 24) + '...';
    const reason = (r.payload.decision.reasonCode ?? '').slice(0, 72);
    console.log(`  ${i + 1}  ${r.id}  ${decision}  ${String(r.payload.decision.score).padStart(3)}    ${agent}  ${dim(reason)}`);
  });

  section('Verify — receipts stand on their own');
  const verified = verifyAuditLog(receipts, audit.signerInfo.signer);
  const allValid = verified.every((v) => v.valid);
  for (const v of verified) {
    console.log(`  receipt ${v.receipt.id} signature ${v.valid ? green('VALID') : red('INVALID')}`);
  }
  console.log(
    allValid
      ? green(`  all ${receipts.length} receipts verified against signer ${audit.signerInfo.signer}`)
      : red('  VERIFICATION FAILURE — audit log is not trustworthy'),
  );

  console.log('\n  Now tamper with the deny receipt and re-verify:');
  const denyReceipt = receipts.find((r) => !r.payload.decision.allowed)!;
  const otherReceipt = receipts.find((r) => r.id !== denyReceipt.id);
  let tamperCaught = true;
  for (const check of tamperChecks(denyReceipt, otherReceipt)) {
    const ok = !check.stillVerifies;
    tamperCaught = tamperCaught && ok;
    console.log(`  tamper: ${check.description} -> ${ok ? green('verification FAILED as expected') : red('STILL VERIFIES (bug!)')}`);
  }

  section('Done');
  console.log('  Re-verify any time without the gateway running:  npm run verify');
  console.log(dim('  (needs only audit/audit-log.jsonl + audit/signer.json + @bolyra/receipts)'));

  upstream.close();
  host.close();

  if (!allValid || !tamperCaught) {
    process.exitCode = 1;
  }
}

main().catch((err) => {
  console.error('demo failed:', err);
  process.exit(1);
});
