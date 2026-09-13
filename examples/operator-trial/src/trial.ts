/**
 * runTrial (spec §3.2): the operator's three attempts, in-process. The CLI
 * and the tests both call this; nothing here calls process.exit.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import {
  buildDevBundle,
  createDemoAgent,
  requiredMask,
  withheldLabel,
  withheldMask,
} from './agents';
import { Audit } from './audit';
import type { AuditIo, SummaryAttempt } from './audit';
import { TrialConfigError } from './config';
import type { TrialConfig } from './config';
import { startEcho } from './echo';
import type { EchoServer } from './echo';
import { buildGatewayConfig } from './gateway-config';
import { startHost } from './host';
import type { HostDecision, TrialHost } from './host';
import { CLI_VERSION } from './versions';

export type Credential = 'granted' | 'withheld' | 'replay';

export interface AttemptResult extends HostDecision {
  n: 1 | 2 | 3;
  credential: Credential;
  /** fetch invocations to the operator endpoint during this attempt. */
  dispatches: number;
}

export interface RunTrialOptions {
  /** Required unless dryRun. In dryRun with a config, the URL is replaced by the echo endpoint. */
  config?: TrialConfig;
  /** Parent of the per-run directory. */
  outDir: string;
  dryRun: boolean;
  /** Dry-run only: echo response status (default 200). */
  echo?: { status: number };
  /** Narration sink (default console.log). */
  log?: (line: string) => void;
  /** Test hooks. */
  fetchImpl?: typeof fetch;
  audit?: { io?: Partial<AuditIo> };
}

export interface TrialSummary {
  ok: boolean;
  runDir: string;
  attempts: AttemptResult[];
  dispatchCounts: [number, number, number];
  /** Dry-run only: requests the echo endpoint observed. */
  echoRequestCount: number | null;
  receiptCount: number | null;
  headReceiptHash: string | null;
  verifyCommand: string | null;
  finalizeReason?: string;
}

export async function runTrial(opts: RunTrialOptions): Promise<TrialSummary> {
  const log = opts.log ?? ((l: string) => console.log(l));
  const startedAt = new Date();

  let echo: EchoServer | undefined;
  let config: TrialConfig;
  if (opts.dryRun) {
    echo = await startEcho(opts.echo);
    config = opts.config
      ? { ...opts.config, url: new URL(echo.url) }
      : {
          action: 'echo-action',
          method: 'POST',
          url: new URL(echo.url),
          headers: {},
          requiredPermission: 'WRITE_DATA',
          secrets: [],
        };
  } else {
    if (!opts.config) throw new TrialConfigError('a config is required unless --dry-run is set');
    config = opts.config;
  }

  const runDir = path.join(opts.outDir, startedAt.toISOString().replace(/[:.]/g, '-'));
  if (fs.existsSync(runDir)) {
    if (echo) await echo.close();
    throw new TrialConfigError(`run directory already exists: ${runDir}`);
  }

  const required = requiredMask(config.requiredPermission);
  const granted = createDemoAgent('granted', required);
  const withheld = createDemoAgent('withheld', withheldMask(config.requiredPermission));
  const gatewayConfig = buildGatewayConfig(config.action, required, granted, withheld);

  // From here on, every exit path closes the servers and leaves no unscanned
  // directory behind (spec §3.3 step 0 / §5).
  let audit: Audit | undefined;
  let host: TrialHost | undefined;
  const attempts: AttemptResult[] = [];
  try {
    audit = new Audit({ runDir, gatewayConfig, io: opts.audit?.io });

    log('Bolyra operator trial');
    log(`  action:   ${config.action}  ${config.method} ${config.url.host}${config.url.pathname}${opts.dryRun ? '  (dry run: built-in echo endpoint)' : ''}`);
    log(`  policy:   ${config.action} requires ${config.requiredPermission}`);
    log(`  headers sent: ${Object.keys(config.headers).join(', ') || '(none)'}`);
    log(`  receipts: ${displayPath(audit.receiptsPath)}  signer ${audit.signerInfo.signer} (ephemeral, ES256K)`);
    log('');
    log('  Controlled trial: credentials are simulated and registered locally; ZK proof verification is disabled (dev mode).');
    log('  Production Bolyra uses real proofs and a credential registry.');
    log('  The trial protects traffic routed through this local Bolyra host. It does not stop anyone from calling the endpoint directly.');
    log("  'dispatched' means this host invoked the request; delivery and execution at your endpoint are not proven by the receipts.");
    if (!opts.dryRun) {
      log('  Use a staging endpoint or a reversible action. Attempt 1 really executes.');
    }
    log('');

    host = await startHost({ config, gatewayConfig, audit, fetchImpl: opts.fetchImpl });
    const first = buildDevBundle(granted);
    attempts.push(await attempt(host, config, 1, 'granted', first.header));
    attempts.push(await attempt(host, config, 2, 'withheld', buildDevBundle(withheld).header));
    attempts.push(await attempt(host, config, 3, 'replay', first.header));
  } catch (err) {
    audit?.abort(config.secrets);
    throw err;
  } finally {
    if (host) await host.close();
    if (echo) await echo.close();
  }
  // The try block either assigned audit or threw; this satisfies the type checker.
  if (!audit) throw new Error('unreachable: audit not created');

  const dispatchCounts: [number, number, number] = [attempts[0].dispatches, attempts[1].dispatches, attempts[2].dispatches];
  const attemptsOk = expectationsMet(attempts) && dispatchCounts.join() === '1,0,0';

  const finishedAt = new Date();
  const fin = audit.finalize({
    attemptsOk,
    attempts: attempts.map(toSummaryAttempt),
    dispatchCounts,
    dryRun: opts.dryRun,
    action: { name: config.action, method: config.method, host: config.url.host, path: config.url.pathname },
    startedAt: startedAt.toISOString(),
    finishedAt: finishedAt.toISOString(),
    secrets: config.secrets,
  });

  const summary: TrialSummary = {
    ok: attemptsOk && fin.ok,
    runDir,
    attempts,
    dispatchCounts,
    echoRequestCount: echo ? echo.requestCount : null,
    receiptCount: fin.receiptCount,
    headReceiptHash: fin.headReceiptHash,
    verifyCommand: fin.verifyCommand,
    finalizeReason: fin.reason,
  };

  narrate(log, config, summary, opts.dryRun);
  return summary;
}

async function attempt(
  host: TrialHost,
  config: TrialConfig,
  n: 1 | 2 | 3,
  credential: Credential,
  authHeader: string,
): Promise<AttemptResult> {
  const before = host.dispatchCount;
  const res = await fetch(`${host.url}/action/${config.action}`, {
    method: 'POST',
    headers: { authorization: authHeader, 'content-type': 'application/json' },
    body: '{}',
  });
  await res.arrayBuffer();
  const decision = await host.nextResult();
  return { n, credential, ...decision, dispatches: host.dispatchCount - before };
}

function expectationsMet(a: AttemptResult[]): boolean {
  const [one, two, three] = a;
  return (
    one.decision === 'allow' && one.dispatched && !one.receiptError &&
    two.decision === 'deny' && two.stage === 'policy_denied' && !two.dispatched && !two.receiptError &&
    three.decision === 'deny' && three.stage === 'verification_failed' && /Nonce already used/.test(three.reason) && !three.dispatched && !three.receiptError
  );
}

function toSummaryAttempt(a: AttemptResult): SummaryAttempt {
  const { dispatches: _dispatches, ...rest } = a;
  return rest;
}

/**
 * Path for narration. Compares real paths so a symlinked cwd (macOS /tmp is
 * /private/tmp) does not print "../../../..."; falls back to the absolute path.
 */
function displayPath(p: string): string {
  try {
    const rel = path.relative(fs.realpathSync(process.cwd()), fs.existsSync(p) ? fs.realpathSync(p) : p);
    return rel.startsWith('..') ? p : rel;
  } catch {
    return p;
  }
}

function narrate(log: (l: string) => void, config: TrialConfig, s: TrialSummary, dryRun: boolean): void {
  const labels: Record<Credential, string> = {
    granted: `credential granted ${config.requiredPermission}`,
    withheld: `credential granted ${withheldLabel(config.requiredPermission)}`,
    replay: "replay of attempt 1's bundle",
  };
  for (const a of s.attempts) {
    const verdict = a.decision === 'allow' && a.dispatched ? 'ALLOW' : a.decision === 'allow' ? 'ALLOW (receipt failed)' : 'DENY';
    const upstream = a.dispatched ? `upstream ${a.upstreamStatus ?? a.outcome}` : '';
    const receipt = a.receiptId ? `receipt ${a.receiptId.slice(0, 8)}…` : `receipt error: ${a.receiptError ?? 'unknown'}`;
    log(`Attempt ${a.n}  ${labels[a.credential].padEnd(40)} -> ${verdict.padEnd(6)} dispatched: ${a.dispatched ? 'yes' : 'no '}  ${upstream.padEnd(13)} ${receipt}`);
  }
  log('');
  log(`dispatches to your endpoint: ${s.dispatchCounts.join(' / ')}`);
  if (fs.existsSync(s.runDir)) log(`bundle: ${displayPath(s.runDir)}/`);
  if (s.verifyCommand) {
    log(`verify independently (needs @bolyra/cli ${CLI_VERSION}; the first npx run downloads it). From inside the bundle directory:`);
    log(`  ${s.verifyCommand}`);
  }
  if (!s.ok) log(`RESULT: FAILED${s.finalizeReason ? ` (${s.finalizeReason})` : ''}`);
  log('');
  log('Receipts verify signed claims and chain integrity against the signer in signer.json, which is ephemeral to this run.');
  log('summary.json is unsigned observation; endpoint execution is not proven by the receipts.');
  log('The bundle was scanned for the values this trial substituted from the environment and the header values that contained them; nothing else is redacted.');
  if (dryRun) {
    log('This was a dry run against the built-in echo endpoint. It does not count toward anything. Point trial.yaml at a staging endpoint or a reversible action you own and run again,');
    log('then email that bundle directory to hello@bolyra.ai. Nothing is sent automatically.');
  } else {
    log('If this ran against an endpoint you own, email the bundle directory to hello@bolyra.ai. Nothing is sent automatically.');
  }
}
