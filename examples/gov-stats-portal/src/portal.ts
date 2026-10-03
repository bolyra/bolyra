/**
 * A mock relying party. For every request on a protected route it asks the
 * PUBLISHED `bolyra verify` (through @bolyra/mpp's fail-closed EVC runner):
 * "did an operator-signed binding authorize THIS agent for THIS capability at
 * THIS audience?" — where the audience is the portal's OWN configured identity,
 * never anything read from the request.
 *
 * Decision origins (every response carries `origin`):
 *   - 'cli'    — a verdict returned by the published verifier (including a
 *                CLI-emitted internal_error, which the runner passes through);
 *   - 'runner' — @bolyra/mpp's runCommandVerifier synthesized the denial on a
 *                transport/process/output failure (timeout, oversize, signal,
 *                unparseable output, non-zero exit without a verdict);
 *   - 'portal' — decided here without consulting the verifier: 401 missing
 *                header, 404 unknown route, 405 method, and 500 for an allow
 *                carrying host-nonce obligations this example does not honor.
 * The runner exposes no provenance, so 'runner' is recognised by its closed set
 * of synthesized messages (see RUNNER_MESSAGES); a verifier that emitted one of
 * those exact strings would be labelled 'runner'. Disclosed in the README.
 */
import * as http from 'node:http';
import { runCommandVerifier, denyProblem, type VerifierRequest, type Verdict } from '@bolyra/mpp';
import { PUBLIC_STATS } from './data';
import type { CommandSpec } from './paths';

export const HEADER = 'x-bolyra-authorization';
export type Origin = 'cli' | 'runner' | 'portal';

export interface PortalConfig {
  /** The portal's own identity: becomes `request.project_key`, compared byte-for-byte by the verifier. */
  audience: string;
  /** Exact GET paths → the capability the portal requires for them. */
  routes: Record<string, string>;
  /** The agent identity the portal expects (binding fields the verifier compares literally). */
  expectedAgent: { agent_name: string; program: string; model: string };
  verifier: CommandSpec;
  now?: () => number;
  /** Test hook: called once per verifier invocation. */
  onVerifierCall?: () => void;
}

/** The runner's closed set of synthesized internal_error messages (@bolyra/mpp evc.ts). */
const RUNNER_MESSAGES = [
  /^verifier spawn failed$/, /^verifier timed out after \d+ms$/, /^verifier stdout exceeded the output cap$/,
  /^verifier died with signal /, /^verifier produced no valid verdict$/, /^verifier exited non-zero \(/,
];
/** Scene fields copied into `verifier_detail`; never the raw detail (it can carry paths). */
const DETAIL_ALLOWLIST = ['field', 'capability', 'request', 'binding', 'required_scope', 'effective_scope', 'excess_bits'] as const;

export function originOf(verdict: Verdict): Origin {
  if (verdict.verdict === 'deny' && verdict.code === 'internal_error' && RUNNER_MESSAGES.some((re) => re.test(verdict.message))) return 'runner';
  return 'cli';
}

function send(res: http.ServerResponse, status: number, body: unknown, contentType = 'application/json', extra: Record<string, string> = {}) {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': contentType, 'content-length': Buffer.byteLength(text), 'cache-control': 'no-store', ...extra });
  res.end(text);
}

function sendDeny(res: http.ServerResponse, verdict: { code: string; message: string; detail?: Record<string, unknown> }, origin: Origin) {
  const problem = denyProblem(verdict as any);
  const verifier_detail: Record<string, unknown> = {};
  if (verdict.detail) for (const k of DETAIL_ALLOWLIST) if (k in verdict.detail) verifier_detail[k] = verdict.detail[k];
  send(res, problem.status, { ...problem, origin, ...(Object.keys(verifier_detail).length ? { verifier_detail } : {}) }, 'application/problem+json');
}

export function createPortal(config: PortalConfig): http.Server {
  const now = config.now ?? (() => Math.floor(Date.now() / 1000));
  return http.createServer(async (req, res) => {
    const path = (req.url ?? '').split('?')[0];
    const capability = Object.prototype.hasOwnProperty.call(config.routes, path) ? config.routes[path] : undefined;
    if (capability === undefined) return send(res, 404, { status: 404, title: 'Not Found', origin: 'portal' }, 'application/problem+json');
    if (req.method !== 'GET') return send(res, 405, { status: 405, title: 'Method Not Allowed', origin: 'portal' }, 'application/problem+json', { allow: 'GET' });
    const raw = req.headers[HEADER];
    const header = (Array.isArray(raw) ? raw[0] : raw ?? '').trim();
    if (header === '') return sendDeny(res, { code: 'missing_authorization', message: `no ${HEADER} header` }, 'portal');

    const request: VerifierRequest = {
      version: 1,
      bundle: header,
      request: { ...config.expectedAgent, project_key: config.audience, granted_capabilities: [capability] },
      now_unix: now(),
    };
    config.onVerifierCall?.();
    const verdict = await runCommandVerifier(config.verifier, request);
    if (verdict.verdict === 'deny') return sendDeny(res, verdict, originOf(verdict));
    if (verdict.consume_nonces && verdict.consume_nonces.length > 0) {
      // Spec §7.3: a host that cannot reserve the nonces MUST NOT act. This example is local-nonce-only.
      return sendDeny(res, { code: 'internal_error', message: 'verifier returned host-nonce obligations; this portal runs the verifier in local nonce mode and does not implement reserve-before-act' }, 'portal');
    }
    // The allow is a CLI verdict; the data is served only after it.
    return send(res, 200, { ...PUBLIC_STATS, capability, audience: config.audience, origin: 'cli' satisfies Origin });
  });
}
