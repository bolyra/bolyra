/**
 * The authorization boundary (spec §3.1).
 *
 * A loopback-only server exposing exactly one action. The shipped gateway
 * middleware does bundle verification, nonce replay, dev credential binding,
 * and tool policy, and writes the 401/403 itself; this host duplicates none
 * of those checks. On allow it persists the receipt, then dispatches exactly
 * one HTTP request to the operator's endpoint. Every decision is published
 * to an in-process result channel after its receipt is persisted (or its
 * persistence failure recorded), because a deny's HTTP body carries no
 * receipt id.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';
import {
  buildDecisionReceiptInput,
  buildDenialReceiptInput,
  createGatewayMiddleware,
} from '@bolyra/gateway';
import type { GatewayConfig, GatewayRequest } from '@bolyra/gateway';
import { verifyReceipt } from '@bolyra/receipts';
import type { Audit } from './audit';
import type { TrialConfig } from './config';

export type Stage =
  | 'missing_auth'
  | 'malformed_bundle'
  | 'verification_failed'
  | 'credential_binding_failed'
  | 'policy_denied';

export type Outcome = 'completed' | 'not_followed' | 'timeout' | 'network_error' | 'not_dispatched';

/** One decision as observed by the host. trial.ts adds `n` and `credential`. */
export interface HostDecision {
  decision: 'allow' | 'deny';
  stage?: Stage;
  /** Middleware reason, or 'allowed'. */
  reason: string;
  /** Status the client saw from the host. */
  httpStatus: number;
  /** The host invoked fetch for this attempt. Not proof of delivery or execution. */
  dispatched: boolean;
  upstreamStatus: number | null;
  outcome: Outcome;
  receiptId: string | null;
  receiptError?: string;
}

export interface HostOptions {
  config: TrialConfig;
  gatewayConfig: GatewayConfig;
  audit: Audit;
  /** Injected for tests. Defaults to global fetch. */
  fetchImpl?: typeof fetch;
  /** Upstream timeout in ms (default 15000). */
  timeoutMs?: number;
  log?: (line: string) => void;
}

export interface TrialHost {
  /** Base URL, e.g. http://127.0.0.1:54321 (no trailing slash). */
  url: string;
  /** Total fetch invocations to the operator endpoint. */
  readonly dispatchCount: number;
  /** Every published decision, in order. */
  readonly results: HostDecision[];
  /** Resolves with the next unconsumed decision. */
  nextResult(): Promise<HostDecision>;
  close(): Promise<void>;
}

export async function startHost(opts: HostOptions): Promise<TrialHost> {
  const { config, gatewayConfig, audit } = opts;
  const fetchImpl = opts.fetchImpl ?? fetch;
  const timeoutMs = opts.timeoutMs ?? 15_000;
  const log = opts.log ?? (() => {});

  // Created ONCE: createGatewayMiddleware builds its in-memory nonce store
  // when called. Per-request creation would let every replay through.
  const middleware = createGatewayMiddleware({ config: gatewayConfig });

  const descriptor = ` | action=${config.action} ${config.method} ${config.url.host}${config.url.pathname}`;
  const routePath = `/action/${config.action}`;

  const results: HostDecision[] = [];
  const pending: HostDecision[] = [];
  const waiters: Array<(d: HostDecision) => void> = [];
  let dispatchCount = 0;

  function publish(d: HostDecision): void {
    results.push(d);
    const waiter = waiters.shift();
    if (waiter) waiter(d);
    else pending.push(d);
  }

  async function dispatch(): Promise<{ upstreamStatus: number | null; outcome: Outcome }> {
    const init: RequestInit = {
      method: config.method,
      headers: config.headers,
      redirect: 'manual',
      signal: AbortSignal.timeout(timeoutMs),
    };
    if (config.body) init.body = new Uint8Array(config.body);
    dispatchCount += 1; // counted at the moment fetch is invoked
    try {
      const res = await fetchImpl(config.url, init);
      // Discard the body without buffering it. A discard failure must not
      // mask the status we already observed.
      try {
        if (res.body) await res.body.cancel();
      } catch {
        // ignore
      }
      if (res.status >= 300 && res.status < 400) return { upstreamStatus: res.status, outcome: 'not_followed' };
      return { upstreamStatus: res.status, outcome: 'completed' };
    } catch (err) {
      const name = (err as Error).name;
      return { upstreamStatus: null, outcome: name === 'TimeoutError' || name === 'AbortError' ? 'timeout' : 'network_error' };
    }
  }

  const server = http.createServer(async (incoming, res) => {
    const req = incoming as GatewayRequest;
    try {
      await drain(req);

      if (req.method !== 'POST' || req.url !== routePath) {
        sendJson(res, 404, { error: 'not found' });
        return;
      }

      const ok = await middleware(req, res, config.action);

      if (!ok) {
        const denial = req.bolyraDenial;
        const result: HostDecision = {
          decision: 'deny',
          stage: denial?.stage,
          reason: denial?.reason ?? 'denied: no reason recorded',
          httpStatus: res.statusCode,
          dispatched: false,
          upstreamStatus: null,
          outcome: 'not_dispatched',
          receiptId: null,
        };
        try {
          const input = buildDenialReceiptInput(denial, gatewayConfig, config.action);
          input.reasonCode = (input.reasonCode ?? result.reason) + descriptor;
          result.receiptId = audit.record(input).id;
        } catch (err) {
          result.receiptError = (err as Error).message;
        }
        log(`deny (${result.stage ?? 'unknown'}): ${result.reason}`);
        publish(result);
        return;
      }

      const authCtx = req.bolyra!;
      const bundle = req.bolyraBundle!;
      const input = buildDecisionReceiptInput(bundle, authCtx, gatewayConfig, true, 'allowed' + descriptor);

      let receiptId: string;
      try {
        const signed = audit.record(input);
        // Verify what is ON DISK, not the object in memory: the persisted line
        // is the only thing the operator can hand to a verifier later.
        const persisted = audit.readBackLast();
        if (
          !persisted ||
          persisted.signature.payloadHash !== signed.signature.payloadHash ||
          !verifyReceipt(persisted, audit.signerInfo.signer)
        ) {
          throw new Error('persisted receipt does not match or does not verify');
        }
        receiptId = signed.id;
      } catch (err) {
        sendJson(res, 500, { error: 'receipt persistence failed' });
        publish({
          decision: 'allow',
          reason: 'allowed',
          httpStatus: 500,
          dispatched: false,
          upstreamStatus: null,
          outcome: 'not_dispatched',
          receiptId: null,
          receiptError: (err as Error).message,
        });
        return;
      }

      const { upstreamStatus, outcome } = await dispatch();
      log(`allow: dispatched ${config.method} ${config.url.host}${config.url.pathname} -> ${upstreamStatus ?? outcome}`);
      const result: HostDecision = {
        decision: 'allow',
        reason: 'allowed',
        httpStatus: 200,
        dispatched: true,
        upstreamStatus,
        outcome,
        receiptId,
      };
      sendJson(res, 200, { decision: 'allow', dispatched: true, upstreamStatus, outcome, receiptId });
      publish(result);
    } catch (err) {
      log(`host error: ${(err as Error).message}`);
      if (!res.headersSent) sendJson(res, 500, { error: 'internal trial host error' });
    }
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}`,
    get dispatchCount() {
      return dispatchCount;
    },
    results,
    nextResult: () =>
      new Promise<HostDecision>((resolve) => {
        const ready = pending.shift();
        if (ready) resolve(ready);
        else waiters.push(resolve);
      }),
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}

function drain(req: http.IncomingMessage): Promise<void> {
  return new Promise((resolve, reject) => {
    req.on('data', () => undefined);
    req.on('end', () => resolve());
    req.on('error', reject);
  });
}

function sendJson(res: http.ServerResponse, status: number, body: unknown): void {
  const text = JSON.stringify(body);
  res.writeHead(status, { 'content-type': 'application/json', 'content-length': Buffer.byteLength(text) });
  res.end(text);
}
