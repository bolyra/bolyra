/**
 * @bolyra/gateway — health check endpoint.
 *
 * Returns gateway status and upstream reachability via a lightweight
 * HEAD probe with a 2s timeout.
 */

import * as http from 'http';
import * as https from 'https';
import type { ServerResponse } from 'http';
import type { GatewayConfig, GatewayRequest } from './types';

const VERSION = '0.1.0';
const PROBE_TIMEOUT = 2000; // 2 seconds

/**
 * Create a health check handler that returns gateway status.
 * Returns 200 with status JSON when everything is OK, 503 when upstream is unreachable.
 */
export function createHealthHandler(
  config: GatewayConfig,
  startTime: number = Date.now(),
): (req: GatewayRequest, res: ServerResponse) => void {
  return async (_req: GatewayRequest, res: ServerResponse) => {
    const uptime = Math.floor((Date.now() - startTime) / 1000);
    let targetReachable = false;

    try {
      targetReachable = await probeUpstream(config.target);
    } catch {
      targetReachable = false;
    }

    const status = targetReachable ? 'ok' : 'degraded';
    const httpStatus = targetReachable ? 200 : 503;

    const body = JSON.stringify({
      status,
      gateway: '@bolyra/gateway',
      version: VERSION,
      uptime,
      target: config.target,
      targetReachable,
      mode: config.devMode ? 'dev' : 'production',
      receiptsEnabled: config.receipts.enabled,
      nonceStore: config.nonce.store,
    });

    res.writeHead(httpStatus, {
      'Content-Type': 'application/json',
      'Content-Length': Buffer.byteLength(body),
    });
    res.end(body);
  };
}

/**
 * Probe upstream reachability with a HEAD request and a 2s timeout.
 */
function probeUpstream(targetUrl: string): Promise<boolean> {
  return new Promise((resolve) => {
    try {
      const url = new URL(targetUrl);
      const isHttps = url.protocol === 'https:';
      const reqFn = isHttps ? https.request : http.request;

      const req = reqFn(
        {
          hostname: url.hostname,
          port: url.port || (isHttps ? '443' : '80'),
          path: url.pathname,
          method: 'HEAD',
          timeout: PROBE_TIMEOUT,
        },
        (res) => {
          res.resume();
          resolve(true);
        },
      );

      req.on('error', () => resolve(false));
      req.on('timeout', () => {
        req.destroy();
        resolve(false);
      });

      req.end();
    } catch {
      resolve(false);
    }
  });
}
