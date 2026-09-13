/**
 * Dry-run endpoint (spec §3.4): a loopback server that counts requests and
 * answers with a configurable status. It is the CI path and the operator's
 * first run, so the mechanics are visible before a real endpoint is touched.
 */

import * as http from 'node:http';
import type { AddressInfo } from 'node:net';

export interface EchoOptions {
  /** HTTP status to answer with (default 200). 3xx adds a Location header. */
  status?: number;
}

export interface EchoServer {
  url: string;
  readonly requestCount: number;
  close(): Promise<void>;
}

export async function startEcho(opts: EchoOptions = {}): Promise<EchoServer> {
  const status = opts.status ?? 200;
  let requestCount = 0;

  const server = http.createServer((req, res) => {
    requestCount += 1;
    req.resume();
    req.on('end', () => {
      const body = JSON.stringify({ echoed: true });
      const headers: Record<string, string> = {
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(body)),
      };
      if (status >= 300 && status < 400) headers.location = '/elsewhere';
      res.writeHead(status, headers);
      res.end(body);
    });
  });

  await new Promise<void>((resolve, reject) => {
    server.once('error', reject);
    server.listen(0, '127.0.0.1', () => resolve());
  });
  const port = (server.address() as AddressInfo).port;

  return {
    url: `http://127.0.0.1:${port}/echo`,
    get requestCount() {
      return requestCount;
    },
    close: () => new Promise<void>((resolve) => server.close(() => resolve())),
  };
}
