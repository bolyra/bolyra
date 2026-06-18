/**
 * @bolyra/gateway — receipt writer.
 *
 * Async, non-blocking receipt output with three modes:
 * - file: day-rotated subdirectories
 * - stdout: NDJSON to process.stdout
 * - webhook: HTTP POST to configured URL
 */

import * as fs from 'fs';
import * as path from 'path';
import * as http from 'http';
import * as https from 'https';
import type { ReceiptOutputConfig, ReceiptWriter } from './types';
import type { SignedReceipt } from '@bolyra/receipts';

/**
 * Create a receipt writer based on config.
 * All write operations are fire-and-forget — they never throw or block.
 */
export function createReceiptWriter(config: ReceiptOutputConfig): ReceiptWriter {
  if (!config.enabled) {
    return { write: () => {}, writeRaw: () => {} };
  }

  switch (config.output) {
    case 'file':
      return createFileWriter(config.dir ?? './receipts/');
    case 'stdout':
      return createStdoutWriter();
    case 'webhook':
      return createWebhookWriter(config.webhook!);
    default:
      return { write: () => {}, writeRaw: () => {} };
  }
}

/** File writer: day-rotated subdirectories. */
function createFileWriter(baseDir: string): ReceiptWriter {
  function writeToFile(data: Record<string, unknown>): void {
    try {
      const now = new Date();
      const dateDir = now.toISOString().split('T')[0]; // YYYY-MM-DD
      const timestamp = now.toISOString().replace(/[:.]/g, '-');
      const receiptId = (data as { receiptId?: string }).receiptId ??
        (data as { payload?: { receiptId?: string } }).payload?.receiptId ??
        `unknown-${Date.now()}`;
      const dir = path.join(baseDir, dateDir);
      fs.mkdirSync(dir, { recursive: true });
      const filePath = path.join(dir, `${timestamp}-${receiptId}.json`);
      fs.writeFileSync(filePath, JSON.stringify(data, bigintReplacer, 2) + '\n');
    } catch (err) {
      // Never throw — log and continue
      console.error('[gateway] receipt file write error:', (err as Error).message);
    }
  }

  return {
    write(receipt: SignedReceipt): void {
      // Fire and forget — schedule for next tick to avoid blocking
      setImmediate(() => writeToFile(receipt as unknown as Record<string, unknown>));
    },
    writeRaw(data: Record<string, unknown>): void {
      setImmediate(() => writeToFile(data));
    },
  };
}

/** Stdout writer: NDJSON format. */
function createStdoutWriter(): ReceiptWriter {
  return {
    write(receipt: SignedReceipt): void {
      try {
        process.stdout.write(JSON.stringify(receipt, bigintReplacer) + '\n');
      } catch (err) {
        console.error('[gateway] receipt stdout write error:', (err as Error).message);
      }
    },
    writeRaw(data: Record<string, unknown>): void {
      try {
        process.stdout.write(JSON.stringify(data, bigintReplacer) + '\n');
      } catch (err) {
        console.error('[gateway] receipt stdout write error:', (err as Error).message);
      }
    },
  };
}

/** Webhook writer: HTTP POST. */
function createWebhookWriter(webhook: { url: string; headers?: Record<string, string> }): ReceiptWriter {
  function postReceipt(data: Record<string, unknown>): void {
    try {
      const url = new URL(webhook.url);
      const body = JSON.stringify(data, bigintReplacer);
      const isHttps = url.protocol === 'https:';
      const reqFn = isHttps ? https.request : http.request;

      const req = reqFn(
        {
          hostname: url.hostname,
          port: url.port || (isHttps ? 443 : 80),
          path: url.pathname + url.search,
          method: 'POST',
          headers: {
            'Content-Type': 'application/json',
            'Content-Length': Buffer.byteLength(body),
            ...webhook.headers,
          },
        },
        (res) => {
          // Consume response to free resources
          res.resume();
        },
      );

      req.on('error', (err) => {
        console.error('[gateway] receipt webhook error:', err.message);
      });

      req.write(body);
      req.end();
    } catch (err) {
      console.error('[gateway] receipt webhook error:', (err as Error).message);
    }
  }

  return {
    write(receipt: SignedReceipt): void {
      setImmediate(() => postReceipt(receipt as unknown as Record<string, unknown>));
    },
    writeRaw(data: Record<string, unknown>): void {
      setImmediate(() => postReceipt(data));
    },
  };
}

/** JSON.stringify replacer that converts bigints to decimal strings. */
function bigintReplacer(_key: string, value: unknown): unknown {
  return typeof value === 'bigint' ? value.toString() : value;
}
