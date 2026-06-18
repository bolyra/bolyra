import * as fs from 'fs';
import * as path from 'path';
import * as os from 'os';
import * as http from 'http';
import { createReceiptWriter } from '../src/receipts';
import type { ReceiptOutputConfig } from '../src/types';

// Minimal SignedReceipt mock
const mockReceipt = {
  payload: {
    receiptId: 'test-receipt-123',
    iss: 'test-gateway',
    iat: 1718700000,
    decision: 'allow',
    rootDid: 'did:bolyra:dev:abc',
    actingDid: 'did:bolyra:dev:abc',
    score: 90,
    permissionBitmask: '3',
  },
  signature: 'deadbeef',
  keyId: 'k1',
};

describe('receipt writer', () => {
  describe('disabled', () => {
    it('write does nothing when disabled', () => {
      const config: ReceiptOutputConfig = { enabled: false, output: 'file' };
      const writer = createReceiptWriter(config);
      // Should not throw
      writer.write(mockReceipt as any);
      writer.writeRaw({ test: true });
    });
  });

  describe('file mode', () => {
    let tmpDir: string;

    beforeEach(() => {
      tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'gateway-receipts-'));
    });

    afterEach(() => {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    });

    it('writes receipt to day-rotated directory', (done) => {
      const config: ReceiptOutputConfig = {
        enabled: true,
        output: 'file',
        dir: tmpDir,
      };
      const writer = createReceiptWriter(config);
      writer.write(mockReceipt as any);

      // Give setImmediate time to execute
      setTimeout(() => {
        const today = new Date().toISOString().split('T')[0];
        const dayDir = path.join(tmpDir, today);
        expect(fs.existsSync(dayDir)).toBe(true);

        const files = fs.readdirSync(dayDir);
        expect(files.length).toBe(1);
        expect(files[0]).toContain('test-receipt-123');
        expect(files[0]).toEndWith('.json');

        const content = JSON.parse(fs.readFileSync(path.join(dayDir, files[0]), 'utf-8'));
        expect(content.payload.receiptId).toBe('test-receipt-123');
        done();
      }, 50);
    });

    it('writeRaw writes arbitrary data', (done) => {
      const config: ReceiptOutputConfig = {
        enabled: true,
        output: 'file',
        dir: tmpDir,
      };
      const writer = createReceiptWriter(config);
      writer.writeRaw({ receiptId: 'raw-receipt', decision: 'deny', reason: 'test' });

      setTimeout(() => {
        const today = new Date().toISOString().split('T')[0];
        const dayDir = path.join(tmpDir, today);
        const files = fs.readdirSync(dayDir);
        expect(files.length).toBe(1);
        expect(files[0]).toContain('raw-receipt');
        done();
      }, 50);
    });
  });

  describe('stdout mode', () => {
    it('writes NDJSON to stdout', () => {
      const config: ReceiptOutputConfig = { enabled: true, output: 'stdout' };
      const writer = createReceiptWriter(config);

      const chunks: string[] = [];
      const originalWrite = process.stdout.write;
      process.stdout.write = ((data: string) => {
        chunks.push(data);
        return true;
      }) as typeof process.stdout.write;

      writer.write(mockReceipt as any);

      process.stdout.write = originalWrite;

      expect(chunks.length).toBe(1);
      expect(chunks[0]).toEndWith('\n');
      const parsed = JSON.parse(chunks[0]);
      expect(parsed.payload.receiptId).toBe('test-receipt-123');
    });
  });

  describe('webhook mode', () => {
    let server: http.Server;
    let receivedBodies: string[];
    let serverPort: number;

    beforeEach((done) => {
      receivedBodies = [];
      server = http.createServer((req, res) => {
        let body = '';
        req.on('data', (chunk) => { body += chunk; });
        req.on('end', () => {
          receivedBodies.push(body);
          res.writeHead(200);
          res.end();
        });
      });
      server.listen(0, () => {
        serverPort = (server.address() as any).port;
        done();
      });
    });

    afterEach((done) => {
      server.close(done);
    });

    it('POSTs receipt to webhook URL', (done) => {
      const config: ReceiptOutputConfig = {
        enabled: true,
        output: 'webhook',
        webhook: {
          url: `http://localhost:${serverPort}/receipts`,
          headers: { 'X-Custom': 'test' },
        },
      };
      const writer = createReceiptWriter(config);
      writer.write(mockReceipt as any);

      setTimeout(() => {
        expect(receivedBodies.length).toBe(1);
        const parsed = JSON.parse(receivedBodies[0]);
        expect(parsed.payload.receiptId).toBe('test-receipt-123');
        done();
      }, 100);
    });
  });
});

// Jest matcher extension for toEndWith
expect.extend({
  toEndWith(received: string, expected: string) {
    const pass = received.endsWith(expected);
    return {
      pass,
      message: () => `expected "${received}" to ${pass ? 'not ' : ''}end with "${expected}"`,
    };
  },
});

declare global {
  namespace jest {
    interface Matchers<R> {
      toEndWith(expected: string): R;
    }
  }
}
