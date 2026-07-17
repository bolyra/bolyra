/**
 * `bolyra mandate issue` — issues a delegated spend mandate and proves the
 * emitted presentation round-trips through the SAME @bolyra/mpp classical
 * verifier a payment gate runs (allow within tier; deny over tier, expired,
 * wrong-audience, tampered).
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { derivePublicKey } from '@bolyra/sdk';
import { verifyClassical, type OperatorKey, type VerifierRequest } from '@bolyra/mpp';

import { run } from '../src/commands/mandate-issue';

const OPERATOR_PRIV = 42n;
const AGENT = 'shopper-bot';
const AUDIENCE = 'api.merchant.example';
const MODEL = 'opus-4.1';
const FAR_FUTURE = 4102444800; // 2100-01-01
const NOW = 1751990400;

let tmpDir: string;
let keyFile: string;

async function trustedOperator(priv: bigint = OPERATOR_PRIV): Promise<OperatorKey> {
  const pub = await derivePublicKey(priv);
  return { x: pub.x.toString(), y: pub.y.toString() };
}

/** Silence + capture console.error; return a restore fn. */
function muteConsole(): { errors: string[]; restore: () => void } {
  const errors: string[] = [];
  const origError = console.error;
  console.error = (...args: unknown[]) => {
    errors.push(args.map(String).join(' '));
  };
  return {
    errors,
    restore() {
      console.error = origError;
    },
  };
}

/** Run the command writing the presentation to a temp file; return it. */
async function issueToFile(extraArgs: string[]): Promise<string> {
  const outFile = path.join(tmpDir, `mandate-${Math.random().toString(36).slice(2)}.txt`);
  const cap = muteConsole();
  try {
    await run(['--operator-key', keyFile, '--out', outFile, ...extraArgs]);
  } finally {
    cap.restore();
  }
  return fs.readFileSync(outFile, 'utf-8').trim();
}

function request(
  bundle: string,
  opts: { granted?: string[]; audience?: string; now?: number } = {},
): VerifierRequest {
  return {
    version: 1,
    bundle,
    request: {
      agent_name: AGENT,
      project_key: opts.audience ?? AUDIENCE,
      program: 'mpp',
      model: MODEL,
      granted_capabilities: opts.granted ?? ['mpp:financial:small'],
    },
    now_unix: opts.now ?? NOW,
  };
}

beforeAll(() => {
  tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-mandate-'));
  keyFile = path.join(tmpDir, 'operator.key');
  // 32-byte raw key = the scalar 42, matching OPERATOR_PRIV.
  fs.writeFileSync(keyFile, Buffer.from(OPERATOR_PRIV.toString(16).padStart(64, '0'), 'hex'), {
    mode: 0o600,
  });
});

afterAll(() => {
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

afterEach(() => {
  process.exitCode = undefined;
});

describe('bolyra mandate issue', () => {
  it('issues a small-tier mandate that verifies (allow) within tier', async () => {
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--tier',
      'small',
      '--expiry',
      String(FAR_FUTURE),
    ]);
    const verdict = await verifyClassical(request(presentation), [await trustedOperator()]);
    expect(verdict).toMatchObject({ verdict: 'allow' });
  });

  it('maps --max-usd to the covering tier (allow)', async () => {
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--max-usd',
      '5000',
      '--expiry',
      String(FAR_FUTURE),
    ]);
    // $5000 → medium tier; a $50 (small) charge is covered.
    const verdict = await verifyClassical(
      request(presentation, { granted: ['mpp:financial:small'] }),
      [await trustedOperator()],
    );
    expect(verdict).toMatchObject({ verdict: 'allow' });
  });

  it('denies an over-tier spend (small mandate, medium charge)', async () => {
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--tier',
      'small',
      '--expiry',
      String(FAR_FUTURE),
    ]);
    const verdict = await verifyClassical(
      request(presentation, { granted: ['mpp:financial:medium'] }),
      [await trustedOperator()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  it('denies an expired mandate', async () => {
    // Expiry must be in the future at ISSUANCE time (parseExpiry is future-only);
    // the gate then evaluates it against a clock at/after that expiry.
    const shortExpiry = Math.floor(Date.now() / 1000) + 3600;
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--tier',
      'small',
      '--expiry',
      String(shortExpiry),
    ]);
    const verdict = await verifyClassical(request(presentation, { now: shortExpiry }), [
      await trustedOperator(),
    ]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
  });

  it('denies a wrong-audience spend', async () => {
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--tier',
      'small',
      '--expiry',
      String(FAR_FUTURE),
    ]);
    const verdict = await verifyClassical(
      request(presentation, { audience: 'api.attacker.example' }),
      [await trustedOperator()],
    );
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
  });

  it('denies a tampered mandate signature', async () => {
    const presentation = await issueToFile([
      '--agent',
      AGENT,
      '--audience',
      AUDIENCE,
      '--model',
      MODEL,
      '--tier',
      'small',
      '--expiry',
      String(FAR_FUTURE),
      '--encoding',
      'json',
    ]);
    const obj = JSON.parse(presentation);
    obj.sig.S = (BigInt(obj.sig.S) + 1n).toString();
    const verdict = await verifyClassical(request(JSON.stringify(obj)), [await trustedOperator()]);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'invalid_signature' });
  });

  describe('fail-closed input handling', () => {
    it('exits 2 when a required flag is missing', async () => {
      const cap = muteConsole();
      try {
        await run(['--operator-key', keyFile, '--agent', AGENT, '--tier', 'small']);
      } finally {
        cap.restore();
      }
      expect(process.exitCode).toBe(2);
    });

    it('exits 2 when neither --tier nor --max-usd is given', async () => {
      const cap = muteConsole();
      try {
        await run([
          '--operator-key',
          keyFile,
          '--agent',
          AGENT,
          '--audience',
          AUDIENCE,
          '--model',
          MODEL,
          '--expiry',
          String(FAR_FUTURE),
        ]);
      } finally {
        cap.restore();
      }
      expect(process.exitCode).toBe(2);
    });

    it('exits 2 when BOTH --tier and --max-usd are given', async () => {
      const cap = muteConsole();
      try {
        await run([
          '--operator-key',
          keyFile,
          '--agent',
          AGENT,
          '--audience',
          AUDIENCE,
          '--model',
          MODEL,
          '--tier',
          'small',
          '--max-usd',
          '50',
          '--expiry',
          String(FAR_FUTURE),
        ]);
      } finally {
        cap.restore();
      }
      expect(process.exitCode).toBe(2);
    });

    it('exits non-zero on an invalid tier', async () => {
      const cap = muteConsole();
      try {
        await run([
          '--operator-key',
          keyFile,
          '--agent',
          AGENT,
          '--audience',
          AUDIENCE,
          '--model',
          MODEL,
          '--tier',
          'huge',
          '--expiry',
          String(FAR_FUTURE),
        ]);
      } finally {
        cap.restore();
      }
      // Invalid tier surfaces via issueMandate throwing → exit code 1.
      expect(process.exitCode).toBe(1);
    });

    it('exits 2 on a past expiry', async () => {
      const cap = muteConsole();
      try {
        await run([
          '--operator-key',
          keyFile,
          '--agent',
          AGENT,
          '--audience',
          AUDIENCE,
          '--model',
          MODEL,
          '--tier',
          'small',
          '--expiry',
          '1000',
        ]);
      } finally {
        cap.restore();
      }
      expect(process.exitCode).toBe(2);
    });

    it('shows help with --help', async () => {
      const origLog = console.log;
      const logs: string[] = [];
      console.log = (...a: unknown[]) => logs.push(a.map(String).join(' '));
      try {
        await run(['--help']);
      } finally {
        console.log = origLog;
      }
      expect(logs.join('\n')).toContain('bolyra mandate issue');
    });
  });
});
