import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { signReceipt } from '../src/sign';
import { createAuthReceipt } from '../src/receipt';
import type { AuthReceiptInput, ReceiptSignerConfig } from '../src/types';

// The CLI reads receipt TEXT, so these cases are written as text: JSON.parse
// turns `{"__proto__": ...}` into an own key, `1e400` into Infinity and `-0`
// into negative zero. None of them has a canonical form, and the CLI must
// report that as an ordinary failed check.

const CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: '0x' + '01'.repeat(32),
};

const CLI_PATH = path.resolve(__dirname, '..', 'src', 'verify-cli.ts');

function makeInput(): AuthReceiptInput {
  return {
    rootDid: 'did:bolyra:root123',
    actingDid: 'did:bolyra:agent456',
    credentialCommitment: '0xabc',
    effectiveCommitment: '0xdef',
    allowed: true,
    score: 95,
    permissionBitmask: '255',
    chainDepth: 0,
    humanProof: { proof: { pi_a: [1, 2], pi_b: [[3, 4], [5, 6]], pi_c: [7, 8] } },
    agentProof: { proof: { pi_a: [9, 10], pi_b: [[11, 12], [13, 14]], pi_c: [15, 16] } },
    humanPublicSignals: ['111', '222'],
    agentPublicSignals: ['333', '444'],
    bundleVersion: 1,
    nonce: '12345',
  };
}

function runCliOnText(text: string): { output: string; exitCode: number } {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-'));
  const file = path.join(dir, 'receipt.json');
  fs.writeFileSync(file, text);
  try {
    const stdout = execSync(`npx tsx ${CLI_PATH} ${file}`, {
      encoding: 'utf-8',
      timeout: 10_000,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    return { output: stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return { output: (e.stdout ?? '') + (e.stderr ?? ''), exitCode: e.status ?? 1 };
  } finally {
    fs.rmSync(dir, { recursive: true });
  }
}

function replaceOnce(text: string, from: string, to: string): string {
  const at = text.indexOf(from);
  if (at === -1 || text.indexOf(from, at + 1) !== -1) {
    throw new Error(`expected exactly one ${JSON.stringify(from)} in the receipt text`);
  }
  return text.slice(0, at) + to + text.slice(at + from.length);
}

describe('verify-cli: receipt text with no canonical form', () => {
  let text: string;

  beforeAll(() => {
    const payload = createAuthReceipt(makeInput(), { issuer: CONFIG.issuer, keyId: CONFIG.keyId });
    text = JSON.stringify(signReceipt(payload, CONFIG));
  });

  it('control: the unaltered text passes', () => {
    const { output, exitCode } = runCliOnText(text);
    expect(exitCode).toBe(0);
    expect(output).toContain('PASS');
  });

  const cases: Array<[string, (t: string) => string]> = [
    ['an own "__proto__" key in the payload', (t) => replaceOnce(t, '"payload":{', '"payload":{"__proto__":{"note":"added"},')],
    ['a number that overflows to Infinity', (t) => replaceOnce(t, '"score":95', '"score":1e400')],
    ['a negative zero', (t) => replaceOnce(t, '"chainDepth":0', '"chainDepth":-0')],
  ];

  it.each(cases)('%s is an ordinary FAIL, exit 1, no uncaught error', (_name, alter) => {
    const { output, exitCode } = runCliOnText(alter(text));
    expect(exitCode).toBe(1);
    expect(output).toContain('FAIL');
    expect(output).toContain('Payload cannot be canonicalized');
    expect(output).not.toMatch(/\b\w*Error\b/);
    expect(output).not.toMatch(/^\s+at /m);
  });

  // The timestamp check formats the date before the hash check runs, so a
  // timestamp that no Date can hold must be an ordinary failed check as well.
  const timestamps: Array<[string, string, boolean]> = [
    ['1e400', 'overflows to Infinity', true],
    ['-1e400', 'overflows to -Infinity', true],
    ['1e300', 'is finite but beyond any date', false],
  ];

  it.each(timestamps)('issuedAt %s (%s) is an ordinary FAIL, exit 1, no uncaught error', (value, _why, noCanonicalForm) => {
    const altered = text.replace(/"issuedAt":\d+/, `"issuedAt":${value}`);
    expect(altered).not.toBe(text);
    const { output, exitCode } = runCliOnText(altered);
    expect(exitCode).toBe(1);
    expect(output).toContain('FAIL');
    expect(output).toContain('Timestamp is outside the supported date range');
    // The hash check still runs after the timestamp check.
    expect(output).toContain(noCanonicalForm ? 'Payload cannot be canonicalized' : 'Payload hash mismatch');
    expect(output).not.toMatch(/\b\w*Error\b/);
    expect(output).not.toMatch(/^\s+at /m);
  });

  // Found by substituting every member of a valid receipt with other JSON
  // values: shapes the schema check did not expect must fail the same way.
  const malformed: Array<[string, (t: string) => string]> = [
    ['the text `null`', () => 'null'],
    ['a number', () => '7'],
    ['a string where payload.proof should be an object', (t) => t.replace(/"proof":\{[^}]*\}/, '"proof":"x"')],
    ['a number where payload.proof should be an object', (t) => t.replace(/"proof":\{[^}]*\}/, '"proof":1e400')],
  ];

  it.each(malformed)('%s is an ordinary FAIL, exit 1, no uncaught error', (_name, alter) => {
    const altered = alter(text);
    expect(altered).not.toBe(text);
    const { output, exitCode } = runCliOnText(altered);
    expect(exitCode).toBe(1);
    expect(output).toContain('FAIL');
    expect(output).toContain('Schema:');
    expect(output).not.toMatch(/\b\w*Error\b/);
    expect(output).not.toMatch(/^\s+at /m);
  });

  // An object that cannot be turned into a string (its own `toString` and
  // `valueOf` members are not functions) must not reach a regular expression
  // test or a message template.
  const UNPRINTABLE = '{"toString":null,"valueOf":null}';
  const unprintable: Array<[string, RegExp]> = [
    ['id', /"id":"[^"]*"/],
    ['signature.signer', /"signer":"[^"]*"/],
    ['signature.payloadHash', /"payloadHash":"[^"]*"/],
    ['signature.value', /"value":"[^"]*"/],
    ['signature.keyId', /"keyId":"[^"]*"(?=[^}]*"signer")|(?<="signature":\{[^}]*)"keyId":"[^"]*"/],
  ];

  it.each(unprintable)('an unprintable object as %s is an ordinary FAIL, exit 1, no uncaught error', (name, pattern) => {
    const key = name.split('.').pop() as string;
    for (const value of [UNPRINTABLE, `[${UNPRINTABLE}]`]) {
      const altered = text.replace(pattern, `"${key}":${value}`);
      expect(altered).not.toBe(text);
      expect(() => JSON.parse(altered)).not.toThrow();
      const { output, exitCode } = runCliOnText(altered);
      expect(exitCode).toBe(1);
      expect(output).toContain('FAIL');
      expect(output).not.toMatch(/\b\w*Error\b/);
      expect(output).not.toMatch(/^\s+at /m);
    }
  });
});
