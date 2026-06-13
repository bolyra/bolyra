import { execSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { signReceipt } from '../src/sign';
import { createAuthReceipt } from '../src/receipt';
import type { AuthReceiptInput, ReceiptSignerConfig } from '../src/types';

const TEST_PRIVATE_KEY = '0x' + '01'.repeat(32);
const TEST_CONFIG: ReceiptSignerConfig = {
  issuer: 'test-server',
  keyId: 'key-1',
  privateKey: TEST_PRIVATE_KEY,
};

// Use tsx to run the TypeScript source directly, avoiding dependency on untracked dist/
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

function writeTempReceipt(data: unknown): string {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-'));
  const tmpFile = path.join(tmpDir, 'receipt.json');
  fs.writeFileSync(tmpFile, JSON.stringify(data, null, 2));
  return tmpFile;
}

function runCli(args: string): { stdout: string; exitCode: number } {
  try {
    const stdout = execSync(`npx tsx ${CLI_PATH} ${args}`, {
      encoding: 'utf-8',
      timeout: 10_000,
    });
    return { stdout, exitCode: 0 };
  } catch (err: unknown) {
    const e = err as { stdout?: string; stderr?: string; status?: number };
    return {
      stdout: (e.stdout ?? '') + (e.stderr ?? ''),
      exitCode: e.status ?? 1,
    };
  }
}

describe('verify-cli', () => {
  let validReceipt: ReturnType<typeof signReceipt>;

  beforeAll(() => {
    const payload = createAuthReceipt(makeInput(), {
      issuer: TEST_CONFIG.issuer,
      keyId: TEST_CONFIG.keyId,
    });
    validReceipt = signReceipt(payload, TEST_CONFIG);
  });

  it('validates a correct receipt (exit 0, PASS)', () => {
    const tmpFile = writeTempReceipt(validReceipt);
    const { stdout, exitCode } = runCli(tmpFile);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('PASS');
    expect(stdout).toContain('Schema valid');
    expect(stdout).toContain('Payload hash matches');
    expect(stdout).toContain('Receipt ID matches');
    expect(stdout).toContain('Signature valid');

    fs.rmSync(path.dirname(tmpFile), { recursive: true });
  });

  it('validates with --signer matching signer address', () => {
    const tmpFile = writeTempReceipt(validReceipt);
    const { stdout, exitCode } = runCli(`${tmpFile} --signer ${validReceipt.signature.signer}`);

    expect(exitCode).toBe(0);
    expect(stdout).toContain('PASS');

    fs.rmSync(path.dirname(tmpFile), { recursive: true });
  });

  it('rejects with wrong --signer (exit 1, FAIL)', () => {
    const wrongSigner = '0x' + '00'.repeat(20);
    const tmpFile = writeTempReceipt(validReceipt);
    const { stdout, exitCode } = runCli(`${tmpFile} --signer ${wrongSigner}`);

    expect(exitCode).toBe(1);
    expect(stdout).toContain('FAIL');

    fs.rmSync(path.dirname(tmpFile), { recursive: true });
  });

  it('rejects tampered payload (exit 1, FAIL)', () => {
    const tampered = JSON.parse(JSON.stringify(validReceipt));
    tampered.payload.decision.score = 0;

    const tmpFile = writeTempReceipt(tampered);
    const { stdout, exitCode } = runCli(tmpFile);

    expect(exitCode).toBe(1);
    expect(stdout).toContain('FAIL');
    expect(stdout).toContain('Payload hash mismatch');

    fs.rmSync(path.dirname(tmpFile), { recursive: true });
  });

  it('rejects invalid JSON (exit 2)', () => {
    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-'));
    const tmpFile = path.join(tmpDir, 'bad.json');
    fs.writeFileSync(tmpFile, 'not json');

    const { exitCode } = runCli(tmpFile);
    expect(exitCode).toBe(2);

    fs.rmSync(tmpDir, { recursive: true });
  });

  it('supports --stdin', () => {
    const json = JSON.stringify(validReceipt);
    try {
      const stdout = execSync(`echo '${json.replace(/'/g, "'\\''")}' | npx tsx ${CLI_PATH} --stdin`, {
        encoding: 'utf-8',
        shell: '/bin/bash',
        timeout: 10_000,
      });
      expect(stdout).toContain('PASS');
    } catch (err: unknown) {
      const e = err as { stdout?: string; status?: number };
      // Should not reach here for valid receipt
      fail(`Expected exit 0 but got ${e.status}: ${e.stdout}`);
    }
  });

  it('shows help with --help (exit 0)', () => {
    const { stdout, exitCode } = runCli('--help');
    expect(exitCode).toBe(0);
    expect(stdout).toContain('Usage:');
    expect(stdout).toContain('--signer');
    expect(stdout).toContain('--max-age');
  });
});
