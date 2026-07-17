/**
 * Smoke test for the `npx @bolyra/mpp demo` entry point: run the demo
 * programmatically and assert the six narrated outcomes appear, in order —
 * then run the BUILT bin the way npx does, so a wrong `bin` path, a missing
 * dist file, or broken argv dispatch fails here and not on a visitor.
 */

import { execFileSync, spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as path from 'node:path';
import { runDemo } from '../src/demo/cli';

jest.setTimeout(120_000);

const PKG_ROOT = path.join(__dirname, '..');

describe('npx demo (smoke)', () => {
  it('narrates the six outcomes end-to-end', async () => {
    const lines: string[] = [];
    await runDemo((line) => lines.push(line));
    const out = lines.join('\n');

    // (1) Operator issues a spend mandate via the package's own issueMandate.
    expect(out).toMatch(/\[1\/6\][^\n]*issues a spend mandate/);
    expect(out).toContain('tier=small');

    // (2) The route is gated by bolyraGate (stub transport, real gate).
    expect(out).toMatch(/\[2\/6\][^\n]*bolyraGate/);
    expect(out).toContain('stub');

    // (3) $25 with the mandate ALLOWS — within the small tier.
    expect(out).toMatch(/\[3\/6\][^\n]*\$25[\s\S]*?HTTP 200 ALLOW/);

    // (4) $500 with the same mandate DENIES with the RFC 9457 problem body,
    //     before any payment logic runs.
    expect(out).toMatch(/\[4\/6\][^\n]*\$500[\s\S]*?HTTP 403 DENY/);
    expect(out).toContain('"code": "request_mismatch"');
    expect(out).toContain('application/problem+json');
    expect(out).toContain('stub payment method ran 0 times');

    // (5) No mandate at all DENIES — fail closed, no 402 challenge issued.
    expect(out).toMatch(/\[5\/6\][^\n]*NO mandate[\s\S]*?HTTP 401 DENY/);
    expect(out).toContain('"code": "missing_authorization"');

    // (6) The signed authorization receipt is printed and its ES256K
    //     signature verifies.
    expect(out).toMatch(/\[6\/6\][^\n]*receipt/);
    expect(out).toContain('signature verified: true');

    // The six steps appear in order.
    const positions = [1, 2, 3, 4, 5, 6].map((n) => out.indexOf(`[${n}/6]`));
    expect(positions.every((p) => p >= 0)).toBe(true);
    expect([...positions].sort((a, b) => a - b)).toEqual(positions);
  });
});

describe('built bin (the file npx actually runs)', () => {
  // package.json's single bin is what `npx @bolyra/mpp` resolves; run THAT
  // file, not the TS source. Build once if dist/ is missing or stale.
  const binRelative = (require('../package.json') as { bin: Record<string, string> }).bin[
    'bolyra-mpp'
  ];
  const binPath = path.join(PKG_ROOT, binRelative);

  beforeAll(() => {
    const srcPath = path.join(PKG_ROOT, 'src', 'demo', 'cli.ts');
    const stale =
      !fs.existsSync(binPath) || fs.statSync(binPath).mtimeMs < fs.statSync(srcPath).mtimeMs;
    if (stale) {
      execFileSync('npx', ['tsc'], { cwd: PKG_ROOT, stdio: 'inherit' });
    }
  });

  it('declares exactly one bin, pointing at an existing built file', () => {
    const bin = (require('../package.json') as { bin: Record<string, string> }).bin;
    expect(Object.keys(bin)).toEqual(['bolyra-mpp']);
    expect(fs.existsSync(binPath)).toBe(true);
    expect(fs.readFileSync(binPath, 'utf8').startsWith('#!/usr/bin/env node')).toBe(true);
  });

  it('`demo` runs the full narrated flow and exits 0', () => {
    const result = spawnSync(process.execPath, [binPath, 'demo'], { encoding: 'utf8' });
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('[6/6]');
    expect(result.stdout).toContain('signature verified: true');
  });

  it('an unknown command errors with usage and exits 1', () => {
    const result = spawnSync(process.execPath, [binPath, 'bogus'], { encoding: 'utf8' });
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('unknown command');
    expect(result.stderr).toContain('Usage: npx @bolyra/mpp demo');
  });
});
