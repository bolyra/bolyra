/**
 * Canonical-validator contract (Bolyra Core vs Bolyra ZK split, gateway side).
 *
 * 1. The gateway's cumulative-bit mask validation must BE the SDK's
 *    validateCumulativeBitEncoding — not a drifting local mirror. The mirror
 *    existed only because the gateway once allowed sdk >=0.5.0, and pre-0.6.1
 *    SDKs eagerly imported snarkjs at module load. With the floor at ^0.6.1
 *    (lazy snarkjs), the SDK import is safe and the SDK is the single source
 *    of truth for circuit-mask semantics.
 *
 * 2. That runtime SDK import must not break the Core guarantee: importing the
 *    gateway and running classical credential binding must NEVER load
 *    snarkjs (same contract as sdk/test/lazy-loading.test.ts).
 */

import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as path from 'path';
import { validateCumulativeBitEncoding } from '@bolyra/sdk';

/** The SDK's message for a mask, or null when the SDK accepts it. */
function sdkMaskError(mask: bigint): string | null {
  try {
    validateCumulativeBitEncoding(mask);
    return null;
  } catch (err) {
    return err instanceof Error ? err.message : String(err);
  }
}

describe('cumulativeMaskError delegates to the SDK canonical validator', () => {
  const { cumulativeMaskError } = require('../src/credential-binding');

  const INVALID_MASKS = [16n, 8n, 20n, 24n]; // bit4 alone, bit3 alone, 4+2, 4+3
  const VALID_MASKS = [0n, 1n, 3n, 4n, 12n, 28n, 31n, 255n];

  it.each(INVALID_MASKS.map((m) => [m.toString(), m] as const))(
    'returns the SDK error message verbatim for invalid mask %s',
    (_label, mask) => {
      const expected = sdkMaskError(mask);
      expect(expected).not.toBeNull(); // sanity: SDK rejects it
      expect(cumulativeMaskError(mask)).toBe(expected);
    },
  );

  it.each(VALID_MASKS.map((m) => [m.toString(), m] as const))(
    'returns null for cumulative-valid mask %s (SDK accepts it too)',
    (_label, mask) => {
      expect(sdkMaskError(mask)).toBeNull();
      expect(cumulativeMaskError(mask)).toBeNull();
    },
  );
});

describe('installed tree carries no pre-0.6.1 @bolyra/sdk (nested copies bypass the floor)', () => {
  // npm nests a second @bolyra/sdk under any dependency whose declared range
  // excludes the top-level version (e.g. @bolyra/mcp <=0.6.3 declares ^0.5.0).
  // @bolyra/mcp's verifyBundle resolves '@bolyra/sdk' relative to ITSELF, so a
  // nested pre-lazy-ZK copy sits on the production verification path no
  // matter what the gateway's own floor says (Codex P2). Scan every
  // node_modules level for @bolyra/sdk and require >=0.6.1 everywhere.
  it('every resolved @bolyra/sdk in node_modules is >=0.6.1', () => {
    const root = path.join(__dirname, '..', 'node_modules');
    const found: Array<{ at: string; version: string }> = [];
    const visit = (nmDir: string) => {
      if (!fs.existsSync(nmDir)) return;
      for (const scope of fs.readdirSync(nmDir)) {
        if (scope.startsWith('.')) continue;
        const pkgs = scope.startsWith('@')
          ? fs.readdirSync(path.join(nmDir, scope)).map((p) => path.join(scope, p))
          : [scope];
        for (const pkg of pkgs) {
          const pkgDir = path.join(nmDir, pkg);
          if (pkg === path.join('@bolyra', 'sdk')) {
            const manifest = JSON.parse(
              fs.readFileSync(path.join(pkgDir, 'package.json'), 'utf8'),
            );
            found.push({ at: pkgDir, version: manifest.version });
          }
          visit(path.join(pkgDir, 'node_modules'));
        }
      }
    };
    visit(root);
    expect(found.length).toBeGreaterThan(0);
    const [major, minor, patch] = [0, 6, 1];
    for (const { at, version } of found) {
      const [M, m, p] = version.split('.').map(Number);
      const ok = M > major || (M === major && (m > minor || (m === minor && p >= patch)));
      if (!ok) {
        throw new Error(`pre-0.6.1 @bolyra/sdk@${version} installed at ${at}`);
      }
    }
  });
});

describe('gateway Core path never loads snarkjs (spawned node child, resolution blocked, built dist)', () => {
  const gatewayRoot = path.join(__dirname, '..');
  const distBinding = path.join(gatewayRoot, 'dist/credential-binding.js');

  // The guarantee must hold for the EMITTED package + the @bolyra/sdk that
  // npm actually resolved from node_modules (jest's moduleNameMapper points
  // at local sdk source, which would mask a bad installed floor). Build
  // dist/ on demand so this runs in CI too.
  beforeAll(() => {
    if (!fs.existsSync(distBinding)) {
      execFileSync(
        process.execPath,
        [path.join(gatewayRoot, 'node_modules', 'typescript', 'bin', 'tsc')],
        { cwd: gatewayRoot, timeout: 120_000 },
      );
    }
  }, 130_000);

  it(
    'runs cumulativeMaskError + checkCredentialBinding from dist with snarkjs unresolvable',
    () => {
      const script = `
        const Module = require('module');
        const origLoad = Module._load;
        Module._load = function (request) {
          if (request === 'snarkjs' || request.startsWith('snarkjs/')) {
            throw new Error('BLOCKED: snarkjs resolution attempted on the gateway Core path');
          }
          return origLoad.apply(this, arguments);
        };
        const binding = require(${JSON.stringify(distBinding)});
        const err = binding.cumulativeMaskError(16n);
        if (!/FINANCIAL_UNLIMITED/.test(String(err))) {
          throw new Error('expected SDK cumulative-bit error, got: ' + err);
        }
        if (binding.cumulativeMaskError(28n) !== null) {
          throw new Error('valid cumulative mask 28 was rejected');
        }
        const registry = new Map([['12345', { permissionBitmask: 3n }]]);
        const bundle = {
          credentialCommitment: '12345',
          agentProof: { proof: {}, publicSignals: ['0', '0', '0', '3'] },
        };
        const result = binding.checkCredentialBinding(bundle, { permissionBitmask: 3n }, registry);
        if (!result.ok) {
          throw new Error('classical binding failed: ' + result.reasonCode);
        }
        // The FULL gateway entry must also stay snarkjs-free — it pulls in
        // @bolyra/mcp, whose own require('@bolyra/sdk') resolves NESTED
        // node_modules first. A nested pre-0.6.1 sdk under @bolyra/mcp
        // (npm nests one when mcp's declared range excludes 0.6.1) would
        // eagerly load snarkjs here despite the top-level floor (Codex P2).
        const gateway = require(${JSON.stringify(path.join(gatewayRoot, 'dist/index.js'))});
        if (typeof gateway.createStaticCredentialResolver !== 'function') {
          throw new Error('gateway entry missing expected export');
        }
        console.log('GATEWAY_CORE_OK_WITHOUT_SNARKJS');
      `;
      const out = execFileSync(process.execPath, ['-e', script], {
        cwd: gatewayRoot,
        encoding: 'utf8',
        timeout: 60_000,
      });
      expect(out).toContain('GATEWAY_CORE_OK_WITHOUT_SNARKJS');
    },
    70_000,
  );
});
