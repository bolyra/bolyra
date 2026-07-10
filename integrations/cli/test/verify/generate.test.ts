/**
 * Drift guard for the committed `bolyra verify` golden fixtures (Task 15).
 *
 * THIS IS THE KEY CI PROOF: it verifies the committed golden `bvp/1` bundles
 * against the COMMITTED vkeys ONLY — it points `circuitsDir` at
 * `test/fixtures/verify/vkeys/` (the three small vkey JSONs that ARE tracked in
 * git) and NEVER touches `BOLYRA_CIRCUITS_DIR` / the gitignored
 * `circuits/build` proving artifacts. If this passes on a clean checkout, the
 * external verifier can validate real proofs on CI with no proving toolchain.
 *
 * To regenerate the goldens (after a circuit/vkey change) run the dev script:
 *   BOLYRA_CIRCUITS_DIR=<repo>/circuits/build npx tsx test/fixtures/verify/generate.ts
 *
 * Each golden is loaded as a full VerifierRequest (§2.1) from its `request.json`
 * and must return `verdict: 'allow'`. A FRESH temp FileNonceStore is used per
 * assertion so re-runs never trip nullifier replay.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { verify, type VerifierRequest, type VerifyFlags } from '../../src/verify/core';
import type { DenyCode } from '../../src/verify/verdict';
import { FileNonceStore } from '../../src/verify/nonce-store';

const FIXTURES = path.resolve(__dirname, '../fixtures/verify');
const VKEYS_DIR = path.join(FIXTURES, 'vkeys');
const ROOTS_FILE = path.join(FIXTURES, 'roots.json');
const CAP_MAP_FILE = path.join(FIXTURES, 'capability-map.json');

/** The committed allow goldens, each a directory with bundle.json + request.json. */
const ALLOW_GOLDENS = ['allow-agent-only', 'allow-human', 'allow-delegation-1hop'] as const;

/**
 * The committed deny goldens (Task 15b): each is a REAL proof that reaches — and
 * fails at — exactly one late §5 check, so the denial code is genuine (not a
 * cheaper upstream failure like `untrusted_root`). Both are verified against the
 * COMMITTED vkeys + roots.json + capability-map only, like the allow goldens.
 */
const DENY_GOLDENS: ReadonlyArray<readonly [dir: string, code: DenyCode]> = [
  ['deny-scope-exceeded', 'scope_exceeded'],
  ['deny-model-mismatch', 'model_mismatch'],
] as const;

/** Load a committed golden's VerifierRequest from its request.json. */
function loadRequest(goldenDir: string): VerifierRequest {
  const p = path.join(FIXTURES, goldenDir, 'request.json');
  return JSON.parse(fs.readFileSync(p, 'utf8')) as VerifierRequest;
}

/** A fresh, isolated temp FileNonceStore so re-runs never trip replay. */
function freshNonceStore(): FileNonceStore {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-drift-nonce-'));
  return new FileNonceStore(dir);
}

describe('verify golden drift guard (committed vkeys only — no circuits/build)', () => {
  jest.setTimeout(30000);

  it('the three committed vkeys exist and are tracked under fixtures/verify/vkeys', () => {
    for (const f of [
      'AgentPolicy_groth16_vkey.json',
      'Delegation_groth16_vkey.json',
      'HumanUniqueness_vkey.json',
    ]) {
      expect(fs.existsSync(path.join(VKEYS_DIR, f))).toBe(true);
    }
  });

  it('does NOT rely on BOLYRA_CIRCUITS_DIR (uses committed vkeys/)', () => {
    // The drift guard must never resolve proving artifacts from the environment;
    // its circuitsDir is the committed vkeys dir. This documents the invariant.
    expect(VKEYS_DIR).toContain(path.join('fixtures', 'verify', 'vkeys'));
  });

  for (const golden of ALLOW_GOLDENS) {
    it(`${golden} → allow (verified against committed vkeys)`, async () => {
      const request = loadRequest(golden);
      const flags: VerifyFlags = {
        circuitsDir: VKEYS_DIR,
        rootsFile: ROOTS_FILE,
        capabilityMapFile: CAP_MAP_FILE,
        nonceStore: freshNonceStore(),
      };
      const verdict = await verify(request, flags);
      expect(verdict.verdict).toBe('allow');
    });
  }

  for (const [golden, code] of DENY_GOLDENS) {
    it(`${golden} → deny ${code} (verified against committed vkeys)`, async () => {
      const request = loadRequest(golden);
      const flags: VerifyFlags = {
        circuitsDir: VKEYS_DIR,
        rootsFile: ROOTS_FILE,
        capabilityMapFile: CAP_MAP_FILE,
        nonceStore: freshNonceStore(),
      };
      const verdict = await verify(request, flags);
      expect(verdict.verdict).toBe('deny');
      // Narrow to DenyVerdict for the code assertion.
      if (verdict.verdict !== 'deny') throw new Error('expected a deny verdict');
      expect(verdict.code).toBe(code);
    });
  }
});
