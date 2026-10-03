import * as fs from 'node:fs';
import * as path from 'node:path';

/** Walk upward from `from` until a package.json is found (works from src/ and dist/src/). */
export function pkgRoot(from: string): string {
  let dir = from;
  for (;;) {
    if (fs.existsSync(path.join(dir, 'package.json'))) return dir;
    const parent = path.dirname(dir);
    if (parent === dir) throw new Error('package.json not found above ' + from);
    dir = parent;
  }
}

export const ROOT = pkgRoot(__dirname);
export const FIXTURES_DIR = path.join(ROOT, 'fixtures');
export const VKEYS_DIR = path.join(FIXTURES_DIR, 'vkeys');
export const ROOTS_PATH = path.join(FIXTURES_DIR, 'roots.json');
export const GOLDEN_REQUEST_PATH = path.join(FIXTURES_DIR, 'allow-agent-only.request.json');
export const CAPABILITY_MAP_PATH = path.join(ROOT, 'capability-map.json');
/** The CLI's own verify fixtures; our copies are asserted byte-equal to these (test/fixtures.test.ts). */
export const CLI_FIXTURES_DIR = path.resolve(ROOT, '..', '..', 'integrations', 'cli', 'test', 'fixtures', 'verify');

/** The five files copied from the CLI fixtures: [our path, their path]. */
export const COPIED_FIXTURES: Array<[string, string]> = [
  ['vkeys/AgentPolicy_groth16_vkey.json', 'vkeys/AgentPolicy_groth16_vkey.json'],
  ['vkeys/Delegation_groth16_vkey.json', 'vkeys/Delegation_groth16_vkey.json'],
  ['vkeys/HumanUniqueness_vkey.json', 'vkeys/HumanUniqueness_vkey.json'],
  ['roots.json', 'roots.json'],
  ['allow-agent-only.request.json', 'allow-agent-only/request.json'],
];

export interface CommandSpec { command: string; args: string[]; timeoutMs: number }

/**
 * The published verifier: `@bolyra/cli` (devDependency) run as `node <main.js> verify …`.
 * `bolyra verify` re-spawns itself with process.execPath + argv[1], so argv[1] must be the real
 * entry file, not the .bin shim. The CLI worker has its own 10 s watchdog; `timeoutMs` here is
 * the host-side bound and does not extend it.
 */
export function verifierSpec(): CommandSpec {
  const cliMain = path.join(path.dirname(require.resolve('@bolyra/cli/package.json')), 'dist', 'main.js');
  return {
    command: process.execPath,
    args: [cliMain, 'verify', '--circuits-dir', VKEYS_DIR, '--roots-file', ROOTS_PATH, '--capability-map', CAPABILITY_MAP_PATH, '--nonce-mode', 'local'],
    timeoutMs: 30_000,
  };
}
