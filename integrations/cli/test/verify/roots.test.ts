import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  loadRootSource,
  isTrusted,
  assertTrusted,
  type RootSource,
} from '../../src/verify/roots';
import { VerifyDenial } from '../../src/verify/verdict';

// Decimal field-element strings, as roots are on the wire.
const AGENT_ROOT = '111111111111111111111111';
const HUMAN_ROOT = '222222222222222222222222';
const OTHER_ROOT = '999999999999999999999999';

/** Write a roots-file into a fresh tmp dir and return its path. */
function writeRootsFile(name: string, contents: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-roots-'));
  const file = path.join(dir, name);
  fs.writeFileSync(file, JSON.stringify(contents), 'utf8');
  return file;
}

describe('loadRootSource + namespaced roots-file', () => {
  it('trusts an agent root from a namespaced file (isTrusted true, assertTrusted no throw)', () => {
    const file = writeRootsFile('roots.json', { agent: [AGENT_ROOT] });
    const source = loadRootSource({ rootsFile: file, env: {} });

    expect(source.unconfigured).toBe(false);
    expect(isTrusted(source, AGENT_ROOT, 'agent')).toBe(true);
    expect(() => assertTrusted(source, AGENT_ROOT, 'agent')).not.toThrow();
  });

  it('denies an unknown root with untrusted_root', () => {
    const file = writeRootsFile('roots.json', { agent: [AGENT_ROOT] });
    const source = loadRootSource({ rootsFile: file, env: {} });

    expect(isTrusted(source, OTHER_ROOT, 'agent')).toBe(false);
    expect(() => assertTrusted(source, OTHER_ROOT, 'agent')).toThrow(VerifyDenial);
    try {
      assertTrusted(source, OTHER_ROOT, 'agent');
      throw new Error('expected assertTrusted to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      const denial = err as VerifyDenial;
      expect(denial.code).toBe('untrusted_root');
      expect(denial.detail).toEqual({ root: OTHER_ROOT, tree: 'agent' });
    }
  });

  it('trusts a human root, but an agent-only root is NOT trusted as delegatee', () => {
    const file = writeRootsFile('roots.json', {
      agent: [AGENT_ROOT],
      human: [HUMAN_ROOT],
    });
    const source = loadRootSource({ rootsFile: file, env: {} });

    // Human namespaced root passes for its own tree.
    expect(isTrusted(source, HUMAN_ROOT, 'human')).toBe(true);
    expect(() => assertTrusted(source, HUMAN_ROOT, 'human')).not.toThrow();

    // Namespacing is strict: an agent-only root does not leak into other trees.
    expect(isTrusted(source, AGENT_ROOT, 'delegatee')).toBe(false);
    expect(isTrusted(source, AGENT_ROOT, 'human')).toBe(false);
    expect(() => assertTrusted(source, AGENT_ROOT, 'delegatee')).toThrow(VerifyDenial);
  });
});

describe('flat-array roots-file', () => {
  it('trusts a flat-array root for ANY tree', () => {
    const file = writeRootsFile('roots.json', [AGENT_ROOT]);
    const source = loadRootSource({ rootsFile: file, env: {} });

    expect(source.unconfigured).toBe(false);
    expect(isTrusted(source, AGENT_ROOT, 'agent')).toBe(true);
    expect(isTrusted(source, AGENT_ROOT, 'human')).toBe(true);
    expect(isTrusted(source, AGENT_ROOT, 'delegatee')).toBe(true);
    expect(() => assertTrusted(source, AGENT_ROOT, 'delegatee')).not.toThrow();
  });
});

describe('inline pins + BOLYRA_TRUSTED_ROOTS env', () => {
  it('trusts inline pin roots for any tree', () => {
    const source = loadRootSource({ rootPins: [AGENT_ROOT], env: {} });

    expect(source.unconfigured).toBe(false);
    expect(isTrusted(source, AGENT_ROOT, 'agent')).toBe(true);
    expect(isTrusted(source, AGENT_ROOT, 'human')).toBe(true);
    expect(isTrusted(source, AGENT_ROOT, 'delegatee')).toBe(true);
  });

  it('trusts env roots (comma-separated, trimmed) for any tree', () => {
    const source = loadRootSource({
      env: { BOLYRA_TRUSTED_ROOTS: `${AGENT_ROOT}, ${HUMAN_ROOT}` },
    });

    expect(source.unconfigured).toBe(false);
    expect(isTrusted(source, AGENT_ROOT, 'delegatee')).toBe(true);
    expect(isTrusted(source, HUMAN_ROOT, 'agent')).toBe(true);
    expect(() => assertTrusted(source, HUMAN_ROOT, 'human')).not.toThrow();
  });
});

describe('unconfigured source (fail-closed)', () => {
  it('flags unconfigured when no file, no pins, no env roots', () => {
    const source: RootSource = loadRootSource({ env: {} });
    expect(source.unconfigured).toBe(true);
  });

  it('assertTrusted throws internal_error when the source is unconfigured', () => {
    const source = loadRootSource({ env: {} });
    try {
      assertTrusted(source, AGENT_ROOT, 'agent');
      throw new Error('expected assertTrusted to throw');
    } catch (err) {
      expect(err).toBeInstanceOf(VerifyDenial);
      expect((err as VerifyDenial).code).toBe('internal_error');
    }
  });
});
