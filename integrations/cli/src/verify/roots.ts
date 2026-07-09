/**
 * Trusted-root source for the `bolyra verify` external verifier (spec §10.5).
 *
 * A verifier must decide whether the Merkle root committed by a proof belongs
 * to an enrollment tree the operator trusts. v1 ships TWO purely-local sources,
 * no network dependency:
 *
 *   1. A roots-file (`--roots-file <path>`) whose JSON is EITHER
 *        - namespaced: `{ agent?: string[]; human?: string[]; delegatee?: string[] }`
 *          — each root is trusted ONLY for its own tree; or
 *        - a flat `string[]` — every root is trusted for ANY tree.
 *   2. Inline pins: repeated `--root <root>` (collected into `rootPins`) plus the
 *      comma-separated `BOLYRA_TRUSTED_ROOTS` env var. Pin/env roots are trusted
 *      for ANY tree.
 *
 * Roots are decimal field-element strings.
 *
 * A registry-RPC source (resolving roots from an on-chain registry) is a
 * DOCUMENTED v2 EXTENSION and is intentionally NOT implemented here.
 *
 * Fail-closed: if no file, no pins, and no env roots are configured, the source
 * is flagged `unconfigured` and `assertTrusted` denies with `internal_error`
 * rather than silently trusting nothing (or everything).
 */

import * as fs from 'node:fs';
import { VerifyDenial } from './verdict';

/** The three enrollment trees a root can belong to. */
export type Tree = 'agent' | 'human' | 'delegatee';

const TREES: readonly Tree[] = ['agent', 'human', 'delegatee'];

/**
 * A resolved, purely-local set of trusted roots.
 *
 * `namespaced[tree]` roots are trusted ONLY for that tree; `anyTree` roots
 * (from a flat file, inline pins, or the env var) are trusted for every tree.
 */
export interface RootSource {
  /** Roots trusted only within their own tree (from a namespaced roots-file). */
  readonly namespaced: Readonly<Record<Tree, ReadonlySet<string>>>;
  /** Roots trusted for ANY tree (flat file array, inline pins, env var). */
  readonly anyTree: ReadonlySet<string>;
  /** True when NO file, NO pins, and NO env roots were supplied. */
  readonly unconfigured: boolean;
}

export interface LoadRootSourceOptions {
  /** Path to the `--roots-file` JSON (namespaced object or flat array). */
  rootsFile?: string;
  /** Inline roots from repeated `--root` flags. Trusted for any tree. */
  rootPins?: string[];
  /** Environment to read `BOLYRA_TRUSTED_ROOTS` from. Defaults to `process.env`. */
  env?: NodeJS.ProcessEnv;
}

/** A JSON value that is not an array and not null: a plain object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Coerce a parsed value into a validated array of decimal root strings. */
function asRootArray(value: unknown, where: string): string[] {
  if (!Array.isArray(value)) {
    throw new VerifyDenial('internal_error', `trusted roots at ${where} must be an array of strings`);
  }
  for (const entry of value) {
    if (typeof entry !== 'string') {
      throw new VerifyDenial('internal_error', `trusted root at ${where} must be a string`);
    }
  }
  return value as string[];
}

/** Split the comma-separated `BOLYRA_TRUSTED_ROOTS` env var into trimmed, non-empty roots. */
function parseEnvRoots(env: NodeJS.ProcessEnv): string[] {
  const raw = env.BOLYRA_TRUSTED_ROOTS;
  if (raw === undefined || raw.trim() === '') return [];
  return raw
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
}

/** Read + parse the `--roots-file`, sorting entries into namespaced vs any-tree sets. */
function loadRootsFile(
  path: string,
  namespaced: Record<Tree, Set<string>>,
  anyTree: Set<string>,
): void {
  let text: string;
  try {
    text = fs.readFileSync(path, 'utf8');
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new VerifyDenial('internal_error', `could not read trusted roots file: ${cause}`, {
      rootsFile: path,
    });
  }

  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (err) {
    const cause = err instanceof Error ? err.message : String(err);
    throw new VerifyDenial('internal_error', `trusted roots file is not valid JSON: ${cause}`, {
      rootsFile: path,
    });
  }

  if (Array.isArray(parsed)) {
    // Flat array — trusted for ANY tree.
    for (const root of asRootArray(parsed, 'roots-file')) anyTree.add(root);
    return;
  }

  if (isPlainObject(parsed)) {
    // Namespaced — each list is trusted only within its own tree.
    for (const tree of TREES) {
      const list = parsed[tree];
      if (list === undefined) continue;
      for (const root of asRootArray(list, `roots-file.${tree}`)) namespaced[tree].add(root);
    }
    return;
  }

  throw new VerifyDenial(
    'internal_error',
    'trusted roots file must be a namespaced object or a flat array of strings',
    { rootsFile: path },
  );
}

/**
 * Build a {@link RootSource} from the two v1 local sources: a `--roots-file`
 * and inline pins (`--root` flags + `BOLYRA_TRUSTED_ROOTS`). Throws
 * `VerifyDenial('internal_error', ...)` if a supplied roots-file cannot be read
 * or is malformed. Returns an `unconfigured` source when nothing is supplied.
 */
export function loadRootSource(opts: LoadRootSourceOptions): RootSource {
  const namespaced: Record<Tree, Set<string>> = {
    agent: new Set<string>(),
    human: new Set<string>(),
    delegatee: new Set<string>(),
  };
  const anyTree = new Set<string>();

  if (opts.rootsFile !== undefined) {
    loadRootsFile(opts.rootsFile, namespaced, anyTree);
  }

  for (const pin of opts.rootPins ?? []) {
    anyTree.add(pin);
  }

  for (const root of parseEnvRoots(opts.env ?? process.env)) {
    anyTree.add(root);
  }

  const totalNamespaced = TREES.reduce((n, tree) => n + namespaced[tree].size, 0);
  const unconfigured = opts.rootsFile === undefined && anyTree.size === 0 && totalNamespaced === 0;

  return { namespaced, anyTree, unconfigured };
}

/**
 * Is `root` trusted for `tree`? Any-tree roots (flat file, pins, env) match any
 * tree; namespaced roots match only their own tree. Does not consider whether
 * the source is configured — see {@link assertTrusted} for the fail-closed gate.
 */
export function isTrusted(source: RootSource, root: string, tree: Tree): boolean {
  return source.anyTree.has(root) || source.namespaced[tree].has(root);
}

/**
 * Assert `root` is trusted for `tree`, throwing a `VerifyDenial` otherwise.
 *
 * - Source `unconfigured` → `internal_error` (fail-closed; the core additionally
 *   non-zero-exits). Trusting nothing is an operator misconfiguration, not a
 *   property of the proof.
 * - Configured but untrusted root → `untrusted_root`.
 */
export function assertTrusted(source: RootSource, root: string, tree: Tree): void {
  if (source.unconfigured) {
    throw new VerifyDenial('internal_error', 'no trusted root source configured');
  }
  if (!isTrusted(source, root, tree)) {
    throw new VerifyDenial('untrusted_root', 'root not in trusted set', { root, tree });
  }
}
