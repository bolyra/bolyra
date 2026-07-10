/**
 * `bolyra verify` — external ZKP proof-bundle verifier (spec §5).
 *
 * Reads an untrusted verification request as JSON on stdin and writes exactly
 * ONE machine-readable verdict object as JSON on stdout. Exit code is 0 for
 * every verdict the algorithm can produce (allow OR a policy/crypto deny) and
 * non-zero ONLY for an `internal_error` deny (an unexpected verifier fault).
 *
 * Two-process design (see verify/isolation.ts): proof verification pulls in
 * native/WASM libraries that may scribble on fd 1. To keep the host-facing
 * stdout a single clean verdict, the PARENT (default mode) re-invokes THIS
 * command as a hidden WORKER (`--__verify-worker`) over a private verdict fd.
 *
 *   - Parent mode (default): read+bound stdin, reject unparseable/oversized
 *     input locally, otherwise hand the raw request to `runVerificationIsolated`
 *     which spawns the worker and returns the parsed verdict. The parent does
 *     the SOLE `process.stdout.write`.
 *   - Worker mode (`--__verify-worker`, hidden): read+bound stdin, run the pure
 *     `verify(request, flags)` algorithm, and emit the verdict ONLY on fd 3 via
 *     `emitVerdictFromWorker`. Writes NOTHING to stdout.
 */

import { parseArgs } from 'node:util';
import * as fs from 'node:fs';

import { verify, type VerifierRequest, type VerifyFlags, type NonceMode } from '../verify/core';
import { deny } from '../verify/verdict';
import {
  runVerificationIsolated,
  emitVerdictFromWorker,
  type IsolationOptions,
} from '../verify/isolation';

/** Upper bound on the request read from stdin: 1 MiB (spec §7.2). */
const MAX_STDIN = 1024 * 1024;

const HELP = `bolyra verify — verify an external Bolyra proof bundle

Reads a verification request as JSON on stdin, writes a single verdict as JSON
on stdout. Exit 0 for any verdict (allow or a policy/crypto deny); non-zero only
on an internal_error deny.

Flags:
  --nonce-mode <local|host>   Replay protection mode (default: local)
  --roots-file <path>         Trusted-roots JSON file
  --root <value>              Inline trusted root (repeatable)
  --capability-map <path>     Capability -> permission-bit map JSON
  --circuits-dir <path>       Circuit vkey/artifact directory
  --verbose                   Verbose diagnostics on stderr
  --help                      Show this help

Usage:
  cat request.json | bolyra verify --roots-file roots.json
`;

/** Parsed flag surface shared by parent + worker modes. */
interface ParsedValues {
  'nonce-mode'?: string;
  'roots-file'?: string;
  root?: string[];
  'capability-map'?: string;
  'circuits-dir'?: string;
  verbose?: boolean;
  help?: boolean;
  '__verify-worker'?: boolean;
}

/** Narrow an unknown value to a non-null, non-array plain object. */
function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Is this verdict a fault (deny/internal_error) that must set a non-zero exit? */
function isInternalErrorVerdict(verdict: unknown): boolean {
  return (
    isPlainObject(verdict) &&
    verdict.verdict === 'deny' &&
    verdict.code === 'internal_error'
  );
}

/** Map parsed flags onto the operator-supplied {@link VerifyFlags}. */
function toVerifyFlags(values: ParsedValues): VerifyFlags {
  const flags: VerifyFlags = {
    // `--nonce-mode` always resolves (default 'local'); anything other than
    // 'host' is treated as local by the core, so a bad value fails safe.
    nonceMode: (values['nonce-mode'] ?? 'local') as NonceMode,
  };
  if (values['circuits-dir'] !== undefined) flags.circuitsDir = values['circuits-dir'];
  if (values['roots-file'] !== undefined) flags.rootsFile = values['roots-file'];
  if (values.root !== undefined && values.root.length > 0) flags.rootPins = values.root;
  if (values['capability-map'] !== undefined) flags.capabilityMapFile = values['capability-map'];
  return flags;
}

/**
 * Reconstruct the value-carrying flags for the worker re-invocation. Only the
 * flags that affect the verification algorithm are forwarded; `--verbose` /
 * `--help` / `--__verify-worker` are intentionally NOT re-emitted.
 */
function reconstructFlags(values: ParsedValues): string[] {
  const out: string[] = ['--nonce-mode', values['nonce-mode'] ?? 'local'];
  if (values['roots-file'] !== undefined) out.push('--roots-file', values['roots-file']);
  for (const root of values.root ?? []) out.push('--root', root);
  if (values['capability-map'] !== undefined) out.push('--capability-map', values['capability-map']);
  if (values['circuits-dir'] !== undefined) out.push('--circuits-dir', values['circuits-dir']);
  return out;
}

/**
 * Read stdin, capped at {@link MAX_STDIN}. Stops as soon as the cap is exceeded
 * and reports `oversize: true` — an oversized request is rejected without ever
 * buffering the whole thing.
 */
async function readStdinBounded(limit: number): Promise<{ data: string; oversize: boolean }> {
  const chunks: Buffer[] = [];
  let total = 0;
  for await (const chunk of process.stdin) {
    const buf = chunk as Buffer;
    total += buf.length;
    if (total > limit) {
      return { data: '', oversize: true };
    }
    chunks.push(buf);
  }
  return { data: Buffer.concat(chunks).toString('utf8'), oversize: false };
}

/**
 * Run the `bolyra verify` command.
 *
 * @param args argv slice AFTER the `verify` subcommand token.
 * @param deps test seam — inject a fake `runIsolated` to avoid real spawns.
 */
export async function run(
  args: string[],
  deps?: { runIsolated?: typeof runVerificationIsolated },
): Promise<void> {
  const { values } = parseArgs({
    args,
    options: {
      'nonce-mode': { type: 'string', default: 'local' },
      'roots-file': { type: 'string' },
      root: { type: 'string', multiple: true },
      'capability-map': { type: 'string' },
      'circuits-dir': { type: 'string' },
      verbose: { type: 'boolean', default: false },
      help: { type: 'boolean', default: false },
      // Hidden: marks the internal worker re-invocation. Not documented.
      '__verify-worker': { type: 'boolean', default: false },
    },
    allowPositionals: false,
    strict: true,
  });

  const parsed = values as ParsedValues;

  if (parsed.help) {
    console.log(HELP);
    return;
  }

  const flags = toVerifyFlags(parsed);

  // ── Worker mode ────────────────────────────────────────────────────────────
  // Read + bound stdin, run the pure algorithm, emit the verdict ONLY on fd 3.
  // Never touch stdout. On unreadable/oversized/unparseable input, fail closed
  // with a malformed_input deny on fd 3.
  if (parsed['__verify-worker']) {
    // Test-only hazard injection (F8, fixture #17): when this env var is set,
    // the worker writes native-style noise DIRECTLY to fd 1 — the exact hazard
    // real proving libs pose. It must be captured by the parent and rerouted to
    // stderr, never leaking into the single host-facing stdout verdict. Gated
    // behind an env var so it never runs on any normal code path.
    if (process.env.BOLYRA_VERIFY_TEST_FD1_NOISE) {
      fs.writeSync(1, 'RAW-FD1-NATIVE-NOISE\n');
    }
    let request: VerifierRequest;
    try {
      const { data, oversize } = await readStdinBounded(MAX_STDIN);
      if (oversize) throw new Error('request exceeds maximum size');
      request = JSON.parse(data) as VerifierRequest;
    } catch {
      emitVerdictFromWorker(deny('malformed_input', 'worker: request stdin is not valid JSON'));
      // fs.writeSync(3, …) already flushed the verdict synchronously. Force-exit
      // because native proving libs (snarkjs/bn128) can leave worker threads /
      // open handles alive, so a plain `return` would never let the process exit
      // and the parent would hang on 'close'. Exit 0: fd-3 carries the verdict.
      process.exit(0);
    }
    const verdict = await verify(request, flags);
    emitVerdictFromWorker(verdict);
    // Same rationale as above: force-exit after the synchronous fd-3 flush so a
    // hung native handle can't keep the worker alive and stall the parent.
    process.exit(0);
  }

  // ── Parent mode (default) ───────────────────────────────────────────────────
  const { data, oversize } = await readStdinBounded(MAX_STDIN);

  // Reject oversized OR unparseable stdin locally — do NOT spawn a worker for
  // input we already know is malformed.
  if (oversize) {
    process.stdout.write(
      JSON.stringify(deny('malformed_input', 'request exceeds maximum size (1 MiB)')),
    );
    process.exitCode = 0;
    return;
  }
  try {
    JSON.parse(data);
  } catch {
    process.stdout.write(JSON.stringify(deny('malformed_input', 'request stdin is not valid JSON')));
    process.exitCode = 0;
    return;
  }

  // Re-invoke THIS command as the isolated worker. `process.argv[1]` is the CLI
  // entry (bin/main.js); the worker routes `verify` back into worker mode.
  const workerEntry = process.argv[1];
  const workerArgs = ['verify', '--__verify-worker', ...reconstructFlags(parsed)];
  const opts: IsolationOptions = { workerEntry, workerArgs };

  const runIsolated = deps?.runIsolated ?? runVerificationIsolated;
  const { verdict } = await runIsolated(data, opts);

  // The SINGLE stdout write. Exit non-zero only for an internal_error fault;
  // every policy/crypto deny (and allow) is a normal, exit-0 verdict.
  process.stdout.write(JSON.stringify(verdict));
  process.exitCode = isInternalErrorVerdict(verdict) ? 1 : 0;
}
