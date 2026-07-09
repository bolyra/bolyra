/**
 * fd-level stdout isolation for proof verification (spec §7.1, OQ-2).
 *
 * Problem: proof verification pulls in native / WASM libraries (snarkjs, ffjavascript,
 * rapidsnark bindings) that may write directly to file descriptor 1 (stdout) — progress
 * bars, warnings, debug spew — bypassing any JS-level `process.stdout.write` wrapper.
 * The host reads a SINGLE verdict object on our stdout, so a stray fd-1 byte would corrupt
 * the machine-readable contract.
 *
 * Approved mechanism: process isolation with a private verdict fd.
 *   - The verifier command spawns a WORKER process that does the verification.
 *   - Worker stdio = ['pipe' (request in on fd0),
 *                     'pipe' (fd1 captured — everything native writes here),
 *                     'inherit' (fd2 -> parent stderr),
 *                     'pipe' (fd3 = the private verdict channel)].
 *   - Inside the worker, ALL native/library noise lands on fd 1, which the PARENT captures
 *     and forwards to the PARENT'S OWN stderr — never to the host-facing stdout.
 *   - The worker emits the single verdict object ONLY on fd 3 via fs.writeSync(3, ...).
 *   - The parent reads fd 3, and the caller performs the sole process.stdout.write(verdict).
 *
 * `spawn` (not `fork`) is used deliberately: a 4-pipe stdio array without an 'ipc' entry
 * throws ERR_CHILD_PROCESS_IPC_REQUIRED under `fork`. `spawn` needs no IPC.
 *
 * This module never throws to the caller. Any failure (spawn error, non-zero exit, empty
 * or garbled fd-3 payload) resolves to a synthesized fail-closed deny verdict.
 */

import { spawn, type ChildProcess } from 'node:child_process';
import * as fs from 'node:fs';

export interface IsolationOptions {
  /** Path to the built worker entry (script run by `process.execPath`). */
  workerEntry: string;
  /** Extra argv passed to the worker (e.g. ['verify','--__verify-worker', ...flags]). */
  workerArgs?: string[];
}

export interface IsolatedResult {
  /** The parsed verdict object read from the worker's private fd-3 channel. */
  verdict: unknown;
  /** 0 on a clean verdict, 1 on any fail-closed path. */
  exitCode: number;
}

/** Synthesize the fail-closed deny verdict returned on any failure path. */
function failClosed(message: string): IsolatedResult {
  return {
    verdict: { verdict: 'deny', code: 'internal_error', message },
    exitCode: 1,
  };
}

/**
 * Run verification in an isolated worker process, guaranteeing that native/library writes
 * to fd 1 can never corrupt the verdict. Resolves (never rejects) with the parsed verdict
 * or a fail-closed deny.
 */
export function runVerificationIsolated(
  requestJson: string,
  opts: IsolationOptions,
): Promise<IsolatedResult> {
  return new Promise<IsolatedResult>((resolve) => {
    let settled = false;
    const done = (result: IsolatedResult): void => {
      if (settled) return;
      settled = true;
      resolve(result);
    };

    const args = [opts.workerEntry, ...(opts.workerArgs ?? [])];

    let child: ChildProcess;
    try {
      // stdio index 0=request in, 1=captured (native noise), 2=inherit->parent stderr,
      // 3=private verdict channel. Do NOT use fork — a 4-pipe array without 'ipc' throws.
      child = spawn(process.execPath, args, {
        stdio: ['pipe', 'pipe', 'inherit', 'pipe'],
      });
    } catch (err) {
      done(failClosed(`failed to spawn verification worker: ${errMsg(err)}`));
      return;
    }

    // Buffer for the private verdict channel (fd 3).
    const verdictChunks: Buffer[] = [];

    // fd 1: native/library noise. Forward every byte to the PARENT'S OWN stderr so it is
    // never mixed into the host-facing stdout. This is the core guarantee.
    const fd1 = child.stdio[1];
    if (fd1) {
      fd1.on('data', (chunk: Buffer) => {
        process.stderr.write(chunk);
      });
      fd1.on('error', () => {
        /* ignore — noise channel errors must not affect the verdict */
      });
    }

    // fd 3: the private verdict channel. BLOCKER guard — if the 4th pipe is not readable
    // on this Node/platform, fail closed loudly rather than silently dropping the guarantee.
    const fd3 = child.stdio[3];
    if (!fd3 || typeof fd3 === 'number' || typeof (fd3 as NodeJS.ReadableStream).on !== 'function') {
      try {
        child.kill();
      } catch {
        /* ignore */
      }
      done(
        failClosed(
          'verdict channel (fd 3) is not a readable stream on this platform; ' +
            'fd-level isolation cannot be established',
        ),
      );
      return;
    }
    const verdictStream = fd3 as NodeJS.ReadableStream;
    verdictStream.on('data', (chunk: Buffer) => {
      verdictChunks.push(chunk);
    });
    verdictStream.on('error', () => {
      /* ignore — handled on close via empty-buffer check */
    });

    // Write the request to the worker's stdin and end it.
    const stdin = child.stdin;
    if (stdin) {
      stdin.on('error', () => {
        /* ignore — EPIPE if the worker exits before reading; handled on close */
      });
      stdin.write(requestJson);
      stdin.end();
    }

    child.on('error', (err: Error) => {
      // Spawn/exec-level failure (e.g. ENOENT for a bad workerEntry).
      done(failClosed(`verification worker error: ${errMsg(err)}`));
    });

    child.on('close', (code: number | null) => {
      if (code !== 0 && code !== null) {
        done(failClosed(`verification worker exited with code ${code}`));
        return;
      }

      const raw = Buffer.concat(verdictChunks).toString('utf8').trim();
      if (raw.length === 0) {
        done(failClosed('verification worker produced no verdict on fd 3'));
        return;
      }

      let verdict: unknown;
      try {
        verdict = JSON.parse(raw);
      } catch {
        // Non-JSON, or multiple concatenated JSON values -> garbled.
        done(failClosed('verification worker emitted a malformed verdict on fd 3'));
        return;
      }

      done({ verdict, exitCode: 0 });
    });
  });
}

/**
 * Worker-side helper: emit the single verdict object on the private fd-3 channel.
 * Writes NOTHING to fd 1 — that fd is reserved for native/library noise which the parent
 * captures and reroutes to its own stderr.
 */
export function emitVerdictFromWorker(verdict: unknown): void {
  fs.writeSync(3, JSON.stringify(verdict));
}

function errMsg(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}
