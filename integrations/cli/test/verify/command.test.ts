/**
 * Unit tests for the `bolyra verify` PARENT shell (src/commands/verify.ts).
 *
 * Scope: parent-mode flag parsing + worker-arg reconstruction + stdin bounding
 * + verdict/exit-code wiring. A FAKE `runIsolated` is injected so NO real worker
 * process is ever spawned here. Worker-mode + real-spawn behavior is covered by
 * the e2e task (task 16); these tests stay purely on the parent + injection seam.
 */

import { Readable } from 'node:stream';
import type { IsolatedResult, IsolationOptions } from '../../src/verify/isolation';
import { run } from '../../src/commands/verify';

const stdinDescriptor = Object.getOwnPropertyDescriptor(process, 'stdin');

function mockStdin(data: string | Buffer): void {
  const buf = typeof data === 'string' ? Buffer.from(data, 'utf8') : data;
  const stream = Readable.from([buf]);
  Object.defineProperty(process, 'stdin', { value: stream, configurable: true });
}

/** A stdin that fails the test if the code under test tries to read it. */
function mockUnreadableStdin(): void {
  const stream = new Readable({
    read() {
      this.destroy(new Error('stdin should not have been read'));
    },
  });
  Object.defineProperty(process, 'stdin', { value: stream, configurable: true });
}

type FakeRunIsolated = (
  requestJson: string,
  opts: IsolationOptions,
) => Promise<IsolatedResult>;

let stdoutSpy: jest.SpyInstance;
let logSpy: jest.SpyInstance;
let originalArgv: string[];

beforeEach(() => {
  process.exitCode = undefined;
  originalArgv = process.argv;
  process.argv = ['node', '/opt/bolyra/bin/main.js', 'verify'];
  stdoutSpy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

afterEach(() => {
  stdoutSpy.mockRestore();
  logSpy.mockRestore();
  process.argv = originalArgv;
  process.exitCode = undefined;
  if (stdinDescriptor) {
    Object.defineProperty(process, 'stdin', stdinDescriptor);
  }
});

/** The single string written to stdout, or undefined if nothing was written. */
function stdoutPayload(): string | undefined {
  const call = stdoutSpy.mock.calls[0];
  return call === undefined ? undefined : String(call[0]);
}

describe('bolyra verify — parent shell', () => {
  it('reconstructs workerArgs from parsed flags (all flags set)', async () => {
    mockStdin('{"version":1}');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run(
      [
        '--nonce-mode',
        'host',
        '--roots-file',
        '/tmp/roots.json',
        '--root',
        'aaa',
        '--root',
        'bbb',
        '--capability-map',
        '/tmp/cap.json',
        '--circuits-dir',
        '/tmp/circ',
      ],
      { runIsolated: runIsolated as unknown as FakeRunIsolated },
    );

    expect(runIsolated).toHaveBeenCalledTimes(1);
    const [reqJson, opts] = runIsolated.mock.calls[0] as [string, IsolationOptions];
    expect(reqJson).toBe('{"version":1}');
    expect(opts.workerEntry).toBe(process.argv[1]);
    expect(opts.workerArgs).toEqual([
      'verify',
      '--__verify-worker',
      '--nonce-mode',
      'host',
      '--roots-file',
      '/tmp/roots.json',
      '--root',
      'aaa',
      '--root',
      'bbb',
      '--capability-map',
      '/tmp/cap.json',
      '--circuits-dir',
      '/tmp/circ',
    ]);
  });

  it('defaults --nonce-mode to local in the reconstructed workerArgs', async () => {
    mockStdin('{"version":1}');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    const [, opts] = runIsolated.mock.calls[0] as [string, IsolationOptions];
    expect(opts.workerArgs).toEqual([
      'verify',
      '--__verify-worker',
      '--nonce-mode',
      'local',
    ]);
  });

  it('denies oversized stdin (>1 MiB) with malformed_input and exit 0, no worker', async () => {
    // 1 MiB + a few bytes of whitespace.
    mockStdin(Buffer.alloc(1024 * 1024 + 16, 0x20));
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    expect(runIsolated).not.toHaveBeenCalled();
    const payload = stdoutPayload();
    expect(payload).toBeDefined();
    const verdict = JSON.parse(payload as string);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('denies unparseable stdin with malformed_input and exit 0, no worker', async () => {
    mockStdin('this is not json');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    expect(runIsolated).not.toHaveBeenCalled();
    const verdict = JSON.parse(stdoutPayload() as string);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('writes the isolated allow verdict to stdout and exits 0', async () => {
    mockStdin('{"version":1,"hello":"world"}');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    const verdict = JSON.parse(stdoutPayload() as string);
    expect(verdict).toEqual({ verdict: 'allow' });
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('sets a non-zero exit code when the isolated verdict is deny/internal_error', async () => {
    mockStdin('{"version":1}');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({
        verdict: { verdict: 'deny', code: 'internal_error', message: 'boom' },
        // Even if isolation reports 0, the parent derives exit from the verdict.
        exitCode: 0,
      });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    const verdict = JSON.parse(stdoutPayload() as string);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
    expect(process.exitCode).toBe(1);
  });

  it('keeps exit 0 for a non-internal_error deny verdict', async () => {
    mockStdin('{"version":1}');
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({
        verdict: { verdict: 'deny', code: 'scope_exceeded', message: 'nope' },
        exitCode: 0,
      });

    await run([], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    const verdict = JSON.parse(stdoutPayload() as string);
    expect(verdict).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
    expect(process.exitCode ?? 0).toBe(0);
  });

  it('--help prints usage and does not read stdin or spawn a worker', async () => {
    mockUnreadableStdin();
    const runIsolated = jest
      .fn<Promise<IsolatedResult>, [string, IsolationOptions]>()
      .mockResolvedValue({ verdict: { verdict: 'allow' }, exitCode: 0 });

    await run(['--help'], { runIsolated: runIsolated as unknown as FakeRunIsolated });

    expect(logSpy).toHaveBeenCalled();
    expect(runIsolated).not.toHaveBeenCalled();
    expect(stdoutSpy).not.toHaveBeenCalled();
  });
});
