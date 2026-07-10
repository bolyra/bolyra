import * as path from 'node:path';
import { runVerificationIsolated } from '../../src/verify/isolation';

const WORKER = path.join(__dirname, '..', 'fixtures', 'isolation-worker.js');

describe('runVerificationIsolated', () => {
  it('routes raw fd-1 native noise away from the verdict channel', async () => {
    // The worker performs a genuine fs.writeSync(1, 'RAW-NATIVE-NOISE') before
    // emitting its verdict on fd 3. The returned verdict must be exactly what
    // the worker wrote to fd 3 — the fd-1 noise must NOT leak into it.
    const result = await runVerificationIsolated('{}', {
      workerEntry: WORKER,
      workerArgs: ['noise'],
    });

    expect(result.exitCode).toBe(0);
    expect(result.verdict).toEqual({ verdict: 'allow' });
    // Guarantee the native noise did not contaminate the verdict at all.
    expect(JSON.stringify(result.verdict)).not.toContain('RAW-NATIVE-NOISE');
  });

  it('fails closed when the worker exits non-zero without writing fd 3', async () => {
    const result = await runVerificationIsolated('{}', {
      workerEntry: WORKER,
      workerArgs: ['crash'],
    });

    expect(result.exitCode).toBe(1);
    expect(result.verdict).toMatchObject({
      verdict: 'deny',
      code: 'internal_error',
    });
  });

  it('fails closed when the worker writes non-JSON garbage to fd 3', async () => {
    const result = await runVerificationIsolated('{}', {
      workerEntry: WORKER,
      workerArgs: ['garbage'],
    });

    expect(result.exitCode).toBe(1);
    expect(result.verdict).toMatchObject({
      verdict: 'deny',
      code: 'internal_error',
    });
  });

  it('fails closed when the worker entry cannot be spawned', async () => {
    const result = await runVerificationIsolated('{}', {
      workerEntry: path.join(__dirname, 'no-such-worker-file.js'),
      workerArgs: [],
    });

    expect(result.exitCode).toBe(1);
    expect(result.verdict).toMatchObject({
      verdict: 'deny',
      code: 'internal_error',
    });
  });

  it('fails closed when the worker emits a verdict then hangs (never exits)', async () => {
    // The worker writes a valid verdict to fd 3 and then stays alive forever
    // (simulating snarkjs/bn128 keeping the process alive). The parent must NOT
    // wait on 'close' indefinitely — it must time out and fail closed.
    const start = Date.now();
    const result = await runVerificationIsolated('{}', {
      workerEntry: WORKER,
      workerArgs: ['hang'],
      timeoutMs: 200,
    });
    const elapsed = Date.now() - start;

    expect(result.exitCode).toBe(1);
    expect(result.verdict).toMatchObject({
      verdict: 'deny',
      code: 'internal_error',
    });
    // Resolved via the timeout, well before any test-runner timeout.
    expect(elapsed).toBeLessThan(5000);
  });

  it('delivers the request JSON to the worker over stdin', async () => {
    const request = JSON.stringify({ hello: 'world' });
    const result = await runVerificationIsolated(request, {
      workerEntry: WORKER,
      workerArgs: ['echo'],
    });

    expect(result.exitCode).toBe(0);
    expect(result.verdict).toEqual({ verdict: 'allow', echoed: { hello: 'world' } });
  });
});
