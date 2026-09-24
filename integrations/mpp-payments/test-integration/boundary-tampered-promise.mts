/**
 * Boundary of the onDecision containment guarantee, kept as an executable
 * pin (spawned by action-counter.test.mts in its own process, so the
 * unhandled rejection is observed by Node rather than by a test runner).
 *
 * An observer returns an ALREADY-REJECTED native Promise whose `constructor`
 * getter throws. `Promise.resolve(p)` reads `p.constructor` before any
 * handler can attach, so it throws synchronously (the gate catches and logs
 * that), and `p`'s own rejection is left unhandled. Tampered native Promise
 * internals are outside the guarantee. Authorization is unaffected.
 *
 * Prints one JSON line: { "allowStatus": 200, "counter": 1, "unhandled": 1 }
 */
import { buildApp, paymentHeader, requestWith, serverMethod, gate, classicalGateOptions } from './harness.mjs';

async function main(): Promise<void> {
  let unhandled = 0;
  process.on('unhandledRejection', () => { unhandled += 1; });
  console.error = () => undefined; // silence the gate's containment log
  const gated = gate(serverMethod(), await classicalGateOptions({
    onDecision: () => {
      const p = Promise.reject(new Error('tampered rejection'));
      Object.defineProperty(p, 'constructor', { get() { throw new Error('constructor getter'); } });
      return p;
    },
  }));
  const { mppx, state, handler } = buildApp(gated);
  const res = await handler(await requestWith({ payment: await paymentHeader(mppx) }));
  for (let i = 0; i < 3; i += 1) await new Promise((resolve) => setImmediate(resolve));
  process.stdout.write(`${JSON.stringify({ allowStatus: res.status, counter: state.counter, unhandled })}\n`);
}
main().catch((e) => { process.stderr.write(String(e)); process.exit(1); });
