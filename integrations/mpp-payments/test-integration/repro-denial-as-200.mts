/**
 * Reproduction of the spec §3.1 finding, kept as documentation.
 * Before the fix this prints
 *   { outerStatus: 200, responseStatus: 401, actionCount: 1 }
 * i.e. mppx reported status 200 to the handler, the handler's protected action
 * ran once, and only THEN the gate's 401 came back as the response body.
 * After the fix the handler throws and this prints
 *   { threw: 'BolyraDeniedError', actionCount: 0 }
 */
import { buildApp, paymentHeader, requestWith, serverMethod, gate, classicalGateOptions } from './harness.mjs';

async function main(): Promise<void> {
  const gated = gate(serverMethod(), await classicalGateOptions());
  const { mppx, state, handler } = buildApp(gated);
  const payment = await paymentHeader(mppx);
  const request = await requestWith({ payment, bundle: null }); // no Bolyra header => missing_authorization
  try {
    const res = await handler(request);
    console.log({ outerStatus: state.lastResultStatus, responseStatus: res.status, actionCount: state.counter });
  } catch (e) {
    console.log({ threw: (e as Error).name, actionCount: state.counter });
  }
}
main().catch((e) => { console.error(e); process.exit(1); });
