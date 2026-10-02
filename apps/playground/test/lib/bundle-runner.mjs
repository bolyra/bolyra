/**
 * Child-process runner: evaluates a bundle file in a fresh V8 context with
 * minimal globals (no DOM, no fetch, no network), then executes a JSON list
 * of operations from stdin against `BolyraPlayground` and prints JSON results.
 * Usage: node bundle-runner.mjs <bundle.js>  < ops.json
 */
import vm from 'node:vm';
import fs from 'node:fs';

const bundlePath = process.argv[2];
const code = fs.readFileSync(bundlePath, 'utf8');
const sandbox = {
  TextEncoder, TextDecoder, crypto: globalThis.crypto,
  console: { log() {}, warn() {}, error() {}, info() {}, debug() {} },
  setTimeout, clearTimeout, queueMicrotask, Promise,
};
sandbox.globalThis = sandbox; sandbox.self = sandbox;
vm.createContext(sandbox);
vm.runInContext(code, sandbox, { filename: 'playground-bundle.js', timeout: 30_000 });
const PG = sandbox.BolyraPlayground;
if (!PG) { console.error('bundle did not define globalThis.BolyraPlayground'); process.exit(2); }

const ops = JSON.parse(fs.readFileSync(0, 'utf8'));
const out = [];
for (const op of ops) {
  if (op.op === 'meta') out.push({ VERSION: PG.VERSION, RECEIPTS_VERSION: PG.RECEIPTS_VERSION, PAYMENT_PROTOCOLS_VERSION: PG.PAYMENT_PROTOCOLS_VERSION, USAGE_EVENTS: PG.USAGE_EVENTS ? [...PG.USAGE_EVENTS] : null, samples: Object.keys(PG.SAMPLES), x402Samples: Object.keys(PG.X402_SAMPLES), exports: Object.keys(PG).sort() });
  else if (op.op === 'x402.parse') out.push(PG.parseChallenge(op.header));
  else if (op.op === 'x402.select') { try { out.push(PG.selectLeg({ headerValue: op.header, resource: op.resource, legIndex: op.legIndex, now: op.now, maxSeconds: op.maxSeconds })); } catch (e) { out.push({ error: { code: e.code, reason: e.detail?.reason } }); } }
  else if (op.op === 'x402.peek') { try { out.push(PG.peekJwsHeader(op.token)); } catch (e) { out.push({ error: { reason: e.reason } }); } }
  else if (op.op === 'x402.inspect') { try { out.push(PG.inspectJwsPayload(op.token)); } catch (e) { out.push({ error: { reason: e.reason } }); } }
  else if (op.op === 'shapes') out.push(PG.EVC_SHAPES);
  else if (op.op === 'sample') out.push(PG.SAMPLES[op.key] ?? null);
  else if (op.op === 'verify') out.push(PG.verifyAll(op.text, op.options ?? {}));
  else if (op.op === 'simulate') {
    let session = PG.newSession();
    const results = [];
    for (const step of op.steps) {
      const r = await PG.decide(session, step);
      results.push({ outcome: r.outcome, seq: r.seq, requiredTier: r.requiredTier, reason: r.reason, allowed: r.receipt?.payload.decision.allowed, reasonCode: r.receipt?.payload.decision.reasonCode });
    }
    const res = { results, jsonl: PG.exportJsonl(session), signer: PG.signerDoc(session), chain: PG.chainInfo(session) };
    if (op.reset) { session = PG.resetSession(session); res.afterReset = { chainId: session.chainId, chain: PG.chainInfo(session), signer: PG.signerDoc(session).signer }; }
    out.push(res);
  } else out.push({ error: `unknown op ${op.op}` });
}
process.stdout.write(JSON.stringify(out));
