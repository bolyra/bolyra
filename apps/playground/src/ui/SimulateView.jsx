import { useRef, useState } from 'react';
import { Field, Status, CodeBlock, CopyButton, DownloadButton } from './shared.jsx';
import { track } from '../core/usage.js';

const PRESETS = [
  { id: 'over-limit', label: '$25 then $500 under small', steps: [{ tier: 'small', amount: '25' }, { tier: 'small', amount: '500' }] },
  { id: 'repeat', label: '$99 × 5 under small', steps: Array(5).fill({ tier: 'small', amount: '99' }) },
];

export function SimulateView({ pg }) {
  const sessionRef = useRef(null);
  if (sessionRef.current === null) sessionRef.current = pg.newSession();
  const [tier, setTier] = useState('small');
  const [amount, setAmount] = useState('25');
  const [runs, setRuns] = useState([]);
  const [chainId, setChainId] = useState(1);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState('');
  const session = sessionRef.current;

  const runSteps = async (steps, { preset = false } = {}) => {
    if (busy) return;
    if (preset) track('sample_simulate');
    track('run_simulate');
    setBusy(true); setError('');
    try {
      for (const step of steps) {
        const r = await pg.decide(session, step);
        track(r.outcome === 'allow' ? 'simulate_ok' : r.outcome === 'deny' ? 'simulate_failed' : 'simulate_invalid');
        setRuns((prev) => [...prev, { ...r, tier: step.tier, amount: String(step.amount) }]);
      }
    } catch (err) { setError(err && err.message ? err.message : String(err)); }
    finally { setBusy(false); }
  };
  const onReset = () => {
    try { sessionRef.current = pg.resetSession(session); setChainId(sessionRef.current.chainId); setRuns([]); setError(''); }
    catch (err) { setError(err && err.message ? err.message : String(err)); }
  };
  const info = pg.chainInfo(session);
  const jsonl = pg.exportJsonl(session);
  const signer = pg.signerDoc(session);
  const signerJson = JSON.stringify(signer, null, 2) + '\n';

  return (
    <section className="view" data-view="simulate">
      <p className="lead">Pick a mandate tier and an amount. The tier is chosen independently of the amount, exactly as an operator signs a mandate before any request exists. The decision is computed locally and labelled simulated; the receipt is signed for real with a temporary key held only in this tab.</p>
      <div className="grid-2">
        <Field label="Mandate tier" hint="Ceilings: small < $100, medium < $10,000, unlimited. Chosen independently of the amount.">
          <select className="input" value={tier} onChange={(e) => setTier(e.target.value)} data-field="tier">
            {pg.TIER_ORDER.map((t) => <option key={t} value={t}>{t} ({pg.describeTierAuthorization(t)})</option>)}
          </select>
        </Field>
        <Field label="Requested amount (USD)" hint="Digits with an optional decimal part. The amount is shown here; it is not inside the signed payload.">
          <input className="input mono" value={amount} onChange={(e) => setAmount(e.target.value)} data-field="amount" inputMode="decimal" />
        </Field>
      </div>
      <div className="actions">
        <button type="button" className="btn btn-primary" disabled={busy} onClick={() => runSteps([{ tier, amount }])} data-action="run">Run</button>
        {PRESETS.map((p) => <button key={p.id} type="button" className="btn" disabled={busy} onClick={() => runSteps(p.steps, { preset: true })} data-preset={p.id}>{p.label}</button>)}
        <button type="button" className="btn btn-ghost" disabled={busy} onClick={onReset} data-action="reset">Reset (new key, new chain)</button>
      </div>
      {error ? <div className="problems"><li>{error}</li></div> : null}
      <div className="chain-strip" data-chain-strip>Chain {chainId} · {info.seq === 0 ? 'no receipts yet' : `seq 0..${info.seq - 1}`} · signer <code>{signer.signer}</code></div>
      {runs.length > 0 ? (
        <ol className="runs">{runs.map((r, i) => (
          <li key={i} className="run" data-run={i} data-outcome={r.outcome}>
            <div className="run-head">
              {r.outcome === 'allow' ? <Status kind="ok">allow (simulated)</Status> : r.outcome === 'deny' ? <Status kind="bad">deny (simulated)</Status> : <Status kind="warn">invalid input</Status>}
              <span className="muted"> tier <code>{r.tier}</code>, amount <code>{r.amount}</code>{r.requiredTier ? <>, requires <code>{r.requiredTier}</code></> : null}{r.outcome === 'deny' ? <>, reason <code>{r.receipt.payload.decision.reasonCode}</code></> : null}{r.outcome === 'invalid' ? <>: {r.reason}. Nothing was signed.</> : null}</span>
            </div>
            {r.receipt ? <details><summary>Receipt seq {r.seq}: real ES256K signature from this session’s temporary key; describes a simulated decision</summary><CodeBlock text={JSON.stringify(r.receipt, null, 2)} tall /></details> : null}
          </li>
        ))}</ol>
      ) : <p className="muted">No runs yet. Run one request or a preset.</p>}
      <div className="export">
        <h3>Export</h3>
        <p className="muted small">Verify the log with the published CLI: <code>npx @bolyra/cli@{pg.CLI_VERSION} receipt verify-chain receipts.jsonl --signer {signer.signer} --expect-count {info.seq}{info.headHash ? ` --expect-head ${info.headHash}` : ''}</code></p>
        <div className="actions">
          <DownloadButton text={jsonl} filename="receipts.jsonl" label="Download receipts.jsonl" mime="application/x-ndjson" />
          <CopyButton text={jsonl} label="Copy JSONL" />
          <DownloadButton text={signerJson} filename="signer.json" label="Download signer.json" mime="application/json" />
          <CopyButton text={signerJson} label="Copy signer document" />
        </div>
        <CodeBlock text={signerJson} />
      </div>
      <p className="fineprint">Signs real receipts describing simulated decisions; no credentials or proofs are verified, no payment or wallet is involved, and the decision is not enforcement. To issue a real mandate, use <a href="https://github.com/bolyra/bolyra/tree/main/integrations/cli#readme"><code>bolyra mandate issue</code></a>.</p>
    </section>
  );
}
