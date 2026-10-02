import { useState } from 'react';
import { Field, Status, CodeBlock } from './shared.jsx';
import { track } from '../core/usage.js';

const SAMPLE_NOTE = 'Bundled sample value, not independently trusted';
const EMPTY = { expectedSigner: '', expectedCount: '', expectedHeadHash: '', allowUnchained: false };

function keyOf(text, opts) { return JSON.stringify([text, opts.expectedSigner, opts.expectedCount, opts.expectedHeadHash, opts.allowUnchained]); }

export function VerifyView({ pg }) {
  const [text, setText] = useState('');
  const [opts, setOpts] = useState(EMPTY);
  const [fromSample, setFromSample] = useState({});
  const [result, setResult] = useState(null);
  const key = keyOf(text, opts);
  const shown = result && result.key === key ? result.value : null;

  const loadSample = (id) => {
    track('sample_verify');
    const s = pg.SAMPLES[id];
    setText(s.text);
    const next = { ...EMPTY, expectedSigner: s.signer ?? '', expectedCount: s.count != null ? String(s.count) : '', expectedHeadHash: s.head ?? '' };
    setOpts(next);
    setFromSample({ expectedSigner: !!s.signer, expectedCount: s.count != null, expectedHeadHash: !!s.head });
  };
  const onText = (v) => {
    setText(v);
    // Clear ONLY the expectations that still carry sample provenance; a value the
    // user supplied independently must survive edits to the text.
    setOpts((o) => ({ ...o, ...(fromSample.expectedSigner ? { expectedSigner: '' } : {}), ...(fromSample.expectedCount ? { expectedCount: '' } : {}), ...(fromSample.expectedHeadHash ? { expectedHeadHash: '' } : {}) }));
    setFromSample({});
  };
  const setOpt = (k, v) => { setOpts((o) => ({ ...o, [k]: v })); setFromSample((f) => ({ ...f, [k]: false })); };
  const onVerify = () => {
    track('run_verify');
    let value;
    try { value = pg.verifyAll(text, opts); }
    catch (err) { value = { overall: 'failed', kind: 'invalid', rows: [], chain: null, checkpoint: { state: 'invalid' }, problems: [`verifier_error: ${err && err.message ? err.message : String(err)}`] }; }
    track(`verify_${value.overall === 'ok' ? 'ok' : value.overall === 'invalid' ? 'invalid' : 'failed'}`);
    setResult({ key, value });
  };

  return (
    <section className="view" data-view="verify">
      <p className="lead">Paste one signed receipt (JSON) or a receipt log (one JSON object per line). Verification runs the published <code>@bolyra/receipts@{pg.RECEIPTS_VERSION}</code> in your browser. Nothing you paste leaves this page.</p>
      <div className="samples">
        <span className="samples-label">Samples from the repository:</span>
        {Object.entries(pg.SAMPLES).map(([id, s]) => <button key={id} type="button" className="btn btn-sm" onClick={() => loadSample(id)} data-sample={id}>{s.label}</button>)}
      </div>
      <Field label="Receipt or receipt log">
        <textarea className="input mono" rows={10} value={text} onChange={(e) => onText(e.target.value)} spellCheck={false} data-field="input" placeholder='{"id": "...", "payload": {...}, "signature": {...}}' />
      </Field>
      <div className="grid-2">
        <Field label="Expected signer (0x address)" hint={fromSample.expectedSigner ? SAMPLE_NOTE : 'Obtain this from the operator out of band. Blank: the signer shown is only the receipt’s own claim.'}>
          <input className="input mono" value={opts.expectedSigner} onChange={(e) => setOpt('expectedSigner', e.target.value)} data-field="expectedSigner" placeholder="0x…" />
        </Field>
        <Field label="Expected receipt count" hint={fromSample.expectedCount ? SAMPLE_NOTE : 'From an anchored checkpoint. Blank: tail truncation is undetectable.'}>
          <input className="input mono" value={opts.expectedCount} onChange={(e) => setOpt('expectedCount', e.target.value)} data-field="expectedCount" inputMode="numeric" placeholder="e.g. 3" />
        </Field>
        <Field label="Expected head hash" hint={fromSample.expectedHeadHash ? SAMPLE_NOTE : 'The anchored receiptHash of the last receipt.'}>
          <input className="input mono" value={opts.expectedHeadHash} onChange={(e) => setOpt('expectedHeadHash', e.target.value)} data-field="expectedHeadHash" placeholder="0x…" />
        </Field>
        <Field label="Unchained prefix" hint="Tolerate receipts that predate chaining at the start of the log. Their order is not protected.">
          <span className="check"><input type="checkbox" checked={opts.allowUnchained} onChange={(e) => setOpt('allowUnchained', e.target.checked)} data-field="allowUnchained" /> allow</span>
        </Field>
      </div>
      <div className="actions">
        <button type="button" className="btn btn-primary" onClick={onVerify} data-action="verify">Verify</button>
        {result && !shown ? <span className="muted">Input or options changed. Results cleared; verify again.</span> : null}
      </div>
      {shown ? <Results r={shown} expectedSigner={opts.expectedSigner.trim() !== ''} /> : null}
      <p className="fineprint">A valid signature establishes that the key controlling <code>signer</code> signed these claims. It does not establish who controls that key, that the action executed, that every action was receipted, or that the decision was right.</p>
    </section>
  );
}

function Overall({ overall }) {
  if (overall === 'ok') return <Status kind="ok">All checks passed</Status>;
  if (overall === 'failed') return <Status kind="bad">Verification failed</Status>;
  return <Status kind="warn">Not verified: input or options invalid</Status>;
}

function checkpointLine(cp, overall, kind) {
  switch (cp.state) {
    case 'not-applicable': return 'Not applicable (single unchained receipt).';
    case 'missing': return 'No checkpoint supplied: a truncated tail is undetectable from the log alone.';
    case 'partial': return `Partial checkpoint (${cp.count !== 'absent' ? 'count only' : 'head only'}): ${cp.count !== 'absent' ? cp.count : cp.head}.`;
    case 'mismatch': return `Checkpoint mismatch: count ${cp.count}, head ${cp.head}.`;
    case 'matched-but-failed': return 'Checkpoint values match, but verification failed (see rows).';
    case 'unchecked': return 'Checkpoint not checked: the chain verifier failed before comparing it (see problems).';
    case 'matched': return overall === 'ok' ? 'Valid chain matches the supplied head and count; complete system coverage is not established.' : 'Checkpoint values match, but verification failed (see rows).';
    default: return `Checkpoint: ${cp.state}.`;
  }
}

function instanceText(inst) {
  if (inst.code === 'ok') return 'ok: reference matches the carried preimage (not compared against independently supplied facts)';
  if (inst.code === 'absent') return 'absent: no instance binding carried; not verified';
  return `${inst.code}${inst.detail ? `: ${inst.detail}` : ''}`;
}

function Results({ r, expectedSigner }) {
  return (
    <div className="results" data-results data-overall={r.overall}>
      <div className="results-head"><Overall overall={r.overall} /> <span className="muted">kind: {r.kind}</span></div>
      {r.problems.length > 0 ? <ul className="problems">{r.problems.map((p, i) => <li key={i}>{p}</li>)}</ul> : null}
      {r.rows.length > 0 ? (
        <div className="table-wrap"><table className="rows">
          <thead><tr><th>#</th><th>Envelope</th><th>Signature</th><th>Expected signer</th><th>Instance binding</th></tr></thead>
          <tbody>{r.rows.map((row) => (
            <tr key={row.index} data-row={row.index}>
              <td className="mono">{row.index}</td>
              <td>{row.envelope.ok ? <Status kind="ok">ok</Status> : <Status kind="bad">not verified</Status>}{row.envelope.ok ? null : <div className="muted small">{row.envelope.problems.join('; ')}</div>}</td>
              <td data-cell="signature">{row.signature === 'valid' ? <Status kind="ok">valid</Status> : row.signature === 'invalid' ? <Status kind="bad">invalid</Status> : <Status kind="neutral">not run</Status>}</td>
              <td data-cell="signer">{row.signerMatch === 'matched' ? <Status kind="ok">matched</Status> : row.signerMatch === 'mismatch' ? <Status kind="bad">mismatch</Status> : <span className="muted small">not checked{expectedSigner ? '' : ': the address in the receipt is its own claim'}</span>}</td>
              <td data-cell="instance">{row.instance.code === 'ok' ? <Status kind="ok">ok</Status> : row.instance.code === 'absent' ? <Status kind="neutral">absent</Status> : <Status kind="bad">{row.instance.code}</Status>}<div className="muted small">{instanceText(row.instance)}</div></td>
            </tr>
          ))}</tbody>
        </table></div>
      ) : null}
      {r.rows.some((row) => row.problems.length > 0) ? <ul className="problems">{r.rows.flatMap((row) => row.problems.map((p, i) => <li key={`${row.index}-${i}`}>#{row.index}: {p}</li>))}</ul> : null}
      {r.chain ? (
        <div className="chain" data-chain>
          <div><strong>Chain:</strong> {r.chain.count} receipt{r.chain.count === 1 ? '' : 's'}, {r.chain.chained} chained{r.chain.unchainedPrefix ? ', unchained prefix accepted (its ordering is not protected by chaining)' : ''}. {r.chain.headHash ? <>Head <code>{r.chain.headHash}</code></> : null}</div>
          {r.chain.issues.length > 0 ? (
            <div className="table-wrap"><table className="rows"><thead><tr><th>Index</th><th>Code</th><th>Message</th></tr></thead>
              <tbody>{r.chain.issues.map((i, n) => <tr key={n}><td className="mono">{i.index}</td><td className="mono">{i.code}</td><td>{i.message}</td></tr>)}</tbody></table></div>
          ) : <div className="muted">No chain issues.</div>}
        </div>
      ) : null}
      <div className="checkpoint" data-checkpoint={r.checkpoint.state}><strong>Checkpoint:</strong> {checkpointLine(r.checkpoint, r.overall, r.kind)}</div>
    </div>
  );
}
