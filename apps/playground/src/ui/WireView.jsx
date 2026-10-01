import { CodeBlock, CopyButton } from './shared.jsx';

function Block({ id, title, json, note, collapsed }) {
  const text = JSON.stringify(json, null, 2);
  const body = <><div className="actions"><CopyButton text={text} label="Copy JSON" /></div><CodeBlock text={text} tall={collapsed} /></>;
  return (
    <div className="shape" data-shape={id}>
      <h3>{title}</h3>
      {note ? <p className="muted small">{note}</p> : null}
      {collapsed ? <details><summary>Show JSON</summary>{body}</details> : body}
    </div>
  );
}

export function WireView({ pg }) {
  const S = pg.EVC_SHAPES;
  return (
    <section className="view" data-view="wire">
      <p className="lead">The External Verifier Contract v1 on the wire: one JSON request on stdin, one fail-closed verdict on stdout. Everything below is extracted at build time from <code>{S.source.spec}</code> (document revision {S.source.revision}, sha256 {S.source.specSha256.slice(0, 12)}…); extraction contracts are checked at build and <code>--check</code> rejects stale generated output. HTTP status, title and <code>type</code> come from <code>@bolyra/mpp@{S.source.mppVersion}</code>, not from the EVC schema.</p>
      <Block id="request-example" title="Request (§2.1)" json={S.request.example} note="The bundle is abbreviated in the spec's example; an abbreviated bundle is not an executable proof input." />
      <Block id="request-schema" title="Request JSON Schema (§2.2)" json={S.request.schema} collapsed />
      <Block id="real-request" title={S.realRequest.label} json={S.realRequest.json} note={`From ${S.source.cliRequest}; bundle ${S.realRequest.bundleChars} characters.`} collapsed />
      <Block id="verdict-allow" title="Verdict: allow (§3.1)" json={S.verdict.allow} note={`An omitted kind means ${S.verdict.omittedKindMeans}.`} />
      <Block id="verdict-consume" title="Verdict: allow with host-owned nonce consumption (§3.2)" json={S.verdict.allowConsume} />
      <Block id="verdict-deny" title="Verdict: deny (§3.3)" json={S.verdict.deny} />
      <Block id="verdict-schema" title="Verdict JSON Schema (§3.4)" json={S.verdict.schema} collapsed />
      <h3>Verifier self-description: kind (§3.5)</h3>
      <div className="table-wrap"><table className="rows"><thead><tr><th>kind</th><th>Proof-system class</th><th>Product line</th><th>Examples</th></tr></thead>
        <tbody>{S.verdict.kinds.map((k) => <tr key={k.kind} data-kind={k.kind}><td className="mono">{k.kind}</td><td>{k.class}</td><td>{k.productLine}</td><td>{k.examples}</td></tr>)}</tbody></table></div>
      <p className="muted small">An omitted <code>kind</code> is read as <code>{S.verdict.omittedKindMeans}</code>.</p>
      <h3>Denial-code registry (§9) — 15 codes</h3>
      <div className="table-wrap"><table className="rows"><thead>
        <tr><th colSpan={2}>EVC §9 registry</th><th colSpan={3}>@bolyra/mpp@{S.source.mppVersion} problem+json</th></tr>
        <tr><th>code</th><th>Meaning</th><th>HTTP</th><th>title</th><th>type</th></tr></thead>
        <tbody>{S.registry.map((r) => <tr key={r.code} data-code={r.code}><td className="mono">{r.code}</td><td>{r.meaning}</td><td className="mono">{r.status}</td><td>{r.title}</td><td className="mono small">{r.type}</td></tr>)}</tbody></table></div>
      <h3>Gate-local code (not in the EVC §9 registry)</h3>
      <div className="table-wrap"><table className="rows"><thead><tr><th>code</th><th>note</th><th>HTTP</th><th>title</th><th>type</th></tr></thead>
        <tbody>{S.gateLocal.map((r) => <tr key={r.code} data-code={r.code}><td className="mono">{r.code}</td><td>{r.note}</td><td className="mono">{r.status}</td><td>{r.title}</td><td className="mono small">{r.type}</td></tr>)}</tbody></table></div>
      <h3>Worked examples (§13)</h3>
      {S.examples.map((e) => (
        <div key={e.id} className="shape" data-example={e.id}>
          <h3>§{e.id} {e.heading}</h3>
          <p className="muted small">{e.notes}</p>
          {e.request ? <div data-example-part="request"><div className="actions"><span className="small">Request</span><CopyButton text={JSON.stringify(e.request, null, 2)} label="Copy request" /></div><CodeBlock text={JSON.stringify(e.request, null, 2)} /></div> : null}
          <div data-example-part="verdict"><div className="actions"><span className="small">Verdict</span><CopyButton text={JSON.stringify(e.verdict, null, 2)} label="Copy verdict" /></div><CodeBlock text={JSON.stringify(e.verdict, null, 2)} /></div>
        </div>
      ))}
      <p className="fineprint">Sources: {S.source.spec} (revision {S.source.revision}), {S.source.cliRequest}, @bolyra/mpp@{S.source.mppVersion}. The build fails when the extraction contracts are violated; a spec edit that keeps them intact changes this page on the next build.</p>
    </section>
  );
}
