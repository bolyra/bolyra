import { useState } from 'react';
import { Field, Status, CodeBlock } from './shared.jsx';
import { track } from '../core/usage.js';

const SAMPLE_NOTE = 'Bundled sample value, not independently trusted';
const EMPTY = { header: '', resource: '', now: '', maxSeconds: '900', audience: '' };
const keyOf = (f) => JSON.stringify([f.header, f.resource, f.now, f.maxSeconds, f.audience]);
/** Render any decoded JSON value as text without coercing objects (a hostile `toString` must not throw). */
const show = (v) => (typeof v === 'string' ? v : v === undefined ? '(none)' : (typeof v === 'number' || typeof v === 'boolean' || v === null) ? String(v) : JSON.stringify(v));
const sentenceWith = (text, needle) => { const m = new RegExp(`[^.]*${needle}[^.]*\\.`).exec(text); return m ? m[0].trim() : null; };

export function DecodeView({ pg }) {
  const [f, setF] = useState(EMPTY);
  const [result, setResult] = useState(null);
  const [sampleLoaded, setSampleLoaded] = useState(false);
  const key = keyOf(f);
  const shown = result && result.key === key ? result.value : null;
  const set = (k, v) => { setF((o) => ({ ...o, [k]: v })); if (k === 'header') setSampleLoaded(false); };
  const loadSample = () => {
    track('sample_decode');
    const s = pg.X402_SAMPLES.tavily;
    setF({ header: s.header, resource: s.resource, now: String(s.now), maxSeconds: '900', audience: '' });
    setSampleLoaded(true);
  };
  const onDecode = () => {
    track('run_decode');
    const problems = [];
    if (f.header.length > pg.X402_LIMITS.MAX_PAYMENT_REQUIRED_CHARS) problems.push(`header exceeds ${pg.X402_LIMITS.MAX_PAYMENT_REQUIRED_CHARS} characters; not decoded`);
    const now = f.now.trim() === '' ? null : Number(f.now);
    if (now === null || !pg.isUnixSeconds(now)) problems.push('now must be a unix time in seconds (finite, non-negative)');
    const cap = Number(f.maxSeconds);
    if (!Number.isInteger(cap) || cap < 1 || cap > pg.X402_LIMITS.MAX_LOCAL_CHALLENGE_SECONDS) problems.push('host cap must be an integer from 1 to 900');
    if (problems.length > 0) { track('decode_invalid'); setResult({ key, value: { ok: false, problems } }); return; }
    const parsed = pg.parseChallenge(f.header); // bytes exactly as pasted: the package and the nonce are byte-sensitive
    if (!parsed.ok) { track('decode_invalid'); setResult({ key, value: { ok: false, problems: [`not usable: ${parsed.code} (reason ${parsed.reason})`] } }); return; }
    const isSample = sampleLoaded && f.header === pg.X402_SAMPLES.tavily.header;
    const legs = parsed.legs.map((entry) => {
      if (entry.leg === null) return { index: entry.index, reason: entry.reason };
      const leg = entry.leg;
      const cls = pg.classifyLeg(leg);
      let token = null;
      if (cls.hasQuoteToken) {
        const compact = leg.extra.quoteToken;
        try {
          const header = pg.peekJwsHeader(compact);
          try { token = { ok: true, header, payload: pg.inspectJwsPayload(compact), sha256: pg.tokenSha256(compact) }; }
          catch (e) { token = { ok: false, stage: 'payload', reason: e.reason, header }; }
        } catch (e) { token = { ok: false, stage: 'header', reason: e.reason }; }
      }
      return { index: entry.index, leg, cls, token, deadline: now + Math.min(leg.maxTimeoutSeconds, cap), observation: isSample && entry.index === 0 ? sentenceWith(pg.X402_SAMPLES.tavily.observation, 'differed on every call') : null };
    });
    track('decode_ok');
    setResult({ key, value: { ok: true, parsed, legs, now, cap, audience: f.audience, resource: f.resource, defaultPayeeMatch: pg.defaultPayeeMatch } }); // host inputs kept byte-exact: the matcher is byte equality
  };
  const p42 = pg.EVC_SHAPES.profile42;

  return (
    <section className="view" data-view="decode">
      <p className="lead">Paste the value of an x402 v2 <code>PAYMENT-REQUIRED</code> header (standard base64 of JSON). Decoding runs in your browser with the header and leg rules of <code>@bolyra/payment-protocols@{pg.PAYMENT_PROTOCOLS_VERSION}</code>’s local-challenge parser (a browser port, differentially tested against the package on its test corpus). Pasted content is processed in your browser and is never included in analytics requests. Nothing here verifies a signature, a mandate, or a payee.</p>
      <div className="samples">
        <span className="samples-label">Sample from the repository:</span>
        <button type="button" className="btn btn-sm" onClick={loadSample} data-sample="tavily">{pg.X402_SAMPLES.tavily.label}</button>
        {sampleLoaded ? <span className="muted small">{pg.X402_SAMPLES.tavily.source}</span> : null}
      </div>
      <Field label="PAYMENT-REQUIRED header value" hint={`Standard base64, at most ${pg.X402_LIMITS.MAX_PAYMENT_REQUIRED_CHARS} characters.`}>
        <textarea className="input mono" rows={6} value={f.header} onChange={(e) => set('header', e.target.value)} spellCheck={false} data-field="x402-header" placeholder="eyJ4NDAyVmVyc2lvbiI6MiwuLi4=" />
      </Field>
      <div className="grid-2">
        <Field label="Your proposed outbound URL (resource)" hint={sampleLoaded ? SAMPLE_NOTE : 'The exact request URL your host would pay for; host-known per §4.2, not read from the header.'}>
          <input className="input mono" value={f.resource} onChange={(e) => set('resource', e.target.value)} data-field="resource" placeholder="https://…" />
        </Field>
        <Field label="Host audience (optional)" hint="The payee identity YOUR mandate names; host policy, never read from the token.">
          <input className="input mono" value={f.audience} onChange={(e) => set('audience', e.target.value)} data-field="audience" placeholder="0x… or an issuer identity" />
        </Field>
        <Field label="Now (unix seconds)" hint={sampleLoaded ? `${SAMPLE_NOTE}: ${pg.X402_SAMPLES.tavily.nowNote}` : 'Receipt time used for the provisional deadline.'}>
          <span className="row"><input className="input mono" value={f.now} onChange={(e) => set('now', e.target.value)} data-field="now" inputMode="numeric" />
          <button type="button" className="btn btn-sm" onClick={() => set('now', String(Math.floor(Date.now() / 1000)))} data-action="use-clock">use my clock</button></span>
        </Field>
        <Field label="Host cap (seconds, ≤ 900)" hint="Provisional deadline = now + min(leg maxTimeoutSeconds, cap).">
          <input className="input mono" value={f.maxSeconds} onChange={(e) => set('maxSeconds', e.target.value)} data-field="maxSeconds" inputMode="numeric" />
        </Field>
      </div>
      <div className="actions">
        <button type="button" className="btn btn-primary" onClick={onDecode} data-action="decode">Decode</button>
        {result && !shown ? <span className="muted">Input changed. Results cleared; decode again.</span> : null}
      </div>
      {shown ? <DecodeResults r={shown} p42={p42} /> : null}
      <div className="trust" data-trust>
        <strong>What is trusted here: nothing.</strong> This page authenticates none of its inputs.
        <ul>
          <li><strong>Counterparty-declared:</strong> the pasted header, its <code>resource</code>, its legs, any quote token and that token’s <code>iss</code>, <code>aud</code> and claims.</li>
          <li><strong>Your proposed host-known outbound URL:</strong> the resource field above (§4.2 local-context paragraph); shown beside the header’s declared resource, never merged with it.</li>
          <li><strong>Your host inputs:</strong> audience, clock, cap.</li>
        </ul>
        <p className="small"><strong>§4.2 Role.</strong> <span data-statement="role">{p42.role}</span></p>
      </div>
      <div className="statements">
        <p className="small"><strong>§4.2 Applicability.</strong> <span data-statement="applicability">{p42.applicability}</span></p>
        <p className="small"><strong>§4.2 Local challenge context.</strong> <span data-statement="local-context">{p42.localContext}</span></p>
        <p className="small"><strong>§4.2 MUST NOT claim.</strong> <span data-statement="must-not-claim">{p42.mustNotClaim}</span></p>
      </div>
      <p className="fineprint">Decoding establishes nothing about payment, payee, or authorization. Source: <code>{pg.EVC_SHAPES.source.profile}</code> (sha256 {pg.EVC_SHAPES.source.profileSha256.slice(0, 12)}…), extracted at build time.</p>
    </section>
  );
}

function DecodeResults({ r, p42 }) {
  if (!r.ok) return <div className="results" data-results-decode data-decode-ok="false"><Status kind="warn">Not decoded</Status><ul className="problems">{r.problems.map((p, i) => <li key={i}>{p}</li>)}</ul></div>;
  const d = r.parsed.decoded;
  return (
    <div className="results" data-results-decode data-decode-ok="true">
      <div className="results-head"><Status kind="ok">Decoded</Status> <span className="muted">x402Version {String(d.x402Version)} · {r.parsed.legs.length} leg{r.parsed.legs.length === 1 ? '' : 's'}</span></div>
      <div className="kv small">
        <div><strong>Header SHA-256 (the local-mode nonce):</strong> <code data-nonce>{r.parsed.headerSha256}</code></div>
        <div><strong>Header-declared resource (counterparty):</strong> <code data-header-resource>{d.resource && typeof d.resource === 'object' && !Array.isArray(d.resource) ? show(d.resource.url) : show(d.resource)}</code>{d.resource && typeof d.resource === 'object' && !Array.isArray(d.resource) && d.resource.description !== undefined ? <span className="muted"> — {show(d.resource.description)}</span> : null}</div>
        <div><strong>Your proposed outbound URL (host-known):</strong> <code data-input-resource>{r.resource || '(none supplied)'}</code></div>
        {d.error !== undefined ? <div><strong>error:</strong> <code>{show(d.error)}</code></div> : null}
      </div>
      {r.legs.map((L) => <LegPanel key={L.index} L={L} r={r} p42={p42} defaultPayeeMatch={r.defaultPayeeMatch} />)}
    </div>
  );
}

function LegPanel({ L, r, p42, defaultPayeeMatch }) {
  if (!L.leg) return <div className="leg" data-leg={L.index} data-classification="unusable"><strong>Leg {L.index}:</strong> <Status kind="bad">not usable</Status> <span className="muted small">reason {L.reason}</span></div>;
  const { leg, cls, token } = L;
  const extraKeys = leg.extra ? Object.keys(leg.extra) : [];
  const tokenFact = cls.hasQuoteToken ? 'carries a quoteToken field' : 'carries no quoteToken field';
  const aud = r.audience;
  return (
    <div className="leg" data-leg={L.index} data-classification={cls.kind}>
      <div className="leg-head"><strong>Leg {L.index}</strong> <span className="muted small">scheme <code>{leg.scheme}</code> · network <code>{leg.network}</code> · asset <code>{leg.asset}</code> · amount <code>{leg.amount}</code> · maxTimeoutSeconds <code>{leg.maxTimeoutSeconds}</code></span></div>
      <div className="small"><strong>payTo:</strong> <code>{leg.payTo}</code></div>
      <div className="small"><strong>extra keys:</strong> {extraKeys.length ? extraKeys.map((k) => <code key={k}>{k}</code>) : <span className="muted">none</span>}</div>
      <div className="small"><strong>Provisional deadline:</strong> <code>{L.deadline}</code> <span className="muted">= now + min({leg.maxTimeoutSeconds}, {r.cap})</span></div>
      {L.observation ? <div className="small muted" data-observation>Spec observation for this sample leg (§4.2 non-normative example): “{L.observation}”</div> : null}
      <div className="require" data-require>
        <strong>What §4.2 would require</strong>
        {cls.kind === 'address-valued' ? (
          <div className="small">
            <p><code>payTo</code> is an address-valued string and this leg {tokenFact}. If a host uses the default payee matcher, its audience must byte-equal <code>payTo</code>.</p>
            <p data-matcher>{aud === '' ? 'Supply a host audience above to see the default-matcher outcome.' : defaultPayeeMatch(aud, leg.payTo) ? <>With audience <code>{aud}</code> under that matcher: byte-equal, so this check passes.</> : <>With audience <code>{aud}</code> under that matcher: differs, so a host would deny <code>request_mismatch</code>.</>}</p>
          </div>
        ) : cls.kind === 'placeholder-urn' && cls.hasQuoteToken && token && token.ok ? (
          <div className="small">
            <p data-shape-sentence>This has the placeholder-and-token shape discussed in §4.2; issuer signature and host configuration are not checked here.</p>
            <p><strong>A host would need</strong> (none of these checks run here):</p>
            <ol className="musts">{p42.hostMusts.map((m, i) => <li key={i}>{m}{i === 6 ? <em> — not performed by this page.</em> : null}</li>)}</ol>
          </div>
        ) : cls.kind === 'placeholder-urn' && cls.hasQuoteToken ? (
          <div className="small"><p><code>payTo</code> is the placeholder discussed in §4.2 and <code>quoteToken</code> is present but not a well-formed compact JWS ({token.stage} stage, reason <code>{token.reason}</code>). No applicability claim can be made.</p></div>
        ) : cls.kind === 'placeholder-urn' ? (
          <div className="small"><p><code>payTo</code> is the placeholder discussed in §4.2 but this leg carries no <code>quoteToken</code> field; §4.2 (8) requires the quote token in <code>extra</code>.</p></div>
        ) : (
          <div className="small"><p>The playground cannot determine whether §4.2 applies to this leg: <code>payTo</code> is neither an address-valued string nor the placeholder discussed in §4.2. This leg {tokenFact}.</p></div>
        )}
      </div>
      {cls.hasQuoteToken && token ? <TokenPanel token={token} now={r.now} /> : null}
    </div>
  );
}

function TokenPanel({ token, now }) {
  if (!token.ok) return <div className="small muted" data-token="malformed">Quote token: present, not a well-formed compact JWS ({token.stage} stage, reason {token.reason}).</div>;
  const exp = token.payload.exp;
  return (
    <div className="token" data-token="decoded">
      <div className="small"><strong>Quote token:</strong> <Status kind="neutral">Decoded; signature not verified</Status> <span className="muted">— no trusted public key configured. Header <code>kid</code>: <code data-kid>{show(token.header.kid)}</code>, <code>alg</code>: <code>{show(token.header.alg)}</code>.</span></div>
      {typeof exp === 'number' && Number.isFinite(exp) ? <div className="small muted">Inspection only: <code>exp</code> {exp} is {exp > now ? 'after' : 'before or equal to'} the <code>now</code> field ({now}).</div> : <div className="small muted">Inspection only: <code>exp</code> is {exp === undefined ? 'absent' : 'not a number'} ({show(exp)}).</div>}
      <div className="small muted">SHA-256 of the compact token (an audit handle, not a quote identifier): <code>{token.sha256}</code></div>
      <details><summary>Protected header and payload — decoded, not verified; iss/aud/claims are the token’s own statements</summary>
        <CodeBlock text={JSON.stringify({ header: token.header, payload: token.payload }, null, 2)} tall />
      </details>
    </div>
  );
}
