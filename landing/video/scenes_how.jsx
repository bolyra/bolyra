// scenes_how.jsx — "How Bolyra works": mandate in, verdict out, receipt signed.
// Every output-looking string below is taken from `npx @bolyra/mpp demo`
// (integrations/mpp-payments/src/demo/cli.ts) and the classical gate
// (integrations/mpp-payments/src/classical.ts, deny.ts, tiers.ts). The path shown
// is the classical (operator-signed) MPP path. Nothing here claims zero-knowledge
// verification, and nothing settles.
//
// Depends on animations.jsx (Sprite, useTime, Easing, clamp, interpolate) and
// system.jsx (C, DISPLAY, MONO, fadeAt, Backdrop, Kicker, Caption, AgentChip,
// Packet, ShieldGlyph). system.jsx is used unchanged.

// ── Shared bits ──────────────────────────────────────────────────────────────

const HOW = {
  agent: 'shopper-bot',
  audience: 'api.merchant.example',
  program: 'mpp',
  capability: 'mpp:financial:small',
  operatorKey: 'operator key · configured trusted issuer',
};

function rise(appear, px = 24) {
  return (1 - Easing.easeOutCubic(clamp(appear, 0, 1))) * px;
}

function Mono({ children, size = 18, color = C.ink, weight = 400, style }) {
  return (
    <span style={{ fontFamily: MONO, fontSize: size, color, fontWeight: weight, whiteSpace: 'nowrap', ...style }}>
      {children}
    </span>
  );
}

function SmallLabel({ children, color = C.inkFaint, style }) {
  return (
    <div style={{ fontFamily: MONO, fontSize: 13, color, letterSpacing: '0.1em', textTransform: 'uppercase', whiteSpace: 'nowrap', ...style }}>
      {children}
    </div>
  );
}

// Local verdict stamp: the words are the verdict words, not the shared VERIFIED/REJECTED labels.
function VerdictStamp({ x, y, kind = 'allow', appear = 1 }) {
  const ok = kind === 'allow';
  const color = ok ? C.ok : C.bad;
  const s = appear < 0.5 ? (1.6 - 1.2 * Easing.easeOutBack(clamp(appear / 0.5, 0, 1))) : 1;
  const rot = ok ? -7 : 6;
  return (
    <div style={{
      position: 'absolute', left: x, top: y,
      transform: `translate(-50%,-50%) rotate(${rot}deg) scale(${s})`,
      opacity: clamp(appear / 0.3, 0, 1),
      display: 'flex', alignItems: 'center', gap: 10,
      padding: '10px 20px', borderRadius: 12,
      background: ok ? C.okSoft : C.badSoft, border: `2px solid ${color}`,
    }}>
      {ok
        ? <svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={color} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="26" height="26" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={color} strokeWidth="2.6" strokeLinecap="round" /></svg>}
      <span style={{ fontFamily: MONO, fontSize: 22, fontWeight: 600, letterSpacing: '0.1em', color }}>{ok ? 'allow' : 'deny'}</span>
    </div>
  );
}

// The honesty label stays on screen from the first simulated output to the end.
function HonestyLabel({ appear = 1 }) {
  return (
    <div style={{
      position: 'absolute', right: 40, bottom: 34, opacity: clamp(appear, 0, 1),
      fontFamily: MONO, fontSize: 17, color: C.inkDim, letterSpacing: '0.01em', whiteSpace: 'nowrap',
      padding: '8px 14px', borderRadius: 8, background: 'rgba(10,13,18,0.7)', border: `1px solid ${C.border}`,
    }}>
      Illustration of <span style={{ color: C.brand }}>npx @bolyra/mpp demo</span>: real verification path, stub transport; nothing settles.
    </div>
  );
}

// ── S0 Title ─────────────────────────────────────────────────────────────────
function TitleScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  const a1 = clamp(t / 0.8, 0, 1);
  const a2 = clamp((t - 1.2) / 0.8, 0, 1);
  const a3 = clamp((t - 2.0) / 0.8, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 34 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 22, opacity: a1, transform: `translateY(${rise(a1)}px)` }}>
          <ShieldGlyph color={C.brand} size={64} />
          <div style={{ fontFamily: DISPLAY, fontSize: 96, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em' }}>Bolyra</div>
        </div>
        <div style={{ opacity: a2, transform: `translateY(${rise(a2)}px)`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 16 }}>
          <Kicker>How Bolyra works</Kicker>
          <div style={{ fontFamily: DISPLAY, fontSize: 60, fontWeight: 600, color: C.ink, letterSpacing: '-0.02em', textAlign: 'center' }}>
            One question before an agent acts.
          </div>
        </div>
        <div style={{ opacity: a3, transform: `translateY(${rise(a3)}px)`, fontFamily: MONO, fontSize: 27, color: C.inkDim, textAlign: 'center', maxWidth: 1300, lineHeight: 1.45 }}>
          Did an operator authorize <span style={{ color: C.ink }}>this agent</span>, for <span style={{ color: C.ink }}>this action</span>, at <span style={{ color: C.ink }}>this audience</span>?
        </div>
      </div>
    </div>
  );
}

// ── S1 Mandate ───────────────────────────────────────────────────────────────
function OperatorCard({ x, y, appear = 1, signing = 0 }) {
  const glow = 0.3 + 0.7 * signing;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise(appear)}px)`, opacity: appear,
      width: 330, boxSizing: 'border-box', padding: '22px 24px',
      background: C.panelStrong, border: `1px solid ${signing > 0 ? C.brandLine : C.border}`, borderRadius: 18,
      boxShadow: `0 0 ${10 + glow * 30}px ${C.brandSoft}, 0 24px 60px rgba(0,0,0,0.5)`,
      display: 'flex', flexDirection: 'column', gap: 12,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14 }}>
        <div style={{ width: 44, height: 44, borderRadius: 12, background: C.brandSoft, border: `1px solid ${C.brandLine}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><circle cx="8.5" cy="12" r="4" stroke={C.brand} strokeWidth="1.8" /><path d="M12.5 12h8m-3 0v3m-3-3v2.4" stroke={C.brand} strokeWidth="1.8" strokeLinecap="round" /></svg>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 3 }}>
          <Mono size={21} weight={500}>OPERATOR</Mono>
          <SmallLabel>a human or org with a key</SmallLabel>
        </div>
      </div>
      <div style={{ fontFamily: MONO, fontSize: 17, color: C.inkDim, lineHeight: 1.45 }}>
        signs one mandate for one agent:<br />what it may ask for, where, until when.
      </div>
    </div>
  );
}

const MANDATE_FIELDS = [
  { k: 'agent_name', v: HOW.agent },
  { k: 'project_key', v: HOW.audience, note: 'the audience' },
  { k: 'program', v: HOW.program },
  { k: 'model', v: '(model identifier, omitted here)', dim: true },
  { k: 'capabilities', v: `[${HOW.capability}]` },
  { k: 'expiry', v: '+1h', note: 'a Unix timestamp in the binding' },
];

function MandateCard({ x, y, appear = 1, reveal = 0, sealed = 0, subline = 0 }) {
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise(appear)}px)`, opacity: appear,
      width: 760, boxSizing: 'border-box',
      background: 'rgba(14,18,24,0.92)', border: `1px solid ${sealed > 0 ? C.brandLine : C.border}`, borderRadius: 18,
      boxShadow: '0 24px 60px rgba(0,0,0,0.5)', overflow: 'hidden',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '18px 26px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <div style={{ width: 10, height: 10, borderRadius: 5, background: sealed > 0 ? C.ok : C.inkDim, boxShadow: sealed > 0 ? `0 0 12px ${C.ok}` : 'none' }} />
          <Mono size={19} weight={500} style={{ letterSpacing: '0.04em' }}>MANDATE</Mono>
          <SmallLabel>the signed binding</SmallLabel>
        </div>
        <div style={{ opacity: clamp(sealed, 0, 1), transform: `scale(${0.8 + 0.2 * clamp(sealed, 0, 1)})`, display: 'flex', alignItems: 'center', gap: 8, padding: '6px 12px', borderRadius: 8, background: C.okSoft, border: `1px solid ${C.ok}` }}>
          <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <Mono size={15} color={C.ok} weight={600} style={{ letterSpacing: '0.08em' }}>operator-signed</Mono>
        </div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', padding: '8px 0' }}>
        {MANDATE_FIELDS.map((f, i) => {
          const a = clamp(reveal - i, 0, 1);
          return (
            <div key={f.k} style={{ display: 'flex', alignItems: 'baseline', gap: 18, padding: '11px 26px', opacity: a, transform: `translateX(${(1 - a) * 14}px)` }}>
              <Mono size={18} color={C.inkFaint} style={{ width: 170, display: 'inline-block' }}>{f.k}</Mono>
              <Mono size={21} color={f.dim ? C.inkDim : C.ink} weight={f.dim ? 400 : 500}>{f.v}</Mono>
              {f.note && <Mono size={15} color={C.inkFaint}>· {f.note}</Mono>}
            </div>
          );
        })}
      </div>
      <div style={{ padding: '14px 26px 18px', borderTop: `1px solid ${C.inkGhost}`, opacity: clamp(subline, 0, 1), fontFamily: MONO, fontSize: 17, color: C.inkDim, lineHeight: 1.5 }}>
        <span style={{ color: C.ink }}>small</span>: under $100 per request · reusable until expiry · a per-request ceiling, not a budget
      </div>
    </div>
  );
}

function MandateScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  const opIn = clamp(t / 0.7, 0, 1);
  const cardIn = clamp((t - 0.6) / 0.7, 0, 1);
  const signing = clamp((t - 1.4) / 0.6, 0, 1) * (1 - clamp((t - 5.0) / 0.8, 0, 1));
  const reveal = clamp((t - 1.8) / 0.42, 0, 6.2);
  const sealed = clamp((t - 4.5) / 0.5, 0, 1);
  const subline = clamp((t - 4.8) / 0.6, 0, 1);
  // a signature pulse travelling from the operator to the mandate while fields fill in
  const pulseT = (t - 1.6) / 1.0;
  const pulse = pulseT > 0 && pulseT < 1 ? pulseT : -1;
  const px = interpolate([0, 1], [560, 820], Easing.easeInOutCubic)(clamp(pulse, 0, 1));
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <OperatorCard x={400} y={560} appear={opIn} signing={signing} />
      <MandateCard x={1240} y={560} appear={cardIn} reveal={reveal} sealed={sealed} subline={subline} />
      {pulse >= 0 && (
        <div style={{ position: 'absolute', left: px, top: 560, transform: 'translate(-50%,-50%)', width: 14, height: 14, borderRadius: 7, background: C.brand, boxShadow: `0 0 18px ${C.brand}`, opacity: 1 - Math.abs(pulse - 0.5) * 0.4 }} />
      )}
      <div style={{ position: 'absolute', left: 690, top: 596, opacity: signing, fontFamily: MONO, fontSize: 14, color: C.inkFaint, letterSpacing: '0.1em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
        signs
      </div>
    </div>
  );
}

// ── S2 Verdict ───────────────────────────────────────────────────────────────
const GATE_ROWS = [
  'trusted operator',
  'binding signature',
  'request fields match',
  'capability in the signed set',
  'model identifier (consistency, not the running model)',
  'scope consistency',
  'permission bits within scope',
  'expiry',
];

// rowStates: array of 'idle' | 'running' | 'pass' | 'fail' | 'skip'
function GateChecklist({ rowStates }) {
  const colorFor = (s) => s === 'pass' ? C.ok : s === 'fail' ? C.bad : s === 'running' ? C.brand : C.inkFaint;
  return (
    <div style={{ display: 'flex', flexDirection: 'column' }}>
      <div style={{ padding: '10px 22px 6px' }}>
        <SmallLabel>selected checks, in the gate's order</SmallLabel>
      </div>
      {GATE_ROWS.map((label, i) => {
        const s = rowStates[i] || 'idle';
        const col = colorFor(s);
        const dim = s === 'skip' ? 0.5 : s === 'idle' ? 0.55 : 1;
        return (
          <div key={label} data-gate-row={i + 1} data-state={s} style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '8px 22px', opacity: dim, borderTop: i ? `1px solid ${C.inkGhost}` : 'none' }}>
            <div style={{ width: 22, height: 22, borderRadius: 6, flexShrink: 0, border: `1.5px solid ${col}`, background: s === 'pass' ? C.okSoft : s === 'fail' ? C.badSoft : 'transparent', display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
              {s === 'pass' && <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg>}
              {s === 'fail' && <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={C.bad} strokeWidth="3" strokeLinecap="round" /></svg>}
              {s === 'running' && <div style={{ width: 8, height: 8, borderRadius: 4, background: C.brand, boxShadow: `0 0 10px ${C.brand}` }} />}
            </div>
            <Mono size={18} color={s === 'idle' || s === 'skip' ? C.inkDim : C.ink}>{label}</Mono>
            {s === 'skip' && <Mono size={13} color={C.inkFaint} style={{ letterSpacing: '0.08em' }}>not reached</Mono>}
          </div>
        );
      })}
    </div>
  );
}

function RelyingPartyPanel({ x, y, appear = 1, rowStates, footnote = 1 }) {
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise(appear)}px)`, opacity: appear,
      width: 820, boxSizing: 'border-box', padding: 18,
      background: C.panel, border: `1px dashed ${C.borderStrong}`, borderRadius: 22,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '2px 8px 14px' }}>
        <Mono size={19} weight={500} style={{ letterSpacing: '0.06em' }}>RELYING PARTY</Mono>
        <SmallLabel>the API being called; it runs the gate</SmallLabel>
      </div>
      <div style={{ background: 'rgba(14,18,24,0.94)', border: `1px solid ${C.brandLine}`, borderRadius: 16, overflow: 'hidden', boxShadow: `0 0 0 1px ${C.brandSoft}, 0 24px 60px rgba(0,0,0,0.5)` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 22px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <ShieldGlyph color={C.brand} size={26} />
          <Mono size={19} weight={500} style={{ letterSpacing: '0.04em' }}>GATE</Mono>
          <SmallLabel>bolyraGate · verifies before any payment logic</SmallLabel>
        </div>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 6, padding: '12px 22px', borderBottom: `1px solid ${C.border}` }}>
          <div style={{ display: 'flex', gap: 14, alignItems: 'baseline' }}><Mono size={15} color={C.inkFaint} style={{ width: 160, display: 'inline-block' }}>trusted operators</Mono><Mono size={17} color={C.inkDim}>[ {HOW.operatorKey} ]</Mono></div>
          <div style={{ display: 'flex', gap: 14, alignItems: 'baseline' }}><Mono size={15} color={C.inkFaint} style={{ width: 160, display: 'inline-block' }}>audience</Mono><Mono size={17}>{HOW.audience}</Mono><Mono size={16} color={C.inkDim}>· its own identity, never from the request</Mono></div>
        </div>
        <GateChecklist rowStates={rowStates} />
        <div style={{ padding: '10px 22px 14px', borderTop: `1px solid ${C.inkGhost}`, opacity: footnote, fontFamily: MONO, fontSize: 16, color: C.inkDim }}>
          routes map amounts to tiers; the binding has no path field
        </div>
      </div>
    </div>
  );
}

function ProblemCard({ x, y, appear = 1, status, code, title }) {
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise(appear)}px)`, opacity: clamp(appear, 0, 1),
      width: 520, boxSizing: 'border-box', padding: '16px 22px',
      background: 'rgba(14,18,24,0.94)', border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.bad}`, borderRadius: 14,
      boxShadow: '0 20px 50px rgba(0,0,0,0.45)', display: 'flex', flexDirection: 'column', gap: 8,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
        <Mono size={24} color={C.bad} weight={600}>{status}</Mono>
        <Mono size={18} color={C.ink} weight={500}>{code}</Mono>
      </div>
      <Mono size={17} color={C.inkDim}>"{title}"</Mono>
      <SmallLabel>application/problem+json · RFC 9457</SmallLabel>
    </div>
  );
}

function RequestLine({ x, y, appear = 1, method, path, amount, mandate }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise(appear)}px)`, opacity: clamp(appear, 0, 1), width: 420, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center' }}>
      <div style={{ display: 'flex', gap: 12, alignItems: 'baseline', padding: '10px 16px', borderRadius: 10, background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}` }}>
        <Mono size={18} color={C.ok}>{method}</Mono>
        <Mono size={18}>{path}</Mono>
        <Mono size={18} color={C.brand} weight={500}>{amount}</Mono>
      </div>
      <Mono size={15} color={mandate === 'no header' ? C.bad : C.inkDim}>{mandate}</Mono>
    </div>
  );
}

// Phase model for the three requests. Local time t in [0, 20].
//   A: 1.0–7.5   B: 7.5–14.0   C: 14.0–20.0
const REQUESTS = [
  { start: 1.0, end: 7.5, method: 'GET', path: '/api/report', amount: '$25', mandate: '+ mandate', outcome: 'allow', status: '200', sub: 'an allow lets the payment flow proceed; nothing settles in this demo' },
  { start: 7.5, end: 14.0, method: 'GET', path: '/api/bulk-export', amount: '$500', mandate: 'same mandate', outcome: 'deny', status: '403', code: 'request_mismatch', title: 'Mandate Does Not Cover This Request', failRow: 4, sub: '$500 maps to tier medium; the signed set holds only small' },
  { start: 14.0, end: 20.0, method: 'GET', path: '/api/report', amount: '$25', mandate: 'no header', outcome: 'deny', status: '401', code: 'missing_authorization', title: 'Authorization Required', failRow: 0, sub: 'no 402 challenge is ever issued' },
];
const ROW_STEP = 0.26;
const ROWS_START = 1.0; // seconds after the request starts, after the packet arrives

function phaseFor(t) {
  for (const r of REQUESTS) {
    if (t >= r.start && t < r.end) return { r, local: t - r.start };
  }
  return null;
}

function rowStatesFor(r, local) {
  if (!r) return GATE_ROWS.map(() => 'idle');
  if (r.outcome === 'deny' && r.failRow === 0) return GATE_ROWS.map(() => 'idle'); // 401: gate-local, no check runs
  const n = GATE_ROWS.length;
  return GATE_ROWS.map((_, i) => {
    const at = ROWS_START + i * ROW_STEP;
    const failing = r.outcome === 'deny' && i + 1 === r.failRow;
    const beyond = r.outcome === 'deny' && i + 1 > r.failRow;
    if (local < at) return beyond && local >= ROWS_START + (r.failRow - 1) * ROW_STEP + 0.25 ? 'skip' : 'idle';
    if (failing) return local < at + 0.25 ? 'running' : 'fail';
    if (beyond) return 'skip';
    return local < at + 0.2 ? 'running' : 'pass';
  });
}

function verdictTime(r) {
  if (r.outcome === 'deny' && r.failRow === 0) return 1.3;
  const lastRow = r.outcome === 'allow' ? GATE_ROWS.length : r.failRow;
  return ROWS_START + (lastRow - 1) * ROW_STEP + 0.6;
}

function VerdictScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  const panelIn = clamp(t / 0.8, 0, 1);
  const agentIn = clamp((t - 0.3) / 0.6, 0, 1);
  const ph = phaseFor(t);
  const r = ph ? ph.r : null;
  const local = ph ? ph.local : 0;
  const rowStates = rowStatesFor(r, local);
  const reqIn = r ? clamp(local / 0.5, 0, 1) * (1 - clamp((local - (r.end - r.start) + 0.5) / 0.5, 0, 1)) : 0;
  // packet travels from the agent to the panel during the first second of each request
  const packetP = r ? clamp((local - 0.2) / 0.9, 0, 1) : 0;
  const packetX = interpolate([0, 1], [470, 880], Easing.easeInOutCubic)(packetP);
  const packetVisible = r && local > 0.2 && local < 1.15;
  const vt = r ? verdictTime(r) : 0;
  const verdictIn = r ? clamp((local - vt) / 0.5, 0, 1) : 0;
  const subIn = r ? clamp((local - vt - 0.6) / 0.5, 0, 1) : 0;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <AgentChip x={330} y={470} label={HOW.agent} appear={agentIn} />
      {r && <RequestLine x={330} y={610} appear={reqIn} method={r.method} path={r.path} amount={r.amount} mandate={r.mandate} />}
      {packetVisible && <Packet x={packetX} y={470} label={r.mandate === 'no header' ? 'request' : 'request + mandate'} color={r.mandate === 'no header' ? C.bad : C.brand} />}
      <RelyingPartyPanel x={1300} y={600} appear={panelIn} rowStates={rowStates} />
      {r && r.outcome === 'allow' && verdictIn > 0 && (
        <React.Fragment>
          <VerdictStamp x={330} y={760} kind="allow" appear={verdictIn} />
          <div style={{ position: 'absolute', left: 330, top: 830, transform: 'translate(-50%,-50%)', opacity: verdictIn, padding: '6px 14px', borderRadius: 8, background: C.okSoft, border: `1px solid ${C.ok}` }}>
            <Mono size={20} color={C.ok} weight={600}>{r.status}</Mono>
          </div>
        </React.Fragment>
      )}
      {r && r.outcome === 'deny' && verdictIn > 0 && (
        <React.Fragment>
          <VerdictStamp x={330} y={740} kind="deny" appear={verdictIn} />
          <ProblemCard x={330} y={880} appear={verdictIn} status={r.status} code={r.code} title={r.title} />
        </React.Fragment>
      )}
      {r && subIn > 0 && (
        <div style={{ position: 'absolute', left: 330, top: r.outcome === 'allow' ? 920 : 985, transform: 'translate(-50%,-50%)', width: 520, textAlign: 'center', opacity: subIn, fontFamily: MONO, fontSize: 16, color: C.inkDim, lineHeight: 1.45 }}>
          {r.sub}
        </div>
      )}
    </div>
  );
}

// ── S3 Receipts ──────────────────────────────────────────────────────────────
function Field({ k, v, color = C.ink }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <span style={{ fontFamily: MONO, fontSize: 12, color: C.inkFaint, letterSpacing: '0.1em', textTransform: 'uppercase' }}>{k}</span>
      <span style={{ fontFamily: MONO, fontSize: 18, color, fontWeight: 500, whiteSpace: 'nowrap' }}>{v}</span>
    </div>
  );
}

function ReceiptCard({ x, y, appear, data, width = 720 }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const ok = data.allowed;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${(1 - a) * 40}px)`, opacity: a,
      width, boxSizing: 'border-box',
      background: 'rgba(14,18,24,0.9)', border: `1px solid ${C.border}`, borderLeft: `3px solid ${ok ? C.ok : C.bad}`,
      borderRadius: 14, padding: '18px 26px', display: 'flex', flexDirection: 'column', gap: 12,
      boxShadow: '0 20px 50px rgba(0,0,0,0.45)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <Mono size={20} weight={600} style={{ letterSpacing: '0.04em' }}>seq={data.seq}</Mono>
          <Mono size={18} color={ok ? C.ok : C.bad}>allowed={String(ok)}</Mono>
        </div>
        <SmallLabel>ES256K</SmallLabel>
      </div>
      <div style={{ display: 'flex', gap: 36 }}>
        {data.fields.map((f) => <Field key={f.k} k={f.k} v={f.v} color={f.color || C.ink} />)}
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 6, borderTop: `1px solid ${C.inkGhost}` }}>
        <SmallLabel>prev</SmallLabel>
        <Mono size={15} color={C.brand}>{data.prev}</Mono>
      </div>
    </div>
  );
}

function ReceiptChainScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  const receipts = [
    { seq: 1, allowed: true, prev: 'hash of seq=0', fields: [{ k: 'amount', v: '$25' }, { k: 'merchant', v: HOW.audience }, { k: 'agent', v: HOW.agent }] },
    { seq: 2, allowed: false, prev: 'hash of seq=1', fields: [{ k: 'amount', v: '$500' }, { k: 'reason', v: 'request_mismatch', color: C.bad }, { k: 'agent', v: HOW.agent }] },
  ];
  const leftIn = clamp(t / 0.8, 0, 1);
  const linkIn = clamp((t - 2.4) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <div style={{ position: 'absolute', left: 150, top: 400, width: 560, display: 'flex', flexDirection: 'column', gap: 22, opacity: leftIn, transform: `translateY(${rise(leftIn)}px)` }}>
        <Kicker>{'> AUDIT TRAIL'}</Kicker>
        <div style={{ fontFamily: DISPLAY, fontSize: 62, fontWeight: 600, color: C.ink, letterSpacing: '-0.025em', lineHeight: 1.04 }}>
          A signed receipt<br />for every decision.
        </div>
        <div style={{ fontFamily: MONO, fontSize: 20, color: C.inkDim, lineHeight: 1.55 }}>
          signed by the relying party's gate (not the operator)<br />
          ES256K · hash-chained per gate<br />
          verifiable offline with the gate signer's public key
        </div>
        <SmallLabel color={C.inkDim}>two of the four receipts the demo signs</SmallLabel>
      </div>
      {receipts.map((r, i) => (
        <ReceiptCard key={r.seq} x={1330} y={440 + i * 250} data={r} appear={clamp((t - (0.8 + i * 0.9)) / 0.6, 0, 1)} />
      ))}
      <div style={{ position: 'absolute', left: 1330, top: 565, transform: 'translate(-50%,-50%)', opacity: linkIn, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 2 }}>
        <div style={{ width: 2, height: 22, background: C.brandLine }} />
        <Mono size={13} color={C.brand} style={{ letterSpacing: '0.1em' }}>prevReceiptHash</Mono>
        <div style={{ width: 2, height: 22, background: C.brandLine }} />
      </div>
    </div>
  );
}

// ── S4 Boundary ──────────────────────────────────────────────────────────────
const BOUNDARY_LINES = [
  'Bolyra verification does not constrain routes that do not invoke it.',
  'The audience is an identity the relying party claims for itself.',
  'The operator decides the scope; the gate enforces it.',
];

function BoundaryScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 26, width: 1240, marginTop: 120 }}>
        {BOUNDARY_LINES.map((line, i) => {
          const a = clamp((t - (0.6 + i * 0.9)) / 0.6, 0, 1);
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 22, opacity: a, transform: `translateX(${(1 - a) * 18}px)`, padding: '22px 30px', borderRadius: 14, background: C.panel, border: `1px solid ${C.border}` }}>
              <div style={{ width: 10, height: 10, borderRadius: 5, background: C.brand, boxShadow: `0 0 12px ${C.brand}`, flexShrink: 0 }} />
              <div style={{ fontFamily: DISPLAY, fontSize: 36, fontWeight: 500, color: C.ink, letterSpacing: '-0.01em' }}>{line}</div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// ── S5 CTA ───────────────────────────────────────────────────────────────────
function HowCTA({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.3);
  const r = rise(clamp(t / 0.7, 0, 1), 26);
  const cmdIn = clamp((t - 0.9) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ transform: `translateY(${r}px)`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 30 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
          <ShieldGlyph color={C.brand} size={68} />
          <div style={{ fontFamily: DISPLAY, fontSize: 104, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em' }}>Bolyra</div>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 28, color: C.inkDim, letterSpacing: '0.02em', whiteSpace: 'nowrap' }}>
          Mandate in, verdict out, receipt signed.
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 8, padding: '18px 30px', borderRadius: 12, background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 27, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span>&nbsp;npx <span style={{ color: C.brand }}>@bolyra/mpp</span> demo
        </div>
        <div style={{ marginTop: 6, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          open spec (draft-kondoju-evc) · open conformance suite · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, {
  TitleScene, MandateScene, VerdictScene, ReceiptChainScene, BoundaryScene, HowCTA, HonestyLabel, VerdictStamp,
});
