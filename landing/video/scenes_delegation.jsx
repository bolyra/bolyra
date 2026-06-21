// scenes_delegation.jsx — Delegation chains: scope-narrowing + privacy-preserving.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

const PERMS = ['READ_DATA', 'WRITE_DATA', 'FINANCIAL_SMALL'];

function DgPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500,
    }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />
      {text}
    </span>
  );
}

// permission chip: state on | off | reject
function PermChip({ label, state = 'on', appear = 1, width = 250 }) {
  const a = clamp(appear, 0, 1);
  const on = state === 'on', rej = state === 'reject';
  const color = rej ? C.bad : on ? C.brand : C.inkFaint;
  const bg = rej ? C.badSoft : on ? C.brandSoft : 'rgba(255,255,255,0.02)';
  const border = rej ? C.bad.replace(')', ' / 0.5)') : on ? C.brandLine : C.inkGhost;
  return (
    <div style={{
      width, boxSizing: 'border-box', opacity: a, transform: `scale(${0.92 + 0.08 * a})`,
      display: 'flex', alignItems: 'center', gap: 10, padding: '12px 16px', borderRadius: 10,
      background: bg, border: `1px solid ${border}`,
    }}>
      <span style={{ width: 16, height: 16, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
        {rej
          ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={color} strokeWidth="3" strokeLinecap="round" /></svg>
          : on
            ? <svg width="14" height="14" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={color} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg>
            : <span style={{ width: 11, height: 2, background: color, borderRadius: 2 }} />}
      </span>
      <span style={{ fontFamily: MONO, fontSize: 17, fontWeight: 500, letterSpacing: '0.02em',
        color: on ? C.ink : rej ? C.bad : C.inkFaint,
        textDecoration: state === 'off' ? 'line-through' : 'none' }}>{label}</span>
    </div>
  );
}

function ChainAgent({ x, y, label, sub, appear = 1, redacted = false, accent = C.brand }) {
  const a = Easing.easeOutBack(clamp(appear, 0, 1));
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * a})`, opacity: clamp(appear, 0, 1),
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
    }}>
      <div style={{
        width: 88, height: 88, borderRadius: 22, flexShrink: 0,
        background: redacted ? 'rgba(255,255,255,0.03)' : accent.replace(')', ' / 0.14)'),
        border: `1.5px solid ${redacted ? C.border : accent.replace(')', ' / 0.55)')}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: redacted ? 'none' : `0 0 26px ${accent.replace(')', ' / 0.18)')}`,
      }}>
        {redacted
          ? <span style={{ fontFamily: MONO, fontSize: 26, color: C.inkFaint, letterSpacing: '0.05em' }}>▓▓</span>
          : <ShieldGlyph color={accent} size={40} />}
      </div>
      <div style={{ fontFamily: MONO, fontSize: 20, color: redacted ? C.inkFaint : C.ink, fontWeight: 500, whiteSpace: 'nowrap', letterSpacing: redacted ? '0.1em' : '0' }}>
        {redacted ? '████████' : label}
      </div>
      {sub && <div style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase' }}>{sub}</div>}
    </div>
  );
}

// delegation link with a Groth16 proof badge
function DelegationLink({ x1, x2, y, appear = 1, active = true, badge = 'Groth16 π', kind = 'ok' }) {
  const a = clamp(appear, 0, 1);
  const mid = (x1 + x2) / 2;
  const col = kind === 'bad' ? C.bad : C.brand;
  return (
    <React.Fragment>
      <div style={{ position: 'absolute', left: x1, top: y, width: x2 - x1, height: 2, transform: 'translateY(-50%)', opacity: a * 0.7,
        background: active ? `linear-gradient(90deg, ${col.replace(')', ' / 0.1)')}, ${col.replace(')', ' / 0.6)')})` : `repeating-linear-gradient(90deg, ${C.inkGhost} 0 10px, transparent 10px 18px)` }} />
      {/* arrowhead */}
      <div style={{ position: 'absolute', left: x2 - 2, top: y, transform: 'translate(-50%,-50%) rotate(45deg)', width: 11, height: 11,
        borderRight: `2px solid ${col.replace(')', ' / 0.7)')}`, borderTop: `2px solid ${col.replace(')', ' / 0.7)')}`, opacity: a * 0.8 }} />
      <div style={{ position: 'absolute', left: mid, top: y - 30, transform: 'translate(-50%,-50%)', opacity: a,
        padding: '5px 12px', borderRadius: 999, background: C.bg, border: `1px solid ${col.replace(')', ' / 0.45)')}`,
        fontFamily: MONO, fontSize: 13, color: col, letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>{badge}</div>
    </React.Fragment>
  );
}

function DStamp({ kind = 'bad', label, x, y, appear = 1 }) {
  const ok = kind === 'ok';
  const color = ok ? C.ok : C.bad;
  const s = appear < 0.5 ? (1.5 - Easing.easeOutBack(clamp(appear / 0.5, 0, 1))) : 1;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) rotate(${ok ? -5 : 5}deg) scale(${s})`,
      opacity: clamp(appear / 0.3, 0, 1), display: 'inline-flex', alignItems: 'center', gap: 11, padding: '11px 22px', borderRadius: 12, whiteSpace: 'nowrap',
      background: ok ? C.okSoft : C.badSoft, border: `2px solid ${color}` }}>
      {ok
        ? <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={color} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={color} strokeWidth="2.6" strokeLinecap="round" /></svg>}
      <span style={{ fontFamily: MONO, fontSize: 21, fontWeight: 600, letterSpacing: '0.06em', color }}>{label}</span>
    </div>
  );
}

// scope stack under a node: list all PERMS, each on/off
function ScopeStack({ x, y, active, appear = 1 }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translateX(-50%)', display: 'flex', flexDirection: 'column', gap: 12 }}>
      {PERMS.map((p) => (
        <PermChip key={p} label={p} state={active.includes(p) ? 'on' : 'off'} appear={appear} />
      ))}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM
function DgProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const n1 = clamp((t - 0.3) / 0.6, 0, 1);
  const link = clamp((t - 1.1) / 0.6, 0, 1);
  const n2 = clamp((t - 1.6) / 0.6, 0, 1);
  const alert = t > 2.6;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="Agents delegate to agents." sub="How do you stop privilege escalation — and hide the chain?" />
      <ChainAgent x={660} y={520} label="agent-alice" sub="delegator" appear={n1} />
      {link > 0 && <DelegationLink x1={760} x2={1160} y={520} appear={link} active={alert} badge="copies full scope" kind={alert ? 'bad' : 'ok'} />}
      <ChainAgent x={1260} y={520} label="agent-bob" sub="delegatee" appear={n2} accent={alert ? C.bad : C.brand} />
      {alert && <DStamp kind="bad" label="OVER-PERMISSIONED · PATH EXPOSED" x={960} y={730} appear={clamp((t - 2.6) / 0.4, 0, 1)} />}
    </div>
  );
}

// SCENE 2 — SCOPE-NARROWING
function DgNarrowing({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const xs = [480, 960, 1440], ny = 392, sy = 506;
  const a1 = clamp((t - 0.3) / 0.6, 0, 1);
  const l1 = clamp((t - 1.6) / 0.6, 0, 1);
  const a2 = clamp((t - 2.1) / 0.6, 0, 1);
  const l2 = clamp((t - 3.4) / 0.6, 0, 1);
  const a3 = clamp((t - 3.9) / 0.6, 0, 1);
  const note = clamp((t - 5.2) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="SCOPE-NARROWING" title="Each hop can only narrow." />
      {l1 > 0 && <DelegationLink x1={xs[0] + 130} x2={xs[1] - 130} y={ny} appear={l1} badge="delegate · Groth16" />}
      {l2 > 0 && <DelegationLink x1={xs[1] + 130} x2={xs[2] - 130} y={ny} appear={l2} badge="delegate · Groth16" />}
      <ChainAgent x={xs[0]} y={ny} label="agent-alice" appear={a1} />
      <ChainAgent x={xs[1]} y={ny} label="agent-bob" appear={a2} />
      <ChainAgent x={xs[2]} y={ny} label="agent-carol" appear={a3} />
      <ScopeStack x={xs[0]} y={sy} active={['READ_DATA', 'WRITE_DATA', 'FINANCIAL_SMALL']} appear={a1} />
      <ScopeStack x={xs[1]} y={sy} active={['READ_DATA', 'FINANCIAL_SMALL']} appear={a2} />
      <ScopeStack x={xs[2]} y={sy} active={['READ_DATA']} appear={a3} />
      <div style={{ position: 'absolute', left: 960, top: 952, transform: 'translate(-50%,-50%)', opacity: note,
        fontFamily: MONO, fontSize: 24, color: C.inkDim, letterSpacing: '0.02em', whiteSpace: 'nowrap' }}>
        Permissions only ever <span style={{ color: C.ink }}>drop</span> — never widen.
      </div>
    </div>
  );
}

// SCENE 3 — ONE-WAY (escalation fails)
function DgOneWay({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const carol = clamp((t - 0.3) / 0.6, 0, 1);
  const link = clamp((t - 1.4) / 0.6, 0, 1);
  const mal = clamp((t - 1.9) / 0.6, 0, 1);
  const reqRead = clamp((t - 2.6) / 0.4, 0, 1);
  const reqWrite = clamp((t - 3.3) / 0.4, 0, 1);
  const reject = t > 4.0;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ONE-WAY" title="Widening fails by construction." />

      <ChainAgent x={560} y={470} label="agent-carol" sub="holds READ_DATA" appear={carol} />
      <div style={{ position: 'absolute', left: 560, top: 600, transform: 'translateX(-50%)', opacity: carol }}>
        <PermChip label="READ_DATA" state="on" appear={carol} width={230} />
      </div>

      {link > 0 && <DelegationLink x1={680} x2={1240} y={470} appear={link} active={reject} badge="delegate ⟶ widen?" kind={reject ? 'bad' : 'ok'} />}
      <ChainAgent x={1360} y={470} label="agent-mallory" sub="requests" appear={mal} accent={reject ? C.bad : C.brand} />

      <div style={{ position: 'absolute', left: 1360, top: 600, transform: 'translateX(-50%)', display: 'flex', flexDirection: 'column', gap: 12 }}>
        {reqRead > 0 && <PermChip label="READ_DATA" state="on" appear={reqRead} width={230} />}
        {reqWrite > 0 && <PermChip label="WRITE_DATA" state={reject ? 'reject' : 'on'} appear={reqWrite} width={230} />}
      </div>

      {reject && <DStamp kind="bad" label="scope_widens · REJECTED" x={960} y={812} appear={clamp((t - 4.0) / 0.4, 0, 1)} />}
      {reject && (
        <div style={{ position: 'absolute', left: 960, top: 902, transform: 'translate(-50%,-50%)', opacity: clamp((t - 4.4) / 0.4, 0, 1),
          fontFamily: MONO, fontSize: 22, color: C.inkDim, whiteSpace: 'nowrap' }}>
          Cumulative-invariant: a child can never hold a permission its parent lacked.
        </div>
      )}
    </div>
  );
}

// SCENE 4 — PRIVACY (zero knowledge)
function DgPrivacy({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const chainIn = clamp((t - 0.3) / 0.6, 0, 1);
  const redact = t > 1.8;
  const collapse = clamp((t - 2.6) / 0.7, 0, 1);
  const proofIn = clamp((t - 3.2) / 0.5, 0, 1);
  const verify = clamp((t - 4.2) / 0.6, 0, 1);
  const xs = [300, 560, 820];
  const cy = 470;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ZERO KNOWLEDGE" title="The verifier never sees the path." />

      {/* the (now redacted) chain */}
      <DelegationLink x1={xs[0] + 60} x2={xs[1] - 60} y={cy} appear={chainIn} active={false} badge="" />
      <DelegationLink x1={xs[1] + 60} x2={xs[2] - 60} y={cy} appear={chainIn} active={false} badge="" />
      <ChainAgent x={xs[0]} y={cy} label="agent-alice" appear={chainIn} redacted={redact} />
      <ChainAgent x={xs[1]} y={cy} label="agent-bob" appear={chainIn} redacted={redact} />
      <ChainAgent x={xs[2]} y={cy} label="agent-carol" appear={chainIn} redacted={redact} />
      <div style={{ position: 'absolute', left: 560, top: cy + 130, transform: 'translate(-50%,-50%)', opacity: redact ? clamp((t - 1.8) / 0.4, 0, 1) : 0,
        fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>delegation path · hidden</div>

      {/* collapse into a single proof */}
      {proofIn > 0 && (
        <div style={{ position: 'absolute', left: 1090, top: cy, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * Easing.easeOutBack(proofIn)})`, opacity: proofIn,
          width: 150, height: 150, borderRadius: 30, background: C.bg, border: `2px solid ${C.brand}`,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6,
          boxShadow: `0 0 36px ${C.brandSoft}, inset 0 0 30px ${C.brandSoft}` }}>
          <span style={{ fontFamily: MONO, fontSize: 40, color: C.brand }}>π</span>
          <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkDim, letterSpacing: '0.1em' }}>Groth16</span>
        </div>
      )}
      {proofIn > 0 && <DelegationLink x1={870} x2={1010} y={cy} appear={proofIn} active badge="" />}
      {verify > 0 && <DelegationLink x1={1170} x2={1380} y={cy} appear={verify} active badge="verify" />}

      {/* verifier card */}
      {verify > 0 && (
        <div style={{ position: 'absolute', left: 1640, top: cy, transform: `translate(-50%,-50%) translateY(${(1 - Easing.easeOutCubic(verify)) * 20}px)`, opacity: verify,
          width: 420, background: 'rgba(14,18,24,0.92)', border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.ok}`,
          borderRadius: 16, padding: '22px 24px', display: 'flex', flexDirection: 'column', gap: 16, boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}>
          <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase' }}>verifier sees</span>
          <PermChip label="READ_DATA · valid" state="on" appear={1} width={372} />
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 11, height: 2, background: C.inkFaint, borderRadius: 2 }} />
            <span style={{ fontFamily: MONO, fontSize: 17, color: C.inkFaint }}>path · <span style={{ letterSpacing: '0.1em' }}>████████</span></span>
          </div>
          <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
            <span style={{ width: 11, height: 2, background: C.inkFaint, borderRadius: 2 }} />
            <span style={{ fontFamily: MONO, fontSize: 17, color: C.inkFaint }}>identities · <span style={{ letterSpacing: '0.1em' }}>██████</span></span>
          </div>
        </div>
      )}
    </div>
  );
}

// SCENE 5 — CTA
function DgCTA({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.3);
  const rise = (1 - Easing.easeOutCubic(clamp(t / 0.7, 0, 1))) * 26;
  const statsIn = clamp((t - 0.7) / 0.6, 0, 1);
  const cmdIn = clamp((t - 1.2) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ transform: `translateY(${rise}px)`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 26 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
          <ShieldGlyph color={C.brand} size={66} />
          <div style={{ fontFamily: DISPLAY, fontSize: 100, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em' }}>Bolyra</div>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 28, color: C.inkDim, whiteSpace: 'nowrap', textAlign: 'center' }}>
          Scope-narrowing delegation chains — <span style={{ color: C.brand }}>live now</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <DgPill text="Circuit 3 · Delegation" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <DgPill text="22,398 constraints" color={C.inkDim} />
          <DgPill text="Groth16 · ~100ms" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 25, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i <span style={{ color: C.brand }}>@bolyra/sdk</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · zero knowledge · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { DgProblem, DgNarrowing, DgOneWay, DgPrivacy, DgCTA });
