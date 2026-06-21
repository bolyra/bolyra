// scenes_handshake.jsx — Mutual ZKP handshake (~140ms, tampered proof rejected).
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

function HsPill({ text, color = C.inkDim, bg, border }) {
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

function HsStamp({ kind = 'ok', label, x, y, appear = 1 }) {
  const ok = kind === 'ok';
  const color = ok ? C.ok : C.bad;
  const s = appear < 0.5 ? (1.5 - Easing.easeOutBack(clamp(appear / 0.5, 0, 1))) : 1;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) rotate(${ok ? -5 : 5}deg) scale(${s})`,
      opacity: clamp(appear / 0.3, 0, 1), display: 'inline-flex', alignItems: 'center', gap: 12, padding: '13px 26px', borderRadius: 12, whiteSpace: 'nowrap',
      background: ok ? C.okSoft : C.badSoft, border: `2px solid ${color}` }}>
      {ok
        ? <svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={color} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="28" height="28" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={color} strokeWidth="2.6" strokeLinecap="round" /></svg>}
      <span style={{ fontFamily: MONO, fontSize: 26, fontWeight: 600, letterSpacing: '0.06em', color }}>{label}</span>
    </div>
  );
}

// party panel: HUMAN (left) / AI AGENT (right)
function PartyPanel({ x, y, title, proves, proveSub, hidden, appear = 1, side = 'left' }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const dx = (side === 'left' ? -1 : 1) * (1 - a) * 40;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateX(${dx}px)`, opacity: a,
      width: 560, boxSizing: 'border-box',
      background: 'rgba(14,18,24,0.9)', border: `1px solid ${C.borderStrong}`, borderRadius: 20, overflow: 'hidden',
      boxShadow: '0 24px 60px rgba(0,0,0,0.5)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '20px 26px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.02)' }}>
        <div style={{ width: 44, height: 44, borderRadius: 12, background: C.brandSoft, border: `1px solid ${C.brandLine}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <ShieldGlyph color={C.brand} size={26} />
        </div>
        <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 600, letterSpacing: '0.06em' }}>{title}</span>
      </div>
      <div style={{ padding: '22px 26px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        <div style={{ display: 'flex', alignItems: 'flex-start', gap: 12 }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ marginTop: 2, flexShrink: 0 }}><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <div style={{ display: 'flex', flexDirection: 'column', gap: 5 }}>
            <span style={{ fontFamily: MONO, fontSize: 23, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{proves}</span>
            <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkFaint }}>{proveSub}</span>
          </div>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, paddingTop: 14, borderTop: `1px solid ${C.inkGhost}` }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0 }}><rect x="5" y="11" width="14" height="9" rx="2" stroke={C.inkFaint} strokeWidth="1.8" /><path d="M8 11V8a4 4 0 0 1 8 0v3" stroke={C.inkFaint} strokeWidth="1.8" /></svg>
          <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint }}>{hidden} · <span style={{ letterSpacing: '0.06em' }}>never revealed</span></span>
        </div>
      </div>
    </div>
  );
}

function ProofToken({ x, y, appear = 1, label, kind = 'ok', size = 110 }) {
  const a = clamp(appear, 0, 1);
  const col = kind === 'bad' ? C.bad : C.brand;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * Easing.easeOutBack(a)})`, opacity: a }}>
      <div style={{ width: size, height: size, borderRadius: size * 0.26, background: C.bg, border: `2px solid ${col}`,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 2,
        boxShadow: `0 0 32px ${col.replace(')', ' / 0.25)')}, inset 0 0 26px ${col.replace(')', ' / 0.12)')}` }}>
        <span style={{ fontFamily: MONO, fontSize: size * 0.34, color: col, lineHeight: 1 }}>π</span>
        <span style={{ fontFamily: MONO, fontSize: 12, color: C.inkDim, letterSpacing: '0.08em' }}>Groth16</span>
      </div>
      {label && <div style={{ position: 'absolute', left: '50%', top: size + 14, transform: 'translateX(-50%)', fontFamily: MONO, fontSize: 15, color: C.inkDim, letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>{label}</div>}
    </div>
  );
}

function NonceCore({ x, y, appear = 1, pulse = 0, color = C.brand }) {
  const a = clamp(appear, 0, 1);
  const ring = 0.5 + 0.5 * Math.sin(pulse * Math.PI * 2);
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * a})`, opacity: a }}>
      <div style={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%,-50%)', width: 150 + ring * 30, height: 150 + ring * 30, borderRadius: '50%', border: `1px solid ${color.replace(')', ' / ' + (0.3 - ring * 0.2) + ')')}` }} />
      <div style={{ width: 132, height: 132, borderRadius: '50%', background: C.bg, border: `2px solid ${color}`,
        display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4,
        boxShadow: `0 0 ${24 + ring * 24}px ${color.replace(')', ' / 0.3)')}` }}>
        <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase' }}>nonce</span>
        <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 600 }}>0x7f3a</span>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM
function HsProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const l = clamp((t - 0.3) / 0.6, 0, 1);
  const r = clamp((t - 0.6) / 0.6, 0, 1);
  const q = t > 2.0;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="A human and an agent must trust each other." sub="The catch: proving who you are usually means revealing it." />
      {/* two facing nodes with a question between */}
      <div style={{ position: 'absolute', left: 560, top: 560, transform: 'translate(-50%,-50%)', opacity: l, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
        <div style={{ width: 110, height: 110, borderRadius: 28, background: C.brandSoft, border: `1.5px solid ${C.brandLine}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ShieldGlyph color={C.brand} size={50} /></div>
        <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 500 }}>human</span>
      </div>
      <div style={{ position: 'absolute', left: 1360, top: 560, transform: 'translate(-50%,-50%)', opacity: r, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14 }}>
        <div style={{ width: 110, height: 110, borderRadius: 28, background: C.brandSoft, border: `1.5px solid ${C.brandLine}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ShieldGlyph color={C.brand} size={50} /></div>
        <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 500 }}>ai agent</span>
      </div>
      {q && (
        <div style={{ position: 'absolute', left: 960, top: 545, transform: 'translate(-50%,-50%)', opacity: clamp((t - 2.0) / 0.4, 0, 1),
          fontFamily: DISPLAY, fontSize: 90, fontWeight: 700, color: C.bad }}>?</div>
      )}
    </div>
  );
}

// SCENE 2 — MUTUAL HANDSHAKE (parallel proofs bound to nonce)
function HsMutual({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const panels = clamp((t - 0.3) / 0.7, 0, 1);
  const nonce = clamp((t - 1.6) / 0.6, 0, 1);
  const proofs = clamp((t - 2.2) / 0.6, 0, 1);
  // proof token travel from panels toward center
  const travel = Easing.easeInOutCubic(clamp((t - 2.6) / 1.2, 0, 1));
  const lpx = 660 + (810 - 660) * travel;
  const rpx = 1260 - (1260 - 1110) * travel;
  const bind = t > 4.0;
  const note = clamp((t - 4.4) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="MUTUAL HANDSHAKE" title="Both prove. Neither reveals." />
      <PartyPanel x={360} y={520} side="left" title="HUMAN" proves="proves uniqueness" proveSub="EdDSA + Poseidon commitment" hidden="identity" appear={panels} />
      <PartyPanel x={1560} y={520} side="right" title="AI AGENT" proves="proves credential" proveSub="operator-signed policy" hidden="credential · model" appear={panels} />
      <NonceCore x={960} y={520} appear={nonce} pulse={bind ? (t * 0.6) % 1 : 0} />
      {proofs > 0 && <ProofToken x={lpx} y={520} appear={proofs} kind="ok" size={92} />}
      {proofs > 0 && <ProofToken x={rpx} y={520} appear={proofs} kind="ok" size={92} />}
      <div style={{ position: 'absolute', left: 960, top: 760, transform: 'translate(-50%,-50%)', opacity: note, textAlign: 'center',
        fontFamily: MONO, fontSize: 24, color: C.inkDim, whiteSpace: 'nowrap' }}>
        Two Groth16 proofs · generated in parallel · <span style={{ color: C.ink }}>bound to one nonce</span>
      </div>
    </div>
  );
}

// SCENE 3 — VERIFY IN ~138ms
function HsVerify({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const ms = Math.round(interpolate([0.8, 2.4], [0, 138], Easing.easeOutCubic)(clamp(t, 0, 2.4)));
  const verified = t > 2.7;
  const sub = clamp((t - 3.2) / 0.5, 0, 1);
  const pulse = (t * 0.7) % 1;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="VERIFY" title="One atomic check." />
      {/* two proofs converged on nonce */}
      <ProofToken x={730} y={500} appear={1} kind={verified ? 'ok' : 'ok'} size={92} label="human proof" />
      <ProofToken x={1190} y={500} appear={1} kind="ok" size={92} label="agent proof" />
      <NonceCore x={960} y={500} appear={1} pulse={pulse} color={verified ? C.ok : C.brand} />

      {/* timer */}
      <div style={{ position: 'absolute', left: 960, top: 700, transform: 'translate(-50%,-50%)', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'baseline', gap: 14, whiteSpace: 'nowrap', fontFamily: DISPLAY, fontSize: 96, fontWeight: 700, color: verified ? C.ok : C.ink, letterSpacing: '-0.02em', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>
          {ms}<span style={{ fontFamily: MONO, fontSize: 38, fontWeight: 500, color: C.inkDim }}>ms</span>
        </div>
        <div style={{ opacity: sub, fontFamily: MONO, fontSize: 22, color: C.inkDim, whiteSpace: 'nowrap' }}>
          verifyHandshake() · both proofs checked together
        </div>
      </div>
      {verified && <HsStamp kind="ok" label="HANDSHAKE VERIFIED" x={960} y={886} appear={clamp((t - 2.7) / 0.4, 0, 1)} />}
    </div>
  );
}

// SCENE 4 — TAMPER REJECTED
function HsTamper({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const rowIn = clamp((t - 0.4) / 0.6, 0, 1);
  const flip = t > 2.0;
  const reject = t > 3.0;
  const bytes = ['9f', '3a', '7c', 'd1', '04', 'e8', 'b2', '5f', 'aa', '13', '6d', 'c0', '88', '2e', 'f1', '47'];
  const flipIdx = 9;
  const note = clamp((t - 3.6) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="TAMPER-EVIDENT" title="Flip one byte — the pairing check fails." />

      <ProofToken x={400} y={520} appear={rowIn} kind={reject ? 'bad' : 'ok'} size={120} label="agent proof π" />

      {/* hex byte row */}
      <div style={{ position: 'absolute', left: 1080, top: 500, transform: 'translate(-50%,-50%)', opacity: rowIn, display: 'flex', flexWrap: 'wrap', gap: 12, width: 760 }}>
        {bytes.map((b, i) => {
          const isFlip = i === flipIdx && flip;
          return (
            <div key={i} style={{
              width: 70, height: 60, borderRadius: 9, display: 'flex', alignItems: 'center', justifyContent: 'center',
              background: isFlip ? C.badSoft : 'rgba(255,255,255,0.03)',
              border: `1px solid ${isFlip ? C.bad : C.inkGhost}`,
              transform: isFlip ? 'scale(1.12)' : 'scale(1)',
              boxShadow: isFlip ? `0 0 18px ${C.badSoft}` : 'none',
              fontFamily: MONO, fontSize: 22, fontWeight: 500, color: isFlip ? C.bad : C.inkDim,
            }}>{isFlip ? 'a1' : b}</div>
          );
        })}
      </div>
      {flip && (
        <div style={{ position: 'absolute', left: 1080, top: 660, transform: 'translate(-50%,-50%)', opacity: clamp((t - 2.0) / 0.4, 0, 1),
          fontFamily: MONO, fontSize: 18, color: C.bad, letterSpacing: '0.04em' }}>1 byte altered · 7c → a1</div>
      )}

      {reject && <HsStamp kind="bad" label="PROOF_INVALID" x={960} y={804} appear={clamp((t - 3.0) / 0.4, 0, 1)} />}
      {reject && (
        <div style={{ position: 'absolute', left: 960, top: 900, transform: 'translate(-50%,-50%)', opacity: note,
          fontFamily: MONO, fontSize: 22, color: C.inkDim, whiteSpace: 'nowrap' }}>
          No threshold, no heuristic — the elliptic-curve pairing simply doesn't hold.
        </div>
      )}
    </div>
  );
}

// SCENE 5 — CTA
function HsCTA({ t, dur }) {
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
          Mutual ZKP handshake in <span style={{ color: C.brand }}>~140ms</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <HsPill text="Groth16 · rapidsnark" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <HsPill text="0 bits leaked" color={C.inkDim} />
          <HsPill text="dev mode · no artifacts" color={C.inkDim} />
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

Object.assign(window, { HsProblem, HsMutual, HsVerify, HsTamper, HsCTA });
