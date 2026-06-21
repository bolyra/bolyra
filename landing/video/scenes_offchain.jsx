// scenes_offchain.jsx — Off-chain mode: verify locally, batch into a Merkle root, ~375x gas reduction.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

function OcPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

// merkle geometry
const LEAF_X = Array.from({ length: 8 }, (_, i) => 300 + i * (1320 / 7));
const L1_X = [0, 1, 2, 3].map(j => (LEAF_X[2 * j] + LEAF_X[2 * j + 1]) / 2);
const L2_X = [0, 1].map(k => (L1_X[2 * k] + L1_X[2 * k + 1]) / 2);
const ROOT_X = 960;
const LEAF_Y = 760, L1_Y = 612, L2_Y = 476, ROOT_Y = 348;

function MNode({ x, y, label, sub, kind = 'hash', appear = 1, active = false }) {
  const a = Easing.easeOutBack(clamp(appear, 0, 1));
  const leaf = kind === 'leaf', root = kind === 'root';
  const col = root ? C.ok : C.brand;
  const w = root ? 200 : leaf ? 96 : 110;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.6 + 0.4 * a})`, opacity: clamp(appear, 0, 1),
      width: w, padding: root ? '16px 10px' : '12px 8px', boxSizing: 'border-box',
      background: active || root ? col.replace(')', ' / 0.14)') : C.panelStrong,
      border: `1.5px solid ${active || root ? col.replace(')', ' / 0.6)') : C.border}`, borderRadius: leaf ? 12 : 14,
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 3,
      boxShadow: active || root ? `0 0 22px ${col.replace(')', ' / 0.22)')}` : 'none' }}>
      <span style={{ fontFamily: MONO, fontSize: root ? 20 : leaf ? 16 : 17, color: C.ink, fontWeight: root ? 600 : 500, whiteSpace: 'nowrap' }}>{label}</span>
      {sub && <span style={{ fontFamily: MONO, fontSize: 12, color: root ? C.ok : C.inkFaint, letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>{sub}</span>}
    </div>
  );
}

function MerkleTree({ t }) {
  const leaves = clamp((t - 0.3) / 0.8, 0, 1);
  const l1 = clamp((t - 1.6) / 0.6, 0, 1);
  const l2 = clamp((t - 2.4) / 0.6, 0, 1);
  const root = clamp((t - 3.2) / 0.6, 0, 1);
  const lineOp = (p) => clamp(p, 0, 1) * 0.6;
  return (
    <React.Fragment>
      <svg style={{ position: 'absolute', inset: 0 }} width="1920" height="1080">
        {LEAF_X.map((lx, i) => <line key={'a' + i} x1={lx} y1={LEAF_Y - 30} x2={L1_X[Math.floor(i / 2)]} y2={L1_Y + 26} stroke={C.brandLine} strokeWidth="1.5" opacity={lineOp(l1)} />)}
        {L1_X.map((lx, i) => <line key={'b' + i} x1={lx} y1={L1_Y - 26} x2={L2_X[Math.floor(i / 2)]} y2={L2_Y + 26} stroke={C.brandLine} strokeWidth="1.5" opacity={lineOp(l2)} />)}
        {L2_X.map((lx, i) => <line key={'c' + i} x1={lx} y1={L2_Y - 26} x2={ROOT_X} y2={ROOT_Y + 32} stroke={C.brandLine} strokeWidth="1.5" opacity={lineOp(root)} />)}
      </svg>
      {LEAF_X.map((lx, i) => <MNode key={'l' + i} x={lx} y={LEAF_Y} label={'s' + (i + 1)} sub="0 gas" kind="leaf" appear={clamp((t - (0.3 + i * 0.08)) / 0.5, 0, 1)} active={leaves > 0.9} />)}
      {L1_X.map((lx, i) => <MNode key={'m1' + i} x={lx} y={L1_Y} label="h()" kind="hash" appear={clamp((t - (1.6 + i * 0.1)) / 0.5, 0, 1)} active={l1 > 0.9} />)}
      {L2_X.map((lx, i) => <MNode key={'m2' + i} x={lx} y={L2_Y} label="h()" kind="hash" appear={clamp((t - (2.4 + i * 0.1)) / 0.5, 0, 1)} active={l2 > 0.9} />)}
      <MNode x={ROOT_X} y={ROOT_Y} label="0x9f3a…root" sub="1 on-chain tx" kind="root" appear={root} />
    </React.Fragment>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM (gas)
function OcProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const n = Math.min(5, Math.floor(clamp((t - 0.8) / 0.55, 0, 5)));
  const totalGas = n * 590;
  const totalUsd = (n * 0.15).toFixed(2);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="Verifying every handshake on-chain costs gas." />
      {/* sessions posting on-chain */}
      <div style={{ position: 'absolute', left: 520, top: 600, transform: 'translate(-50%,-50%)', display: 'flex', flexDirection: 'column', gap: 14, width: 560 }}>
        {Array.from({ length: 5 }).map((_, i) => {
          const ap = clamp((t - (0.8 + i * 0.55)) / 0.4, 0, 1);
          return (
            <div key={i} style={{ opacity: ap, transform: `translateX(${(1 - ap) * -16}px)`, display: 'flex', alignItems: 'center', justifyContent: 'space-between',
              padding: '16px 22px', borderRadius: 12, background: C.panel, border: `1px solid ${C.border}` }}>
              <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, whiteSpace: 'nowrap' }}>session #{i + 1}</span>
              <span style={{ fontFamily: MONO, fontSize: 18, color: C.bad, whiteSpace: 'nowrap' }}>+590k gas</span>
            </div>
          );
        })}
      </div>
      {/* running meter */}
      <div style={{ position: 'absolute', left: 1340, top: 600, transform: 'translate(-50%,-50%)', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase' }}>on-chain cost</span>
        <div style={{ fontFamily: DISPLAY, fontSize: 96, fontWeight: 700, color: C.bad, lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>{totalGas}k</div>
        <div style={{ fontFamily: MONO, fontSize: 26, color: C.inkDim }}>≈ ${totalUsd}{n >= 5 ? ' … and counting' : ''}</div>
      </div>
    </div>
  );
}

// SCENE 2 — OFF-CHAIN VERIFY
function OcLocal({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const verifier = clamp((t - 0.4) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="OFF-CHAIN" title="Verify locally. Zero gas." />
      {/* central local verifier */}
      <div style={{ position: 'absolute', left: 960, top: 540, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * Easing.easeOutBack(verifier)})`, opacity: verifier,
        width: 360, padding: '30px', background: C.panelStrong, border: `1.5px solid ${C.brandLine}`, borderRadius: 22,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, boxShadow: `0 0 36px ${C.brandSoft}` }}>
        <ShieldGlyph color={C.brand} size={54} />
        <span style={{ fontFamily: MONO, fontSize: 24, color: C.ink, fontWeight: 600, whiteSpace: 'nowrap' }}>local verifier</span>
        <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkFaint, letterSpacing: '0.06em' }}>snarkjs.groth16.verify</span>
      </div>
      {/* verified session chips flying in */}
      {Array.from({ length: 6 }).map((_, i) => {
        const ang = (i / 6) * Math.PI * 2;
        const ap = clamp((t - (1.4 + i * 0.22)) / 0.5, 0, 1);
        const r = 330 - 30 * ap;
        const cx = 960 + Math.cos(ang) * r * 1.45;
        const cy = 540 + Math.sin(ang) * r * 0.78;
        return (
          <div key={i} style={{ position: 'absolute', left: cx, top: cy, transform: 'translate(-50%,-50%)', opacity: ap,
            display: 'flex', alignItems: 'center', gap: 9, padding: '9px 15px', borderRadius: 9, background: C.okSoft, border: `1px solid ${C.ok.replace(')', ' / 0.5)')}`, whiteSpace: 'nowrap' }}>
            <svg width="16" height="16" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <span style={{ fontFamily: MONO, fontSize: 16, color: C.ink }}>s{i + 1} · 0 gas</span>
          </div>
        );
      })}
      <div style={{ position: 'absolute', left: 960, top: 820, transform: 'translate(-50%,-50%)', opacity: clamp((t - 3.4) / 0.5, 0, 1),
        fontFamily: MONO, fontSize: 24, color: C.inkDim, whiteSpace: 'nowrap' }}>
        Same proof the on-chain verifier was generated from — <span style={{ color: C.ink }}>off-chain</span>.
      </div>
    </div>
  );
}

// SCENE 3 — MERKLE BATCH
function OcBatch({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const post = t > 4.2;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="BATCH" title="Many sessions, one Merkle root." />
      <MerkleTree t={t} />
      {post && (
        <div style={{ position: 'absolute', left: 960, top: 920, transform: 'translate(-50%,-50%)', opacity: clamp((t - 4.2) / 0.4, 0, 1) }}>
          <OcPill text="post root → 1 transaction settles the whole batch" color={C.ok} bg={C.okSoft} border={C.ok.replace(')', ' / 0.5)')} />
        </div>
      )}
    </div>
  );
}

// SCENE 4 — 375x
function OcStat({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const left = clamp((t - 0.4) / 0.6, 0, 1);
  const right = clamp((t - 1.0) / 0.6, 0, 1);
  const big = clamp((t - 1.8) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="AT BATCH SIZE 100" title="One root settles a hundred handshakes." />
      {/* before */}
      <div style={{ position: 'absolute', left: 430, top: 600, transform: 'translate(-50%,-50%)', textAlign: 'center', opacity: left, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>naive · 100 txs</span>
        <div style={{ fontFamily: DISPLAY, fontSize: 76, fontWeight: 700, color: C.bad, lineHeight: 1, whiteSpace: 'nowrap' }}>59M<span style={{ fontFamily: MONO, fontSize: 30, color: C.inkDim }}> gas</span></div>
      </div>
      {/* arrow / big stat */}
      <div style={{ position: 'absolute', left: 960, top: 600, transform: 'translate(-50%,-50%)', textAlign: 'center', opacity: big, display: 'flex', flexDirection: 'column', gap: 8, alignItems: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'baseline', whiteSpace: 'nowrap', fontFamily: DISPLAY, fontSize: 150, fontWeight: 700, color: C.ok, lineHeight: 1, letterSpacing: '-0.03em' }}>
          ~375<span style={{ fontFamily: MONO, fontSize: 56, color: C.inkDim, marginLeft: 4 }}>×</span>
        </div>
        <span style={{ fontFamily: MONO, fontSize: 24, color: C.inkDim, letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>less gas</span>
      </div>
      {/* after */}
      <div style={{ position: 'absolute', left: 1490, top: 600, transform: 'translate(-50%,-50%)', textAlign: 'center', opacity: right, display: 'flex', flexDirection: 'column', gap: 12, alignItems: 'center' }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>batched · 1 root tx</span>
        <div style={{ fontFamily: DISPLAY, fontSize: 76, fontWeight: 700, color: C.brand, lineHeight: 1, whiteSpace: 'nowrap' }}>~590k<span style={{ fontFamily: MONO, fontSize: 30, color: C.inkDim }}> gas</span></div>
      </div>
    </div>
  );
}

// SCENE 5 — CTA
function OcCTA({ t, dur }) {
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
          Off-chain mode — <span style={{ color: C.brand }}>batch &amp; settle</span> for a fraction of the gas
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <OcPill text="verify locally · 0 gas" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <OcPill text="~375× at batch 100" color={C.inkDim} />
          <OcPill text="single Merkle root" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 25, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i <span style={{ color: C.brand }}>@bolyra/sdk</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · Base L2 · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { OcProblem, OcLocal, OcBatch, OcStat, OcCTA });
