// scenes_oauth.jsx — "Why not just OAuth?" — the differentiation story.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

function OaPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

const ROWS = [
  { cap: 'Delegated scope narrowing', oauth: 'Manual policy engine', bolyra: 'Circuit-enforced, one-way' },
  { cap: 'Per-tool permissions', oauth: 'Custom middleware per tool', bolyra: 'YAML config, one gateway' },
  { cap: 'Replay protection', oauth: 'Token expiry only', bolyra: 'Nonce store (memory / Redis)' },
  { cap: 'Signed audit trail', oauth: 'Application logging', bolyra: 'ES256K receipts, every call' },
  { cap: 'Privacy-preserving upgrade', oauth: 'Not possible', bolyra: 'ZKP — verifier never sees identity' },
];

// table geometry
const COL = { cap: 470, oauth: 990, bolyra: 1470 };
const TABLE_TOP = 396, ROW_H = 104;

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — THE QUESTION
function OaQuestion({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const rise = (1 - Easing.easeOutCubic(clamp((t - 0.3) / 0.7, 0, 1))) * 28;
  const sub = clamp((t - 1.4) / 0.5, 0, 1);
  const tag = clamp((t - 2.2) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 28, transform: `translateY(${rise}px)`, textAlign: 'center' }}>
        <Kicker>{'// THE OBJECTION'}</Kicker>
        <div style={{ fontFamily: DISPLAY, fontSize: 132, fontWeight: 700, color: C.ink, letterSpacing: '-0.035em', lineHeight: 0.98 }}>
          Why not just<br /><span style={{ color: C.brand }}>OAuth?</span>
        </div>
        <div style={{ opacity: sub, fontFamily: MONO, fontSize: 28, color: C.inkDim, maxWidth: 1100, lineHeight: 1.5 }}>
          OAuth proves a token is valid. It can't prove what an agent is <span style={{ color: C.ink }}>allowed to do</span> — privately.
        </div>
        <div style={{ opacity: tag, marginTop: 6 }}>
          <OaPill text="agents need more than a bearer token" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
        </div>
      </div>
    </div>
  );
}

// SCENE 2 + 3 — COMPARISON TABLE (rows build over two sprites; pass rowsShown)
function ComparisonTable({ t, dur, rowsShown, headerStart = 0.3 }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const head = clamp((t - headerStart) / 0.5, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="OAUTH / JWT  vs  BOLYRA" title="Built for agents, not browsers." />

      {/* column headers */}
      <div style={{ opacity: head }}>
        <div style={{ position: 'absolute', left: COL.oauth, top: TABLE_TOP - 56, transform: 'translate(-50%,-50%)',
          fontFamily: MONO, fontSize: 20, color: C.inkDim, letterSpacing: '0.12em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>OAuth / JWT</div>
        <div style={{ position: 'absolute', left: COL.bolyra, top: TABLE_TOP - 56, transform: 'translate(-50%,-50%)', display: 'flex', alignItems: 'center', gap: 10 }}>
          <ShieldGlyph color={C.brand} size={24} />
          <span style={{ fontFamily: MONO, fontSize: 20, color: C.brand, letterSpacing: '0.12em', textTransform: 'uppercase', fontWeight: 600 }}>Bolyra</span>
        </div>
      </div>
      {/* vertical divider before Bolyra column */}
      <div style={{ position: 'absolute', left: 1235, top: TABLE_TOP - 80, width: 1, height: 80 + ROWS.length * ROW_H, background: C.brandLine, opacity: head * 0.5 }} />

      {ROWS.map((r, i) => {
        const ap = clamp(rowsShown - i, 0, 1);
        const y = TABLE_TOP + i * ROW_H;
        const bolyraPop = Easing.easeOutBack(clamp((rowsShown - i) * 1.4, 0, 1));
        return (
          <React.Fragment key={i}>
            {/* row separator */}
            <div style={{ position: 'absolute', left: 280, top: y + ROW_H / 2 - 4, width: 1360, height: 1, background: C.inkGhost, opacity: ap * 0.7 }} />
            {/* capability */}
            <div style={{ position: 'absolute', left: COL.cap, top: y, transform: 'translate(-50%,-50%)', opacity: ap, width: 380, textAlign: 'left',
              fontFamily: DISPLAY, fontSize: 27, color: C.ink, fontWeight: 500, letterSpacing: '-0.01em' }}>{r.cap}</div>
            {/* oauth cell */}
            <div style={{ position: 'absolute', left: COL.oauth, top: y, transform: `translate(-50%,-50%) translateX(${(1 - ap) * -14}px)`, opacity: ap,
              display: 'flex', alignItems: 'center', gap: 11, whiteSpace: 'nowrap' }}>
              <svg width="20" height="20" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0 }}><path d="M6 6l12 12M18 6 6 18" stroke={C.inkFaint} strokeWidth="2.4" strokeLinecap="round" /></svg>
              <span style={{ fontFamily: MONO, fontSize: 21, color: C.inkDim }}>{r.oauth}</span>
            </div>
            {/* bolyra cell */}
            <div style={{ position: 'absolute', left: COL.bolyra, top: y, transform: `translate(-50%,-50%) scale(${0.8 + 0.2 * bolyraPop})`, opacity: ap,
              display: 'flex', alignItems: 'center', gap: 11, whiteSpace: 'nowrap' }}>
              <svg width="22" height="22" viewBox="0 0 24 24" fill="none" style={{ flexShrink: 0 }}><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
              <span style={{ fontFamily: MONO, fontSize: 21, color: C.ink, fontWeight: 500 }}>{r.bolyra}</span>
            </div>
          </React.Fragment>
        );
      })}
    </div>
  );
}

function OaTableA({ t, dur }) {
  // rows 0..2 build
  const rowsShown = clamp((t - 1.0) / 2.4, 0, 3);
  return <ComparisonTable t={t} dur={dur} rowsShown={rowsShown} />;
}
function OaTableB({ t, dur }) {
  // rows 0..2 already in, 3..4 build; keep all five visible
  const rowsShown = 3 + clamp((t - 0.2) / 1.8, 0, 2);
  const last = t > 2.4;
  return (
    <React.Fragment>
      <ComparisonTable t={t} dur={dur} rowsShown={rowsShown} headerStart={-1} />
      {last && (
        <div style={{ position: 'absolute', left: COL.bolyra, top: TABLE_TOP + 4 * ROW_H + 60, transform: 'translate(-50%,-50%)', opacity: clamp((t - 2.4) / 0.5, 0, 1) }}>
          <OaPill text="only Bolyra: privacy-preserving" color={C.ok} bg={C.okSoft} border={C.ok.replace(')', ' / 0.5)')} />
        </div>
      )}
    </React.Fragment>
  );
}

// SCENE 4 — THE ZKP UPGRADE
function OaUpgrade({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  // left: OAuth reveals identity; right: Bolyra hides it
  const left = clamp((t - 0.4) / 0.6, 0, 1);
  const right = clamp((t - 1.2) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE UPGRADE PATH" title="Same receipts today. Zero-knowledge tomorrow." />

      {/* OAuth side */}
      <div style={{ position: 'absolute', left: 530, top: 580, transform: 'translate(-50%,-50%)', opacity: left, width: 520,
        background: 'rgba(13,17,23,0.9)', border: `1px solid ${C.border}`, borderRadius: 20, padding: '30px 32px', display: 'flex', flexDirection: 'column', gap: 18 }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase' }}>OAuth bearer token</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontFamily: MONO, fontSize: 20 }}>
          <span style={{ color: C.inkDim }}>sub: <span style={{ color: C.bad }}>user_8f2c@acme.com</span></span>
          <span style={{ color: C.inkDim }}>scope: <span style={{ color: C.bad }}>read write charge</span></span>
          <span style={{ color: C.inkDim }}>iss: <span style={{ color: C.bad }}>acme-corp</span></span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 12, borderTop: `1px solid ${C.inkGhost}` }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={C.bad} strokeWidth="2.4" strokeLinecap="round" /></svg>
          <span style={{ fontFamily: MONO, fontSize: 17, color: C.bad }}>identity exposed to every verifier</span>
        </div>
      </div>

      {/* Bolyra side */}
      <div style={{ position: 'absolute', left: 1390, top: 580, transform: 'translate(-50%,-50%)', opacity: right, width: 520,
        background: 'rgba(13,17,23,0.9)', border: `1px solid ${C.brandLine}`, borderRadius: 20, padding: '30px 32px', display: 'flex', flexDirection: 'column', gap: 18,
        boxShadow: `0 0 30px ${C.brandSoft}` }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.brand, letterSpacing: '0.12em', textTransform: 'uppercase' }}>Bolyra ZKP proof</span>
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, fontFamily: MONO, fontSize: 20 }}>
          <span style={{ color: C.inkDim }}>identity: <span style={{ color: C.inkFaint, letterSpacing: '0.1em' }}>████████</span></span>
          <span style={{ color: C.inkDim }}>scope: <span style={{ color: C.ok }}>READ_DATA ✓</span></span>
          <span style={{ color: C.inkDim }}>proof: <span style={{ color: C.brand }}>Groth16 π · valid</span></span>
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 12, borderTop: `1px solid ${C.inkGhost}` }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <span style={{ fontFamily: MONO, fontSize: 17, color: C.ok }}>proven valid, identity never revealed</span>
        </div>
      </div>

      {/* arrow between */}
      <div style={{ position: 'absolute', left: 960, top: 580, transform: 'translate(-50%,-50%)', opacity: right,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6 }}>
        <svg width="60" height="30" viewBox="0 0 60 30" fill="none"><path d="M4 15h48m0 0-12-9m12 9-12 9" stroke={C.brand} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
        <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.08em', whiteSpace: 'nowrap' }}>wire-compatible</span>
      </div>
    </div>
  );
}

// SCENE 5 — CTA
function OaCTA({ t, dur }) {
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
          Auth built for agents — <span style={{ color: C.brand }}>not browsers</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <OaPill text="circuit-enforced scope" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <OaPill text="ES256K receipts" color={C.inkDim} />
          <OaPill text="ZKP privacy path" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 25, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npx <span style={{ color: C.brand }}>@bolyra/gateway</span> <span style={{ color: C.inkDim }}>--target &lt;your-mcp&gt;</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · drop-in, no migration · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { OaQuestion, OaTableA, OaTableB, OaUpgrade, OaCTA });
