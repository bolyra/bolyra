// scenes_devmode.jsx — MCP dev mode: authenticated MCP server in 60 seconds, zero circuit artifacts.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

const KW = C.brand, STR = C.ok, FN = 'oklch(78% 0.13 300)', CMT = C.inkFaint, PNC = C.inkDim, IDN = C.ink;
const tk = (text, color = IDN) => ({ text, color });

function DvPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

// code window with line-by-line reveal
function CodeBlock({ x, y, width = 1000, appear = 1, reveal = 1, lines, filename = 'server.ts', highlightLine = -1 }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const total = lines.length;
  const shown = reveal * total;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${(1 - a) * 24}px)`, opacity: a,
      width, boxSizing: 'border-box', background: 'rgba(11,14,19,0.94)', border: `1px solid ${C.borderStrong}`, borderRadius: 16, overflow: 'hidden',
      boxShadow: '0 30px 70px rgba(0,0,0,0.55)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 22px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
        </div>
        <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkDim, letterSpacing: '0.04em' }}>{filename}</span>
      </div>
      <div style={{ padding: '24px 30px', display: 'flex', flexDirection: 'column', gap: 2 }}>
        {lines.map((ln, i) => {
          const op = clamp(shown - i, 0, 1);
          const hl = i === highlightLine;
          return (
            <div key={i} style={{ minHeight: 34, display: 'flex', alignItems: 'center', opacity: op, transform: `translateX(${(1 - op) * -10}px)`,
              background: hl ? C.brandSoft : 'transparent', borderRadius: 6, margin: hl ? '0 -10px' : 0, padding: hl ? '2px 10px' : 0 }}>
              <span style={{ fontFamily: MONO, fontSize: 25, lineHeight: 1.35, whiteSpace: 'pre' }}>
                {ln.map((seg, j) => <span key={j} style={{ color: seg.color }}>{seg.text}</span>)}
              </span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

function ToolRow({ name, online, appear = 1 }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '14px 22px', opacity: clamp(appear, 0, 1),
      borderBottom: `1px solid ${C.inkGhost}` }}>
      <span style={{ fontFamily: MONO, fontSize: 20, color: online ? C.ink : C.inkFaint }}>{name}</span>
      <span style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.08em', whiteSpace: 'nowrap', color: online ? C.ok : C.inkFaint }}>{online ? 'GATED ✓' : '…'}</span>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM
function DvProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const steps = ['generate .ptau', 'trusted setup ceremony', 'compile circuits', 'export .zkey artifacts', 'wire verifier keys'];
  const push = interpolate([0, dur], [1.0, 1.04], Easing.easeInOutSine)(t);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, transform: `scale(${push})`, transformOrigin: 'center' }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="Auth on an MCP server is a setup ceremony." sub="…before you authenticate a single tool call." />
      <div style={{ position: 'absolute', left: 960, top: 590, transform: 'translate(-50%,-50%)', display: 'flex', flexDirection: 'column', gap: 16, width: 700 }}>
        {steps.map((s, i) => {
          const ap = clamp((t - (0.8 + i * 0.45)) / 0.4, 0, 1);
          return (
            <div key={i} style={{ opacity: ap, transform: `translateX(${(1 - ap) * -16}px)`, display: 'flex', alignItems: 'center', gap: 16,
              padding: '16px 22px', borderRadius: 12, background: C.panel, border: `1px solid ${C.border}` }}>
              <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkFaint, width: 24 }}>{String(i + 1).padStart(2, '0')}</span>
              <span style={{ fontFamily: MONO, fontSize: 24, color: C.inkDim, whiteSpace: 'nowrap' }}>{s}</span>
              <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 15, color: C.bad, letterSpacing: '0.06em' }}>{t > 3.2 ? 'hours' : ''}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// SCENE 2 — THE WRAP
function DvWrap({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const reveal = clamp((t - 0.6) / 2.6, 0, 1);
  const hl = t > 3.6;
  const lines = [
    [tk('import ', KW), tk('{ withBolyraAuthStdio } ', IDN), tk('from ', KW), tk("'@bolyra/mcp'", STR), tk(';', PNC)],
    [],
    [tk('const ', KW), tk('server ', IDN), tk('= ', PNC), tk('new ', KW), tk('McpServer', IDN), tk('({ … });', PNC)],
    [],
    [tk('withBolyraAuthStdio', FN), tk('(server, {', PNC)],
    [tk('  devMode: ', IDN), tk('true', KW), tk(',', PNC), tk('       // zero circuit artifacts', CMT)],
    [tk('  toolPolicy', IDN), tk(',', PNC)],
    [tk('  receiptSigner', IDN), tk(',', PNC)],
    [tk('});', PNC)],
  ];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ONE WRAPPER" title="Wrap your server. That's the integration." />
      <CodeBlock x={960} y={580} width={1040} appear={1} reveal={reveal} lines={lines} filename="server.ts" highlightLine={hl ? 5 : -1} />
    </div>
  );
}

// SCENE 3 — 60 SECONDS
function DvSixty({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const secs = Math.round(interpolate([0.6, 2.6], [0, 52], Easing.easeOutCubic)(clamp(t, 0, 2.6)));
  const tools = ['search()', 'fetch()', 'charge()', 'delete()'];
  const ready = t > 3.0;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ZERO ARTIFACTS" title="Authenticated in 60 seconds." />

      {/* timer */}
      <div style={{ position: 'absolute', left: 560, top: 560, transform: 'translate(-50%,-50%)', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'baseline', gap: 12, whiteSpace: 'nowrap', fontFamily: DISPLAY, fontSize: 150, fontWeight: 700, color: ready ? C.ok : C.ink, letterSpacing: '-0.03em', lineHeight: 1, fontVariantNumeric: 'tabular-nums' }}>
          {secs}<span style={{ fontFamily: MONO, fontSize: 46, fontWeight: 500, color: C.inkDim }}>s</span>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 22, color: C.inkDim, whiteSpace: 'nowrap' }}>npm install → authenticated server</div>
        <div style={{ opacity: clamp((t - 3.2) / 0.4, 0, 1) }}><DvPill text="createDevIdentities() · no .zkey, no .ptau" color={C.ok} bg={C.okSoft} border={C.ok.replace(')', ' / 0.5)')} /></div>
      </div>

      {/* server panel booting */}
      <div style={{ position: 'absolute', left: 1360, top: 560, transform: 'translate(-50%,-50%)', width: 380,
        background: C.panelStrong, border: `1px solid ${ready ? C.brandLine : C.border}`, borderRadius: 18, overflow: 'hidden',
        boxShadow: ready ? `0 0 0 1px ${C.brandSoft}, 0 24px 60px rgba(0,0,0,0.5)` : '0 24px 60px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '18px 22px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <span style={{ width: 10, height: 10, borderRadius: 5, background: ready ? C.ok : C.inkFaint, boxShadow: ready ? `0 0 12px ${C.ok}` : 'none' }} />
          <span style={{ fontFamily: MONO, fontSize: 19, color: C.ink, letterSpacing: '0.04em', fontWeight: 500 }}>MCP&nbsp;SERVER</span>
          <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 13, color: ready ? C.ok : C.inkFaint, letterSpacing: '0.08em', whiteSpace: 'nowrap' }}>{ready ? 'AUTH ON' : 'booting…'}</span>
        </div>
        {tools.map((name, i) => <ToolRow key={i} name={name} online={t > 1.4 + i * 0.45} appear={clamp((t - (0.8 + i * 0.3)) / 0.4, 0, 1)} />)}
      </div>
    </div>
  );
}

// SCENE 4 — NOT A MOCK
function DvReal({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const feats = [
    ['Per-tool gating', 'every call checked against policy'],
    ['Signed receipts', 'audit evidence from line one'],
    ['Delegation chains', 'scope-narrowing, built in'],
    ['stdio + HTTP', 'wherever your server runs'],
  ];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="NOT A MOCK" title="Dev mode is the real protocol." sub="Flip devMode off for production — same API, real ZKPs." />
      <div style={{ position: 'absolute', left: 960, top: 600, transform: 'translate(-50%,-50%)', display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 22, width: 1180 }}>
        {feats.map((f, i) => {
          const ap = clamp((t - (0.7 + i * 0.4)) / 0.5, 0, 1);
          return (
            <div key={i} style={{ opacity: ap, transform: `translateY(${(1 - ap) * 16}px)`, display: 'flex', alignItems: 'flex-start', gap: 16,
              padding: '24px 26px', borderRadius: 14, background: C.panel, border: `1px solid ${C.border}` }}>
              <svg width="26" height="26" viewBox="0 0 24 24" fill="none" style={{ marginTop: 2, flexShrink: 0 }}><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
              <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
                <span style={{ fontFamily: MONO, fontSize: 24, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{f[0]}</span>
                <span style={{ fontFamily: MONO, fontSize: 17, color: C.inkFaint }}>{f[1]}</span>
              </div>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// SCENE 5 — CTA
function DvCTA({ t, dur }) {
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
          MCP dev mode — <span style={{ color: C.brand }}>v0.6.3</span> live now on npm
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <DvPill text="authed in 60s" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <DvPill text="zero circuit artifacts" color={C.inkDim} />
          <DvPill text="stdio + HTTP" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 25, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i <span style={{ color: C.brand }}>@bolyra/mcp</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · runnable example included · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { DvProblem, DvWrap, DvSixty, DvReal, DvCTA });
