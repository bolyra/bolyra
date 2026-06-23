// scenes_cli.jsx — Credential CLI v0.2.0: run, observe, replay, dev from-receipt.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

function CliPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

// Terminal window with a typed command + revealed output lines.
// cmd: string; out: array of {text, color} ; localTime drives typing+reveal
function Terminal({ x, y, width = 1180, title = 'bolyra', cmd, out = [], t, typeStart = 0.3, typeDur = 1.2, outStart = 1.7, outStep = 0.34, appear = 1 }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const local = t - typeStart;
  const chars = Math.round(clamp(local / typeDur, 0, 1) * cmd.length);
  const shown = cmd.slice(0, chars);
  const typed = chars >= cmd.length;
  const blink = Math.floor(useTime() * 1.6) % 2 === 0;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${(1 - a) * 22}px)`, opacity: a,
      width, boxSizing: 'border-box', background: 'rgba(10,13,18,0.94)', border: `1px solid ${C.borderStrong}`, borderRadius: 16, overflow: 'hidden',
      boxShadow: '0 30px 70px rgba(0,0,0,0.55)' }}>
      <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '15px 22px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
        <div style={{ display: 'flex', gap: 8 }}>
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
          <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
        </div>
        <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkDim, letterSpacing: '0.04em' }}>{title}</span>
      </div>
      <div style={{ padding: '24px 30px', display: 'flex', flexDirection: 'column', gap: 9, minHeight: 220 }}>
        <div style={{ fontFamily: MONO, fontSize: 26, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> <span style={{ color: C.ink }}>{shown}</span>
          <span style={{ opacity: typed ? 0 : (blink ? 1 : 0.2), color: C.brand }}>▍</span>
        </div>
        {out.map((ln, i) => {
          const op = clamp((t - (outStart + i * outStep)) / 0.3, 0, 1);
          return (
            <div key={i} style={{ fontFamily: MONO, fontSize: 22, lineHeight: 1.3, opacity: op, whiteSpace: 'nowrap',
              transform: `translateX(${(1 - op) * -8}px)` }}>
              {ln.map((s, j) => <span key={j} style={{ color: s.color }}>{s.text}</span>)}
            </div>
          );
        })}
      </div>
    </div>
  );
}
const ot = (text, color = C.inkDim) => ({ text, color });

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — INTRO: the verbs
function CliIntro({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const rise = (1 - Easing.easeOutCubic(clamp((t - 0.3) / 0.7, 0, 1))) * 26;
  const verbs = ['run', 'observe', 'replay', 'dev'];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 34, transform: `translateY(${rise}px)`, textAlign: 'center' }}>
        <Kicker>{'// CREDENTIAL CLI · v0.2.0'}</Kicker>
        <div style={{ fontFamily: DISPLAY, fontSize: 96, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em', lineHeight: 1.0 }}>
          The whole lifecycle,<br />one command.
        </div>
        <div style={{ display: 'flex', gap: 16, opacity: clamp((t - 1.4) / 0.6, 0, 1) }}>
          {verbs.map((v, i) => (
            <div key={i} style={{ opacity: clamp((t - (1.5 + i * 0.18)) / 0.4, 0, 1), transform: `translateY(${(1 - clamp((t - (1.5 + i * 0.18)) / 0.4, 0, 1)) * 12}px)`,
              padding: '14px 26px', borderRadius: 12, background: C.panel, border: `1px solid ${C.border}`,
              fontFamily: MONO, fontSize: 26, color: C.ink, fontWeight: 500 }}>
              <span style={{ color: C.inkFaint }}>bolyra </span><span style={{ color: C.brand }}>{v}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}

// SCENE 2 — bolyra run
function CliRun({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="bolyra run" title="Run any stdio MCP server — authed, on HTTP." />
      <Terminal x={960} y={580} t={t} title="bolyra run"
        cmd="bolyra run --server 'npx some-mcp-server' --dev"
        out={[
          [ot('✓ ', C.ok), ot('spawned', C.ink), ot(' npx some-mcp-server', C.inkDim)],
          [ot('✓ ', C.ok), ot('dev credentials', C.ink), ot(' generated  ', C.inkDim), ot('did:bolyra:8f2c…', C.brand)],
          [ot('✓ ', C.ok), ot('auth proxy', C.ink), ot(' listening on ', C.inkDim), ot('http://localhost:4100', C.brand)],
          [ot('  4 tools gated · receipts → ./receipts.jsonl', C.inkFaint)],
        ]} />
    </div>
  );
}

// SCENE 3 — bolyra observe
function CliObserve({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const feedIn = clamp((t - 0.5) / 0.6, 0, 1);
  const calls = [
    { tool: 'search()', perm: 'READ_DATA', ok: true },
    { tool: 'fetch()', perm: 'READ_DATA', ok: true },
    { tool: 'write_file()', perm: 'WRITE_DATA', ok: true },
    { tool: 'charge()', perm: 'FINANCIAL_SMALL', ok: true },
    { tool: 'delete()', perm: 'WRITE_DATA', ok: false },
  ];
  const policyIn = clamp((t - 3.4) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="bolyra observe" title="Watch live calls. Auto-generate the policy." />
      {/* live feed */}
      <div style={{ position: 'absolute', left: 560, top: 600, transform: 'translate(-50%,-50%)', opacity: feedIn, width: 600,
        background: 'rgba(10,13,18,0.92)', border: `1px solid ${C.borderStrong}`, borderRadius: 16, overflow: 'hidden', boxShadow: '0 24px 60px rgba(0,0,0,0.5)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 20px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <span style={{ width: 9, height: 9, borderRadius: 5, background: C.ok, boxShadow: `0 0 10px ${C.ok}` }} />
          <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkDim, letterSpacing: '0.06em' }}>live activity</span>
        </div>
        {calls.map((c, i) => {
          const ap = clamp((t - (0.9 + i * 0.42)) / 0.4, 0, 1);
          const col = c.ok ? C.ok : C.bad;
          return (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '14px 20px', borderTop: i ? `1px solid ${C.inkGhost}` : 'none', opacity: ap }}>
              <span style={{ width: 18, height: 18, display: 'flex', alignItems: 'center', justifyContent: 'center', flexShrink: 0 }}>
                {c.ok ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={col} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg>
                       : <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={col} strokeWidth="3" strokeLinecap="round" /></svg>}
              </span>
              <span style={{ fontFamily: MONO, fontSize: 20, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{c.tool}</span>
              <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 16, color: C.inkFaint, whiteSpace: 'nowrap' }}>{c.perm}</span>
            </div>
          );
        })}
      </div>
      {/* arrow */}
      <div style={{ position: 'absolute', left: 960, top: 600, transform: 'translate(-50%,-50%)', opacity: policyIn }}>
        <svg width="70" height="30" viewBox="0 0 70 30" fill="none"><path d="M4 15h58m0 0-12-9m12 9-12 9" stroke={C.brand} strokeWidth="2.4" strokeLinecap="round" strokeLinejoin="round" /></svg>
      </div>
      {/* generated policy */}
      <div style={{ position: 'absolute', left: 1390, top: 600, transform: 'translate(-50%,-50%)', opacity: policyIn, width: 480,
        background: 'rgba(11,14,19,0.94)', border: `1px solid ${C.brandLine}`, borderRadius: 16, overflow: 'hidden', boxShadow: `0 0 28px ${C.brandSoft}` }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, padding: '14px 20px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <span style={{ fontFamily: MONO, fontSize: 16, color: C.brand }}>tool-policy.yaml</span>
          <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.06em' }}>generated</span>
        </div>
        <div style={{ padding: '18px 22px', display: 'flex', flexDirection: 'column', gap: 7, fontFamily: MONO, fontSize: 19 }}>
          <span style={{ color: C.inkDim }}>tools:</span>
          <span style={{ color: C.inkDim }}>  search: <span style={{ color: C.ok }}>READ_DATA</span></span>
          <span style={{ color: C.inkDim }}>  fetch: <span style={{ color: C.ok }}>READ_DATA</span></span>
          <span style={{ color: C.inkDim }}>  write_file: <span style={{ color: C.ok }}>WRITE_DATA</span></span>
          <span style={{ color: C.inkDim }}>  charge: <span style={{ color: C.ok }}>FINANCIAL_SMALL</span></span>
        </div>
      </div>
    </div>
  );
}

// SCENE 4 — bolyra replay + dev from-receipt
function CliReplay({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="bolyra replay · dev from-receipt" title="Re-judge history. Turn it into tests." />
      <Terminal x={960} y={500} width={1180} t={t} title="bolyra replay"
        typeStart={0.3} typeDur={1.0} outStart={1.5} outStep={0.3}
        cmd="bolyra replay --receipts ./receipts.jsonl --policy new.yaml"
        out={[
          [ot('  replaying 128 receipts…', C.inkFaint)],
          [ot('  126 unchanged   ', C.inkDim), ot('2 regressions', C.bad), ot('   0 relaxations', C.inkDim)],
          [ot('✗ ', C.bad), ot('rcpt_03', C.ink), ot('  delete · allow → ', C.inkDim), ot('deny', C.bad)],
        ]} />
      <Terminal x={960} y={772} width={1180} t={t} title="bolyra dev from-receipt"
        typeStart={3.0} typeDur={1.0} outStart={4.2} outStep={0.3}
        cmd="bolyra dev from-receipt rcpt_03 > fixtures/delete.test.json"
        out={[
          [ot('✓ ', C.ok), ot('fixture written', C.ink), ot('  ./fixtures/delete.test.json', C.inkDim)],
          [ot('  regression is now a permanent test case', C.inkFaint)],
        ]} />
    </div>
  );
}

// SCENE 5 — CTA
function CliCTA({ t, dur }) {
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
          Credential CLI — <span style={{ color: C.brand }}>run · observe · replay · dev</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <CliPill text="wrap any stdio server" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <CliPill text="auto-generate policy" color={C.inkDim} />
          <CliPill text="receipts → fixtures" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 25, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i -g <span style={{ color: C.brand }}>@bolyra/cli</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · v0.2.0 · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { CliIntro, CliRun, CliObserve, CliReplay, CliCTA });
