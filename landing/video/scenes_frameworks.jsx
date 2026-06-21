// scenes_frameworks.jsx — Framework integrations: drop Bolyra into Vercel AI SDK / OpenAI Agents / LangChain.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

const KW2 = C.brand, STR2 = C.ok, FN2 = 'oklch(78% 0.13 300)', PNC2 = C.inkDim, IDN2 = C.ink, CMT2 = C.inkFaint;
const seg = (text, color = IDN2) => ({ text, color });

function FwPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

// monogram tile for a framework
function FwBadge({ mono, color = C.brand, size = 56 }) {
  return (
    <div style={{ width: size, height: size, borderRadius: size * 0.26, flexShrink: 0,
      background: color.replace(')', ' / 0.14)'), border: `1px solid ${color.replace(')', ' / 0.5)')}`,
      display: 'flex', alignItems: 'center', justifyContent: 'center',
      fontFamily: MONO, fontSize: size * 0.34, fontWeight: 700, color, letterSpacing: '0.02em' }}>{mono}</div>
  );
}

// adapter card: badge + name + one-line code
function AdapterCard({ x, y, appear = 1, mono, badgeColor, name, pkg, code, highlight = false }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${(1 - a) * 26}px)`, opacity: a,
      width: 1180, boxSizing: 'border-box', background: 'rgba(13,17,23,0.92)',
      border: `1px solid ${highlight ? C.brandLine : C.borderStrong}`, borderRadius: 18, padding: '22px 26px',
      display: 'flex', alignItems: 'center', gap: 24, boxShadow: highlight ? `0 0 28px ${C.brandSoft}, 0 24px 60px rgba(0,0,0,0.45)` : '0 24px 60px rgba(0,0,0,0.45)' }}>
      <FwBadge mono={mono} color={badgeColor} size={62} />
      <div style={{ display: 'flex', flexDirection: 'column', gap: 5, width: 320, flexShrink: 0 }}>
        <span style={{ fontFamily: DISPLAY, fontSize: 28, color: C.ink, fontWeight: 600, letterSpacing: '-0.01em', whiteSpace: 'nowrap' }}>{name}</span>
        <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: '0.02em', whiteSpace: 'nowrap' }}>{pkg}</span>
      </div>
      <div style={{ flex: 1, padding: '16px 20px', borderRadius: 11, background: 'rgba(10,13,18,0.8)', border: `1px solid ${C.border}` }}>
        <span style={{ fontFamily: MONO, fontSize: 23, lineHeight: 1.3, whiteSpace: 'nowrap' }}>
          {code.map((s, i) => <span key={i} style={{ color: s.color }}>{s.text}</span>)}
        </span>
      </div>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM
function FwProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const fw = [
    { mono: 'AI', name: 'Vercel AI SDK', color: C.brand },
    { mono: 'OA', name: 'OpenAI Agents', color: 'oklch(78% 0.13 300)' },
    { mono: 'LC', name: 'LangChain', color: C.ok },
  ];
  const alert = t > 2.4;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="Every agent framework calls tools its own way." sub="None of them know who's calling — or whether they're allowed." />
      <div style={{ position: 'absolute', left: 960, top: 580, transform: 'translate(-50%,-50%)', display: 'flex', gap: 40 }}>
        {fw.map((f, i) => {
          const ap = clamp((t - (0.6 + i * 0.4)) / 0.5, 0, 1);
          return (
            <div key={i} style={{ opacity: ap, transform: `translateY(${(1 - ap) * 18}px)`, width: 320,
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 18,
              padding: '30px 24px', borderRadius: 18, background: C.panel, border: `1px solid ${alert ? C.badSoft : C.border}` }}>
              <FwBadge mono={f.mono} color={alert ? C.bad : f.color} size={72} />
              <span style={{ fontFamily: DISPLAY, fontSize: 26, color: C.ink, fontWeight: 600, whiteSpace: 'nowrap' }}>{f.name}</span>
              <span style={{ fontFamily: MONO, fontSize: 15, letterSpacing: '0.08em', textTransform: 'uppercase',
                color: alert ? C.bad : C.inkFaint, whiteSpace: 'nowrap' }}>{alert ? 'no auth' : 'tool calls'}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// SCENE 2 — ONE LINE EACH
function FwAdapters({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const a1 = clamp((t - 0.5) / 0.6, 0, 1);
  const a2 = clamp((t - 1.5) / 0.6, 0, 1);
  const a3 = clamp((t - 2.5) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="DROP-IN" title="One line wires auth into your stack." />
      <AdapterCard x={960} y={428} appear={a1} mono="AI" badgeColor={C.brand} name="Vercel AI SDK" pkg="npm i @bolyra/ai"
        code={[seg('withBolyraAuth', FN2), seg('(', PNC2), seg('model', IDN2), seg(')', PNC2)]} highlight={t > 0.5 && t < 1.5} />
      <AdapterCard x={960} y={580} appear={a2} mono="OA" badgeColor="oklch(78% 0.13 300)" name="OpenAI Agents SDK" pkg="pip install bolyra-agents"
        code={[seg('BolyraAuthGuardrail', FN2), seg('()', PNC2), seg('  ·  ', CMT2), seg('BolyraToolWrapper', FN2), seg('()', PNC2)]} highlight={t > 1.5 && t < 2.5} />
      <AdapterCard x={960} y={732} appear={a3} mono="LC" badgeColor={C.ok} name="LangChain" pkg="pip install bolyra-langchain"
        code={[seg('BolyraAuthTool', FN2), seg(', ', PNC2), seg('BolyraDelegateTool', FN2), seg(', ', PNC2), seg('BolyraSDJWTTool', FN2)]} highlight={t > 2.5 && t < 3.5} />
    </div>
  );
}

// SCENE 3 — UNIFIED GATE (all converge on the same verification)
function FwUnified({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const nodesIn = clamp((t - 0.4) / 0.6, 0, 1);
  const flow = Easing.easeInOutCubic(clamp((t - 1.4) / 1.3, 0, 1));
  const core = clamp((t - 1.0) / 0.6, 0, 1);
  const verified = t > 3.2;
  const fw = [
    { mono: 'AI', color: C.brand, y: 360 },
    { mono: 'OA', color: 'oklch(78% 0.13 300)', y: 540 },
    { mono: 'LC', color: C.ok, y: 720 },
  ];
  const srcX = 460, gateX = 960;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ONE PROTOCOL" title="Different SDKs. Identical verification." />

      {/* wires */}
      <svg style={{ position: 'absolute', inset: 0 }} width="1920" height="1080">
        {fw.map((f, i) => (
          <line key={i} x1={srcX + 60} y1={f.y} x2={gateX - 90} y2={540}
            stroke={verified ? C.ok.replace(')', ' / 0.5)') : C.brandLine} strokeWidth="1.5"
            opacity={nodesIn * 0.7} strokeDasharray="6 8" />
        ))}
      </svg>

      {/* framework source nodes */}
      {fw.map((f, i) => (
        <div key={i} style={{ position: 'absolute', left: srcX, top: f.y, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * Easing.easeOutBack(clamp((t - (0.4 + i * 0.15)) / 0.5, 0, 1))})`, opacity: clamp((t - (0.4 + i * 0.15)) / 0.5, 0, 1) }}>
          <FwBadge mono={f.mono} color={f.color} size={74} />
        </div>
      ))}

      {/* traveling proof tokens */}
      {fw.map((f, i) => {
        if (flow <= 0 || flow >= 1) return null;
        const px = (srcX + 60) + (gateX - 90 - srcX - 60) * flow;
        const py = f.y + (540 - f.y) * flow;
        return (
          <div key={'p' + i} style={{ position: 'absolute', left: px, top: py, transform: 'translate(-50%,-50%)',
            padding: '5px 11px', borderRadius: 8, background: f.color.replace(')', ' / 0.16)'), border: `1px solid ${f.color.replace(')', ' / 0.5)')}`, whiteSpace: 'nowrap',
            fontFamily: MONO, fontSize: 14, color: C.ink }}>verifyBundle()</div>
        );
      })}

      {/* central verifier core */}
      <div style={{ position: 'absolute', left: gateX, top: 540, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * Easing.easeOutBack(core)})`, opacity: core,
        width: 300, padding: '30px', background: C.panelStrong, border: `1.5px solid ${verified ? C.ok.replace(')', ' / 0.6)') : C.brandLine}`, borderRadius: 24,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, boxShadow: `0 0 40px ${verified ? C.okSoft : C.brandSoft}` }}>
        <ShieldGlyph color={verified ? C.ok : C.brand} size={56} />
        <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 600, whiteSpace: 'nowrap' }}>Bolyra verify</span>
        <span style={{ fontFamily: MONO, fontSize: 14, color: C.inkFaint, letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>same 3 Groth16 circuits</span>
      </div>

      {/* output checks */}
      {verified && (
        <div style={{ position: 'absolute', left: 1380, top: 540, transform: 'translate(-50%,-50%)', opacity: clamp((t - 3.2) / 0.4, 0, 1),
          display: 'flex', flexDirection: 'column', gap: 14 }}>
          {['credential ✓', 'scope ✓', 'replay ✓', 'receipt ✓'].map((c, i) => (
            <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 10, padding: '10px 18px', borderRadius: 10,
              background: C.okSoft, border: `1px solid ${C.ok.replace(')', ' / 0.5)')}`, whiteSpace: 'nowrap',
              opacity: clamp((t - (3.3 + i * 0.12)) / 0.3, 0, 1) }}>
              <span style={{ fontFamily: MONO, fontSize: 18, color: C.ink, fontWeight: 500 }}>{c}</span>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// SCENE 4 — BREADTH
function FwBreadth({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const items = [
    { mono: 'MCP', name: 'MCP Middleware' }, { mono: 'GW', name: 'Auth Gateway' },
    { mono: 'AI', name: 'Vercel AI SDK' }, { mono: 'OA', name: 'OpenAI Agents' },
    { mono: 'LC', name: 'LangChain' }, { mono: 'PY', name: 'Python SDK' },
    { mono: 'OC', name: 'OpenClaw' }, { mono: 'CD', name: 'Claude Desktop' },
    { mono: 'CLI', name: 'Credential CLI' }, { mono: 'ZK', name: 'Prebuilt Circuits' },
  ];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ECOSYSTEM" title="Wherever your agents already run." />
      <div style={{ position: 'absolute', left: 960, top: 600, transform: 'translate(-50%,-50%)', display: 'grid', gridTemplateColumns: 'repeat(5, 1fr)', gap: 26, width: 1400 }}>
        {items.map((it, i) => {
          const ap = clamp((t - (0.5 + i * 0.12)) / 0.5, 0, 1);
          return (
            <div key={i} style={{ opacity: ap, transform: `translateY(${(1 - ap) * 16}px) scale(${0.9 + 0.1 * ap})`,
              display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 14, padding: '26px 14px', borderRadius: 16,
              background: C.panel, border: `1px solid ${C.border}` }}>
              <FwBadge mono={it.mono} color={C.brand} size={56} />
              <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkDim, textAlign: 'center', whiteSpace: 'nowrap' }}>{it.name}</span>
            </div>
          );
        })}
      </div>
    </div>
  );
}

// SCENE 5 — CTA
function FwCTA({ t, dur }) {
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
          Native adapters for the frameworks you <span style={{ color: C.brand }}>already ship</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <FwPill text="Vercel AI SDK" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <FwPill text="OpenAI Agents" color={C.inkDim} />
          <FwPill text="LangChain" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 24, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i <span style={{ color: C.brand }}>@bolyra/ai</span> · pip install <span style={{ color: C.brand }}>bolyra-agents</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · TS + Python · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { FwProblem, FwAdapters, FwUnified, FwBreadth, FwCTA });
