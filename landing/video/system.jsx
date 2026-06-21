// system.jsx — palette, type, and shared visual primitives for the Bolyra Gateway launch video.
// Canvas is 1920 x 1080. Everything is coordinate-driven for predictable motion.

const C = {
  bg: '#0a0c10',
  ink: '#eef1f5',
  inkDim: 'rgba(238,241,245,0.56)',
  inkFaint: 'rgba(238,241,245,0.30)',
  inkGhost: 'rgba(238,241,245,0.12)',
  brand: 'oklch(72% 0.15 256)',
  brandSoft: 'oklch(72% 0.15 256 / 0.16)',
  brandLine: 'oklch(72% 0.15 256 / 0.5)',
  ok: 'oklch(78% 0.17 156)',
  okSoft: 'oklch(78% 0.17 156 / 0.16)',
  bad: 'oklch(67% 0.20 24)',
  badSoft: 'oklch(67% 0.20 24 / 0.16)',
  panel: 'rgba(255,255,255,0.035)',
  panelStrong: 'rgba(255,255,255,0.06)',
  border: 'rgba(255,255,255,0.10)',
  borderStrong: 'rgba(255,255,255,0.18)',
};

const DISPLAY = "'Space Grotesk', system-ui, sans-serif";
const MONO = "'JetBrains Mono', ui-monospace, SFMono-Regular, monospace";

// fade helper: returns opacity 0..1 for a sprite-local time given fade in/out windows
function fadeAt(localTime, duration, fin = 0.4, fout = 0.4) {
  if (localTime < 0) return 0;
  if (localTime < fin) return clamp(localTime / fin, 0, 1);
  if (localTime > duration - fout) return clamp((duration - localTime) / fout, 0, 1);
  return 1;
}

// ── Ambient background: faint drifting grid + soft vignette + glow ───────────
function Backdrop({ glowX = 960, glowY = 540, glowColor = C.brand, glowStrength = 0.0 }) {
  const time = useTime();
  const drift = (time * 6) % 64;
  return (
    <div style={{ position: 'absolute', inset: 0, background: C.bg, overflow: 'hidden' }}>
      <div style={{
        position: 'absolute', inset: -64,
        backgroundImage: `linear-gradient(${C.inkGhost} 1px, transparent 1px), linear-gradient(90deg, ${C.inkGhost} 1px, transparent 1px)`,
        backgroundSize: '64px 64px',
        transform: `translate(${drift}px, ${drift * 0.5}px)`,
        opacity: 0.5,
        maskImage: 'radial-gradient(ellipse 75% 70% at 50% 50%, #000 55%, transparent 100%)',
        WebkitMaskImage: 'radial-gradient(ellipse 75% 70% at 50% 50%, #000 55%, transparent 100%)',
      }} />
      <div style={{
        position: 'absolute', inset: 0,
        background: `radial-gradient(circle 640px at ${glowX}px ${glowY}px, oklch(72% 0.15 256 / ${0.13 + glowStrength}), transparent 70%)`,
        opacity: 1,
      }} />
      <div style={{
        position: 'absolute', inset: 0,
        boxShadow: 'inset 0 0 320px rgba(0,0,0,0.7)',
      }} />
    </div>
  );
}

// ── Mono kicker label (eyebrow) ──────────────────────────────────────────────
function Kicker({ children, color = C.brand, style }) {
  return (
    <div style={{
      fontFamily: MONO, fontSize: 22, letterSpacing: '0.32em', whiteSpace: 'nowrap',
      textTransform: 'uppercase', color, fontWeight: 500, ...style,
    }}>{children}</div>
  );
}

// ── Lower-third caption ──────────────────────────────────────────────────────
function Caption({ t, dur, kicker, title, sub, x = 960, y = 880, align = 'center' }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const rise = (1 - clamp(t / 0.6, 0, 1)) * 22;
  return (
    <div style={{
      position: 'absolute', left: x, top: y,
      transform: `translate(-50%, ${rise}px)`, opacity: o,
      textAlign: align, width: 1300,
      display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center',
    }}>
      {kicker && <Kicker>{kicker}</Kicker>}
      {title && <div style={{ fontFamily: DISPLAY, fontSize: 58, fontWeight: 600, color: C.ink, letterSpacing: '-0.02em', lineHeight: 1.05 }}>{title}</div>}
      {sub && <div style={{ fontFamily: MONO, fontSize: 26, color: C.inkDim, fontWeight: 400, letterSpacing: '0.01em' }}>{sub}</div>}
    </div>
  );
}

// ── Agent chip ───────────────────────────────────────────────────────────────
// state: 'idle' | 'rogue'
function AgentChip({ x, y, label, state = 'idle', appear = 1, dim = false }) {
  const rogue = state === 'rogue';
  const accent = rogue ? C.bad : C.brand;
  const s = 0.7 + 0.3 * appear;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${s})`,
      opacity: (dim ? 0.4 : 1) * appear,
      display: 'flex', alignItems: 'center', gap: 14,
      padding: '14px 20px 14px 16px',
      background: C.panel, border: `1px solid ${rogue ? C.badSoft : C.border}`,
      borderRadius: 14, width: 300, boxSizing: 'border-box',
      backdropFilter: 'blur(2px)',
    }}>
      <div style={{
        width: 40, height: 40, borderRadius: 10, flexShrink: 0,
        background: rogue ? C.badSoft : C.brandSoft,
        border: `1px solid ${accent.replace(')', ' / 0.5)')}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
      }}>
        <div style={{ width: 12, height: 12, borderRadius: 3, background: accent }} />
      </div>
      <div style={{ display: 'flex', flexDirection: 'column', gap: 3, minWidth: 0 }}>
        <div style={{ fontFamily: MONO, fontSize: 19, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap', overflow: 'hidden', textOverflow: 'ellipsis' }}>{label}</div>
        <div style={{ fontFamily: MONO, fontSize: 13, color: rogue ? C.bad : C.inkFaint, letterSpacing: '0.06em', textTransform: 'uppercase' }}>{rogue ? 'unverified' : 'agent'}</div>
      </div>
    </div>
  );
}

// ── MCP server node ──────────────────────────────────────────────────────────
function ServerNode({ x, y, appear = 1, guarded = false, breach = 0 }) {
  const tools = [
    { name: 'search()', risk: false },
    { name: 'fetch()', risk: false },
    { name: 'charge()', risk: true },
    { name: 'delete()', risk: true },
  ];
  const s = 0.85 + 0.15 * appear;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${s})`,
      opacity: appear, width: 320,
      background: C.panelStrong, border: `1px solid ${guarded ? C.brandLine : C.border}`,
      borderRadius: 18, overflow: 'hidden',
      boxShadow: guarded ? `0 0 0 1px ${C.brandSoft}, 0 24px 60px rgba(0,0,0,0.5)` : '0 24px 60px rgba(0,0,0,0.5)',
    }}>
      <div style={{
        display: 'flex', alignItems: 'center', gap: 12, padding: '18px 22px',
        borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)',
      }}>
        <div style={{ width: 10, height: 10, borderRadius: 5, background: breach > 0.5 ? C.bad : (guarded ? C.ok : C.inkDim), boxShadow: `0 0 12px ${breach > 0.5 ? C.bad : (guarded ? C.ok : 'transparent')}` }} />
        <div style={{ fontFamily: MONO, fontSize: 19, color: C.ink, letterSpacing: '0.04em', fontWeight: 500 }}>MCP&nbsp;SERVER</div>
      </div>
      <div style={{ display: 'flex', flexDirection: 'column' }}>
        {tools.map((tool, i) => (
          <div key={i} style={{
            display: 'flex', alignItems: 'center', justifyContent: 'space-between',
            padding: '15px 22px', borderBottom: i < tools.length - 1 ? `1px solid ${C.inkGhost}` : 'none',
          }}>
            <span style={{ fontFamily: MONO, fontSize: 20, color: tool.risk ? C.ink : C.inkDim, fontWeight: tool.risk ? 500 : 400 }}>{tool.name}</span>
            <span style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.08em',
              color: guarded ? C.ok : (tool.risk ? C.bad : C.inkFaint) }}>
              {guarded ? 'GATED' : (tool.risk ? 'OPEN' : 'open')}
            </span>
          </div>
        ))}
      </div>
    </div>
  );
}

// ── The gateway gate ─────────────────────────────────────────────────────────
function Gate({ x, y, h = 560, appear = 1, pulse = 0 }) {
  const drop = (1 - appear) * -120;
  const glow = 0.4 + 0.6 * (0.5 + 0.5 * Math.sin(pulse * Math.PI * 2));
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: appear }}>
      {/* vertical beam */}
      <div style={{
        position: 'absolute', left: '50%', top: drop, transform: 'translate(-50%,-50%)',
        width: 8, height: h, borderRadius: 4,
        background: `linear-gradient(${C.brand}, ${C.brandLine})`,
        boxShadow: `0 0 ${18 + glow * 26}px ${C.brand.replace(')', ' / ' + (0.4 + glow * 0.4) + ')')}`,
      }} />
      {/* shield medallion */}
      <div style={{
        position: 'absolute', left: '50%', top: drop, transform: 'translate(-50%,-50%)',
        width: 110, height: 110, borderRadius: 26,
        background: C.bg, border: `2px solid ${C.brand}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center',
        boxShadow: `0 0 ${20 + glow * 30}px ${C.brandSoft}, inset 0 0 30px ${C.brandSoft}`,
      }}>
        <ShieldGlyph color={C.brand} size={50} />
      </div>
    </div>
  );
}

function ShieldGlyph({ color = C.brand, size = 44 }) {
  return (
    <svg width={size} height={size} viewBox="0 0 24 24" fill="none">
      <path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 8.4 7.5 10 4.3-1.6 7.5-5.4 7.5-10v-6L12 2.5Z" stroke={color} strokeWidth="1.6" strokeLinejoin="round" fill={color.replace(')', ' / 0.12)')} />
      <path d="M8.6 12.2l2.4 2.4 4.4-4.6" stroke={color} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

// ── Data packet traveling horizontally ───────────────────────────────────────
function Packet({ x, y, label, color = C.brand, scale = 1, opacity = 1 }) {
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${scale})`, opacity,
      display: 'flex', alignItems: 'center', gap: 9,
      padding: '8px 14px', borderRadius: 9,
      background: color.replace(')', ' / 0.14)'), border: `1px solid ${color.replace(')', ' / 0.55)')}`,
      whiteSpace: 'nowrap', backdropFilter: 'blur(2px)',
    }}>
      <div style={{ width: 8, height: 8, borderRadius: 4, background: color, boxShadow: `0 0 10px ${color}` }} />
      <span style={{ fontFamily: MONO, fontSize: 16, color: C.ink, fontWeight: 500 }}>{label}</span>
    </div>
  );
}

// ── Stamp (VERIFIED / REJECTED) ──────────────────────────────────────────────
function Stamp({ x, y, kind = 'ok', appear = 1 }) {
  const ok = kind === 'ok';
  const color = ok ? C.ok : C.bad;
  const s = appear < 0.5 ? (1.6 - 1.2 * Easing.easeOutBack(clamp(appear / 0.5, 0, 1))) : 1;
  const rot = ok ? -8 : 7;
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
      <span style={{ fontFamily: MONO, fontSize: 22, fontWeight: 600, letterSpacing: '0.1em', color }}>{ok ? 'VERIFIED' : 'REJECTED'}</span>
    </div>
  );
}

Object.assign(window, {
  C, DISPLAY, MONO, fadeAt,
  Backdrop, Kicker, Caption, AgentChip, ServerNode, Gate, ShieldGlyph, Packet, Stamp,
});
