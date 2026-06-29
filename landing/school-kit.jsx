// bolyra-kit.jsx — shared palette, helpers, and reusable characters/props
// Reads Stage/Sprite/Easing/etc from window (animations.jsx loaded first).

const C = {
  ink:      '#2E2350',
  inkSoft:  '#6B5E94',
  purple:   '#A98BFF',
  purpleDk: '#7C5CFF',
  amber:    '#FFB85C',
  amberDk:  '#F3982F',
  green:    '#46D39A',
  greenDk:  '#1FA873',
  red:      '#FF7184',
  redDk:    '#E5485E',
  blue:     '#6DA8FF',
  blueDk:   '#3E7BE0',
  teal:     '#4FC9DD',
  tealDk:   '#26A7BD',
  cream:    '#FFFFFF',
  lav:      '#F4F0FF',
  lav2:     '#ECE4FF',
  warm:     '#FFF6EC',
  cool:     '#EAF1FF',
};

// ── timing helpers ──────────────────────────────────────────────────────────
const smooth = (t) => { t = Math.max(0, Math.min(1, t)); return t * t * (3 - 2 * t); };
const rise = (lt, a, b) => smooth((lt - a) / (b - a));
// appear at [a,b], hold, disappear at [c,d]
const env = (lt, a, b, c = 1e9, d = 1e9) => rise(lt, a, b) * (1 - rise(lt, c, d));
const mix = (t, p, q) => p + (q - p) * t;
const TAU = Math.PI * 2;

// soft drop shadow presets
const SH = {
  sm: '0 4px 14px rgba(60,40,110,0.12)',
  md: '0 12px 30px rgba(60,40,110,0.16)',
  lg: '0 22px 50px rgba(60,40,110,0.22)',
  glow: (c) => `0 0 0 6px ${c}22, 0 14px 34px ${c}55`,
};

const FH = "'Fredoka', system-ui, sans-serif";  // headings
const FB = "'Nunito', system-ui, sans-serif";    // body

// ── Critter ─────────────────────────────────────────────────────────────────
// kind: human | robot | villain ; mood: happy|worried|sneaky|shocked|cool
function Critter({ kind = 'human', x = 0, y = 0, size = 220, look = { x: 0, y: 0 },
                   mood = 'happy', t = 0, phase = 0, style = {}, flip = false }) {
  const pal = {
    human:   { body: '#A98BFF', dk: '#7C5CFF', cheek: '#FF9FC0', foot: '#6B4FE0' },
    robot:   { body: '#4FC9DD', dk: '#2BA9BE', cheek: '#BDEFF6', foot: '#1E94A8' },
    villain: { body: '#6E5E8C', dk: '#4B3D68', cheek: '#897aa6', foot: '#3A2F52' },
  }[kind];
  const bob = Math.sin((t + phase) * 2.0) * (size * 0.018);
  const px = look.x, py = look.y;

  const mouths = {
    happy:   <path d="M46 98 Q60 114 74 98" stroke={pal.dk} strokeWidth="5" fill="none" strokeLinecap="round" />,
    worried: <path d="M48 106 Q60 98 72 106" stroke={pal.dk} strokeWidth="5" fill="none" strokeLinecap="round" />,
    sneaky:  <path d="M45 99 Q62 110 78 96" stroke={pal.dk} strokeWidth="5" fill="none" strokeLinecap="round" />,
    shocked: <ellipse cx="60" cy="104" rx="8" ry="10" fill={pal.dk} />,
    cool:    <path d="M48 100 Q60 108 72 100" stroke={pal.dk} strokeWidth="5" fill="none" strokeLinecap="round" />,
  };

  return (
    <div style={{ position: 'absolute', left: x, top: y, width: size, height: size * 1.25,
      transform: `translate(-50%,-50%) ${flip ? 'scaleX(-1)' : ''}`, ...style }}>
      <svg viewBox="0 0 120 150" width={size} height={size * 1.25}
           style={{ transform: `translateY(${bob}px)`, overflow: 'visible' }}>
        {/* feet */}
        <ellipse cx="46" cy="142" rx="13" ry="7" fill={pal.foot} />
        <ellipse cx="74" cy="142" rx="13" ry="7" fill={pal.foot} />
        {/* arms */}
        <ellipse cx="13" cy="92" rx="10" ry="17" fill={pal.body} />
        <ellipse cx="107" cy="92" rx="10" ry="17" fill={pal.body} />
        {/* body */}
        <ellipse cx="60" cy="80" rx="48" ry="60" fill={pal.body} />
        <ellipse cx="60" cy="92" rx="34" ry="40" fill="#ffffff" opacity="0.10" />

        {/* villain hat + mask sits behind eyes */}
        {kind === 'villain' && (
          <g>
            <rect x="30" y="14" width="60" height="16" rx="8" fill={pal.dk} />
            <rect x="44" y="2" width="32" height="18" rx="8" fill={pal.dk} />
            <rect x="16" y="56" width="88" height="26" rx="13" fill="#241C38" />
          </g>
        )}

        {/* robot antenna */}
        {kind === 'robot' && (
          <g>
            <line x1="60" y1="24" x2="60" y2="6" stroke={pal.dk} strokeWidth="4" strokeLinecap="round" />
            <circle cx="60" cy="5" r="7" fill={C.amber}>
              <animate attributeName="opacity" values="1;0.4;1" dur="1.4s" repeatCount="indefinite" />
            </circle>
          </g>
        )}
        {/* human flower */}
        {kind === 'human' && (
          <g transform="translate(86 26)">
            {[0,1,2,3,4].map(i => (
              <circle key={i} cx={Math.cos(i/5*TAU)*7} cy={Math.sin(i/5*TAU)*7} r="5.5" fill={C.amber} />
            ))}
            <circle cx="0" cy="0" r="5" fill={C.amberDk} />
          </g>
        )}

        {/* eyes */}
        <ellipse cx="45" cy="70" rx="13" ry="15" fill="#fff" />
        <ellipse cx="75" cy="70" rx="13" ry="15" fill="#fff" />
        <circle cx={45 + px * 5} cy={70 + py * 5} r={kind === 'robot' ? 6.5 : 6} fill="#241C38" />
        <circle cx={75 + px * 5} cy={70 + py * 5} r={kind === 'robot' ? 6.5 : 6} fill="#241C38" />
        <circle cx={43 + px * 5} cy={67 + py * 5} r="2.4" fill="#fff" />
        <circle cx={73 + px * 5} cy={67 + py * 5} r="2.4" fill="#fff" />

        {/* brows for mood */}
        {mood === 'worried' && (<g stroke={pal.dk} strokeWidth="4" strokeLinecap="round">
          <line x1="36" y1="50" x2="52" y2="55" /><line x1="84" y1="50" x2="68" y2="55" /></g>)}
        {(mood === 'sneaky' || mood === 'cool') && (<g stroke={pal.dk} strokeWidth="4" strokeLinecap="round">
          <line x1="34" y1="56" x2="54" y2="52" /><line x1="86" y1="56" x2="66" y2="52" /></g>)}

        {/* cheeks */}
        <circle cx="30" cy="86" r="7" fill={pal.cheek} opacity="0.7" />
        <circle cx="90" cy="86" r="7" fill={pal.cheek} opacity="0.7" />

        {mouths[mood] || mouths.happy}
      </svg>
    </div>
  );
}

// ── Speech bubble ───────────────────────────────────────────────────────────
function Bubble({ x, y, text, color = '#fff', textColor = C.ink, tail = 'down',
                 op = 1, scale = 1, size = 30, align = 'center', accent }) {
  const pop = smooth(scale);
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-100%) scale(${0.6 + 0.4 * pop})`,
      opacity: op, transformOrigin: tail === 'down' ? 'center bottom' : 'center top', willChange: 'transform,opacity' }}>
      <div style={{ position: 'relative', background: color, color: textColor, padding: '14px 22px',
        borderRadius: 22, fontFamily: FH, fontSize: size, fontWeight: 600, whiteSpace: 'nowrap',
        boxShadow: SH.md, border: accent ? `3px solid ${accent}` : 'none', textAlign: align }}>
        {text}
        <div style={{ position: 'absolute', left: '50%', bottom: -12, transform: 'translateX(-50%)',
          width: 0, height: 0, borderLeft: '12px solid transparent', borderRight: '12px solid transparent',
          borderTop: `14px solid ${accent || color}` }} />
        {accent && <div style={{ position: 'absolute', left: '50%', bottom: -8, transform: 'translateX(-50%)',
          width: 0, height: 0, borderLeft: '9px solid transparent', borderRight: '9px solid transparent',
          borderTop: `11px solid ${color}` }} />}
      </div>
    </div>
  );
}

// ── Caption pill (bottom) ───────────────────────────────────────────────────
function Cap({ lt, a, b, c = 1e9, d = 1e9, text, sub, y = 968, accent = C.purpleDk }) {
  const op = env(lt, a, b, c, d);
  if (op <= 0.002) return null;
  const up = (1 - smooth(rise(lt, a, b))) * 14;
  return (
    <div style={{ position: 'absolute', left: 960, top: y, transform: `translate(-50%,-50%) translateY(${up}px)`,
      opacity: op, textAlign: 'center', willChange: 'transform,opacity' }}>
      <div style={{ display: 'inline-block', background: '#fff', borderRadius: 999, padding: sub ? '14px 34px 16px' : '16px 38px',
        boxShadow: SH.md, borderBottom: `4px solid ${accent}` }}>
        <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 36, color: C.ink, lineHeight: 1.1 }}>{text}</div>
        {sub && <div style={{ fontFamily: FB, fontWeight: 700, fontSize: 22, color: C.inkSoft, marginTop: 4 }}>{sub}</div>}
      </div>
    </div>
  );
}

// ── Big scene title ─────────────────────────────────────────────────────────
function SceneTitle({ lt, a = 0.2, b = 1.0, c = 1e9, d = 1e9, kicker, title, y = 150, color = C.ink }) {
  const op = env(lt, a, b, c, d);
  if (op <= 0.002) return null;
  const up = (1 - smooth(rise(lt, a, b))) * 22;
  return (
    <div style={{ position: 'absolute', left: 960, top: y, transform: `translate(-50%,0) translateY(${up}px)`,
      opacity: op, textAlign: 'center' }}>
      {kicker && <div style={{ fontFamily: FB, fontWeight: 800, fontSize: 24, letterSpacing: '0.22em',
        color: C.purpleDk, textTransform: 'uppercase', marginBottom: 8 }}>{kicker}</div>}
      <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 64, color, lineHeight: 1.05 }}>{title}</div>
    </div>
  );
}

// ── Scene background (soft radial) ──────────────────────────────────────────
function SceneBg({ lt, D, base = C.lav, glow = C.lav2, gx = 50, gy = 38 }) {
  const op = env(lt, 0, 0.45, D - 0.45, D);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: op,
      background: `radial-gradient(120% 90% at ${gx}% ${gy}%, ${glow} 0%, ${base} 60%, ${base} 100%)` }} />
  );
}

// soft floating blobs decoration for backgrounds
function Floaters({ t, tint = '#ffffff', op = 0.5, seed = 0 }) {
  const items = [
    { x: 180, y: 250, r: 70 }, { x: 1680, y: 200, r: 90 }, { x: 1500, y: 820, r: 60 },
    { x: 300, y: 800, r: 80 }, { x: 980, y: 120, r: 46 },
  ];
  return items.map((it, i) => (
    <div key={i} style={{ position: 'absolute', left: it.x, top: it.y + Math.sin((t + seed + i) * 0.8) * 14,
      width: it.r * 2, height: it.r * 2, marginLeft: -it.r, marginTop: -it.r, borderRadius: '50%',
      background: tint, opacity: op * 0.5, filter: 'blur(2px)' }} />
  ));
}

// ── Poseidon hash machine ───────────────────────────────────────────────────
// A magical grinder. `spin` (0..1+) drives gear rotation, `glow` intensity.
function Poseidon({ x, y, scale = 1, spin = 0, glow = 0, label = 'POSEIDON', op = 1 }) {
  const W = 280, H = 230;
  return (
    <div style={{ position: 'absolute', left: x, top: y, width: W, height: H,
      transform: `translate(-50%,-50%) scale(${scale})`, opacity: op }}>
      {/* hopper */}
      <div style={{ position: 'absolute', left: W/2 - 60, top: -18, width: 120, height: 46,
        background: C.purpleDk, borderRadius: '12px 12px 4px 4px',
        clipPath: 'polygon(0 0,100% 0,78% 100%,22% 100%)', boxShadow: SH.sm }} />
      {/* body */}
      <div style={{ position: 'absolute', inset: 0, top: 24, background: `linear-gradient(160deg, ${C.purple}, ${C.purpleDk})`,
        borderRadius: 30, boxShadow: glow > 0.02 ? SH.glow(C.purpleDk) : SH.md, overflow: 'hidden' }}>
        <div style={{ position: 'absolute', inset: 0, opacity: 0.25 + glow * 0.5,
          background: `radial-gradient(60% 60% at 50% 40%, ${C.amber}, transparent 70%)` }} />
        {/* window with gears */}
        <div style={{ position: 'absolute', left: '50%', top: 96, transform: 'translate(-50%,-50%)',
          width: 150, height: 110, borderRadius: 18, background: '#241C38',
          border: `5px solid ${C.purpleDk}`, overflow: 'hidden', boxShadow: 'inset 0 4px 12px rgba(0,0,0,0.5)' }}>
          {[{cx:52,cy:54,r:34,dir:1},{cx:104,cy:60,r:26,dir:-1}].map((g,i)=>(
            <svg key={i} viewBox="0 0 150 110" width="150" height="110" style={{ position:'absolute', inset:0 }}>
              <g transform={`rotate(${spin*360*g.dir} ${g.cx} ${g.cy})`}>
                {Array.from({length:10}).map((_,k)=>(
                  <rect key={k} x={g.cx-4} y={g.cy-g.r-4} width="8" height="10" rx="2" fill={i?C.teal:C.amber}
                    transform={`rotate(${k*36} ${g.cx} ${g.cy})`} />
                ))}
                <circle cx={g.cx} cy={g.cy} r={g.r} fill={i?C.tealDk:C.amberDk} />
                <circle cx={g.cx} cy={g.cy} r={g.r*0.45} fill="#241C38" />
              </g>
            </svg>
          ))}
          {/* sparkles */}
          {glow>0.3 && Array.from({length:5}).map((_,i)=>(
            <div key={i} style={{ position:'absolute', left: 20+i*26, top: 14 + (i%2)*70,
              width:6, height:6, borderRadius:'50%', background:'#fff', opacity: (Math.sin(spin*12+i)+1)/2 }} />
          ))}
        </div>
        {/* spout */}
        <div style={{ position: 'absolute', right: -2, top: 150, width: 40, height: 26,
          background: C.purpleDk, borderRadius: '6px 14px 14px 6px' }} />
      </div>
      <div style={{ position: 'absolute', left: '50%', top: H + 2, transform: 'translateX(-50%)',
        fontFamily: FB, fontWeight: 900, fontSize: 18, letterSpacing: '0.18em', color: C.purpleDk }}>{label}</div>
    </div>
  );
}

// ── generic glyph card (a "tag"/"commitment") ──────────────────────────────
function Glyph({ size = 120, color = C.amber, icon }) {
  return (
    <svg viewBox="0 0 100 100" width={size} height={size} style={{ overflow: 'visible' }}>
      <defs>
        <pattern id={'hx'+color.replace('#','')} width="14" height="12" patternUnits="userSpaceOnUse" patternTransform="rotate(0)">
          <path d="M7 0 L14 4 L14 8 L7 12 L0 8 L0 4 Z" fill="none" stroke="#ffffff" strokeOpacity="0.5" strokeWidth="1" />
        </pattern>
      </defs>
      <circle cx="50" cy="50" r="46" fill={color} />
      <circle cx="50" cy="50" r="46" fill={`url(#hx${color.replace('#','')})`} />
      <circle cx="50" cy="50" r="46" fill="none" stroke="#fff" strokeWidth="3" strokeDasharray="4 6" opacity="0.8" />
      {icon}
    </svg>
  );
}

Object.assign(window, { BK: { C, smooth, rise, env, mix, TAU, SH, FH, FB,
  Critter, Bubble, Cap, SceneTitle, SceneBg, Floaters, Poseidon, Glyph } });
