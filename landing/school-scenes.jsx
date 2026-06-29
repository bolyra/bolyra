// bolyra-scenes.jsx — the 13-scene explainer. Loads after animations.jsx + bolyra-kit.jsx.
const { C, smooth, rise, env, mix, TAU, SH, FH, FB,
        Critter, Bubble, Cap, SceneTitle, SceneBg, Floaters, Poseidon, Glyph } = window.BK;
const { useSprite, useTime, interpolate, animate, Easing, clamp, Sprite, Stage } = window;

const E = Easing;
const A = (from, to, start, end, ease = E.easeInOutCubic) => animate({ from, to, start, end, ease });
// shorthand: value of tween at lt
const tw = (lt, from, to, start, end, ease = E.easeInOutCubic) => A(from, to, start, end, ease)(lt);

// ── small shared bits ───────────────────────────────────────────────────────
function Card({ x, y, w, h, op = 1, sc = 1, bg = '#fff', radius = 26, shadow = SH.md, style = {}, children }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, width: w, height: h, opacity: op,
      transform: `translate(-50%,-50%) scale(${sc})`, background: bg, borderRadius: radius,
      boxShadow: shadow, ...style }}>{children}</div>
  );
}
function Chip({ label, color = C.purpleDk, bg = '#fff', size = 26 }) {
  return (
    <div style={{ display: 'inline-flex', alignItems: 'center', gap: 8, background: bg, color,
      fontFamily: FH, fontWeight: 600, fontSize: size, padding: '8px 16px', borderRadius: 999,
      boxShadow: SH.sm, border: `2px solid ${color}33` }}>{label}</div>
  );
}
function Token({ x, y, text, op = 1, color = C.ink, bg = '#fff', accent = C.purpleDk, size = 30, mono }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op }}>
      <div style={{ fontFamily: mono ? "'JetBrains Mono', monospace" : FH, fontWeight: 700, fontSize: size,
        color, background: bg, padding: '10px 18px', borderRadius: 14, boxShadow: SH.sm,
        border: `2.5px solid ${accent}`, whiteSpace: 'nowrap' }}>{text}</div>
    </div>
  );
}
function QMark({ x, y, t, delay = 0, size = 60 }) {
  const f = (Math.sin((t + delay) * 1.6) + 1) / 2;
  return (
    <div style={{ position: 'absolute', left: x, top: y - f * 16, fontFamily: FH, fontWeight: 700,
      fontSize: size, color: C.purpleDk, opacity: 0.55 + f * 0.4, transform: 'translate(-50%,-50%)' }}>?</div>
  );
}
function Sparkle({ x, y, t, d = 0, s = 14 }) {
  const k = (Math.sin((t + d) * 4) + 1) / 2;
  return <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.4 + k})`,
    opacity: 0.4 + k * 0.6, color: '#fff', fontSize: s }}>✦</div>;
}

// =============================================================================
// SCENE 1 — THE PROBLEM
// =============================================================================
function S1() {
  const { localTime: lt, duration: D } = useSprite();
  const hx = tw(lt, 380, 600, 0.3, 1.6, E.easeOutBack);
  const rx = tw(lt, 1540, 1320, 0.5, 1.8, E.easeOutBack);
  const vY = tw(lt, 1260, 760, 5.4, 6.6, E.easeOutBack);
  const vX = tw(lt, 1120, 960, 5.4, 6.8, E.easeOutCubic);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow={C.lav2} />
      <Floaters t={lt} tint={C.purple} op={0.35} />
      <SceneTitle lt={lt} a={0.2} b={1.1} c={4.4} d={5.0} kicker="Scene 1" title="On the internet, who is who?" />

      <Critter kind="human" x={hx} y={650} size={230} t={lt} mood={lt > 6.4 ? 'worried' : 'happy'}
        look={{ x: 0.4, y: 0 }} />
      <Critter kind="robot" x={rx} y={650} size={230} t={lt} phase={1.2} mood={lt > 6.4 ? 'worried' : 'happy'}
        look={{ x: -0.4, y: 0 }} />
      {lt > 5.2 && <Critter kind="villain" x={vX} y={vY} size={250} t={lt} phase={2.1} mood="sneaky" />}

      <Bubble x={600} y={500} text="I'm Alice!" op={env(lt, 2.1, 2.5, 12, 13)} scale={rise(lt, 2.1, 2.6)}
        accent={C.purpleDk} />
      <Bubble x={1320} y={500} text="I'm Helpful Bot!" op={env(lt, 3.0, 3.4, 12, 13)} scale={rise(lt, 3.0, 3.5)}
        accent={C.tealDk} />
      <Bubble x={830} y={620} text="I'm Alice too!" op={env(lt, 7.0, 7.4, 12, 13)} scale={rise(lt, 7.0, 7.5)}
        accent={C.redDk} color="#FFF0F2" />
      <Bubble x={1090} y={620} text="I'm Helpful Bot too!" op={env(lt, 8.6, 9.0, 12, 13)} scale={rise(lt, 8.6, 9.1)}
        accent={C.redDk} color="#FFF0F2" />

      {lt > 9.6 && [[470, 360, 0], [960, 300, 1.4], [1460, 360, 2.6], [720, 410, 3.4], [1230, 420, 0.7]].map((q, i) => (
        <QMark key={i} x={q[0]} y={q[1]} t={lt} delay={q[2]} size={i % 2 ? 54 : 72} />
      ))}

      <Cap lt={lt} a={10.4} b={11.0} text="On the internet, ANYONE can say ANYTHING." sub="So how do we know who's real?" />
    </>
  );
}

// =============================================================================
// SCENE 2 — WHY NOT PASSWORDS
// =============================================================================
function Server({ x, y, op = 1, face = 'happy' }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op }}>
      <div style={{ width: 150, height: 180, background: '#fff', borderRadius: 22, boxShadow: SH.md,
        border: `3px solid ${C.blueDk}33`, padding: 14, boxSizing: 'border-box' }}>
        {[0, 1, 2].map(i => (
          <div key={i} style={{ height: 30, background: C.cool, borderRadius: 8, marginBottom: 10,
            display: 'flex', alignItems: 'center', paddingLeft: 10 }}>
            <div style={{ width: 12, height: 12, borderRadius: '50%', background: i === 0 ? C.green : C.blue }} />
          </div>
        ))}
        <div style={{ display: 'flex', justifyContent: 'center', gap: 18, marginTop: 6 }}>
          <div style={{ width: 12, height: 12, borderRadius: '50%', background: C.ink }} />
          <div style={{ width: 12, height: 12, borderRadius: '50%', background: C.ink }} />
        </div>
        <div style={{ textAlign: 'center', marginTop: 2, color: C.ink, fontSize: 22 }}>
          {face === 'confused' ? '~' : '‿'}</div>
      </div>
      <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 800, color: C.blueDk, marginTop: 6 }}>SERVER</div>
    </div>
  );
}
function S2() {
  const { localTime: lt, duration: D } = useSprite();
  // pipe from 430 -> 1470 at y 560
  const x0 = 430, x1 = 1470, py = 560;
  const wordP = tw(lt, 0, 1, 2.4, 6.4, E.easeInOutSine); // travel progress
  const caught = lt > 5.0;
  const wordX = caught ? mix(rise(lt, 5.0, 5.8), x0 + (x1 - x0) * 0.52, 960) : mix(wordP, x0 + 40, x0 + (x1 - x0) * 0.52);
  const wordY = caught ? mix(rise(lt, 5.0, 5.8), py, 760) : py;
  const morph = rise(lt, 7.2, 8.6); // hacker -> alice
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.warm} glow="#FFEFD6" gx={50} gy={30} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 2" title="Why not just passwords?" />

      {/* pipe */}
      <div style={{ position: 'absolute', left: x0, top: py - 22, width: x1 - x0, height: 44,
        background: 'linear-gradient(#fff,#EFE6FF)', borderRadius: 999, boxShadow: 'inset 0 2px 6px rgba(0,0,0,.06)',
        border: `3px solid ${C.purple}55` }} />
      <div style={{ position: 'absolute', left: x0 + 6, top: py - 14, width: (x1 - x0) - 12, height: 8,
        background: '#fff', borderRadius: 999, opacity: 0.7 }} />

      <Critter kind="human" x={300} y={560} size={200} t={lt} mood="happy" look={{ x: 0.4, y: 0 }} />
      <Server x={1600} y={560} face={lt > 8.8 ? 'confused' : 'happy'} />

      {/* the travelling secret */}
      <Token x={wordX} y={wordY} text="dolphin123" mono accent={caught ? C.redDk : C.purpleDk}
        color={caught ? C.redDk : C.ink} op={env(lt, 2.2, 2.6, 11.6, 12)} size={28} />

      {/* hacker reaching up from below the wire */}
      <div style={{ opacity: 1 - morph * 0.92 }}>
        <Critter kind="villain" x={960} y={800} size={230} t={lt} phase={1} mood={morph > 0.5 ? 'sneaky' : 'cool'} />
      </div>
      {/* morph: villain becomes a copy of Alice */}
      {morph > 0.02 && <div style={{ position: 'absolute', left: 960, top: 800, transform: 'translate(-50%,-50%)',
        opacity: morph }}><Critter kind="human" x={0} y={0} size={230} t={lt} phase={1} mood="sneaky" style={{ position: 'static' }} /></div>}

      <Bubble x={300} y={430} text="psst… dolphin123" op={env(lt, 1.0, 1.4, 2.4, 2.8)} scale={rise(lt, 1.0, 1.5)} accent={C.purpleDk} size={26} />
      <Bubble x={960} y={720} text="Gotcha!" op={env(lt, 5.4, 5.8, 7.2, 7.6)} scale={rise(lt, 5.4, 5.9)} accent={C.redDk} color="#FFF0F2" />
      <Bubble x={960} y={680} text="Now I'm Alice!" op={env(lt, 8.8, 9.2, 13.4, 13.8)} scale={rise(lt, 8.8, 9.3)} accent={C.redDk} color="#FFF0F2" />

      <Cap lt={lt} a={10.2} b={10.8} text="Passwords travel. Travelers get caught." sub="Anyone who copies it becomes you." accent={C.redDk} />
    </>
  );
}

// =============================================================================
// SCENE 3 — ZERO KNOWLEDGE
// =============================================================================
function S3() {
  const { localTime: lt, duration: D } = useSprite();
  // curtain at center; prover left (sees color), verifier right (colorblind)
  const ballsIn = rise(lt, 1.0, 2.0);
  // rounds montage 4.0 -> 12.5
  const rStart = 4.0, rEnd = 12.5, rounds = 20;
  const rp = clamp((lt - rStart) / (rEnd - rStart), 0, 1);
  const count = Math.min(rounds, Math.floor(rp * rounds + 0.0001));
  const cyc = (lt - rStart) * 2.0; // curtain open/close pulse
  const curtainOpen = lt < 3.6 ? 1 : (lt > rEnd ? 1 : (Math.sin(cyc) > 0 ? 1 : 0));
  const curtainK = lt < 3.6 ? 1 : (lt > rEnd ? rise(lt, rEnd, rEnd + 0.5) : (0.5 + 0.5 * Math.sin(cyc * Math.PI)));
  const conf = Math.round(clamp(rp, 0, 1) * 100);
  const swapped = Math.floor((lt - rStart) * 1.3) % 2 === 0;
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow="#EAFBF3" gx={50} gy={40} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={3.0} d={3.6} kicker="Scene 3" title="Zero-Knowledge: the magic trick" />

      {/* prover (sees colors) left, verifier (colorblind) right */}
      <Critter kind="human" x={270} y={650} size={190} t={lt} mood="cool" look={{ x: 0.4, y: 0.1 }} />
      <div style={{ position: 'absolute', left: 270, top: 802, transform: 'translate(-50%,-50%)', fontFamily: FB,
        fontWeight: 800, color: C.purpleDk, fontSize: 22 }}>PROVER · sees colors</div>

      <Critter kind="robot" x={1650} y={650} size={190} t={lt} phase={1} mood="happy" look={{ x: -0.4, y: 0.1 }} />
      <div style={{ position: 'absolute', left: 1650, top: 802, transform: 'translate(-50%,-50%)', fontFamily: FB,
        fontWeight: 800, color: C.tealDk, fontSize: 22 }}>FRIEND · colorblind</div>

      {/* curtain / booth */}
      <div style={{ position: 'absolute', left: 960, top: 560, transform: 'translate(-50%,-50%)' }}>
        <div style={{ position: 'relative', width: 460, height: 360, background: '#fff', borderRadius: 24,
          boxShadow: SH.lg, border: `4px solid ${C.purple}44`, overflow: 'hidden' }}>
          {/* two balls inside */}
          <div style={{ position: 'absolute', top: 150, left: swapped ? 300 : 110, width: 80, height: 80,
            borderRadius: '50%', background: 'radial-gradient(circle at 35% 30%, #ff9aa6,' + C.red + ')',
            boxShadow: SH.sm, transition: 'none' }} />
          <div style={{ position: 'absolute', top: 150, left: swapped ? 110 : 300, width: 80, height: 80,
            borderRadius: '50%', background: 'radial-gradient(circle at 35% 30%, #9ff0c4,' + C.green + ')',
            boxShadow: SH.sm }} />
          {/* curtain panels */}
          <div style={{ position: 'absolute', top: 0, left: 0, bottom: 0, width: '50%',
            background: `linear-gradient(90deg, ${C.purpleDk}, ${C.purple})`, transform: `translateX(${-curtainK * 100}%)`,
            borderRight: '3px solid #fff' }} />
          <div style={{ position: 'absolute', top: 0, right: 0, bottom: 0, width: '50%',
            background: `linear-gradient(270deg, ${C.purpleDk}, ${C.purple})`, transform: `translateX(${curtainK * 100}%)`,
            borderLeft: '3px solid #fff' }} />
        </div>
        <div style={{ position: 'absolute', left: '50%', top: -34, transform: 'translateX(-50%)', fontFamily: FH,
          fontWeight: 600, fontSize: 26, color: C.ink }}>behind the curtain…</div>
      </div>

      {/* prover's verdict */}
      <Bubble x={500} y={420} text={swapped ? 'You swapped!' : "You didn't swap!"} op={env(lt, 4.4, 4.7, 12.6, 13)}
        scale={rise(lt, 4.4, 4.8)} accent={C.greenDk} color="#EEFBF4" size={26} />

      {/* round counter + confidence */}
      {lt > 3.8 && (
        <div style={{ position: 'absolute', left: 960, top: 880, transform: 'translate(-50%,-50%)', textAlign: 'center' }}>
          <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 30, color: C.ink }}>
            Round <span style={{ color: C.purpleDk }}>{count}</span> / 20 &nbsp; <span style={{ color: C.greenDk }}>✓</span>
          </div>
          <div style={{ width: 520, height: 22, background: '#fff', borderRadius: 999, marginTop: 12,
            boxShadow: SH.sm, overflow: 'hidden', border: `2px solid ${C.green}55` }}>
            <div style={{ height: '100%', width: conf + '%', borderRadius: 999,
              background: `linear-gradient(90deg, ${C.green}, ${C.greenDk})` }} />
          </div>
          <div style={{ fontFamily: FB, fontWeight: 800, color: C.greenDk, marginTop: 6 }}>confidence {conf}%</div>
        </div>
      )}

      <Cap lt={lt} a={13.0} b={13.6} c={15.4} d={15.9} text="Convinced — but never learned which ball was which." accent={C.greenDk} />
      {/* formula */}
      {lt > 15.6 && (
        <div style={{ position: 'absolute', left: 960, top: 540, transform: 'translate(-50%,-50%)',
          opacity: rise(lt, 15.6, 16.4), textAlign: 'center' }}>
          <div style={{ display: 'flex', gap: 30, alignItems: 'center', justifyContent: 'center' }}>
            <div style={{ background: '#fff', borderRadius: 22, padding: '26px 40px', boxShadow: SH.md, borderBottom: `5px solid ${C.purpleDk}` }}>
              <div style={{ fontFamily: FH, fontSize: 40, fontWeight: 600, color: C.purpleDk }}>PROVE</div>
              <div style={{ fontFamily: FB, fontWeight: 700, color: C.inkSoft, fontSize: 24 }}>you know it</div>
            </div>
            <div style={{ fontFamily: FH, fontSize: 50, color: C.ink }}>+</div>
            <div style={{ background: '#fff', borderRadius: 22, padding: '26px 40px', boxShadow: SH.md, borderBottom: `5px solid ${C.greenDk}` }}>
              <div style={{ fontFamily: FH, fontSize: 40, fontWeight: 600, color: C.greenDk }}>REVEAL</div>
              <div style={{ fontFamily: FB, fontWeight: 700, color: C.inkSoft, fontSize: 24 }}>nothing</div>
            </div>
          </div>
        </div>
      )}
    </>
  );
}

// =============================================================================
// SCENE 4 — HUMAN IDENTITY: THE LOCKED BOX
// =============================================================================
function S4() {
  const { localTime: lt, duration: D } = useSprite();
  const secretX = tw(lt, 470, 855, 1.2, 3.0, E.easeInOutCubic);
  const secretOp = env(lt, 1.0, 1.4, 3.0, 3.4);
  const inHopper = lt > 2.8;
  const spin = inHopper ? (lt - 2.8) * 1.6 : 0;
  const glow = env(lt, 3.0, 3.6, 5.2, 5.8);
  const outOp = env(lt, 5.0, 5.6, 13.5, 14);
  const outX = tw(lt, 1090, 1330, 5.0, 6.4, E.easeOutBack);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow={C.lav2} gx={45} gy={42} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 4 · Human identity" title="The Locked Box" />

      <Token x={secretX} y={420} text="secret 8 4 7 1 9" mono op={secretOp} accent={C.purpleDk} size={28} />
      <Poseidon x={960} y={560} scale={1.05} spin={spin} glow={glow} op={env(lt, 0.4, 1.0, 13.6, 14)} />

      {/* output commitment tag */}
      <div style={{ position: 'absolute', left: outX, top: 560, transform: 'translate(-50%,-50%)', opacity: outOp }}>
        <div style={{ filter: glow > 0.1 ? `drop-shadow(0 0 18px ${C.amber})` : 'none' }}>
          <Glyph size={150} color={C.amber} icon={<g>
            <rect x="38" y="44" width="24" height="20" rx="4" fill="#fff" />
            <path d="M42 44 v-6 a8 8 0 0 1 16 0 v6" fill="none" stroke="#fff" strokeWidth="4" />
          </g>} />
        </div>
        <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 900, color: C.amberDk, marginTop: 8, fontSize: 20 }}>
          COMMITMENT</div>
        <div style={{ textAlign: 'center', fontFamily: "'JetBrains Mono',monospace", color: C.inkSoft, fontSize: 16 }}>
          0x9f3a…c1</div>
      </div>
      {glow > 0.1 && [0, 1, 2, 3].map(i => <Sparkle key={i} x={outX - 40 + i * 30} y={490 + (i % 2) * 140} t={lt} d={i} />)}

      {/* one-way arrows */}
      {lt > 6.4 && (
        <div style={{ position: 'absolute', left: 960, top: 800, transform: 'translate(-50%,-50%)', opacity: rise(lt, 6.4, 7.0),
          display: 'flex', alignItems: 'center', gap: 16 }}>
          <Chip label="secret →" color={C.purpleDk} />
          <div style={{ fontFamily: FH, fontSize: 30, color: C.green }}>easy ✓</div>
          <div style={{ width: 30 }} />
          <Chip label="← reverse" color={C.redDk} />
          <div style={{ fontFamily: FH, fontSize: 30, color: C.redDk }}>impossible ✗</div>
        </div>
      )}

      <Cap lt={lt} a={8.0} b={8.6} text="A locked chest with your name on it — that nobody can open." sub="Everyone sees the tag. The secret stays inside." accent={C.amberDk} />
    </>
  );
}

// =============================================================================
// SCENE 5 — AGENT IDENTITY: THE SEALED ENVELOPE
// =============================================================================
function IngredientChip({ icon, label, color }) {
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 12, background: '#fff', borderRadius: 16,
      padding: '12px 20px', boxShadow: SH.sm, border: `2.5px solid ${color}` }}>
      <div style={{ width: 44, height: 44, borderRadius: 12, background: color + '22', display: 'flex',
        alignItems: 'center', justifyContent: 'center' }}>{icon}</div>
      <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 26, color: C.ink }}>{label}</div>
    </div>
  );
}
function S5() {
  const { localTime: lt, duration: D } = useSprite();
  const ings = [
    { label: 'Model Hash', color: C.blueDk, icon: <svg width="28" height="28" viewBox="0 0 24 24"><path d="M12 3a5 5 0 0 0-5 5 4 4 0 0 0-1 8 4 4 0 0 0 6 3 4 4 0 0 0 6-3 4 4 0 0 0-1-8 5 5 0 0 0-5-5z" fill="none" stroke={C.blueDk} strokeWidth="1.8" /></svg> },
    { label: 'Operator Signature', color: C.purpleDk, icon: <svg width="28" height="28" viewBox="0 0 24 24"><circle cx="12" cy="9" r="6" fill="none" stroke={C.purpleDk} strokeWidth="1.8" /><path d="M9 15l-1 6 4-2 4 2-1-6" fill="none" stroke={C.purpleDk} strokeWidth="1.8" /></svg> },
    { label: 'Permission Bits', color: C.green, icon: <svg width="30" height="30" viewBox="0 0 24 24"><rect x="3" y="7" width="18" height="10" rx="5" fill="none" stroke={C.greenDk} strokeWidth="1.8" /><circle cx="9" cy="12" r="3" fill={C.greenDk} /></svg> },
    { label: 'Expiry Clock', color: C.amberDk, icon: <svg width="28" height="28" viewBox="0 0 24 24"><circle cx="12" cy="13" r="8" fill="none" stroke={C.amberDk} strokeWidth="1.8" /><path d="M12 13V9M12 13l4 2M9 3h6" stroke={C.amberDk} strokeWidth="1.8" fill="none" strokeLinecap="round" /></svg> },
  ];
  const enterAt = [1.2, 2.2, 3.2, 4.2];
  const sealOp = env(lt, 6.4, 7.2, 13.6, 14);
  const spin = lt > 5.0 ? (lt - 5.0) * 1.4 : 0;
  const glow = env(lt, 5.4, 6.0, 6.8, 7.4);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.cool} glow="#E2ECFF" gx={40} gy={38} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 5 · Agent identity" title="The Sealed Envelope" />

      {/* ingredients stack on the left, fly into hopper */}
      {ings.map((ig, i) => {
        const op = env(lt, enterAt[i], enterAt[i] + 0.4, 4.8 + i * 0.1, 5.2 + i * 0.15);
        const x = tw(lt, 360, 940, enterAt[i] + 0.3, enterAt[i] + 1.4, E.easeInOutCubic);
        const y = tw(lt, 320 + i * 120, 430, enterAt[i] + 0.3, enterAt[i] + 1.4);
        return (
          <div key={i} style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op }}>
            <IngredientChip {...ig} />
          </div>
        );
      })}

      <Poseidon x={960} y={600} scale={1.05} spin={spin} glow={glow} op={env(lt, 0.4, 1.0, 13.6, 14)} />

      {/* sealed envelope output */}
      <div style={{ position: 'absolute', left: 1340, top: 600, transform: 'translate(-50%,-50%)', opacity: sealOp }}>
        <div style={{ filter: glow > 0.1 ? `drop-shadow(0 0 16px ${C.amber})` : 'none', position: 'relative' }}>
          <div style={{ width: 180, height: 124, background: '#fff', borderRadius: 14, boxShadow: SH.md,
            border: `3px solid ${C.amber}`, position: 'relative', overflow: 'hidden' }}>
            <div style={{ position: 'absolute', top: 0, left: 0, right: 0, height: 64,
              background: `linear-gradient(135deg, ${C.amber}33, ${C.amber}11)`,
              clipPath: 'polygon(0 0,100% 0,50% 80%)' }} />
            <div style={{ position: 'absolute', left: '50%', top: 62, transform: 'translate(-50%,-50%)',
              width: 40, height: 40, borderRadius: '50%', background: `radial-gradient(circle at 35% 30%, ${C.red}, ${C.redDk})`,
              boxShadow: SH.sm, display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff',
              fontFamily: FH, fontWeight: 700, fontSize: 20 }}>B</div>
          </div>
          <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 900, color: C.amberDk, marginTop: 8, fontSize: 20 }}>
            AGENT COMMITMENT</div>
        </div>
      </div>
      {glow > 0.1 && [0, 1, 2].map(i => <Sparkle key={i} x={1280 + i * 50} y={520 + (i % 2) * 130} t={lt} d={i} />)}

      <Cap lt={lt} a={8.2} b={8.8} text="Four secrets sealed into one tamper-proof envelope." sub="The badge is inside — nobody can peek." accent={C.amberDk} />
    </>
  );
}

// =============================================================================
// SCENE 6 — THE HANDSHAKE
// =============================================================================
function ProofGears({ x, y, spin, color, label, op = 1 }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op }}>
      <div style={{ width: 150, height: 150, borderRadius: 28, background: '#fff', boxShadow: SH.md,
        border: `3px solid ${color}55`, position: 'relative', overflow: 'hidden' }}>
        {[{ cx: 56, cy: 62, r: 30 }, { cx: 104, cy: 96, r: 22 }].map((g, i) => (
          <svg key={i} viewBox="0 0 150 150" width="150" height="150" style={{ position: 'absolute', inset: 0 }}>
            <g transform={`rotate(${spin * 360 * (i ? -1 : 1)} ${g.cx} ${g.cy})`}>
              {Array.from({ length: 9 }).map((_, k) => (
                <rect key={k} x={g.cx - 4} y={g.cy - g.r - 5} width="8" height="11" rx="2" fill={color}
                  transform={`rotate(${k * 40} ${g.cx} ${g.cy})`} />))}
              <circle cx={g.cx} cy={g.cy} r={g.r} fill={color} />
              <circle cx={g.cx} cy={g.cy} r={g.r * 0.4} fill="#fff" />
            </g>
          </svg>
        ))}
      </div>
      <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 800, color, marginTop: 6 }}>{label}</div>
    </div>
  );
}
function S6() {
  const { localTime: lt, duration: D } = useSprite();
  const coinDrop = tw(lt, 200, 320, 1.4, 2.4, E.easeOutBack);
  const spin = lt > 3.0 && lt < 8.6 ? (lt - 3.0) * 1.3 : (lt >= 8.6 ? (8.6 - 3.0) * 1.3 : 0);
  const timer = Math.min(140, Math.max(0, (lt - 3.0) / 5.6 * 140));
  const hpx = tw(lt, 420, 760, 8.6, 10.0, E.easeInOutCubic);
  const apx = tw(lt, 1500, 1160, 8.6, 10.0, E.easeInOutCubic);
  const verified = lt > 10.4;
  const proofsGone = env(lt, 8.6, 9.0, 10.0, 10.4);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow={C.lav2} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 6" title="The Handshake" />

      <Critter kind="human" x={250} y={620} size={200} t={lt} mood={verified ? 'cool' : 'happy'} look={{ x: 0.4, y: 0 }} />
      <Critter kind="robot" x={1670} y={620} size={200} t={lt} phase={1} mood={verified ? 'cool' : 'happy'} look={{ x: -0.4, y: 0 }} />

      {/* session nonce coin */}
      <div style={{ position: 'absolute', left: 960, top: coinDrop, transform: 'translate(-50%,-50%)',
        opacity: env(lt, 1.2, 1.6, 13.4, 13.9) }}>
        <div style={{ width: 96, height: 96, borderRadius: '50%', background: `radial-gradient(circle at 35% 30%, #FFE08A, ${C.amber})`,
          boxShadow: SH.glow(C.amber), display: 'flex', alignItems: 'center', justifyContent: 'center',
          border: `4px solid ${C.amberDk}`, fontFamily: FH, fontWeight: 700, fontSize: 30, color: C.amberDk }}>⬢</div>
        <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 800, color: C.amberDk, marginTop: 6, fontSize: 20 }}>
          SESSION NONCE</div>
        <div style={{ textAlign: 'center', fontFamily: "'JetBrains Mono',monospace", color: C.inkSoft, fontSize: 15 }}>fresh · never reused</div>
      </div>

      {/* parallel proof generation */}
      <ProofGears x={520} y={560} spin={spin} color={C.purpleDk} label="Human proof" op={env(lt, 2.8, 3.2, 8.4, 8.8) * (1 - proofsGone)} />
      <ProofGears x={1400} y={560} spin={spin} color={C.tealDk} label="Agent proof" op={env(lt, 2.8, 3.2, 8.4, 8.8) * (1 - proofsGone)} />
      {lt > 3.0 && lt < 8.8 && (
        <div style={{ position: 'absolute', left: 960, top: 540, transform: 'translate(-50%,-50%)', textAlign: 'center' }}>
          <div style={{ fontFamily: "'JetBrains Mono',monospace", fontWeight: 700, fontSize: 30, color: C.ink }}>
            {Math.round(timer)}ms</div>
          <div style={{ fontFamily: FB, fontWeight: 700, color: C.inkSoft, fontSize: 18 }}>Groth16 · in parallel…</div>
        </div>
      )}

      {/* proofs sliding to verify gate */}
      {lt > 8.6 && lt < 10.6 && (<>
        <Token x={hpx} y={560} text="π human" accent={C.purpleDk} op={1 - rise(lt, 10.0, 10.4)} />
        <Token x={apx} y={560} text="π agent" accent={C.tealDk} op={1 - rise(lt, 10.0, 10.4)} />
      </>)}

      {/* verify gate */}
      <div style={{ position: 'absolute', left: 960, top: 560, transform: 'translate(-50%,-50%)', opacity: env(lt, 8.4, 8.9, 13.4, 13.9) }}>
        <div style={{ width: 200, height: 150, borderRadius: 26, background: verified ? `linear-gradient(160deg, ${C.green}, ${C.greenDk})` : '#fff',
          boxShadow: verified ? SH.glow(C.green) : SH.md, border: `4px solid ${verified ? C.greenDk : C.purple + '55'}`,
          display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 6,
          transition: 'none' }}>
          <div style={{ width: 30, height: 30, borderRadius: '50%', background: verified ? '#fff' : '#ddd',
            boxShadow: verified ? '0 0 16px #fff' : 'none' }} />
          <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 28, color: verified ? '#fff' : C.inkSoft }}>
            {verified ? 'VERIFIED' : 'VERIFY'}</div>
        </div>
      </div>

      {/* outputs */}
      {verified && (
        <div style={{ position: 'absolute', left: 960, top: 830, transform: 'translate(-50%,-50%)',
          opacity: rise(lt, 10.6, 11.2), display: 'flex', gap: 16 }}>
          {['humanNullifier', 'agentNullifier', 'scopeCommitment'].map((o, i) => (
            <div key={i} style={{ background: '#fff', borderRadius: 14, padding: '12px 18px', boxShadow: SH.sm,
              fontFamily: "'JetBrains Mono',monospace", fontWeight: 700, fontSize: 20, color: C.greenDk,
              border: `2px solid ${C.green}66` }}>{o}</div>
          ))}
        </div>
      )}

      <Cap lt={lt} a={11.6} b={12.2} text="Both proved they're real." sub="Neither learned who the other actually is." accent={C.greenDk} />
    </>
  );
}

// =============================================================================
// SCENE 7 — PERMISSIONS CONTROL PANEL
// =============================================================================
function S7() {
  const { localTime: lt, duration: D } = useSprite();
  const sw = [
    { l: 'READ', c: C.blue }, { l: 'WRITE', c: C.blue }, { l: '$', c: C.green },
    { l: '$$', c: C.green, req: '$' }, { l: '$$$', c: C.green, req: '$+$$' },
    { l: 'SIGN', c: C.purpleDk }, { l: 'DELEGATE', c: C.purpleDk }, { l: 'PII', c: C.red },
  ];
  const buildAt = i => 1.0 + i * 0.35;
  // illegal attempt on $$$ at 5.4-7.0
  const illegal = lt > 5.6 && lt < 7.2;
  const snap = illegal ? Math.sin((lt - 5.6) * 18) * (1 - rise(lt, 5.6, 7.0)) : 0;
  // valid config at 8.5+: READ WRITE $ on
  const validOn = i => lt > 8.6 && (i === 0 || i === 1 || i === 2);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.cool} glow="#E6EEFF" />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 7" title="Permissions: the control panel" />

      <div style={{ position: 'absolute', left: 960, top: 520, transform: 'translate(-50%,-50%)' }}>
        <div style={{ background: '#fff', borderRadius: 30, boxShadow: SH.lg, padding: '34px 40px',
          border: `4px solid ${C.purple}33`, display: 'grid', gridTemplateColumns: 'repeat(4,1fr)', gap: 26 }}>
          {sw.map((s, i) => {
            const op = env(lt, buildAt(i), buildAt(i) + 0.4);
            const on = validOn(i);
            const isIllegal = illegal && i === 4;
            return (
              <div key={i} style={{ opacity: op, textAlign: 'center', width: 150,
                transform: isIllegal ? `translateX(${snap * 6}px)` : 'none' }}>
                <div style={{ width: 110, height: 56, margin: '0 auto', borderRadius: 999,
                  background: on ? `linear-gradient(90deg, ${C.green}, ${C.greenDk})` : (isIllegal ? '#FFE3E6' : '#E9E4F5'),
                  boxShadow: 'inset 0 2px 6px rgba(0,0,0,.12)', position: 'relative', transition: 'none',
                  border: isIllegal ? `2px solid ${C.redDk}` : 'none' }}>
                  <div style={{ position: 'absolute', top: 5, left: on ? 58 : 6, width: 46, height: 46,
                    borderRadius: '50%', background: '#fff', boxShadow: SH.sm }} />
                  {isIllegal && <div style={{ position: 'absolute', left: '50%', top: '50%', transform: 'translate(-50%,-50%)',
                    color: C.redDk, fontFamily: FH, fontWeight: 700, fontSize: 30 }}>✕</div>}
                </div>
                <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 26, color: s.c, marginTop: 10 }}>{s.l}</div>
                {s.req && <div style={{ fontFamily: FB, fontWeight: 700, fontSize: 16, color: C.inkSoft }}>needs {s.req}</div>}
              </div>
            );
          })}
        </div>
      </div>

      <Bubble x={1300} y={400} text="$$$ without $? Nope." op={env(lt, 5.8, 6.2, 7.2, 7.6)} scale={rise(lt, 5.8, 6.3)}
        accent={C.redDk} color="#FFF0F2" size={26} />

      {/* binary readout for valid config */}
      {lt > 9.2 && (
        <div style={{ position: 'absolute', left: 960, top: 830, transform: 'translate(-50%,-50%)',
          opacity: rise(lt, 9.2, 9.8), display: 'flex', alignItems: 'center', gap: 20 }}>
          <Chip label="READ + WRITE + $" color={C.greenDk} size={28} />
          <span style={{ fontFamily: FH, fontSize: 34, color: C.ink }}>=</span>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontSize: 40, fontWeight: 700, color: C.purpleDk }}>00000111</span>
          <span style={{ fontFamily: FH, fontSize: 34, color: C.ink }}>=</span>
          <div style={{ width: 70, height: 70, borderRadius: '50%', background: C.amber, display: 'flex',
            alignItems: 'center', justifyContent: 'center', fontFamily: FH, fontWeight: 700, fontSize: 40,
            color: C.ink, boxShadow: SH.md }}>7</div>
        </div>
      )}

      <Cap lt={lt} a={11.0} b={11.6} text="The circuit enforces the rules — you can't cheat." accent={C.purpleDk} />
    </>
  );
}

// =============================================================================
// SCENE 8 — DELEGATION: SHARING STICKERS
// =============================================================================
function Sticker({ label, color, op = 1, x, y, sc = 1, rot = 0 }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) rotate(${rot}deg) scale(${sc})`,
      opacity: op }}>
      <div style={{ background: color, color: '#fff', fontFamily: FH, fontWeight: 600, fontSize: 22,
        padding: '10px 16px', borderRadius: 14, boxShadow: SH.sm, border: '3px solid #fff', whiteSpace: 'nowrap' }}>{label}</div>
    </div>
  );
}
function S8() {
  const { localTime: lt, duration: D } = useSprite();
  // Parent (left), Child (mid), Grandchild (right)
  const peelRW = rise(lt, 2.6, 4.2); // READ+WRITE move parent->child
  const peelR = rise(lt, 7.0, 8.4);  // READ move child->grandchild
  const keyMorph1 = rise(lt, 11.0, 12.2);
  const keyMorph2 = rise(lt, 12.2, 13.4);
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow="#FFF0E0" gx={50} gy={36} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 8" title="Delegation: sharing your stickers" />

      {/* three agents */}
      <Critter kind="robot" x={330} y={560} size={170} t={lt} mood="happy" />
      <div style={{ position: 'absolute', left: 330, top: 670, transform: 'translate(-50%,-50%)', fontFamily: FB, fontWeight: 800, color: C.tealDk }}>PARENT</div>
      <Critter kind="robot" x={960} y={560} size={150} t={lt} phase={1} mood="happy" />
      <div style={{ position: 'absolute', left: 960, top: 660, transform: 'translate(-50%,-50%)', fontFamily: FB, fontWeight: 800, color: C.tealDk }}>CHILD</div>
      <Critter kind="robot" x={1560} y={560} size={130} t={lt} phase={2} mood="happy" />
      <div style={{ position: 'absolute', left: 1560, top: 650, transform: 'translate(-50%,-50%)', fontFamily: FB, fontWeight: 800, color: C.tealDk }}>GRANDCHILD</div>

      {/* parent's stickers: $ SIGN DELEGATE stay; READ WRITE move to child */}
      <Sticker label="$" color={C.green} x={250} y={360} op={env(lt, 0.8, 1.2)} rot={-6} />
      <Sticker label="SIGN" color={C.purpleDk} x={350} y={330} op={env(lt, 1.0, 1.4)} rot={4} />
      <Sticker label="DELEGATE" color={C.amberDk} x={300} y={420} op={env(lt, 1.2, 1.6)} rot={-3} />
      <Sticker label="READ" color={C.blue} x={mix(peelRW, 380, 900)} y={mix(peelRW, 360, 360)} op={env(lt, 1.4, 1.8)} rot={mix(peelRW, 6, 0)} />
      <Sticker label="WRITE" color={C.blue} x={mix(peelRW, 420, 1010)} y={mix(peelRW, 410, 350)} op={env(lt, 1.6, 2.0)} rot={mix(peelRW, -5, 0)} />

      {/* child's READ moves to grandchild */}
      <Sticker label="READ" color={C.blue} x={mix(peelR, 900, 1530)} y={mix(peelR, 360, 360)} op={peelRW * env(lt, 0, 0.1)} />

      {/* expiry clocks (shorter down the chain) */}
      {[{ x: 330, p: 0.9, lbl: '60 min' }, { x: 960, p: 0.55, lbl: '15 min' }, { x: 1560, p: 0.25, lbl: '3 min' }].map((c, i) => (
        <div key={i} style={{ position: 'absolute', left: c.x, top: 760, transform: 'translate(-50%,-50%)',
          opacity: env(lt, 3 + i * 2.2, 3.4 + i * 2.2), textAlign: 'center' }}>
          <svg width="56" height="56" viewBox="0 0 56 56">
            <circle cx="28" cy="30" r="22" fill="#fff" stroke={C.amberDk} strokeWidth="3" />
            <path d={`M28 30 L28 12`} stroke={C.amberDk} strokeWidth="3" strokeLinecap="round" transform={`rotate(${c.p * 330} 28 30)`} />
            <circle cx="28" cy="30" r="3" fill={C.amberDk} />
          </svg>
          <div style={{ fontFamily: FB, fontWeight: 800, fontSize: 18, color: C.amberDk }}>{c.lbl}</div>
        </div>
      ))}

      {/* arrow chain count */}
      {lt > 9.0 && (
        <div style={{ position: 'absolute', left: 960, top: 880, transform: 'translate(-50%,-50%)',
          opacity: rise(lt, 9.0, 9.6), display: 'flex', alignItems: 'center', gap: 14, fontFamily: FH, fontWeight: 600, fontSize: 30, color: C.ink }}>
          <span>Parent <b style={{ color: C.tealDk }}>[5]</b></span><span style={{ color: C.purpleDk }}>→</span>
          <span>Child <b style={{ color: C.tealDk }}>[2]</b></span><span style={{ color: C.purpleDk }}>→</span>
          <span>Grandchild <b style={{ color: C.tealDk }}>[1]</b></span>
        </div>
      )}

      {/* key morph analogy bottom-right */}
      {lt > 10.8 && (
        <div style={{ position: 'absolute', left: 1560, top: 880, transform: 'translate(-50%,-50%)', opacity: rise(lt, 10.8, 11.2),
          display: 'flex', gap: 10, alignItems: 'center', fontFamily: FB, fontWeight: 800, color: C.inkSoft, fontSize: 16 }}>
          <span style={{ opacity: 1 - keyMorph1 * 0.5 }}>🏠</span>→
          <span style={{ opacity: 1 - keyMorph2 * 0.5 }}>🍳</span>→
          <span>🧊</span>
        </div>
      )}

      <Cap lt={lt} a={9.6} b={10.2} text="Each hop can only get NARROWER. Never wider." sub="Enforced by math." accent={C.purpleDk} />
    </>
  );
}

// =============================================================================
// SCENE 9 — NULLIFIERS: ANONYMOUS RECEIPTS
// =============================================================================
function S9() {
  const { localTime: lt, duration: D } = useSprite();
  // three voters stamp ballots; P1 unique, P2 duplicate(of P1), P3 different
  const voters = [
    { at: 1.4, pat: 'A', dup: false, x: 560 },
    { at: 5.0, pat: 'A', dup: true, x: 960 },
    { at: 9.0, pat: 'B', dup: false, x: 1360 },
  ];
  const patColor = { A: C.purpleDk, B: C.blueDk };
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow={C.lav2} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 9" title="Nullifiers: anonymous receipts" />

      {/* voting booth */}
      <div style={{ position: 'absolute', left: 960, top: 360, transform: 'translate(-50%,-50%)' }}>
        <div style={{ width: 240, height: 120, background: C.purpleDk, borderRadius: '18px 18px 0 0', display: 'flex',
          alignItems: 'center', justifyContent: 'center', color: '#fff', fontFamily: FH, fontWeight: 600, fontSize: 28,
          boxShadow: SH.md }}>VOTE</div>
        <div style={{ width: 240, height: 12, background: C.amber }} />
      </div>

      {voters.map((v, i) => {
        const stamped = lt > v.at + 1.0;
        const op = env(lt, v.at, v.at + 0.4);
        const col = patColor[v.pat];
        return (
          <div key={i} style={{ position: 'absolute', left: v.x, top: 620, transform: 'translate(-50%,-50%)', opacity: op }}>
            <Critter kind={i === 1 ? 'villain' : 'human'} x={0} y={-40} size={130} t={lt} phase={i} mood={v.dup ? 'sneaky' : 'happy'} style={{ position: 'static' }} />
            {/* ballot */}
            <div style={{ width: 150, height: 110, background: '#fff', borderRadius: 12, boxShadow: SH.sm,
              border: `2px solid ${C.purple}44`, marginTop: 80, position: 'relative', overflow: 'hidden' }}>
              {stamped && (
                <div style={{ position: 'absolute', inset: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
                  opacity: rise(lt, v.at + 1.0, v.at + 1.5) }}>
                  <svg width="80" height="80" viewBox="0 0 80 80">
                    <circle cx="40" cy="40" r="34" fill="none" stroke={v.dup ? C.redDk : col} strokeWidth="5" />
                    <text x="40" y="52" textAnchor="middle" fontFamily="JetBrains Mono" fontWeight="700" fontSize="34"
                      fill={v.dup ? C.redDk : col}>{v.pat}</text>
                  </svg>
                </div>
              )}
            </div>
            {/* verdict */}
            {stamped && (
              <div style={{ textAlign: 'center', marginTop: 8, fontFamily: FH, fontWeight: 600, fontSize: 22,
                color: v.dup ? C.redDk : C.greenDk, opacity: rise(lt, v.at + 1.3, v.at + 1.8) }}>
                {v.dup ? '⚠ DUPLICATE!' : '✓ unique'}</div>
            )}
          </div>
        );
      })}

      <Bubble x={960} y={520} text="Same stamp — voted twice!" op={env(lt, 6.4, 6.8, 8.8, 9.2)} scale={rise(lt, 6.4, 6.9)}
        accent={C.redDk} color="#FFF0F2" size={26} />

      <Cap lt={lt} a={11.2} b={11.8} c={13.4} d={13.9} text="Detect cheaters — without ever knowing names." accent={C.redDk} />
      {lt > 13.4 && (
        <div style={{ position: 'absolute', left: 960, top: 968, transform: 'translate(-50%,-50%)', opacity: rise(lt, 13.4, 14.0) }}>
          <div style={{ background: '#fff', borderRadius: 999, padding: '14px 32px', boxShadow: SH.md, borderBottom: `4px solid ${C.purpleDk}`,
            fontFamily: "'JetBrains Mono',monospace", fontWeight: 700, fontSize: 28, color: C.ink }}>
            nullifier = Poseidon(<span style={{ color: C.purpleDk }}>scope</span>, <span style={{ color: C.amberDk }}>secret</span>)
          </div>
        </div>
      )}
    </>
  );
}

// =============================================================================
// SCENE 10 — SCOPE COMMITMENTS: THE CHAIN
// =============================================================================
function ChainLink({ x, y, size, color, idx, contents, op = 1 }) {
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op }}>
      <div style={{ width: size, height: size * 0.78, borderRadius: 999, border: `${size * 0.13}px solid ${color}`,
        background: '#fff', boxShadow: SH.md, display: 'flex', flexDirection: 'column', alignItems: 'center',
        justifyContent: 'center', position: 'relative' }}>
        <div style={{ fontFamily: FH, fontWeight: 600, fontSize: size * 0.13, color }}>scope_{idx}</div>
        {contents && <div style={{ fontFamily: FB, fontWeight: 800, fontSize: size * 0.085, color: C.inkSoft, textAlign: 'center', lineHeight: 1.3, marginTop: 4 }}>{contents}</div>}
      </div>
    </div>
  );
}
function S10() {
  const { localTime: lt, duration: D } = useSprite();
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.warm} glow="#FFF0DA" />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 10" title="Scope commitments: the chain" />

      <ChainLink x={520} y={540} size={300} color={C.amberDk} idx="0" op={env(lt, 1.0, 1.8)}
        contents={<>permissions<br />+ credential<br />+ expiry</>} />
      {/* connector */}
      <div style={{ position: 'absolute', left: 720, top: 540, width: 120, height: 20, background: C.amber,
        borderRadius: 999, transform: 'translateY(-50%)', opacity: env(lt, 4.4, 5.0) }} />
      <ChainLink x={960} y={540} size={230} color={C.greenDk} idx="1" op={env(lt, 4.6, 5.4)}
        contents={<>narrower<br />+ expiry</>} />
      <div style={{ position: 'absolute', left: 1110, top: 540, width: 100, height: 18, background: C.green,
        borderRadius: 999, transform: 'translateY(-50%)', opacity: env(lt, 7.6, 8.2) }} />
      <ChainLink x={1330} y={540} size={175} color={C.purpleDk} idx="2" op={env(lt, 7.8, 8.6)}
        contents={<>narrowest</>} />

      {/* delegation labels */}
      <div style={{ position: 'absolute', left: 740, top: 420, transform: 'translate(-50%,-50%)', fontFamily: FB, fontWeight: 800,
        color: C.greenDk, fontSize: 22, opacity: env(lt, 4.2, 4.8) }}>delegate ↓</div>
      <div style={{ position: 'absolute', left: 1115, top: 440, transform: 'translate(-50%,-50%)', fontFamily: FB, fontWeight: 800,
        color: C.purpleDk, fontSize: 22, opacity: env(lt, 7.4, 8.0) }}>delegate ↓</div>

      <Cap lt={lt} a={9.4} b={10.0} text="Each link proves the one before it was valid." sub="Unbreakable — like a chain of custody." accent={C.amberDk} />
    </>
  );
}

// =============================================================================
// SCENE 11 — THE THREE CIRCUITS
// =============================================================================
function Factory({ x, color, title, sub, inLabel, outLabel, steps, meta, t, appear }) {
  const belt = (t * 60) % 40;
  return (
    <div style={{ position: 'absolute', left: x, top: 540, transform: 'translate(-50%,-50%)', opacity: appear }}>
      <div style={{ width: 440, height: 470, background: '#fff', borderRadius: 26, boxShadow: SH.md,
        border: `4px solid ${color}55`, padding: 22, boxSizing: 'border-box' }}>
        {/* roof */}
        <div style={{ height: 54, background: color, borderRadius: '14px 14px 0 0', margin: '-22px -22px 16px',
          display: 'flex', alignItems: 'center', justifyContent: 'center', color: '#fff', fontFamily: FH, fontWeight: 600, fontSize: 28,
          clipPath: 'polygon(0 100%, 8% 0, 92% 0, 100% 100%)' }}>{title}</div>
        <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 800, color: C.inkSoft, fontSize: 18, marginBottom: 14 }}>{sub}</div>
        {/* steps */}
        <div style={{ display: 'flex', flexDirection: 'column', gap: 10, alignItems: 'center' }}>
          <Chip label={inLabel} color={color} size={22} />
          {steps.map((s, i) => (
            <div key={i} style={{ fontFamily: FB, fontWeight: 800, color: color, fontSize: 19 }}>↓ {s}</div>
          ))}
          <div style={{ background: color, color: '#fff', borderRadius: 12, padding: '10px 18px', fontFamily: FH,
            fontWeight: 600, fontSize: 22, boxShadow: SH.sm }}>{outLabel}</div>
        </div>
        {/* conveyor */}
        <div style={{ marginTop: 18, height: 22, borderRadius: 6, background: `repeating-linear-gradient(90deg, ${color}33 0 ${20 - belt / 2}px, ${color}66 ${20 - belt / 2}px 40px)` }} />
        <div style={{ textAlign: 'center', marginTop: 12, fontFamily: "'JetBrains Mono',monospace", fontWeight: 700, fontSize: 15, color }}>{meta}</div>
      </div>
      <div style={{ textAlign: 'center', marginTop: 12, fontFamily: FB, fontWeight: 800, color: C.inkSoft, fontSize: 16 }}>“{sub}”</div>
    </div>
  );
}
function S11() {
  const { localTime: lt, duration: D } = useSprite();
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.lav} glow={C.lav2} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 11" title="The three circuits" />

      <Factory x={490} color={C.blueDk} title="HumanUniqueness" sub="I'm in the group" inLabel="secret"
        steps={['Merkle proof checked']} outLabel="nullifier + nonce" meta="16,409 constraints" t={lt} appear={env(lt, 0.8, 1.6)} />
      <Factory x={960} color={C.greenDk} title="AgentPolicy" sub="I have valid credentials" inLabel="credential"
        steps={['signature verified', 'permissions checked']} outLabel="scope commitment" meta="20,923 constraints" t={lt} appear={env(lt, 1.6, 2.4)} />
      <Factory x={1430} color={C.amberDk} title="Delegation" sub="I'm giving fewer permissions" inLabel="parent + child scope"
        steps={['narrowing verified']} outLabel="new chain link" meta="22,398 constraints" t={lt} appear={env(lt, 2.4, 3.2)} />

      <Cap lt={lt} a={11.0} b={11.6} text="Three Groth16 circuits — rapidsnark proves each in ~100ms." accent={C.purpleDk} />
    </>
  );
}

// =============================================================================
// SCENE 12 — ON-CHAIN VERIFICATION
// =============================================================================
function S12() {
  const { localTime: lt, duration: D } = useSprite();
  const riseY = tw(lt, 760, 360, 2.0, 5.0, E.easeInOutCubic);
  const proofOp = env(lt, 1.6, 2.0, 5.0, 5.4);
  const gas = Math.min(590000, Math.max(0, (lt - 9.0) / 2.5 * 590000));
  // off-chain phase geometry
  const leaves = [750, 810, 870, 930, 990, 1050, 1110, 1170];
  const l1 = [780, 900, 1020, 1140], l2 = [840, 1080], rootX = 960;
  const yL = 450, y1 = 545, y2 = 635, yR = 720;
  const oL1 = rise(lt, 16.0, 16.7), oL2 = rise(lt, 16.9, 17.5), oR = rise(lt, 17.6, 18.4);
  const sessCount = Math.min(100, Math.floor(rise(lt, 14.6, 16.6) * 100));
  return (
    <>
      <SceneBg lt={lt} D={D} base={C.cool} glow="#E6EEFF" gy={30} />
      <SceneTitle lt={lt} a={0.2} b={1.0} c={2.0} d={2.6} kicker="Scene 12" title="On-chain verification" />

      {/* ===== PHASE A — on-chain ===== */}
      <div style={{ opacity: 1 - rise(lt, 13.0, 13.8) }}>
      {/* laptop */}
      <div style={{ position: 'absolute', left: 960, top: 880, transform: 'translate(-50%,-50%)', opacity: env(lt, 0.6, 1.2) }}>
        <div style={{ width: 260, height: 150, background: '#fff', borderRadius: '14px 14px 4px 4px', boxShadow: SH.md,
          border: `4px solid ${C.purple}44`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
          <span style={{ fontFamily: FB, fontWeight: 800, color: C.inkSoft, fontSize: 18, textAlign: 'center' }}>your computer<br />~140 ms</span>
        </div>
        <div style={{ width: 320, height: 16, background: C.purple, borderRadius: '0 0 12px 12px', marginLeft: -30 }} />
      </div>

      {/* two proofs rising */}
      <Token x={860} y={riseY} text="π human" accent={C.purpleDk} op={proofOp} />
      <Token x={1060} y={riseY} text="π agent" accent={C.tealDk} op={proofOp} />

      {/* blockchain cloud */}
      <div style={{ position: 'absolute', left: 960, top: 360, transform: 'translate(-50%,-50%)', opacity: env(lt, 4.0, 4.8) }}>
        <div style={{ width: 760, height: 300, background: 'linear-gradient(160deg,#fff,#F0F4FF)', borderRadius: 60,
          boxShadow: SH.lg, border: `4px solid ${C.blue}44`, padding: 24, boxSizing: 'border-box' }}>
          <div style={{ textAlign: 'center', fontFamily: FH, fontWeight: 600, fontSize: 30, color: C.blueDk }}>☁ Base Blockchain</div>
          <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 800, color: C.inkSoft, marginTop: 2, fontSize: 18 }}>IdentityRegistry contract</div>
          <div style={{ display: 'flex', justifyContent: 'center', gap: 18, marginTop: 18 }}>
            {[{ l: 'verify π human', at: 5.6 }, { l: 'verify π agent', at: 6.4 }, { l: 'nonce binding', at: 7.2 }].map((c, i) => (
              <div key={i} style={{ background: '#fff', borderRadius: 14, padding: '12px 16px', boxShadow: SH.sm,
                border: `2px solid ${lt > c.at ? C.green : '#ddd'}`, fontFamily: FB, fontWeight: 800, fontSize: 18,
                color: C.ink, display: 'flex', alignItems: 'center', gap: 8, opacity: env(lt, 5.0, 5.4) }}>
                <span style={{ color: C.greenDk, opacity: lt > c.at ? 1 : 0.2 }}>✓</span>{c.l}
              </div>
            ))}
          </div>
          {/* event stamp */}
          {lt > 8.0 && (
            <div style={{ textAlign: 'center', marginTop: 18, opacity: rise(lt, 8.0, 8.6),
              transform: `scale(${mix(rise(lt, 8.0, 8.5), 1.4, 1)})` }}>
              <span style={{ display: 'inline-block', background: C.green, color: '#fff', fontFamily: FH, fontWeight: 600,
                fontSize: 26, padding: '8px 24px', borderRadius: 12, boxShadow: SH.glow(C.green), border: '3px solid #fff',
                transform: 'rotate(-3deg)' }}>● HandshakeVerified</span>
            </div>
          )}
        </div>
      </div>

      {/* gas counter */}
      {lt > 9.0 && (
        <div style={{ position: 'absolute', left: 960, top: 760, transform: 'translate(-50%,-50%)', opacity: rise(lt, 9.0, 9.6),
          display: 'flex', alignItems: 'center', gap: 16, background: '#fff', borderRadius: 999, padding: '12px 28px', boxShadow: SH.md }}>
          <span style={{ fontFamily: "'JetBrains Mono',monospace", fontWeight: 700, fontSize: 30, color: C.purpleDk }}>
            ~{Math.round(gas).toLocaleString()} gas</span>
          <span style={{ fontFamily: FH, fontSize: 28, color: C.ink }}>≈</span>
          <span style={{ fontFamily: FH, fontWeight: 600, fontSize: 30, color: C.greenDk }}>$0.15</span>
        </div>
      )}

      <Cap lt={lt} a={12.0} b={12.6} c={12.9} d={13.6} text="Permanent. Trustless. Verifiable. Forever." accent={C.greenDk} />
      </div>

      {/* ===== PHASE B — off-chain mode ===== */}
      {lt > 13.6 && (<>
        <SceneTitle lt={lt} a={13.9} b={14.6} c={23.4} d={24} kicker="Scene 12 · Off-chain mode" title="Or — skip the chain almost entirely" />

        {/* local laptop, zero gas */}
        <div style={{ position: 'absolute', left: 430, top: 610, transform: 'translate(-50%,-50%)', opacity: env(lt, 13.9, 14.6, 23.6, 24) }}>
          <div style={{ width: 240, height: 150, background: '#fff', borderRadius: '14px 14px 4px 4px', boxShadow: SH.md,
            border: `4px solid ${C.green}66`, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 4 }}>
            <span style={{ fontFamily: FB, fontWeight: 800, color: C.inkSoft, fontSize: 16 }}>verify locally</span>
            <span style={{ fontFamily: FH, fontWeight: 600, fontSize: 38, color: C.greenDk }}>0 gas</span>
          </div>
          <div style={{ width: 300, height: 16, background: C.green, borderRadius: '0 0 12px 12px', marginLeft: -30 }} />
          <div style={{ textAlign: 'center', marginTop: 16, fontFamily: FH, fontWeight: 600, fontSize: 26, color: C.ink }}>
            <span style={{ color: C.greenDk }}>{sessCount}</span> / 100 sessions ✓</div>
        </div>

        {/* merkle tree collapsing 100 → 1 root */}
        <svg viewBox="0 0 1920 1080" width="1920" height="1080" style={{ position: 'absolute', inset: 0, opacity: env(lt, 14.5, 15.0, 23.6, 24) }}>
          {leaves.map((x, i) => (<line key={'e' + i} x1={x} y1={yL} x2={l1[i >> 1]} y2={y1} stroke={C.blue} strokeWidth="2.5" opacity={oL1 * 0.55} />))}
          {l1.map((x, i) => (<line key={'f' + i} x1={x} y1={y1} x2={l2[i >> 1]} y2={y2} stroke={C.blueDk} strokeWidth="2.5" opacity={oL2 * 0.6} />))}
          {l2.map((x, i) => (<line key={'g' + i} x1={x} y1={y2} x2={rootX} y2={yR} stroke={C.amberDk} strokeWidth="3.5" opacity={oR * 0.7} />))}
          {leaves.map((x, i) => (<rect key={'l' + i} x={x - 13} y={yL - 13} width="26" height="26" rx="6" fill={C.blue} opacity={rise(lt, 14.8 + i * 0.09, 15.1 + i * 0.09)} />))}
          {l1.map((x, i) => (<rect key={'a' + i} x={x - 12} y={y1 - 12} width="24" height="24" rx="6" fill={C.blueDk} opacity={oL1} />))}
          {l2.map((x, i) => (<rect key={'b' + i} x={x - 14} y={y2 - 14} width="28" height="28" rx="7" fill={C.purpleDk} opacity={oL2} />))}
        </svg>
        <div style={{ position: 'absolute', left: 960, top: 400, transform: 'translate(-50%,-50%)', opacity: env(lt, 15.0, 15.6, 23.6, 24),
          fontFamily: FB, fontWeight: 800, fontSize: 22, color: C.blueDk }}>100 verified sessions</div>

        {/* merkle root */}
        <div style={{ position: 'absolute', left: rootX, top: yR, transform: `translate(-50%,-50%) scale(${mix(rise(lt, 17.6, 18.2), 0.5, 1)})`, opacity: oR }}>
          <div style={{ width: 96, height: 96, borderRadius: 24, background: `radial-gradient(circle at 35% 30%, #FFE08A, ${C.amber})`,
            boxShadow: SH.glow(C.amber), border: `4px solid ${C.amberDk}`, display: 'flex', alignItems: 'center', justifyContent: 'center',
            fontFamily: FH, fontWeight: 700, fontSize: 40, color: C.amberDk, margin: '0 auto' }}>⬢</div>
          <div style={{ textAlign: 'center', fontFamily: FB, fontWeight: 900, fontSize: 18, color: C.amberDk, marginTop: 6 }}>MERKLE ROOT</div>
        </div>
        {oR > 0.3 && [0, 1, 2, 3].map(i => <Sparkle key={i} x={910 + i * 34} y={690 + (i % 2) * 60} t={lt} d={i} />)}

        {/* settle on chain in one tx */}
        {lt > 18.4 && (<>
          <div style={{ position: 'absolute', left: 958, top: 788, width: 5, height: 70, background: C.amber, borderRadius: 3,
            opacity: env(lt, 18.4, 19.0, 23.6, 24) }} />
          <div style={{ position: 'absolute', left: 960, top: 852, transform: 'translate(-50%,-50%)', opacity: env(lt, 18.6, 19.2, 23.6, 24) }}>
            <div style={{ background: 'linear-gradient(160deg,#fff,#F0F4FF)', borderRadius: 18, padding: '14px 30px', boxShadow: SH.md, whiteSpace: 'nowrap',
              border: `3px solid ${C.blue}55`, fontFamily: FH, fontWeight: 600, fontSize: 26, color: C.blueDk, display: 'flex', alignItems: 'center', gap: 12 }}>
              ☁ Base L2 <span style={{ color: C.inkSoft, fontFamily: FB, fontWeight: 800, fontSize: 22 }}>· 1 transaction settles all 100</span>
            </div>
          </div>
        </>)}

        {/* 375x badge */}
        {lt > 19.6 && (
          <div style={{ position: 'absolute', left: 1480, top: 600, transform: `translate(-50%,-50%) rotate(-4deg) scale(${mix(rise(lt, 19.6, 20.1), 1.35, 1)})`,
            opacity: env(lt, 19.6, 20.1, 23.6, 24) }}>
            <div style={{ background: C.green, color: '#fff', borderRadius: 18, padding: '16px 28px', boxShadow: SH.glow(C.green),
              border: '3px solid #fff', textAlign: 'center' }}>
              <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 38 }}>~375× less gas</div>
              <div style={{ fontFamily: FB, fontWeight: 800, fontSize: 20 }}>at a batch of 100</div>
            </div>
          </div>
        )}

        <Cap lt={lt} a={20.6} b={21.2} text="Verify locally for free — settle 100 sessions in ONE transaction." accent={C.greenDk} />
      </>)}
    </>
  );
}

// =============================================================================
// SCENE 13 — WHY THIS MATTERS
// =============================================================================
function S13() {
  const { localTime: lt, duration: D } = useSprite();
  const fade = rise(lt, 3.0, 6.0); // left fades to grayscale
  const glowR = rise(lt, 3.0, 6.0);
  return (
    <>
      <div style={{ position: 'absolute', inset: 0, background: C.lav, opacity: env(lt, 0, 0.4, D - 0.4, D) }} />
      {/* divider */}
      <div style={{ position: 'absolute', left: 960, top: 0, bottom: 0, width: 4, background: '#fff', opacity: env(lt, 0.6, 1.2) }} />

      {/* LEFT — old */}
      <div style={{ position: 'absolute', left: 0, top: 0, width: 960, height: 1080,
        filter: `grayscale(${fade}) brightness(${mix(fade, 1, 0.82)})`, opacity: mix(fade, 1, 0.55) }}>
        <div style={{ textAlign: 'center', marginTop: 120, fontFamily: FH, fontWeight: 600, fontSize: 40, color: C.inkSoft }}>The old way</div>
        {[{ x: 240, y: 360, l: '🔑 API key' }, { x: 600, y: 300, l: '🔑 copied' }, { x: 420, y: 520, l: '🔑 stolen' }].map((k, i) => (
          <div key={i} style={{ position: 'absolute', left: k.x, top: k.y + Math.sin((lt + i) * 1.2) * 10, transform: 'translate(-50%,-50%)',
            background: '#fff', borderRadius: 14, padding: '12px 20px', boxShadow: SH.sm, fontFamily: FH, fontWeight: 600, fontSize: 26,
            color: C.redDk, border: `2px solid ${C.red}55` }}>{k.l}</div>
        ))}
        <div style={{ position: 'absolute', left: 480, top: 720, transform: 'translate(-50%,-50%)', textAlign: 'center',
          fontFamily: FB, fontWeight: 800, fontSize: 24, color: C.inkSoft }}>
          servers peek at your data ·<br />single agents, no hierarchy</div>
      </div>

      {/* RIGHT — new */}
      <div style={{ position: 'absolute', left: 960, top: 0, width: 960, height: 1080,
        filter: glowR > 0.1 ? `drop-shadow(0 0 30px ${C.purple}66)` : 'none' }}>
        <div style={{ textAlign: 'center', marginTop: 120, fontFamily: FH, fontWeight: 600, fontSize: 40, color: C.purpleDk }}>The Bolyra way</div>
        {[{ x: 240, y: 320, l: '✓ ZK proof', c: C.greenDk }, { x: 560, y: 300, l: '✓ unforgeable', c: C.greenDk },
          { x: 400, y: 470, l: '✓ learns nothing', c: C.blueDk }, { x: 640, y: 520, l: '✓ narrowing', c: C.purpleDk }].map((k, i) => (
          <div key={i} style={{ position: 'absolute', left: k.x, top: k.y + Math.sin((lt + i) * 1.2) * 10, transform: 'translate(-50%,-50%)',
            background: '#fff', borderRadius: 14, padding: '12px 20px', boxShadow: glowR > 0.2 ? SH.glow(k.c) : SH.sm, fontFamily: FH,
            fontWeight: 600, fontSize: 26, color: k.c, border: `2px solid ${k.c}55`, opacity: env(lt, 1.0 + i * 0.3, 1.4 + i * 0.3) }}
            >{k.l}</div>
        ))}
        <div style={{ position: 'absolute', left: 480, top: 720, transform: 'translate(-50%,-50%)', textAlign: 'center',
          fontFamily: FB, fontWeight: 800, fontSize: 24, color: C.inkSoft }}>
          agents delegate to sub-agents ·<br />provably narrowing permissions</div>
      </div>

      {/* final line */}
      {lt > 7.0 && (
        <div style={{ position: 'absolute', left: 960, top: 920, transform: 'translate(-50%,-50%)', opacity: rise(lt, 7.0, 8.0), textAlign: 'center' }}>
          <div style={{ background: C.ink, borderRadius: 22, padding: '22px 46px', boxShadow: SH.lg }}>
            <span style={{ fontFamily: FH, fontWeight: 600, fontSize: 44, color: '#fff' }}>
              Identity isn't who you <span style={{ color: C.amber }}>ARE</span>.
              It's what you can <span style={{ color: C.green }}>PROVE</span>.</span>
          </div>
        </div>
      )}
    </>
  );
}

// =============================================================================
// LOGO OUTRO
// =============================================================================
function Logo() {
  const { localTime: lt, duration: D } = useSprite();
  const pop = rise(lt, 0.3, 1.4);
  const ring = lt * 0.4;
  return (
    <>
      <div style={{ position: 'absolute', inset: 0, background: `radial-gradient(60% 60% at 50% 45%, ${C.lav2}, ${C.lav})`,
        opacity: env(lt, 0, 0.4, D - 0.5, D) }} />
      <div style={{ position: 'absolute', left: 960, top: 460, transform: `translate(-50%,-50%) scale(${0.6 + 0.4 * smooth(pop)})`, opacity: pop }}>
        <svg width="220" height="220" viewBox="0 0 100 100" style={{ overflow: 'visible' }}>
          <g transform={`rotate(${ring * 40} 50 50)`}>
            {Array.from({ length: 6 }).map((_, i) => (
              <circle key={i} cx={50 + Math.cos(i / 6 * TAU) * 34} cy={50 + Math.sin(i / 6 * TAU) * 34} r="6"
                fill={[C.purple, C.amber, C.green, C.teal, C.blue, C.red][i]} opacity="0.9" />))}
          </g>
          <circle cx="50" cy="50" r="26" fill={C.purpleDk} />
          <text x="50" y="62" textAnchor="middle" fontFamily="'Fredoka',sans-serif" fontWeight="600" fontSize="34" fill="#fff">B</text>
        </svg>
      </div>
      <div style={{ position: 'absolute', left: 960, top: 660, transform: 'translate(-50%,-50%)', opacity: rise(lt, 1.2, 2.0), textAlign: 'center' }}>
        <div style={{ fontFamily: FH, fontWeight: 600, fontSize: 76, color: C.ink, letterSpacing: '0.02em' }}>Bolyra</div>
        <div style={{ fontFamily: FB, fontWeight: 800, fontSize: 26, color: C.purpleDk, letterSpacing: '0.16em', marginTop: 6 }}>
          PROVE WHO YOU ARE · TELL NO SECRETS</div>
      </div>
      {lt > 1.0 && [0, 1, 2, 3, 4, 5].map(i => <Sparkle key={i} x={760 + i * 80} y={380 + (i % 2) * 220} t={lt} d={i} s={20} />)}
    </>
  );
}

// =============================================================================
// ROOT
// =============================================================================
const SCENES = [S1, S2, S3, S4, S5, S6, S7, S8, S9, S10, S11, S12, S13, Logo];
const DUR =    [16, 15, 18, 13, 14, 16, 16, 17, 15, 14, 15, 24, 14, 7];
const TOTAL = DUR.reduce((a, b) => a + b, 0);

function BolyraExplainer() {
  let off = 0;
  const items = SCENES.map((Comp, i) => {
    const s = off; off += DUR[i];
    return (
      <Sprite key={i} start={s} end={off}>
        <Comp />
      </Sprite>
    );
  });
  return (
    <Stage width={1920} height={1080} duration={TOTAL} background={C.lav} persistKey="bolyra">
      {items}
    </Stage>
  );
}

window.BolyraExplainer = BolyraExplainer;
