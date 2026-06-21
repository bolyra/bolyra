// scenes_hero.jsx — the evolving hero diagram: problem -> gate drop-in + command -> verify/reject.
// Drives all internal state from a single localTime `t` (0..18) so it stays mounted (no flicker).

const LANE = { x: 360, y0: 384, y1: 540, y2: 696 };
const GATE_X = 962;
const SRV_X = 1486;
const SRV_LEFT = 1330;       // left edge of server panel
const AGENT_RIGHT = 512;     // right edge of an agent chip

// Typing terminal for the install command
function TerminalCommand({ t, start, x = 960, y = 902, width = 1180 }) {
  const cmd = 'npx @bolyra/gateway --target http://localhost:3000/mcp';
  const local = t - start;
  const o = clamp(local / 0.5, 0, 1);
  if (o <= 0) return null;
  const typeDur = 1.9;
  const chars = Math.round(clamp(local / typeDur, 0, 1) * cmd.length);
  const shown = cmd.slice(0, chars);
  const done = chars >= cmd.length;
  const blink = Math.floor(useTime() * 1.6) % 2 === 0;
  const rise = (1 - clamp(local / 0.45, 0, 1)) * 16;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${rise}px)`,
      opacity: o, width, boxSizing: 'border-box',
      background: 'rgba(10,13,18,0.82)', border: `1px solid ${C.borderStrong}`,
      borderRadius: 14, padding: '20px 26px', display: 'flex', alignItems: 'center', gap: 18,
      boxShadow: '0 24px 60px rgba(0,0,0,0.5)', backdropFilter: 'blur(4px)',
    }}>
      <div style={{ display: 'flex', gap: 8, flexShrink: 0 }}>
        <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
        <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
        <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
      </div>
      <div style={{ fontFamily: MONO, fontSize: 27, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap', letterSpacing: '0.005em' }}>
        <span style={{ color: C.ok }}>$</span>&nbsp;
        <span>npx </span>
        <span style={{ color: C.brand }}>{shown.slice(4) ? '@bolyra/gateway' : ''}</span>
        <span style={{ color: C.inkDim }}>{shown.slice(19)}</span>
        <span style={{ opacity: (done ? blink : true) ? 1 : 0, color: C.brand }}>▍</span>
      </div>
    </div>
  );
}

// One request packet, with phase-aware trajectory.
function renderRequest(req, t) {
  const age = t - req.launchT;
  const y = req.y;
  if (age < 0) return null;

  if (req.mode === 'direct') {
    // agent -> server straight through (no gate)
    const life = 1.5;
    if (age > life + 0.3) return null;
    const p = clamp(age / life, 0, 1);
    const x = AGENT_RIGHT + (SRV_LEFT - AGENT_RIGHT) * Easing.easeInOutQuad(p);
    const op = clamp(age / 0.2, 0, 1) * (age > life ? clamp((life + 0.3 - age) / 0.3, 0, 1) : 1);
    return <Packet key={req.id} x={x} y={y} label={req.label} color={req.kind === 'rogue' ? C.bad : C.brand} opacity={op} />;
  }

  // gated mode: agent -> gate (check) -> (valid: gate->server) | (rogue: bounce back)
  const segIn = 0.85;
  const stampAt = segIn + 0.05;
  const els = [];
  if (age <= segIn) {
    const p = clamp(age / segIn, 0, 1);
    const x = AGENT_RIGHT + (GATE_X - 96 - AGENT_RIGHT) * Easing.easeInOutQuad(p);
    const op = clamp(age / 0.18, 0, 1);
    els.push(<Packet key={req.id} x={x} y={y} label={req.label} color={req.kind === 'rogue' ? C.bad : C.brand} opacity={op} />);
  } else {
    // stamp at gate
    const sAge = age - stampAt;
    if (sAge > 0 && sAge < 1.4) {
      els.push(<Stamp key={req.id + '-stamp'} x={GATE_X} y={y - 50} kind={req.kind === 'rogue' ? 'bad' : 'ok'} appear={clamp(sAge / 0.3, 0, 1)} />);
    }
    if (req.kind === 'valid') {
      const p = clamp((age - segIn - 0.35) / 0.95, 0, 1);
      if (p > 0) {
        const x = (GATE_X + 70) + (SRV_LEFT - GATE_X - 70) * Easing.easeInOutQuad(p);
        const op = p > 0.85 ? clamp((1 - p) / 0.15, 0, 1) : 1;
        els.push(<Packet key={req.id + '-ok'} x={x} y={y} label="200 OK" color={C.ok} opacity={op} />);
      }
    } else {
      const p = clamp((age - segIn - 0.35) / 0.9, 0, 1);
      if (p > 0) {
        const x = (GATE_X - 96) - ((GATE_X - 96) - AGENT_RIGHT - 40) * Easing.easeInQuad(p);
        const op = clamp((1 - p) / 0.4, 0, 1);
        els.push(<Packet key={req.id + '-rej'} x={x} y={y - 4} label="403" color={C.bad} opacity={op} />);
      }
    }
  }
  return <React.Fragment key={req.id}>{els}</React.Fragment>;
}

function HeroDiagram({ t }) {
  // ── phase flags ──
  const gateAppear = clamp((t - 5.3) / 1.0, 0, 1);
  const gateOn = gateAppear > 0.05;
  const gA = Easing.easeOutBack(gateAppear);
  const guarded = t > 6.3;
  const elemAppear = Easing.easeOutCubic(clamp((t - 0.2) / 0.9, 0, 1));

  // rogue breach flash in P1
  const breach = (t > 3.35 && t < 4.9) ? clamp((t - 3.35) / 0.25, 0, 1) * clamp((4.9 - t) / 0.6, 0, 1) : 0;

  // gentle slow push-in
  const s = interpolate([0, 18], [1.0, 1.07], Easing.easeInOutSine)(t);
  const fx = interpolate([0, 5, 10, 18], [960, 1000, 980, 1120], Easing.easeInOutSine)(t);
  const fy = 540;
  const tx = 960 - fx * s, ty = 540 - fy * s;

  // ── request schedule ──
  const reqs = [];
  // P1 problem: direct hits
  reqs.push({ id: 'p1a', launchT: 1.3, y: LANE.y0, kind: 'valid', mode: 'direct', label: 'search()' });
  reqs.push({ id: 'p1b', launchT: 1.75, y: LANE.y1, kind: 'valid', mode: 'direct', label: 'fetch()' });
  reqs.push({ id: 'p1c', launchT: 2.2, y: LANE.y2, kind: 'rogue', mode: 'direct', label: 'delete()' });
  reqs.push({ id: 'p1d', launchT: 3.0, y: LANE.y0, kind: 'rogue', mode: 'direct', label: 'charge()' });
  // P3 gated: verify / reject
  reqs.push({ id: 'g1', launchT: 10.6, y: LANE.y0, kind: 'valid', mode: 'gated', label: 'search() + receipt' });
  reqs.push({ id: 'g2', launchT: 11.5, y: LANE.y2, kind: 'rogue', mode: 'gated', label: 'delete() (no cred)' });
  reqs.push({ id: 'g3', launchT: 12.7, y: LANE.y1, kind: 'valid', mode: 'gated', label: 'charge() + receipt' });
  reqs.push({ id: 'g4', launchT: 14.0, y: LANE.y0, kind: 'rogue', mode: 'gated', label: 'replayed nonce' });
  reqs.push({ id: 'g5', launchT: 15.1, y: LANE.y2, kind: 'valid', mode: 'gated', label: 'fetch() + receipt' });

  return (
    <div style={{ position: 'absolute', inset: 0, transformOrigin: '0 0', transform: `translate(${tx}px, ${ty}px) scale(${s})` }}>
      {/* lane wires */}
      {[LANE.y0, LANE.y1, LANE.y2].map((y, i) => (
        <div key={i} style={{
          position: 'absolute', left: AGENT_RIGHT, top: y, width: SRV_LEFT - AGENT_RIGHT, height: 2,
          transform: 'translateY(-50%)', opacity: 0.5 * elemAppear,
          background: `repeating-linear-gradient(90deg, ${C.inkGhost} 0 12px, transparent 12px 22px)`,
        }} />
      ))}

      {/* agents */}
      <AgentChip x={LANE.x} y={LANE.y0} label="agent-alice" state="idle" appear={elemAppear} />
      <AgentChip x={LANE.x} y={LANE.y1} label="agent-bob" state="idle" appear={elemAppear} />
      <AgentChip x={LANE.x} y={LANE.y2} label="agent-x" state="rogue" appear={elemAppear} />

      {/* gate */}
      {gateOn && (
        <>
          <Gate x={GATE_X} y={540} h={470} appear={gA} pulse={(t * 0.5) % 1} />
          <div style={{
            position: 'absolute', left: GATE_X, top: 250, transform: 'translate(-50%,-50%)',
            opacity: clamp((t - 6.0) / 0.6, 0, 1), display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 6,
          }}>
            <div style={{ fontFamily: MONO, fontSize: 24, color: C.brand, fontWeight: 600, letterSpacing: '0.02em' }}>@bolyra/gateway</div>
            <div style={{ fontFamily: MONO, fontSize: 14, color: C.inkFaint, letterSpacing: '0.22em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>auth reverse proxy</div>
          </div>
        </>
      )}

      {/* server */}
      <ServerNode x={SRV_X} y={540} appear={elemAppear} guarded={guarded} breach={breach} />

      {/* requests */}
      {reqs.map((r) => renderRequest(r, t))}
    </div>
  );
}

Object.assign(window, { HeroDiagram, TerminalCommand });
