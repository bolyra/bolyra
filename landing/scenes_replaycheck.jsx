// scenes_replaycheck.jsx — Replay Check (GitHub Action): CI for agent behavior regressions.
// Reuses system.jsx: C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph.

const KW3 = C.brand, STR3 = C.ok, PNC3 = C.inkDim, IDN3 = C.ink, CMT3 = C.inkFaint, ATTR = 'oklch(78% 0.13 300)';
const rc = (text, color = IDN3) => ({ text, color });

function RcPill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{ display: 'inline-flex', alignItems: 'center', gap: 8, padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.06em', color, fontWeight: 500 }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />{text}
    </span>
  );
}

// a GitHub-ish check row
function CheckRow({ status = 'pending', label, sub, appear = 1 }) {
  const a = clamp(appear, 0, 1);
  const col = status === 'pass' ? C.ok : status === 'fail' ? C.bad : C.inkFaint;
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 22px', opacity: a,
      borderTop: `1px solid ${C.inkGhost}` }}>
      <span style={{ width: 26, height: 26, borderRadius: 13, flexShrink: 0, display: 'flex', alignItems: 'center', justifyContent: 'center',
        background: col.replace(')', ' / 0.16)'), border: `1.5px solid ${col.replace(')', ' / 0.6)')}` }}>
        {status === 'pass'
          ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={col} strokeWidth="3" strokeLinecap="round" strokeLinejoin="round" /></svg>
          : status === 'fail'
            ? <svg width="15" height="15" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={col} strokeWidth="3" strokeLinecap="round" /></svg>
            : <span style={{ width: 9, height: 9, borderRadius: 5, background: col }} />}
      </span>
      <span style={{ fontFamily: MONO, fontSize: 21, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{label}</span>
      {sub && <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 16, color: col, letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>{sub}</span>}
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM: you changed the policy
function RcProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const card = clamp((t - 0.5) / 0.6, 0, 1);
  const diffIn = clamp((t - 1.6) / 0.6, 0, 1);
  const worry = t > 3.0;
  const lines = [
    { sign: ' ', text: 'tools:', color: C.inkDim },
    { sign: ' ', text: '  read_file:  READ_DATA', color: C.inkDim },
    { sign: '-', text: '  delete:     WRITE_DATA', color: C.bad },
    { sign: '+', text: '  delete:     ADMIN_DATA', color: C.ok },
    { sign: ' ', text: '  charge:     FINANCIAL_SMALL', color: C.inkDim },
  ];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="You tightened one permission." sub="Did you just break a working agent — or three?" />
      {/* policy diff card */}
      <div style={{ position: 'absolute', left: 960, top: 580, transform: `translate(-50%,-50%) translateY(${(1 - Easing.easeOutCubic(card)) * 24}px)`, opacity: card,
        width: 920, background: 'rgba(11,14,19,0.94)', border: `1px solid ${C.borderStrong}`, borderRadius: 16, overflow: 'hidden', boxShadow: '0 30px 70px rgba(0,0,0,0.55)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '16px 24px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <svg width="20" height="20" viewBox="0 0 24 24" fill="none"><path d="M6 3v12M6 21a3 3 0 1 0 0-6 3 3 0 0 0 0 6ZM18 9a3 3 0 1 0 0-6 3 3 0 0 0 0 6Zm0 0c0 6-12 3-12 9" stroke={C.inkDim} strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <span style={{ fontFamily: MONO, fontSize: 17, color: C.inkDim }}>tool-policy.yaml</span>
          <span style={{ marginLeft: 'auto', fontFamily: MONO, fontSize: 14, color: C.inkFaint, letterSpacing: '0.08em' }}>+1 −1</span>
        </div>
        <div style={{ padding: '18px 0' }}>
          {lines.map((ln, i) => {
            const op = clamp((diffIn * 5) - i * 0.6, 0, 1);
            const bg = ln.sign === '+' ? C.okSoft : ln.sign === '-' ? C.badSoft : 'transparent';
            const flash = worry && (ln.sign === '+' || ln.sign === '-');
            return (
              <div key={i} style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '7px 24px', opacity: op, background: bg,
                boxShadow: flash ? `inset 3px 0 0 ${ln.sign === '+' ? C.ok : C.bad}` : 'none' }}>
                <span style={{ fontFamily: MONO, fontSize: 22, color: ln.color, width: 14, textAlign: 'center' }}>{ln.sign}</span>
                <span style={{ fontFamily: MONO, fontSize: 24, color: ln.sign === ' ' ? C.inkDim : ln.color, whiteSpace: 'pre' }}>{ln.text}</span>
              </div>
            );
          })}
        </div>
      </div>
      {worry && (
        <div style={{ position: 'absolute', left: 960, top: 884, transform: 'translate(-50%,-50%)', opacity: clamp((t - 3.0) / 0.4, 0, 1) }}>
          <RcPill text="no test catches an agent-behavior regression" color={C.bad} bg={C.badSoft} border={C.bad.replace(')', ' / 0.5)')} />
        </div>
      )}
    </div>
  );
}

// SCENE 2 — THE ACTION: drop into CI
function RcAction({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const reveal = clamp((t - 0.6) / 2.2, 0, 1);
  const hl = t > 3.2;
  const lines = [
    [rc('# .github/workflows/agents.yml', CMT3)],
    [rc('on: ', KW3), rc('[pull_request]', ATTR)],
    [],
    [rc('jobs:', KW3)],
    [rc('  replay-check:', IDN3)],
    [rc('    runs-on: ', KW3), rc('ubuntu-latest', STR3)],
    [rc('    steps:', KW3)],
    [rc('      - ', PNC3), rc('uses: ', KW3), rc('bolyra/bolyra/actions/replay-check@main', STR3)],
  ];
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ONE STEP" title="Add a check to every pull request." />
      <div style={{ position: 'absolute', left: 960, top: 580, transform: 'translate(-50%,-50%)', width: 1080, boxSizing: 'border-box',
        background: 'rgba(11,14,19,0.94)', border: `1px solid ${C.borderStrong}`, borderRadius: 16, overflow: 'hidden', boxShadow: '0 30px 70px rgba(0,0,0,0.55)' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '16px 24px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <div style={{ display: 'flex', gap: 8 }}>
            <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
            <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
            <span style={{ width: 13, height: 13, borderRadius: 7, background: 'rgba(255,255,255,0.14)' }} />
          </div>
          <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkDim }}>agents.yml</span>
        </div>
        <div style={{ padding: '24px 32px', display: 'flex', flexDirection: 'column', gap: 3 }}>
          {lines.map((ln, i) => {
            const op = clamp((reveal * lines.length) - i, 0, 1);
            const isHl = hl && i === 7;
            return (
              <div key={i} style={{ minHeight: 34, display: 'flex', alignItems: 'center', opacity: op, transform: `translateX(${(1 - op) * -10}px)`,
                background: isHl ? C.brandSoft : 'transparent', borderRadius: 6, margin: isHl ? '0 -12px' : 0, padding: isHl ? '2px 12px' : 0 }}>
                <span style={{ fontFamily: MONO, fontSize: 24, lineHeight: 1.4, whiteSpace: 'pre' }}>
                  {ln.length ? ln.map((s, j) => <span key={j} style={{ color: s.color }}>{s.text}</span>) : ' '}
                </span>
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}

// SCENE 3 — REPLAY: receipt history re-evaluated
function RcReplay({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const histIn = clamp((t - 0.4) / 0.6, 0, 1);
  // receipts stream through the gate
  const receipts = [
    { id: 'rcpt_01', was: 'allow', now: 'allow' },
    { id: 'rcpt_02', was: 'allow', now: 'allow' },
    { id: 'rcpt_03', was: 'allow', now: 'deny' },
    { id: 'rcpt_04', was: 'deny', now: 'allow' },
    { id: 'rcpt_05', was: 'allow', now: 'allow' },
    { id: 'rcpt_06', was: 'allow', now: 'deny' },
  ];
  const gateX = 960, histX = 420, outX = 1500;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="REPLAY" title="Your receipt history, re-judged by the new policy." />

      {/* history stack */}
      <div style={{ position: 'absolute', left: histX, top: 560, transform: 'translate(-50%,-50%)', opacity: histIn, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10 }}>
        <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: '0.12em', textTransform: 'uppercase', marginBottom: 6 }}>receipt history</span>
        {receipts.map((r, i) => (
          <div key={i} style={{ width: 230, padding: '10px 16px', borderRadius: 9, background: C.panel, border: `1px solid ${C.border}`,
            display: 'flex', alignItems: 'center', justifyContent: 'space-between', opacity: clamp((t - (0.5 + i * 0.08)) / 0.4, 0, 1) }}>
            <span style={{ fontFamily: MONO, fontSize: 17, color: C.inkDim }}>{r.id}</span>
            <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint }}>{r.was}</span>
          </div>
        ))}
      </div>

      {/* policy gate */}
      <div style={{ position: 'absolute', left: gateX, top: 560, transform: 'translate(-50%,-50%)', opacity: clamp((t - 0.8) / 0.5, 0, 1),
        width: 260, padding: '28px', background: C.panelStrong, border: `1.5px solid ${C.brandLine}`, borderRadius: 22,
        display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 12, boxShadow: `0 0 36px ${C.brandSoft}` }}>
        <ShieldGlyph color={C.brand} size={50} />
        <span style={{ fontFamily: MONO, fontSize: 20, color: C.ink, fontWeight: 600, whiteSpace: 'nowrap' }}>new policy</span>
        <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.06em', whiteSpace: 'nowrap' }}>re-evaluate()</span>
      </div>

      {/* traveling receipts */}
      {receipts.map((r, i) => {
        const launch = 1.6 + i * 0.32;
        const age = t - launch;
        if (age < 0 || age > 1.4) return null;
        const p = Easing.easeInOutCubic(clamp(age / 1.1, 0, 1));
        const startX = histX + 130, endX = outX - 150;
        const x = startX + (endX - startX) * p;
        const y = 560 + (i - 2.5) * 8;
        const changed = r.was !== r.now;
        const col = r.now === 'deny' ? C.bad : (changed ? C.brand : C.ok);
        const op = age > 1.1 ? clamp((1.4 - age) / 0.3, 0, 1) : clamp(age / 0.2, 0, 1);
        return (
          <div key={'t' + i} style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', opacity: op,
            padding: '7px 13px', borderRadius: 8, background: col.replace(')', ' / 0.16)'), border: `1px solid ${col.replace(')', ' / 0.55)')}`, whiteSpace: 'nowrap',
            fontFamily: MONO, fontSize: 15, color: C.ink }}>{r.id} · {r.now}{changed ? ' ⚠' : ''}</div>
        );
      })}

      {/* tally */}
      <div style={{ position: 'absolute', left: outX, top: 560, transform: 'translate(-50%,-50%)', opacity: clamp((t - 4.6) / 0.5, 0, 1),
        display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'flex-start' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><span style={{ width: 12, height: 12, borderRadius: 6, background: C.ok }} /><span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, whiteSpace: 'nowrap' }}>3 unchanged</span></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><span style={{ width: 12, height: 12, borderRadius: 6, background: C.bad }} /><span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, whiteSpace: 'nowrap' }}>2 regressions</span></div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}><span style={{ width: 12, height: 12, borderRadius: 6, background: C.brand }} /><span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, whiteSpace: 'nowrap' }}>1 relaxation</span></div>
      </div>
    </div>
  );
}

// SCENE 4 — THE PR COMMENT / DIFF
function RcDiff({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const card = clamp((t - 0.4) / 0.6, 0, 1);
  const r1 = clamp((t - 1.2) / 0.5, 0, 1);
  const r2 = clamp((t - 1.7) / 0.5, 0, 1);
  const r3 = clamp((t - 2.4) / 0.5, 0, 1);
  const fail = t > 3.4;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="ON EVERY PR" title="Regressions fail the check." />
      <div style={{ position: 'absolute', left: 960, top: 560, transform: `translate(-50%,-50%) translateY(${(1 - Easing.easeOutCubic(card)) * 24}px)`, opacity: card,
        width: 1080, background: 'rgba(13,17,23,0.94)', border: `1px solid ${C.borderStrong}`, borderRadius: 18, overflow: 'hidden', boxShadow: '0 30px 70px rgba(0,0,0,0.55)' }}>
        {/* comment header */}
        <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '18px 26px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.025)' }}>
          <div style={{ width: 32, height: 32, borderRadius: 8, background: C.brandSoft, border: `1px solid ${C.brandLine}`, display: 'flex', alignItems: 'center', justifyContent: 'center' }}><ShieldGlyph color={C.brand} size={20} /></div>
          <span style={{ fontFamily: MONO, fontSize: 19, color: C.ink, fontWeight: 600 }}>bolyra-replay-check</span>
          <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint }}>commented on #482</span>
          <span style={{ marginLeft: 'auto' }}><RcPill text={fail ? 'check failed' : 'running…'} color={fail ? C.bad : C.inkFaint} bg={fail ? C.badSoft : undefined} border={fail ? C.bad.replace(')', ' / 0.5)') : undefined} /></span>
        </div>
        <div style={{ padding: '22px 26px', display: 'flex', flexDirection: 'column', gap: 14 }}>
          <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkDim, letterSpacing: '0.04em' }}>Replayed 6 receipts against the updated policy:</span>
          {/* regression rows */}
          <DiffLine appear={r1} kind="bad" id="rcpt_03" detail="delete · ADMIN_DATA" from="allow" to="deny" />
          <DiffLine appear={r2} kind="bad" id="rcpt_06" detail="delete · ADMIN_DATA" from="allow" to="deny" />
          <DiffLine appear={r3} kind="warn" id="rcpt_04" detail="charge · FINANCIAL_SMALL" from="deny" to="allow" />
        </div>
        {fail && (
          <div style={{ display: 'flex', alignItems: 'center', gap: 14, padding: '18px 26px', borderTop: `1px solid ${C.border}`, background: C.badSoft, opacity: clamp((t - 3.4) / 0.4, 0, 1) }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={C.bad} strokeWidth="2.6" strokeLinecap="round" /></svg>
            <span style={{ fontFamily: MONO, fontSize: 19, color: C.bad, fontWeight: 600, whiteSpace: 'nowrap' }}>2 regressions found — merge blocked</span>
          </div>
        )}
      </div>
    </div>
  );
}
function DiffLine({ appear, kind, id, detail, from, to }) {
  const a = clamp(appear, 0, 1);
  const col = kind === 'bad' ? C.bad : 'oklch(80% 0.15 85)';
  return (
    <div style={{ display: 'flex', alignItems: 'center', gap: 16, padding: '14px 20px', borderRadius: 11, opacity: a, transform: `translateX(${(1 - a) * -14}px)`,
      background: kind === 'bad' ? C.badSoft : 'oklch(80% 0.15 85 / 0.12)', border: `1px solid ${col.replace(')', ' / 0.4)')}` }}>
      <span style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.1em', textTransform: 'uppercase', color: col, fontWeight: 600, width: 110, whiteSpace: 'nowrap' }}>{kind === 'bad' ? 'regression' : 'relaxation'}</span>
      <span style={{ fontFamily: MONO, fontSize: 20, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{id}</span>
      <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkDim, whiteSpace: 'nowrap' }}>{detail}</span>
      <span style={{ marginLeft: 'auto', display: 'flex', alignItems: 'center', gap: 10, whiteSpace: 'nowrap' }}>
        <span style={{ fontFamily: MONO, fontSize: 18, color: C.inkDim }}>{from}</span>
        <span style={{ fontFamily: MONO, fontSize: 18, color: col }}>→</span>
        <span style={{ fontFamily: MONO, fontSize: 18, color: col, fontWeight: 600 }}>{to}</span>
      </span>
    </div>
  );
}

// SCENE 5 — CTA
function RcCTA({ t, dur }) {
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
          Replay Check — <span style={{ color: C.brand }}>CI for agent behavior</span>
        </div>
        <div style={{ display: 'flex', gap: 14, opacity: statsIn, transform: `translateY(${(1 - statsIn) * 12}px)` }}>
          <RcPill text="runs on every PR" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
          <RcPill text="catches allow→deny" color={C.inkDim} />
          <RcPill text="replays real receipts" color={C.inkDim} />
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 23, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.inkDim }}>uses: </span><span style={{ color: C.brand }}>bolyra/bolyra/actions/replay-check@main</span>
        </div>
        <div style={{ marginTop: 2, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · GitHub Actions · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { RcProblem, RcAction, RcReplay, RcDiff, RcCTA });
