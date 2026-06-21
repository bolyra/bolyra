// scenes_commerce.jsx — v0.7.0 auth + commerce receipts launch.
// Reuses system.jsx primitives (C, MONO, DISPLAY, fadeAt, Backdrop, Caption, Kicker, ShieldGlyph, Packet).

// ── small shared bits ────────────────────────────────────────────────────────
function Pill({ text, color = C.inkDim, bg, border }) {
  return (
    <span style={{
      display: 'inline-flex', alignItems: 'center', gap: 8,
      padding: '6px 14px', borderRadius: 999, whiteSpace: 'nowrap',
      background: bg || 'rgba(255,255,255,0.04)', border: `1px solid ${border || C.border}`,
      fontFamily: MONO, fontSize: 15, letterSpacing: '0.08em', color, fontWeight: 500,
    }}>
      <span style={{ width: 7, height: 7, borderRadius: 4, background: color, boxShadow: `0 0 8px ${color}` }} />
      {text}
    </span>
  );
}

function CodeChip({ children, x, y, appear = 1, align = 'center' }) {
  const a = clamp(appear, 0, 1);
  const tx = align === 'center' ? '-50%' : '0';
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(${tx}, ${(1 - a) * 12}px)`, opacity: a,
      padding: '16px 24px', borderRadius: 12, whiteSpace: 'nowrap',
      background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`,
      fontFamily: MONO, fontSize: 25, color: C.ink, letterSpacing: '0.005em',
    }}>
      {children}
    </div>
  );
}

function DecisionStamp({ kind = 'ok', label, x, y, appear = 1 }) {
  const ok = kind === 'ok';
  const color = ok ? C.ok : C.bad;
  const s = appear < 0.5 ? (1.5 - 1.0 * Easing.easeOutBack(clamp(appear / 0.5, 0, 1))) : 1;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) rotate(${ok ? -6 : 6}deg) scale(${s})`,
      opacity: clamp(appear / 0.3, 0, 1), display: 'inline-flex', alignItems: 'center', gap: 11,
      padding: '11px 22px', borderRadius: 12, whiteSpace: 'nowrap',
      background: ok ? C.okSoft : C.badSoft, border: `2px solid ${color}`,
    }}>
      {ok
        ? <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={color} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
        : <svg width="24" height="24" viewBox="0 0 24 24" fill="none"><path d="M6 6l12 12M18 6 6 18" stroke={color} strokeWidth="2.6" strokeLinecap="round" /></svg>}
      <span style={{ fontFamily: MONO, fontSize: 21, fontWeight: 600, letterSpacing: '0.08em', color }}>{label}</span>
    </div>
  );
}

// ── PaymentIntent card ───────────────────────────────────────────────────────
function PaymentIntentCard({ x, y, amount, currency = 'USD', agent, scope, cap, statusText, statusColor, appear = 1, alert = false, width = 600 }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const slide = (1 - a) * 30;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${slide}px)`, opacity: a,
      width, boxSizing: 'border-box',
      background: 'rgba(13,17,23,0.92)', border: `1px solid ${alert ? C.bad : C.borderStrong}`,
      borderRadius: 20, overflow: 'hidden',
      boxShadow: alert ? `0 0 40px ${C.badSoft}, 0 30px 70px rgba(0,0,0,0.5)` : `0 30px 70px rgba(0,0,0,0.5)`,
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between', padding: '20px 26px', borderBottom: `1px solid ${C.border}`, background: 'rgba(255,255,255,0.02)' }}>
        <span style={{ fontFamily: MONO, fontSize: 20, color: C.ink, fontWeight: 500, letterSpacing: '0.02em' }}>PaymentIntent</span>
        <Pill text={statusText} color={statusColor} bg={(statusColor || C.inkDim).replace(')', ' / 0.14)')} border={(statusColor || C.border).replace(')', ' / 0.4)')} />
      </div>
      <div style={{ padding: '24px 26px', display: 'flex', flexDirection: 'column', gap: 22 }}>
        <div style={{ display: 'flex', alignItems: 'baseline', gap: 14 }}>
          <span style={{ fontFamily: DISPLAY, fontSize: 64, fontWeight: 600, color: C.ink, letterSpacing: '-0.02em', lineHeight: 1 }}>{amount}</span>
          <span style={{ fontFamily: MONO, fontSize: 24, color: C.inkDim }}>{currency}</span>
        </div>
        <div style={{ display: 'flex', gap: 40, paddingTop: 18, borderTop: `1px solid ${C.inkGhost}` }}>
          <KV k="delegatee" v={agent} />
          <KV k="scope" v={scope} vColor={scope === 'none' ? C.bad : C.ink} />
          <KV k="cap" v={cap} />
        </div>
      </div>
    </div>
  );
}
function KV({ k, v, vColor = C.ink }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 6 }}>
      <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.1em', textTransform: 'uppercase' }}>{k}</span>
      <span style={{ fontFamily: MONO, fontSize: 19, color: vColor, fontWeight: 500, whiteSpace: 'nowrap' }}>{v}</span>
    </div>
  );
}

// ════════════════════════════════════════════════════════════════════════════
// SCENE 1 — PROBLEM
function CmProblem({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const appear = clamp((t - 0.2) / 0.7, 0, 1);
  const alert = t > 1.6;
  const push = interpolate([0, dur], [1.0, 1.05], Easing.easeInOutSine)(t);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, transform: `scale(${push})`, transformOrigin: 'center' }}>
      <PaymentIntentCard x={960} y={552} amount="$480.00" agent="agent-x" scope="none" cap="—"
        statusText={alert ? 'unauthorized' : 'requires_authorization'} statusColor={alert ? C.bad : C.inkDim} appear={appear} alert={alert} />
      {alert && (
        <div style={{ position: 'absolute', left: 960, top: 760, transform: 'translate(-50%,-50%)', opacity: clamp((t - 1.7) / 0.4, 0, 1) }}>
          <DecisionStamp kind="bad" label="NO SCOPE · NO PROOF" x={0} y={0} appear={clamp((t - 1.7) / 0.4, 0, 1)} />
        </div>
      )}
      <Caption t={t} dur={dur} y={104} kicker="THE PROBLEM" title="Your agent just charged $480." sub="Who authorized it? Where's the proof?" />
    </div>
  );
}

// SCENE 2 — AUTHORIZE
function CmAuthorize({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const code = clamp((t - 0.4) / 0.5, 0, 1);
  const row1 = clamp((t - 1.6) / 0.6, 0, 1);
  const stamp1 = clamp((t - 2.5) / 0.4, 0, 1);
  const row2 = clamp((t - 3.4) / 0.6, 0, 1);
  const stamp2 = clamp((t - 4.3) / 0.4, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="AUTHORIZE" title="Gate the spend against delegated scope." />
      <CodeChip x={960} y={352} appear={code}>
        <span style={{ color: C.brand }}>verifyStripeACPSpend</span>
        <span style={{ color: C.inkDim }}>(ctx, </span><span style={{ color: C.ok }}>amount</span><span style={{ color: C.inkDim }}>, </span><span style={{ color: C.ok }}>'USD'</span><span style={{ color: C.inkDim }}>, </span><span style={{ color: C.brand }}>'authorize'</span><span style={{ color: C.inkDim }}>)</span>
      </CodeChip>

      {/* row 1 — within cap */}
      <DecisionRow y={540} appear={row1}
        left="charge $25 · FINANCIAL_SMALL" sub="within $50 cap"
        stampKind="ok" stampLabel="AUTHORIZED" stampAppear={stamp1} />
      {/* row 2 — over cap */}
      <DecisionRow y={700} appear={row2}
        left="charge $480 · FINANCIAL_SMALL" sub="exceeds cap"
        stampKind="bad" stampLabel="amount_exceeds_cap" stampAppear={stamp2} />
    </div>
  );
}

function DecisionRow({ y, appear, left, sub, stampKind, stampLabel, stampAppear }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  return (
    <React.Fragment>
      <div style={{
        position: 'absolute', left: 360, top: y, transform: `translateY(-50%) translateX(${(1 - a) * -20}px)`, opacity: a,
        width: 640, padding: '22px 28px', boxSizing: 'border-box',
        background: C.panel, border: `1px solid ${C.border}`, borderRadius: 16,
        display: 'flex', flexDirection: 'column', gap: 7,
      }}>
        <span style={{ fontFamily: MONO, fontSize: 26, color: C.ink, fontWeight: 500 }}>{left}</span>
        <span style={{ fontFamily: MONO, fontSize: 16, color: C.inkFaint, letterSpacing: '0.04em' }}>{sub}</span>
      </div>
      {/* connector */}
      <div style={{ position: 'absolute', left: 1000, top: y, width: 200, height: 2, transform: 'translateY(-50%)', opacity: a * 0.6,
        background: `repeating-linear-gradient(90deg, ${C.inkGhost} 0 10px, transparent 10px 18px)` }} />
      {stampAppear > 0 && <DecisionStamp kind={stampKind} label={stampLabel} x={1380} y={y} appear={stampAppear} />}
    </React.Fragment>
  );
}

// SCENE 3 — AUTHORIZE → CONFIRM
function CmConfirm({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const stepsIn = clamp((t - 0.5) / 0.6, 0, 1);
  const authDone = t > 1.6;
  const confirmFail = t > 2.6 && t < 5.0;
  const grant = t > 4.6;            // SIGN_ON_BEHALF granted
  const confirmOk = t > 5.4;
  const code = clamp((t - 0.4) / 0.5, 0, 1);

  // node positions
  const nx = [430, 960, 1490], ny = 560;
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <Caption t={t} dur={dur} y={104} kicker="AUTHORIZE → CONFIRM" title="Confirm fails closed without sign-on-behalf." />

      {/* connectors with gates */}
      <PipeGate x1={nx[0]} x2={nx[1]} y={ny} appear={stepsIn} kind="ok" active={authDone} label="authorize" />
      <PipeGate x1={nx[1]} x2={nx[2]} y={ny} appear={stepsIn}
        kind={confirmOk ? 'ok' : confirmFail ? 'bad' : 'idle'} active={confirmOk || confirmFail}
        label="confirm" requireTag={grant ? 'SIGN_ON_BEHALF ✓' : 'needs SIGN_ON_BEHALF'} requireOk={grant} />

      <StateNode x={nx[0]} y={ny} appear={stepsIn} label="requires_auth" color={C.inkDim} done />
      <StateNode x={nx[1]} y={ny} appear={stepsIn} label="authorized" color={authDone ? C.ok : C.inkFaint} done={authDone} />
      <StateNode x={nx[2]} y={ny} appear={stepsIn} label={confirmOk ? 'confirmed' : 'canceled'} color={confirmOk ? C.ok : confirmFail ? C.bad : C.inkFaint} done={confirmOk || confirmFail} />

      {/* fails-closed callout */}
      {confirmFail && (
        <div style={{ position: 'absolute', left: nx[2], top: ny + 150, transform: 'translate(-50%,-50%)', opacity: clamp((t - 2.7) / 0.4, 0, 1) * clamp((5.0 - t) / 0.4, 0, 1) }}>
          <Pill text="fails closed — no capture" color={C.bad} bg={C.badSoft} border={C.bad.replace(')', ' / 0.5)')} />
        </div>
      )}
      {confirmOk && (
        <div style={{ position: 'absolute', left: nx[2], top: ny + 150, transform: 'translate(-50%,-50%)', opacity: clamp((t - 5.5) / 0.4, 0, 1) }}>
          <Pill text="$25.00 captured" color={C.ok} bg={C.okSoft} border={C.ok.replace(')', ' / 0.5)')} />
        </div>
      )}

      <CodeChip x={960} y={820} appear={code}>
        <span style={{ color: C.brand }}>verifyStripeACPSpend</span>
        <span style={{ color: C.inkDim }}>(ctx, </span><span style={{ color: C.ok }}>25</span><span style={{ color: C.inkDim }}>, </span><span style={{ color: C.ok }}>'USD'</span><span style={{ color: C.inkDim }}>, </span><span style={{ color: C.brand }}>'confirm'</span><span style={{ color: C.inkDim }}>)</span>
      </CodeChip>
    </div>
  );
}

function StateNode({ x, y, appear, label, color, done }) {
  const a = Easing.easeOutBack(clamp(appear, 0, 1));
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) scale(${0.7 + 0.3 * a})`, opacity: clamp(appear, 0, 1),
      padding: '16px 24px', borderRadius: 14, whiteSpace: 'nowrap',
      background: C.panelStrong, border: `1.5px solid ${done ? color.replace(')', ' / 0.6)') : C.border}`,
      display: 'flex', alignItems: 'center', gap: 10,
      boxShadow: done ? `0 0 24px ${color.replace(')', ' / 0.18)')}` : 'none',
    }}>
      <span style={{ width: 9, height: 9, borderRadius: 5, background: color, boxShadow: `0 0 10px ${color}` }} />
      <span style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 500 }}>{label}</span>
    </div>
  );
}

function PipeGate({ x1, x2, y, appear, kind = 'idle', active, label, requireTag, requireOk }) {
  const a = clamp(appear, 0, 1);
  const mid = (x1 + x2) / 2;
  const col = kind === 'ok' ? C.ok : kind === 'bad' ? C.bad : C.inkDim;
  return (
    <React.Fragment>
      <div style={{ position: 'absolute', left: x1 + 90, top: y, width: x2 - x1 - 180, height: 2, transform: 'translateY(-50%)', opacity: a * 0.7,
        background: active ? col.replace(')', ' / 0.6)') : `repeating-linear-gradient(90deg, ${C.inkGhost} 0 10px, transparent 10px 18px)` }} />
      {/* gate marker */}
      <div style={{ position: 'absolute', left: mid, top: y, transform: 'translate(-50%,-50%)', opacity: a,
        width: 50, height: 50, borderRadius: 12, background: C.bg, border: `1.5px solid ${active ? col : C.border}`,
        display: 'flex', alignItems: 'center', justifyContent: 'center', boxShadow: active ? `0 0 18px ${col.replace(')', ' / 0.3)')}` : 'none' }}>
        <ShieldGlyph color={active ? col : C.inkDim} size={26} />
      </div>
      <div style={{ position: 'absolute', left: mid, top: y - 52, transform: 'translate(-50%,-50%)', opacity: a,
        fontFamily: MONO, fontSize: 15, color: C.inkDim, letterSpacing: '0.1em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>{label}</div>
      {requireTag && (
        <div style={{ position: 'absolute', left: mid, top: y + 52, transform: 'translate(-50%,-50%)', opacity: a,
          fontFamily: MONO, fontSize: 14, color: requireOk ? C.ok : C.inkFaint, letterSpacing: '0.04em', whiteSpace: 'nowrap' }}>{requireTag}</div>
      )}
    </React.Fragment>
  );
}

// SCENE 4 — SIGNED COMMERCE RECEIPT
function CmReceipt({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.4);
  const card = clamp((t - 0.6) / 0.6, 0, 1);
  const verify = clamp((t - 2.4) / 0.5, 0, 1);
  const typed = clamp((t - 2.9) / 1.0, 0, 1);
  const verifyCmd = 'bolyra-receipt-verify rcpt_cmrc_7e0';
  const shown = verifyCmd.slice(0, Math.round(typed * verifyCmd.length));
  const okLine = t > 4.2;
  const push = interpolate([0, dur], [1.0, 1.04], Easing.easeInOutSine)(t);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, transform: `scale(${push})`, transformOrigin: 'center' }}>
      <div style={{ position: 'absolute', left: 150, top: 360, width: 560, display: 'flex', flexDirection: 'column', gap: 22 }}>
        <Kicker>{'> AUTH + COMMERCE'}</Kicker>
        <div style={{ fontFamily: DISPLAY, fontSize: 62, fontWeight: 600, color: C.ink, letterSpacing: '-0.025em', lineHeight: 1.04 }}>
          Every decision,<br />signed.
        </div>
        <div style={{ fontFamily: MONO, fontSize: 23, color: C.inkDim, lineHeight: 1.5 }}>
          secp256k1 · keccak256 · EVM-compatible.<br />Audit-grade evidence for every charge.
        </div>
      </div>

      {/* commerce receipt card */}
      <div style={{
        position: 'absolute', left: 1290, top: 470, transform: `translate(-50%,-50%) translateY(${(1 - Easing.easeOutCubic(card)) * 30}px)`, opacity: card,
        width: 680, background: 'rgba(14,18,24,0.92)', border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.ok}`,
        borderRadius: 16, padding: '24px 28px', display: 'flex', flexDirection: 'column', gap: 18, boxShadow: '0 24px 60px rgba(0,0,0,0.5)',
      }}>
        <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
          <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
            <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
            <span style={{ fontFamily: MONO, fontSize: 21, color: C.ink, fontWeight: 600 }}>rcpt_cmrc_7e0</span>
          </div>
          <Pill text="stripe-acp" color={C.brand} bg={C.brandSoft} border={C.brandLine} />
        </div>
        <div style={{ display: 'flex', gap: 36, flexWrap: 'wrap' }}>
          <KV k="decision" v="AUTHORIZE" vColor={C.ok} />
          <KV k="amount" v="$25.00 USD" />
          <KV k="scope" v="FINANCIAL_SMALL" />
        </div>
        <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 8, borderTop: `1px solid ${C.inkGhost}` }}>
          <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.08em', textTransform: 'uppercase' }}>sig</span>
          <span style={{ fontFamily: MONO, fontSize: 16, color: C.brand, whiteSpace: 'nowrap' }}>secp256k1 · 0x7e05…2cd</span>
        </div>
      </div>

      {/* verify terminal */}
      <div style={{
        position: 'absolute', left: 1290, top: 730, transform: 'translate(-50%,-50%)', opacity: verify,
        width: 680, boxSizing: 'border-box',
        background: 'rgba(10,13,18,0.85)', border: `1px solid ${C.borderStrong}`, borderRadius: 12, padding: '18px 24px',
        fontFamily: MONO, fontSize: 20, color: C.ink, display: 'flex', flexDirection: 'column', gap: 8,
      }}>
        <div style={{ whiteSpace: 'nowrap' }}><span style={{ color: C.ok }}>$</span> {shown}<span style={{ opacity: okLine ? 0 : 1 }}>▍</span></div>
        {okLine && <div style={{ color: C.ok, whiteSpace: 'nowrap', opacity: clamp((t - 4.2) / 0.3, 0, 1) }}>✓ signature valid · secp256k1 · keccak256</div>}
      </div>
    </div>
  );
}

// SCENE 5 — CTA
function CmCTA({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.3);
  const rise = (1 - Easing.easeOutCubic(clamp(t / 0.7, 0, 1))) * 26;
  const cmdIn = clamp((t - 0.9) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', alignItems: 'center', justifyContent: 'center' }}>
      <div style={{ transform: `translateY(${rise}px)`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 28 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
          <ShieldGlyph color={C.brand} size={66} />
          <div style={{ fontFamily: DISPLAY, fontSize: 100, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em' }}>Bolyra</div>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 28, color: C.inkDim, letterSpacing: '0.01em', whiteSpace: 'nowrap', textAlign: 'center' }}>
          auth + commerce receipts — <span style={{ color: C.brand }}>v0.7.0</span> live now on npm
        </div>
        <div style={{ opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`, marginTop: 6, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`, fontFamily: MONO, fontSize: 24, color: C.ink, whiteSpace: 'nowrap' }}>
          <span style={{ color: C.ok }}>$</span> npm i <span style={{ color: C.brand }}>@bolyra/payment-protocols @bolyra/receipts</span>
        </div>
        <div style={{ marginTop: 4, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · Stripe ACP · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { CmProblem, CmAuthorize, CmConfirm, CmReceipt, CmCTA });
