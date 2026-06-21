// scenes_more.jsx — ReceiptsScene, RedisScene (v0.2.0), CTAScene.

// ── Receipt card ─────────────────────────────────────────────────────────────
function ReceiptCard({ x, y, appear, data, width = 660 }) {
  const a = Easing.easeOutCubic(clamp(appear, 0, 1));
  const slide = (1 - a) * 40;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: `translate(-50%,-50%) translateY(${slide}px)`, opacity: a,
      width, boxSizing: 'border-box',
      background: 'rgba(14,18,24,0.9)', border: `1px solid ${C.border}`, borderLeft: `3px solid ${C.ok}`,
      borderRadius: 14, padding: '20px 26px', display: 'flex', flexDirection: 'column', gap: 14,
      boxShadow: '0 20px 50px rgba(0,0,0,0.45)',
    }}>
      <div style={{ display: 'flex', alignItems: 'center', justifyContent: 'space-between' }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12 }}>
          <svg width="22" height="22" viewBox="0 0 24 24" fill="none"><path d="M5 12.5l4.5 4.5L19 7" stroke={C.ok} strokeWidth="2.6" strokeLinecap="round" strokeLinejoin="round" /></svg>
          <span style={{ fontFamily: MONO, fontSize: 20, color: C.ink, fontWeight: 600, letterSpacing: '0.04em' }}>{data.id}</span>
        </div>
        <span style={{ fontFamily: MONO, fontSize: 15, color: C.inkFaint, letterSpacing: '0.1em' }}>{data.ts}</span>
      </div>
      <div style={{ display: 'flex', gap: 40 }}>
        <Field k="action" v={data.action} />
        <Field k="perm" v={data.perm} />
        <Field k="amount" v={data.amount} />
      </div>
      <div style={{ display: 'flex', alignItems: 'center', gap: 10, paddingTop: 6, borderTop: `1px solid ${C.inkGhost}` }}>
        <span style={{ fontFamily: MONO, fontSize: 13, color: C.inkFaint, letterSpacing: '0.08em', textTransform: 'uppercase' }}>sig</span>
        <span style={{ fontFamily: MONO, fontSize: 16, color: C.brand, whiteSpace: 'nowrap' }}>{data.sig}</span>
      </div>
    </div>
  );
}
function Field({ k, v }) {
  return (
    <div style={{ display: 'flex', flexDirection: 'column', gap: 4 }}>
      <span style={{ fontFamily: MONO, fontSize: 12, color: C.inkFaint, letterSpacing: '0.1em', textTransform: 'uppercase' }}>{k}</span>
      <span style={{ fontFamily: MONO, fontSize: 18, color: C.ink, fontWeight: 500, whiteSpace: 'nowrap' }}>{v}</span>
    </div>
  );
}

function ReceiptsScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  const receipts = [
    { id: 'rcpt_9f2c', ts: '12:04:51', action: 'checkout.charge', perm: 'FINANCIAL_SMALL', amount: '$25 USD', sig: '0x4af9…e1b' },
    { id: 'rcpt_a7d1', ts: '12:04:52', action: 'data.fetch', perm: 'READ_DATA', amount: '—', sig: '0x18c2…9fa' },
    { id: 'rcpt_b330', ts: '12:04:53', action: 'checkout.charge', perm: 'FINANCIAL_SMALL', amount: '$12 USD', sig: '0x7e05…2cd' },
  ];
  const push = interpolate([0, dur], [1.0, 1.05], Easing.easeInOutSine)(t);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, transform: `scale(${push})`, transformOrigin: 'center' }}>
      {/* left column */}
      <div style={{ position: 'absolute', left: 150, top: 380, display: 'flex', flexDirection: 'column', gap: 22, width: 560 }}>
        <Kicker>{'> AUDIT TRAIL'}</Kicker>
        <div style={{ fontFamily: DISPLAY, fontSize: 70, fontWeight: 600, color: C.ink, letterSpacing: '-0.025em', lineHeight: 1.02 }}>
          A signed receipt<br />for every call.
        </div>
        <div style={{ fontFamily: MONO, fontSize: 24, color: C.inkDim, lineHeight: 1.5 }}>
          secp256k1 · keccak256 · EVM-compatible<br />audit-grade evidence, generated automatically.
        </div>
      </div>
      {/* right stack */}
      {receipts.map((r, i) => (
        <ReceiptCard key={r.id} x={1340} y={336 + i * 168} data={r} appear={clamp((t - (0.7 + i * 0.55)) / 0.6, 0, 1)} />
      ))}
    </div>
  );
}

// ── Redis cylinder ───────────────────────────────────────────────────────────
function RedisStore({ x, y, w = 260, seen = false }) {
  const c = seen ? C.brand : C.inkDim;
  return (
    <div style={{ position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)', width: w }}>
      <div style={{
        width: w, height: 150, borderRadius: '50% / 22%',
        background: C.panelStrong, border: `1px solid ${C.borderStrong}`,
        position: 'relative', boxShadow: seen ? `0 0 30px ${C.brandSoft}` : 'none',
        display: 'flex', alignItems: 'center', justifyContent: 'center', flexDirection: 'column', gap: 6,
      }}>
        <div style={{ position: 'absolute', top: 0, left: 0, width: w, height: 34, borderRadius: '50%', border: `1px solid ${C.borderStrong}`, background: C.bg, boxSizing: 'border-box' }} />
        <div style={{ fontFamily: MONO, fontSize: 22, color: C.ink, fontWeight: 600, zIndex: 1, marginTop: 8 }}>RedisNonceStore</div>
        <div style={{ fontFamily: MONO, fontSize: 14, color: c, letterSpacing: '0.12em', zIndex: 1 }}>{seen ? 'nonce 0x9f2c · SEEN' : 'shared nonce log'}</div>
      </div>
    </div>
  );
}

function MiniGateway({ x, y, label, status = 'idle' }) {
  // status: idle | accept | reject
  const ring = status === 'accept' ? C.ok : status === 'reject' ? C.bad : C.border;
  return (
    <div style={{
      position: 'absolute', left: x, top: y, transform: 'translate(-50%,-50%)',
      width: 230, padding: '20px 18px', boxSizing: 'border-box',
      background: C.panel, border: `1px solid ${ring}`, borderRadius: 16,
      display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 10,
      boxShadow: status !== 'idle' ? `0 0 26px ${(status === 'accept' ? C.okSoft : C.badSoft)}` : 'none',
    }}>
      <ShieldGlyph color={status === 'reject' ? C.bad : status === 'accept' ? C.ok : C.brand} size={38} />
      <div style={{ fontFamily: MONO, fontSize: 18, color: C.ink, fontWeight: 500 }}>{label}</div>
      <div style={{ fontFamily: MONO, fontSize: 13, letterSpacing: '0.1em', textTransform: 'uppercase',
        color: status === 'accept' ? C.ok : status === 'reject' ? C.bad : C.inkFaint, whiteSpace: 'nowrap' }}>
        {status === 'accept' ? 'stored ✓' : status === 'reject' ? 'replay ✗' : 'ready'}
      </div>
    </div>
  );
}

function RedisScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.5);
  // beat timing (local)
  const g1status = t > 1.4 ? 'accept' : 'idle';
  const g3status = t > 3.2 ? 'reject' : 'idle';
  const seen = t > 1.6;
  const gx = [620, 960, 1300], gy = 462;
  const redisY = 786;

  // token A: into gateway-1 (t 0.6 -> 1.4)
  const tokA = clamp((t - 0.6) / 0.8, 0, 1);
  // token C replay: into gateway-3 (t 2.4 -> 3.2)
  const tokC = clamp((t - 2.4) / 0.8, 0, 1);

  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o }}>
      <div style={{ position: 'absolute', left: 960, top: 150, transform: 'translateX(-50%)', textAlign: 'center', display: 'flex', flexDirection: 'column', gap: 14, alignItems: 'center' }}>
        <div style={{ display: 'inline-flex', alignItems: 'center', gap: 12, padding: '8px 18px', borderRadius: 999, border: `1px solid ${C.brandLine}`, background: C.brandSoft }}>
          <span style={{ width: 9, height: 9, borderRadius: 5, background: C.brand, boxShadow: `0 0 10px ${C.brand}` }} />
          <span style={{ fontFamily: MONO, fontSize: 18, letterSpacing: '0.18em', color: C.brand, fontWeight: 600, whiteSpace: 'nowrap' }}>NEW IN v0.2.0</span>
        </div>
        <div style={{ fontFamily: DISPLAY, fontSize: 52, fontWeight: 600, color: C.ink, letterSpacing: '-0.02em', maxWidth: 1200, whiteSpace: 'nowrap' }}>Replay protection across every instance</div>
      </div>

      {/* connector lines gateways -> redis */}
      <svg style={{ position: 'absolute', inset: 0 }} width="1920" height="1080">
        {gx.map((x, i) => (
          <line key={i} x1={x} y1={gy + 60} x2={960} y2={redisY - 60} stroke={C.inkGhost} strokeWidth="2" strokeDasharray="6 8" />
        ))}
      </svg>

      <MiniGateway x={gx[0]} y={gy} label="gateway-1" status={g1status} />
      <MiniGateway x={gx[1]} y={gy} label="gateway-2" status="idle" />
      <MiniGateway x={gx[2]} y={gy} label="gateway-3" status={g3status} />

      {/* token A travelling down into gateway 1 then to redis */}
      {tokA > 0 && tokA < 1 && (
        <Packet x={gx[0]} y={gy - 120 + (redisY - gy) * 0.5 * tokA} label="nonce 0x9f2c" color={C.brand} opacity={1} />
      )}
      {/* token C replay travelling into gateway 3 */}
      {tokC > 0 && tokC < 1 && (
        <Packet x={gx[2]} y={gy - 120 + 90 * tokC} label="replay 0x9f2c" color={C.bad} opacity={1} />
      )}

      <RedisStore x={960} y={redisY} seen={seen} />

      <div style={{ position: 'absolute', left: 960, top: 880, transform: 'translateX(-50%)', textAlign: 'center', opacity: clamp((t - 3.4) / 0.5, 0, 1) }}>
        <div style={{ fontFamily: MONO, fontSize: 24, color: C.inkDim }}>Same nonce, different instance — <span style={{ color: C.bad }}>rejected</span>. No replay slips through a load balancer.</div>
      </div>
    </div>
  );
}

// ── CTA ──────────────────────────────────────────────────────────────────────
function CTAScene({ t, dur }) {
  const o = fadeAt(t, dur, 0.5, 0.3);
  const rise = (1 - Easing.easeOutCubic(clamp(t / 0.7, 0, 1))) * 26;
  const cmdIn = clamp((t - 0.9) / 0.6, 0, 1);
  return (
    <div style={{ position: 'absolute', inset: 0, opacity: o, display: 'flex', flexDirection: 'column', alignItems: 'center', justifyContent: 'center', gap: 0 }}>
      <div style={{ transform: `translateY(${rise}px)`, display: 'flex', flexDirection: 'column', alignItems: 'center', gap: 30 }}>
        <div style={{ display: 'flex', alignItems: 'center', gap: 22 }}>
          <ShieldGlyph color={C.brand} size={68} />
          <div style={{ fontFamily: DISPLAY, fontSize: 104, fontWeight: 700, color: C.ink, letterSpacing: '-0.03em' }}>Bolyra</div>
        </div>
        <div style={{ fontFamily: MONO, fontSize: 30, color: C.inkDim, letterSpacing: '0.02em', whiteSpace: 'nowrap' }}>
          <span style={{ color: C.brand }}>@bolyra/gateway</span> v0.2.0 — live now on npm
        </div>
        <div style={{
          opacity: cmdIn, transform: `translateY(${(1 - cmdIn) * 14}px)`,
          marginTop: 8, padding: '18px 30px', borderRadius: 12,
          background: 'rgba(14,18,24,0.85)', border: `1px solid ${C.borderStrong}`,
          fontFamily: MONO, fontSize: 27, color: C.ink, whiteSpace: 'nowrap',
        }}>
          <span style={{ color: C.ok }}>$</span>&nbsp;npx <span style={{ color: C.brand }}>@bolyra/gateway</span> <span style={{ color: C.inkDim }}>--target &lt;your-mcp&gt;</span>
        </div>
        <div style={{ marginTop: 6, fontFamily: MONO, fontSize: 18, color: C.inkFaint, letterSpacing: '0.14em', textTransform: 'uppercase', whiteSpace: 'nowrap' }}>
          Apache-2.0 · zero circuit artifacts · bolyra.ai
        </div>
      </div>
    </div>
  );
}

Object.assign(window, { ReceiptsScene, RedisScene, CTAScene });
