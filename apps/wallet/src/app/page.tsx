"use client";

import { useState } from "react";

// ── Types ──────────────────────────────────────────────────────

interface Delegation {
  id: string;
  agent: string;
  tools: string[];
  maxPerTx: string;
  maxPerDay: string;
  expiresAt: string;
  expiresIn: string;
  status: "active" | "revoked" | "expired";
  createdAt: string;
  receipts: Receipt[];
}

interface Receipt {
  id: string;
  decision: "allow" | "deny";
  tool: string;
  amount?: string;
  timestamp: string;
  reason?: string;
}

// ── Mock data ──────────────────────────────────────────────────

const TOOLS = [
  { name: "get_portfolio", label: "Read Portfolio", risk: "read", icon: "📊" },
  { name: "get_stock_quote", label: "Stock Quotes", risk: "read", icon: "📈" },
  { name: "place_stock_order", label: "Place Stock Order", risk: "financial", icon: "💰" },
  { name: "transfer_token", label: "Transfer Tokens", risk: "financial", icon: "💸" },
  { name: "swap_tokens", label: "Swap Tokens", risk: "financial", icon: "🔄" },
  { name: "deploy_contract", label: "Deploy Contract", risk: "critical", icon: "📜" },
  { name: "cancel_order", label: "Cancel Order", risk: "write", icon: "❌" },
  { name: "pay_for_api", label: "Pay for API (x402)", risk: "financial", icon: "🔑" },
];

// ── Components ─────────────────────────────────────────────────

function Nav() {
  return (
    <nav className="flex items-center justify-between px-6 py-4 border-b border-[#222]">
      <div className="flex items-center gap-3">
        <svg width="28" height="28" viewBox="0 0 24 24" fill="none">
          <path d="M12 2.5 4.5 5.5v6c0 4.6 3.2 8.4 7.5 10 4.3-1.6 7.5-5.4 7.5-10v-6L12 2.5Z" stroke="#6366f1" strokeWidth="1.6" strokeLinejoin="round" fill="rgba(99,102,241,0.12)" />
          <path d="M8.6 12.2l2.4 2.4 4.4-4.6" stroke="#6366f1" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round" />
        </svg>
        <span className="text-lg font-bold text-[#6366f1]">Bolyra Wallet</span>
      </div>
      <div className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#111] border border-[#222] text-sm text-[#888]">
        <span className="w-2 h-2 rounded-full bg-[#4ade80]" />
        Base Sepolia
      </div>
    </nav>
  );
}

function ConsentScreen({ onApprove, onCancel }: { onApprove: (d: Omit<Delegation, "id" | "status" | "createdAt" | "receipts">) => void; onCancel: () => void }) {
  const [agent, setAgent] = useState("research-agent-01");
  const [selected, setSelected] = useState<string[]>(["get_portfolio", "get_stock_quote"]);
  const [maxTx, setMaxTx] = useState("1.00");
  const [maxDay, setMaxDay] = useState("5.00");
  const [expiry, setExpiry] = useState("2h");

  const toggle = (name: string) => {
    setSelected(s => s.includes(name) ? s.filter(n => n !== name) : [...s, name]);
  };

  const hasFinancial = selected.some(s => {
    const t = TOOLS.find(tt => tt.name === s);
    return t && (t.risk === "financial" || t.risk === "critical");
  });

  return (
    <div className="max-w-lg mx-auto mt-8">
      <div className="bg-[#111] border border-[#222] rounded-2xl overflow-hidden">
        <div className="px-6 py-5 border-b border-[#222] bg-[rgba(255,255,255,0.02)]">
          <h2 className="text-xl font-bold mb-1">New Delegation</h2>
          <p className="text-sm text-[#888]">Grant an agent permission to act on your behalf</p>
        </div>

        <div className="px-6 py-5 space-y-5">
          {/* Agent name */}
          <div>
            <label className="block text-sm text-[#888] mb-2">Agent Name</label>
            <input
              type="text"
              value={agent}
              onChange={e => setAgent(e.target.value)}
              className="w-full px-4 py-2.5 rounded-lg bg-[#0a0a0a] border border-[#222] text-[#e0e0e0] text-sm font-mono focus:border-[#6366f1] focus:outline-none"
            />
          </div>

          {/* Tool selection */}
          <div>
            <label className="block text-sm text-[#888] mb-2">Allowed Tools</label>
            <div className="grid grid-cols-2 gap-2">
              {TOOLS.map(tool => {
                const isSelected = selected.includes(tool.name);
                const riskColor = tool.risk === "critical" ? "border-red-500/40 bg-red-500/5" :
                  tool.risk === "financial" ? "border-yellow-500/40 bg-yellow-500/5" :
                  tool.risk === "write" ? "border-orange-400/40 bg-orange-400/5" :
                  "border-[#222] bg-[rgba(255,255,255,0.02)]";
                return (
                  <button
                    key={tool.name}
                    onClick={() => toggle(tool.name)}
                    className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border text-left text-sm transition-all ${
                      isSelected ? "border-[#6366f1] bg-[rgba(99,102,241,0.1)]" : riskColor
                    }`}
                  >
                    <span className="text-base">{tool.icon}</span>
                    <div>
                      <div className={`font-medium ${isSelected ? "text-[#e0e0e0]" : "text-[#888]"}`}>{tool.label}</div>
                      <div className="text-xs text-[#555] font-mono">{tool.name}</div>
                    </div>
                    {isSelected && <span className="ml-auto text-[#6366f1]">✓</span>}
                  </button>
                );
              })}
            </div>
          </div>

          {/* Spend limits (only if financial tools selected) */}
          {hasFinancial && (
            <div className="p-4 rounded-lg border border-yellow-500/30 bg-yellow-500/5">
              <div className="text-sm font-semibold text-[#fbbf24] mb-3">Spend Limits (financial tools selected)</div>
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <label className="block text-xs text-[#888] mb-1">Max per transaction</label>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-[#888]">$</span>
                    <input type="text" value={maxTx} onChange={e => setMaxTx(e.target.value)}
                      className="flex-1 px-3 py-2 rounded-lg bg-[#0a0a0a] border border-[#222] text-sm font-mono text-[#e0e0e0] focus:border-[#6366f1] focus:outline-none" />
                    <span className="text-xs text-[#888]">USDC</span>
                  </div>
                </div>
                <div>
                  <label className="block text-xs text-[#888] mb-1">Max per day</label>
                  <div className="flex items-center gap-2">
                    <span className="text-sm text-[#888]">$</span>
                    <input type="text" value={maxDay} onChange={e => setMaxDay(e.target.value)}
                      className="flex-1 px-3 py-2 rounded-lg bg-[#0a0a0a] border border-[#222] text-sm font-mono text-[#e0e0e0] focus:border-[#6366f1] focus:outline-none" />
                    <span className="text-xs text-[#888]">USDC</span>
                  </div>
                </div>
              </div>
            </div>
          )}

          {/* Expiry */}
          <div>
            <label className="block text-sm text-[#888] mb-2">Expires in</label>
            <div className="flex gap-2">
              {["1h", "2h", "8h", "24h", "7d"].map(e => (
                <button key={e} onClick={() => setExpiry(e)}
                  className={`px-4 py-2 rounded-lg text-sm font-mono transition-all ${
                    expiry === e ? "bg-[rgba(99,102,241,0.15)] border border-[#6366f1] text-[#6366f1]" : "bg-[#0a0a0a] border border-[#222] text-[#888]"
                  }`}>{e}</button>
              ))}
            </div>
          </div>
        </div>

        {/* Consent bar */}
        <div className="px-6 py-4 border-t border-[#222] bg-[rgba(255,255,255,0.02)]">
          <div className="text-sm text-[#888] mb-3">
            Allow <span className="text-[#e0e0e0] font-semibold">{agent}</span> to call{" "}
            <span className="text-[#e0e0e0] font-semibold">{selected.length} tool{selected.length !== 1 ? "s" : ""}</span>
            {hasFinancial && <> with up to <span className="text-[#fbbf24] font-semibold">${maxTx}/tx</span>, <span className="text-[#fbbf24] font-semibold">${maxDay}/day</span></>}
            , expiring in <span className="text-[#e0e0e0] font-semibold">{expiry}</span>?
          </div>
          <div className="flex gap-3">
            <button onClick={onCancel} className="flex-1 px-4 py-3 rounded-lg border border-[#222] text-sm font-semibold text-[#888] hover:bg-[rgba(255,255,255,0.04)] transition-all">
              Deny
            </button>
            <button
              onClick={() => {
                const now = new Date();
                const expiryMs = expiry.endsWith("h") ? parseInt(expiry) * 3600000 : parseInt(expiry) * 86400000;
                onApprove({
                  agent,
                  tools: selected,
                  maxPerTx: maxTx,
                  maxPerDay: maxDay,
                  expiresAt: new Date(now.getTime() + expiryMs).toISOString(),
                  expiresIn: expiry,
                });
              }}
              disabled={selected.length === 0}
              className="flex-1 px-4 py-3 rounded-lg bg-[#6366f1] text-white text-sm font-semibold hover:bg-[#818cf8] transition-all disabled:opacity-40 disabled:cursor-not-allowed"
            >
              Approve Delegation
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function DelegationCard({ delegation, onRevoke, onSimulate }: { delegation: Delegation; onRevoke: () => void; onSimulate: () => void }) {
  const isActive = delegation.status === "active";
  const statusColor = isActive ? "text-[#4ade80]" : delegation.status === "revoked" ? "text-[#f87171]" : "text-[#888]";
  const statusBg = isActive ? "bg-[rgba(74,222,128,0.1)]" : delegation.status === "revoked" ? "bg-[rgba(248,113,113,0.1)]" : "bg-[rgba(255,255,255,0.04)]";

  return (
    <div className="bg-[#111] border border-[#222] rounded-2xl overflow-hidden">
      <div className="flex items-center justify-between px-6 py-4 border-b border-[#222] bg-[rgba(255,255,255,0.02)]">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-xl bg-[rgba(99,102,241,0.12)] border border-[rgba(99,102,241,0.3)] flex items-center justify-center text-[#6366f1] font-bold">
            {delegation.agent.charAt(0).toUpperCase()}
          </div>
          <div>
            <div className="font-semibold">{delegation.agent}</div>
            <div className="text-xs text-[#888] font-mono">did:bolyra:base-sepolia:0x{delegation.id.slice(0, 8)}...</div>
          </div>
        </div>
        <span className={`px-3 py-1 rounded-full text-xs font-semibold ${statusColor} ${statusBg}`}>
          {delegation.status.toUpperCase()}
        </span>
      </div>

      <div className="px-6 py-4 space-y-3">
        <div className="flex flex-wrap gap-2">
          {delegation.tools.map(t => {
            const tool = TOOLS.find(tt => tt.name === t);
            return (
              <span key={t} className="px-2.5 py-1 rounded-md bg-[rgba(255,255,255,0.04)] border border-[#222] text-xs font-mono text-[#888]">
                {tool?.icon} {t}
              </span>
            );
          })}
        </div>
        <div className="grid grid-cols-3 gap-4 text-sm">
          <div><span className="text-[#888]">Max/tx:</span> <span className="font-mono">${delegation.maxPerTx}</span></div>
          <div><span className="text-[#888]">Max/day:</span> <span className="font-mono">${delegation.maxPerDay}</span></div>
          <div><span className="text-[#888]">Expires:</span> <span className="font-mono">{delegation.expiresIn}</span></div>
        </div>

        {/* Receipts */}
        {delegation.receipts.length > 0 && (
          <div className="mt-3 pt-3 border-t border-[#222]">
            <div className="text-xs text-[#888] font-semibold mb-2">RECEIPT TIMELINE</div>
            <div className="space-y-1.5">
              {delegation.receipts.map(r => (
                <div key={r.id} className="flex items-center gap-3 text-xs">
                  <span className={`w-1.5 h-1.5 rounded-full ${r.decision === "allow" ? "bg-[#4ade80]" : "bg-[#f87171]"}`} />
                  <span className="font-mono text-[#888]">{new Date(r.timestamp).toLocaleTimeString()}</span>
                  <span className={`font-semibold ${r.decision === "allow" ? "text-[#4ade80]" : "text-[#f87171]"}`}>
                    {r.decision.toUpperCase()}
                  </span>
                  <span className="font-mono text-[#e0e0e0]">{r.tool}</span>
                  {r.amount && <span className="text-[#888]">${r.amount}</span>}
                  {r.reason && <span className="text-[#f87171] ml-auto">{r.reason}</span>}
                </div>
              ))}
            </div>
          </div>
        )}
      </div>

      {isActive && (
        <div className="flex gap-2 px-6 py-3 border-t border-[#222] bg-[rgba(255,255,255,0.02)]">
          <button onClick={onSimulate} className="flex-1 px-4 py-2.5 rounded-lg border border-[#6366f1] text-[#6366f1] text-sm font-semibold hover:bg-[rgba(99,102,241,0.1)] transition-all">
            Simulate Agent Call
          </button>
          <button onClick={onRevoke} className="px-4 py-2.5 rounded-lg border border-[#f87171] text-[#f87171] text-sm font-semibold hover:bg-[rgba(248,113,113,0.1)] transition-all">
            Revoke
          </button>
        </div>
      )}
    </div>
  );
}

// ── Main App ───────────────────────────────────────────────────

export default function WalletPage() {
  const [view, setView] = useState<"home" | "create">("home");
  const [delegations, setDelegations] = useState<Delegation[]>([]);

  const createDelegation = (d: Omit<Delegation, "id" | "status" | "createdAt" | "receipts">) => {
    const newDel: Delegation = {
      ...d,
      id: Math.random().toString(36).slice(2, 10) + Date.now().toString(36),
      status: "active",
      createdAt: new Date().toISOString(),
      receipts: [],
    };
    setDelegations(prev => [newDel, ...prev]);
    setView("home");
  };

  const revoke = (id: string) => {
    setDelegations(prev => prev.map(d => d.id === id ? { ...d, status: "revoked" as const } : d));
  };

  const simulate = (id: string) => {
    setDelegations(prev => prev.map(d => {
      if (d.id !== id || d.status !== "active") return d;
      // Pick a random allowed tool
      const tool = d.tools[Math.floor(Math.random() * d.tools.length)];
      const toolDef = TOOLS.find(t => t.name === tool);
      const isFinancial = toolDef?.risk === "financial" || toolDef?.risk === "critical";
      const amount = isFinancial ? (Math.random() * 2).toFixed(2) : undefined;
      const overLimit = amount && parseFloat(amount) > parseFloat(d.maxPerTx);
      const receipt: Receipt = {
        id: "rcp_" + Math.random().toString(36).slice(2, 8),
        decision: overLimit ? "deny" : "allow",
        tool,
        amount,
        timestamp: new Date().toISOString(),
        reason: overLimit ? `$${amount} exceeds $${d.maxPerTx}/tx limit` : undefined,
      };
      return { ...d, receipts: [...d.receipts, receipt] };
    }));
  };

  return (
    <div className="min-h-screen">
      <Nav />

      {view === "home" && (
        <div className="max-w-lg mx-auto px-4 py-8">
          <div className="flex items-center justify-between mb-6">
            <h1 className="text-2xl font-bold">Delegations</h1>
            <button
              onClick={() => setView("create")}
              className="px-4 py-2 rounded-lg bg-[#6366f1] text-white text-sm font-semibold hover:bg-[#818cf8] transition-all"
            >
              + New Delegation
            </button>
          </div>

          {delegations.length === 0 ? (
            <div className="text-center py-16">
              <div className="text-4xl mb-4">🛡️</div>
              <div className="text-lg font-semibold mb-2">No delegations yet</div>
              <p className="text-sm text-[#888] mb-6">Create a delegation to grant an AI agent permission to act on your behalf.</p>
              <button
                onClick={() => setView("create")}
                className="px-6 py-3 rounded-lg bg-[#6366f1] text-white font-semibold hover:bg-[#818cf8] transition-all"
              >
                Create First Delegation
              </button>
            </div>
          ) : (
            <div className="space-y-4">
              {delegations.map(d => (
                <DelegationCard
                  key={d.id}
                  delegation={d}
                  onRevoke={() => revoke(d.id)}
                  onSimulate={() => simulate(d.id)}
                />
              ))}
            </div>
          )}

          <div className="mt-12 text-center text-xs text-[#555]">
            This wallet runs locally. No real funds are moved. <a href="https://bolyra.ai" className="text-[#6366f1]">bolyra.ai</a>
          </div>
        </div>
      )}

      {view === "create" && (
        <ConsentScreen
          onApprove={createDelegation}
          onCancel={() => setView("home")}
        />
      )}
    </div>
  );
}
