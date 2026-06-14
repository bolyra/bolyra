// generate.ts — deterministic audit-log generator for Bolyra sales demo
// Outputs demo/audit/data.json with 1000 realistic signed-receipt records.

import { writeFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

// ── Seeded PRNG (LCG) ──────────────────────────────────────────────
let seed = 42;
function rand(): number {
  seed = (seed * 1664525 + 1013904223) & 0x7fffffff;
  return seed / 0x7fffffff;
}
function randInt(min: number, max: number): number {
  return Math.floor(rand() * (max - min + 1)) + min;
}
function pick<T>(arr: T[]): T {
  return arr[Math.floor(rand() * arr.length)];
}
function hexHash(len = 64): string {
  const chars = "0123456789abcdef";
  let h = "";
  for (let i = 0; i < len; i++) h += chars[Math.floor(rand() * 16)];
  return h;
}

// ── Types ───────────────────────────────────────────────────────────
interface AuditRecord {
  id: string;
  timestamp: string;
  agent: string;
  agentDid: string;
  tool: string;
  decision: "allowed" | "denied";
  reason?: string;
  failedCheck?: string;
  score: number;
  permissions: string;
  chainDepth: number;
  cost?: number;
  receiptHash: string;
  signatureValid: boolean;
}

// ── Agent definitions ───────────────────────────────────────────────
interface AgentDef {
  name: string;
  did: string;
  tools: string[];
  permissions: number; // 8-bit bitmask
  baseScore: number;
  maxChainDepth: number;
  costTools: Record<string, [number, number]>; // tool -> [min, max] cents
}

const agents: AgentDef[] = [
  {
    name: "sales-research-agent",
    did: "did:bolyra:agent:0x1a2b3c4d5e6f",
    tools: ["search_contacts", "enrich_lead", "send_email"],
    permissions: 0b00000011, // READ + WRITE
    baseScore: 85,
    maxChainDepth: 2,
    costTools: { send_email: [3, 15] },
  },
  {
    name: "support-triage-agent",
    did: "did:bolyra:agent:0x2b3c4d5e6f7a",
    tools: ["lookup_ticket", "search_kb", "escalate_ticket"],
    permissions: 0b00000001, // READ only
    baseScore: 90,
    maxChainDepth: 1,
    costTools: {},
  },
  {
    name: "billing-ops-agent",
    did: "did:bolyra:agent:0x3c4d5e6f7a8b",
    tools: ["create_invoice", "process_refund", "charge_card"],
    permissions: 0b00001111, // READ+WRITE+FIN_SMALL+FIN_MEDIUM
    baseScore: 78,
    maxChainDepth: 3,
    costTools: {
      create_invoice: [20, 200],
      process_refund: [10, 100],
      charge_card: [30, 350],
    },
  },
  {
    name: "code-review-agent",
    did: "did:bolyra:agent:0x4d5e6f7a8b9c",
    tools: ["read_file", "write_file", "run_tests"],
    permissions: 0b00000011, // READ + WRITE
    baseScore: 92,
    maxChainDepth: 4,
    costTools: {},
  },
  {
    name: "data-export-agent",
    did: "did:bolyra:agent:0x5e6f7a8b9c0d",
    tools: ["export_customers", "export_transactions"],
    permissions: 0b10000001, // READ + ACCESS_PII
    baseScore: 70,
    maxChainDepth: 1,
    costTools: {},
  },
];

// ── Time range: 30 days ending "today" ──────────────────────────────
const END = new Date("2026-06-13T17:00:00Z");
const START = new Date(END.getTime() - 30 * 24 * 60 * 60 * 1000);

function randomTimestamp(): Date {
  return new Date(START.getTime() + rand() * (END.getTime() - START.getTime()));
}

// ── Denial reasons ──────────────────────────────────────────────────
type DenialKind = "bitmask" | "score" | "chainDepth" | "budget" | "anomaly";

function denialInfo(kind: DenialKind): { reason: string; failedCheck: string } {
  switch (kind) {
    case "bitmask":
      return { reason: "insufficient permissions", failedCheck: "bitmask" };
    case "score":
      return { reason: "trust score below threshold", failedCheck: "score" };
    case "chainDepth":
      return {
        reason: "delegation depth exceeded",
        failedCheck: "chainDepth",
      };
    case "budget":
      return { reason: "spend limit exceeded", failedCheck: "budget" };
    case "anomaly":
      return { reason: "anomaly detected", failedCheck: "anomaly" };
  }
}

// ── Build records ───────────────────────────────────────────────────
const records: AuditRecord[] = [];

// Target distribution
const TOTAL = 1000;
const DENIED_POLICY = 100; // bitmask + score + chainDepth
const DENIED_BUDGET = 35;
const ANOMALIES = 15;
const ALLOWED = TOTAL - DENIED_POLICY - DENIED_BUDGET - ANOMALIES;

// Pre-assign denial slots
type Slot = { kind: "allowed" } | { kind: DenialKind };
const slots: Slot[] = [];
for (let i = 0; i < ALLOWED; i++) slots.push({ kind: "allowed" });
for (let i = 0; i < 40; i++) slots.push({ kind: "bitmask" });
for (let i = 0; i < 35; i++) slots.push({ kind: "score" });
for (let i = 0; i < 25; i++) slots.push({ kind: "chainDepth" });
for (let i = 0; i < DENIED_BUDGET; i++) slots.push({ kind: "budget" });
for (let i = 0; i < ANOMALIES; i++) slots.push({ kind: "anomaly" });

// Fisher-Yates shuffle with seeded PRNG
for (let i = slots.length - 1; i > 0; i--) {
  const j = Math.floor(rand() * (i + 1));
  [slots[i], slots[j]] = [slots[j], slots[i]];
}

// Agent weighting: support-triage is highest volume, data-export lowest
const agentWeights = [20, 35, 18, 17, 10]; // percentages, roughly
function pickWeightedAgent(): AgentDef {
  const r = rand() * 100;
  let cum = 0;
  for (let i = 0; i < agentWeights.length; i++) {
    cum += agentWeights[i];
    if (r < cum) return agents[i];
  }
  return agents[agents.length - 1];
}

// Anomaly descriptions for the dashboard
const anomalyDescriptions: string[] = [];

for (let i = 0; i < TOTAL; i++) {
  const slot = slots[i];
  const agent = pickWeightedAgent();
  const tool = pick(agent.tools);
  const ts = randomTimestamp();
  const isAllowed = slot.kind === "allowed";

  let score = agent.baseScore + randInt(-8, 8);
  let chainDepth = randInt(0, agent.maxChainDepth);
  let permissions = agent.permissions.toString(2).padStart(8, "0");

  // Adjust fields for denial types
  if (slot.kind === "score") score = randInt(20, 49);
  if (slot.kind === "chainDepth") chainDepth = agent.maxChainDepth + randInt(1, 3);
  if (slot.kind === "bitmask") {
    // Strip a required bit
    const stripped = agent.permissions & ~(1 << randInt(0, 3));
    permissions = stripped.toString(2).padStart(8, "0");
  }
  if (slot.kind === "anomaly") {
    // Force unusual hour
    ts.setUTCHours(randInt(1, 4));
    ts.setUTCMinutes(randInt(0, 59));
  }

  // Cost — only for cost-bearing tools
  let cost: number | undefined;
  const costRange = agent.costTools[tool];
  if (costRange) {
    cost = randInt(costRange[0], costRange[1]); // cents
  }
  if (slot.kind === "budget" && cost === undefined) {
    // Force a cost tool for budget denials
    const costToolNames = Object.keys(agent.costTools);
    if (costToolNames.length > 0) {
      const ct = pick(costToolNames);
      const cr = agent.costTools[ct];
      cost = cr[1] + randInt(50, 200); // over budget
    } else {
      // Fallback: use billing agent's charge_card
      cost = randInt(500, 1200);
    }
  }

  const record: AuditRecord = {
    id: `audit-${String(i + 1).padStart(4, "0")}`,
    timestamp: ts.toISOString(),
    agent: agent.name,
    agentDid: agent.did,
    tool,
    decision: isAllowed ? "allowed" : "denied",
    score: Math.max(0, Math.min(100, score)),
    permissions,
    chainDepth,
    receiptHash: hexHash(64),
    signatureValid: true,
    ...(cost !== undefined && { cost: Math.round(cost) }),
    ...(!isAllowed && denialInfo(slot.kind)),
  };

  // Collect anomaly descriptions
  if (slot.kind === "anomaly") {
    const hour = ts.getUTCHours().toString().padStart(2, "0");
    const min = ts.getUTCMinutes().toString().padStart(2, "0");
    anomalyDescriptions.push(
      `${agent.name} attempted ${tool} at ${hour}:${min} UTC -- DENIED (outside business hours)`
    );
  }

  records.push(record);
}

// Sort by timestamp
records.sort(
  (a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime()
);

// ── Summary stats ───────────────────────────────────────────────────
const totalCalls = records.length;
const allowed = records.filter((r) => r.decision === "allowed").length;
const denied = records.filter((r) => r.decision === "denied").length;
const totalSpendCents = records
  .filter((r) => r.decision === "allowed" && r.cost)
  .reduce((s, r) => s + (r.cost ?? 0), 0);
const anomalyCount = records.filter(
  (r) => r.failedCheck === "anomaly"
).length;

// Per-agent stats
const agentStats = agents.map((a) => {
  const agentRecords = records.filter((r) => r.agent === a.name);
  const agentAllowed = agentRecords.filter(
    (r) => r.decision === "allowed"
  ).length;
  const agentDenied = agentRecords.filter(
    (r) => r.decision === "denied"
  ).length;
  const agentSpend = agentRecords
    .filter((r) => r.decision === "allowed" && r.cost)
    .reduce((s, r) => s + (r.cost ?? 0), 0);

  // Top tool
  const toolCounts: Record<string, number> = {};
  agentRecords.forEach((r) => {
    toolCounts[r.tool] = (toolCounts[r.tool] || 0) + 1;
  });
  const topTool = Object.entries(toolCounts).sort(
    (a, b) => b[1] - a[1]
  )[0]?.[0] ?? "";

  return {
    name: a.name,
    calls: agentRecords.length,
    allowed: agentAllowed,
    denied: agentDenied,
    spend: agentSpend,
    topTool,
  };
});

// Per-tool stats
const toolStats: Record<string, { allowed: number; denied: number }> = {};
records.forEach((r) => {
  if (!toolStats[r.tool]) toolStats[r.tool] = { allowed: 0, denied: 0 };
  toolStats[r.tool][r.decision === "allowed" ? "allowed" : "denied"]++;
});

const output = {
  summary: {
    totalCalls,
    signedReceipts: totalCalls,
    allowed,
    denied,
    totalSpendCents,
    totalSpendFormatted: `$${(totalSpendCents / 100).toFixed(2)}`,
    anomalies: anomalyCount,
  },
  agentStats,
  toolStats,
  anomalyDescriptions: anomalyDescriptions.slice(0, 15),
  records,
};

const outPath = join(dirname(fileURLToPath(import.meta.url)), "data.json");
writeFileSync(outPath, JSON.stringify(output, null, 2));

console.log(`Generated ${totalCalls} audit records -> ${outPath}`);
console.log(
  `  Allowed: ${allowed}  Denied: ${denied}  Spend: ${output.summary.totalSpendFormatted}  Anomalies: ${anomalyCount}`
);
