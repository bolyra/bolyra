// integrations/openai-agents/delegation-example.ts
//
// Bolyra Delegation x OpenAI Agents SDK: gate a tool call on a signed
// delegation receipt. Run with:  npx ts-node delegation-example.ts
//
// Requires:  npm i @bolyra/delegation @openai/agents zod

import { allow, verify, generateKeyPair, PERM, type Receipt } from "@bolyra/delegation";

// --- Stand-ins for the OpenAI Agents SDK so this example runs standalone. ---
// In a real integration, replace these with imports from "@openai/agents":
//   import { Agent, tool, run } from "@openai/agents";
type ToolHandler<I, O> = (input: I, ctx: ToolCtx) => Promise<O>;
interface ToolCtx { receipt?: Receipt; invocationAmount?: { amount: number; currency: string } }
function tool<I, O>(name: string, handler: ToolHandler<I, O>) {
  return { name, handler };
}
// ---------------------------------------------------------------------------

/**
 * withDelegation: wrap any tool handler so it only runs when the caller
 * presents a valid receipt for the expected (agent, action, audience).
 *
 * This is the entire integration surface. ~30 lines. Copy + adapt.
 */
function withDelegation<I, O>(opts: {
  agent: string;
  action: string;
  audience: string;
  trustedIssuers: CryptoKey | CryptoKey[];
  handler: ToolHandler<I, O>;
}): ToolHandler<I, O> {
  return async (input, ctx) => {
    if (!ctx.receipt) {
      throw new Error(`tool '${opts.action}' requires a delegation receipt`);
    }
    const result = await verify(ctx.receipt, {
      expectedAgent: opts.agent,
      expectedAction: opts.action,
      expectedAudience: opts.audience,
      trustedIssuers: opts.trustedIssuers,
      invocationAmount: ctx.invocationAmount,
    });
    if (!result.valid) {
      throw new Error(`delegation rejected: ${result.reason}${result.detail ? ` (${result.detail})` : ""}`);
    }
    return opts.handler(input, ctx);
  };
}

// --- Demo ------------------------------------------------------------------

async function main() {
  // 1. Human generates a keypair (one-time, persisted client-side).
  const human = await generateKeyPair();

  // 2. Human signs a scoped receipt for agent_alice.
  const receipt = await allow(
    {
      agent: "agent_alice",
      action: "purchase",
      audience: "example.com",
      permission: PERM.FINANCIAL_SMALL,
      maxAmount: { amount: 50, currency: "USD" },
      expiresIn: "1h",
    },
    human.privateKey,
    human.publicKey,
  );

  // 3. Define a tool gated by the delegation. The wrapper does ALL the
  // verification before the handler ever runs.
  const purchaseTool = tool(
    "purchase",
    withDelegation({
      agent: "agent_alice",
      action: "purchase",
      audience: "example.com",
      trustedIssuers: human.publicKey,
      handler: async (input: { sku: string; amount: number }) => {
        // (In reality, this would call Stripe / your merchant.)
        return { ok: true, sku: input.sku, charged: input.amount };
      },
    }),
  );

  // 4. Happy path: agent invokes with valid receipt + amount within cap.
  const ok = await purchaseTool.handler(
    { sku: "BOOK-1", amount: 25 },
    { receipt, invocationAmount: { amount: 25, currency: "USD" } },
  );
  console.log("OK:", ok);

  // 5. Rejection: same receipt, but agent tries to charge $75 (cap is $50).
  try {
    await purchaseTool.handler(
      { sku: "BOOK-2", amount: 75 },
      { receipt, invocationAmount: { amount: 75, currency: "USD" } },
    );
  } catch (err) {
    console.log("REJECTED (expected):", (err as Error).message);
  }

  // 6. Rejection: agent tries to use the receipt against a different merchant.
  const wrongAudienceTool = tool(
    "purchase",
    withDelegation({
      agent: "agent_alice",
      action: "purchase",
      audience: "attacker.com",
      trustedIssuers: human.publicKey,
      handler: async () => ({ ok: true }),
    }),
  );
  try {
    await wrongAudienceTool.handler(
      { sku: "BOOK-3", amount: 10 },
      { receipt, invocationAmount: { amount: 10, currency: "USD" } },
    );
  } catch (err) {
    console.log("REJECTED (expected):", (err as Error).message);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
