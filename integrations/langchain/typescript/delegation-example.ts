// integrations/langchain/typescript/delegation-example.ts
//
// Bolyra Delegation x LangChain.js: gate a DynamicTool on a signed delegation
// receipt. Run with:  npx ts-node delegation-example.ts
//
// Requires:  npm i @bolyra/delegation @langchain/core

import { allow, verify, generateKeyPair, PERM, type Receipt } from "@bolyra/delegation";

// --- Stand-in for @langchain/core/tools so this example runs standalone. ---
// In a real integration, replace with:
//   import { DynamicTool } from "@langchain/core/tools";
class DynamicTool {
  name: string;
  description: string;
  func: (input: string) => Promise<string>;
  constructor(opts: { name: string; description: string; func: (input: string) => Promise<string> }) {
    this.name = opts.name;
    this.description = opts.description;
    this.func = opts.func;
  }
  async invoke(input: string) {
    return this.func(input);
  }
}
// ---------------------------------------------------------------------------

interface ToolInput {
  _receipt: Receipt;
  payload: Record<string, unknown>;
}

/**
 * withDelegation wraps a LangChain DynamicTool's func so it only runs when
 * the input includes a valid receipt for the expected (agent, action, audience).
 * The wrapper expects the agent to pass a JSON string of shape:
 *   { "_receipt": "<jws>", "payload": { ... } }
 */
function withDelegation(opts: {
  agent: string;
  action: string;
  audience: string;
  trustedIssuers: CryptoKey | CryptoKey[];
  body: (payload: Record<string, unknown>) => Promise<string>;
}): (input: string) => Promise<string> {
  return async (input: string) => {
    let parsed: ToolInput;
    try {
      parsed = JSON.parse(input) as ToolInput;
    } catch {
      throw new Error("tool input must be JSON: { _receipt, payload }");
    }
    if (!parsed._receipt) {
      throw new Error(`tool '${opts.action}' requires a delegation receipt`);
    }

    const invocationAmount = (parsed.payload?.amount && parsed.payload?.currency)
      ? { amount: Number(parsed.payload.amount), currency: String(parsed.payload.currency) }
      : undefined;

    const result = await verify(parsed._receipt, {
      expectedAgent: opts.agent,
      expectedAction: opts.action,
      expectedAudience: opts.audience,
      trustedIssuers: opts.trustedIssuers,
      invocationAmount,
    });

    if (!result.valid) {
      throw new Error(`delegation rejected: ${result.reason}${result.detail ? ` (${result.detail})` : ""}`);
    }

    return opts.body(parsed.payload);
  };
}

// --- Demo ------------------------------------------------------------------

async function main() {
  const human = await generateKeyPair();

  const receipt = await allow(
    {
      agent: "agent_alice",
      action: "send_email",
      audience: "transactional-email-service",
      permission: PERM.WRITE_DATA,
      expiresIn: "5m",
    },
    human.privateKey,
    human.publicKey,
  );

  const sendEmailTool = new DynamicTool({
    name: "send_email",
    description: "Send a transactional email. Requires a Bolyra delegation receipt.",
    func: withDelegation({
      agent: "agent_alice",
      action: "send_email",
      audience: "transactional-email-service",
      trustedIssuers: human.publicKey,
      body: async (payload) => {
        // (In reality, call SES / SendGrid / Postmark.)
        return JSON.stringify({ delivered: true, to: payload.to });
      },
    }),
  });

  // Happy path: receipt valid for this tool.
  const ok = await sendEmailTool.invoke(
    JSON.stringify({
      _receipt: receipt,
      payload: { to: "user@example.com", subject: "Hello" },
    }),
  );
  console.log("OK:", ok);

  // Rejection: missing receipt.
  try {
    await sendEmailTool.invoke(
      JSON.stringify({ payload: { to: "user@example.com", subject: "no auth" } }),
    );
  } catch (err) {
    console.log("REJECTED (expected):", (err as Error).message);
  }

  // Rejection: receipt for the wrong agent.
  const otherReceipt = await allow(
    {
      agent: "agent_mallory",
      action: "send_email",
      audience: "transactional-email-service",
      permission: PERM.WRITE_DATA,
    },
    human.privateKey,
    human.publicKey,
  );
  try {
    await sendEmailTool.invoke(
      JSON.stringify({ _receipt: otherReceipt, payload: { to: "user@example.com" } }),
    );
  } catch (err) {
    console.log("REJECTED (expected):", (err as Error).message);
  }
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
