// integrations/mcp/examples/delegation-example.ts
//
// Bolyra Delegation x MCP: gate an MCP server tool call on a signed delegation
// receipt. Run with:  npx ts-node delegation-example.ts
//
// Requires:  npm i @bolyra/delegation @modelcontextprotocol/sdk

import { allow, verify, generateKeyPair, PERM, type Receipt } from "@bolyra/delegation";

// --- Stand-in for @modelcontextprotocol/sdk so this example runs standalone. -
// In a real integration, replace with imports from
// "@modelcontextprotocol/sdk/server" and register the tool with your Server.
// The shape below mirrors the SDK's CallToolRequest handler signature.
interface CallToolRequest {
  params: {
    name: string;
    arguments?: Record<string, unknown>;
    _meta?: { delegation?: Receipt };
  };
}
interface CallToolResult {
  content: Array<{ type: "text"; text: string }>;
  isError?: boolean;
}
type CallToolHandler = (req: CallToolRequest) => Promise<CallToolResult>;
// ---------------------------------------------------------------------------

/**
 * gateMcpTool wraps an MCP CallTool handler so it only runs when the request
 * carries a valid delegation receipt under params._meta.delegation.
 *
 * Why _meta: MCP allows arbitrary metadata on tool invocations; this is the
 * natural place to attach a per-call authorization token without changing the
 * tool's input schema.
 */
function gateMcpTool(opts: {
  agent: string;
  action: string;
  audience: string;
  trustedIssuers: CryptoKey | CryptoKey[];
  handler: CallToolHandler;
}): CallToolHandler {
  return async (req) => {
    const receipt = req.params._meta?.delegation;
    if (!receipt) {
      return {
        isError: true,
        content: [{ type: "text", text: `tool '${opts.action}' requires _meta.delegation receipt` }],
      };
    }

    const args = req.params.arguments ?? {};
    const invocationAmount = (args.amount && args.currency)
      ? { amount: Number(args.amount), currency: String(args.currency) }
      : undefined;

    const result = await verify(receipt, {
      expectedAgent: opts.agent,
      expectedAction: opts.action,
      expectedAudience: opts.audience,
      trustedIssuers: opts.trustedIssuers,
      invocationAmount,
    });

    if (!result.valid) {
      return {
        isError: true,
        content: [
          {
            type: "text",
            text: `delegation rejected: ${result.reason}${result.detail ? ` (${result.detail})` : ""}`,
          },
        ],
      };
    }

    return opts.handler(req);
  };
}

// --- Demo ------------------------------------------------------------------

async function main() {
  const human = await generateKeyPair();

  const receipt = await allow(
    {
      agent: "agent_alice",
      action: "filesystem.write",
      audience: "bolyra-fs-mcp-server",
      permission: PERM.WRITE_DATA,
      expiresIn: "10m",
    },
    human.privateKey,
    human.publicKey,
  );

  const writeFileHandler = gateMcpTool({
    agent: "agent_alice",
    action: "filesystem.write",
    audience: "bolyra-fs-mcp-server",
    trustedIssuers: human.publicKey,
    handler: async (req) => ({
      content: [
        { type: "text", text: `wrote ${(req.params.arguments as { path?: string })?.path}` },
      ],
    }),
  });

  // Happy path
  const ok = await writeFileHandler({
    params: {
      name: "filesystem.write",
      arguments: { path: "/tmp/hello.txt", content: "hi" },
      _meta: { delegation: receipt },
    },
  });
  console.log("OK:", JSON.stringify(ok));

  // Rejection: no receipt at all
  const noReceipt = await writeFileHandler({
    params: {
      name: "filesystem.write",
      arguments: { path: "/tmp/oops.txt", content: "no auth" },
    },
  });
  console.log("REJECTED (expected):", JSON.stringify(noReceipt));

  // Rejection: receipt issued for a different MCP server
  const wrongAudienceReceipt = await allow(
    {
      agent: "agent_alice",
      action: "filesystem.write",
      audience: "some-other-mcp-server",
      permission: PERM.WRITE_DATA,
    },
    human.privateKey,
    human.publicKey,
  );
  const wrongAud = await writeFileHandler({
    params: {
      name: "filesystem.write",
      arguments: { path: "/tmp/x.txt" },
      _meta: { delegation: wrongAudienceReceipt },
    },
  });
  console.log("REJECTED (expected):", JSON.stringify(wrongAud));
}

main().catch((e) => {
  console.error(e);
  process.exit(1);
});
