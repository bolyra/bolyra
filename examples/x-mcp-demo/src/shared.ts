/**
 * Shared dev identities and helpers for the X MCP demo.
 * Uses createDevIdentities() — no circuit artifacts needed.
 */
import { createDevIdentities } from '@bolyra/sdk';
import { attachBolyraProof, attachDelegatedBolyraProof } from '@bolyra/mcp';

/** Full-permission agent (all 8 bits). */
export async function createFullAgent() {
  return createDevIdentities();
}

/** Read-only agent (READ_DATA only). */
export async function createReadOnlyAgent() {
  return createDevIdentities({ permissionBitmask: 0b00000001n });
}

export async function proveFullAccess() {
  const { human, agent } = await createFullAgent();
  return attachBolyraProof(human, agent, { devMode: true });
}

export async function proveReadOnly() {
  const full = await createFullAgent();
  const readOnly = await createReadOnlyAgent();
  return attachDelegatedBolyraProof(
    full.human,
    full.agent,
    [{
      delegator: full.agent,
      delegatorOperatorPrivateKey: full.operatorKey,
      delegateeCommitment: readOnly.agent.commitment,
      delegateeScope: 0b00000001n,
      delegateeExpiry: full.agent.expiryTimestamp,
    }],
    { devMode: true },
  );
}

export function jsonRpcCall(id: number, toolName: string, args: Record<string, any>, meta?: any) {
  return JSON.stringify({
    jsonrpc: '2.0',
    method: 'tools/call',
    id,
    params: {
      name: toolName,
      arguments: args,
      ...(meta ? { _meta: meta } : {}),
    },
  });
}

export function jsonRpcInit(id: number) {
  return JSON.stringify({
    jsonrpc: '2.0',
    method: 'initialize',
    id,
    params: {
      protocolVersion: '2025-03-26',
      clientInfo: { name: 'x-mcp-demo', version: '0.1.0' },
      capabilities: {},
    },
  });
}

export function printHeader(title: string) {
  const line = '='.repeat(60);
  console.log(`\n${line}`);
  console.log(`  ${title}`);
  console.log(`${line}\n`);
}

/** Wait to ensure unique nonce (dev mode uses second-level timestamps). */
export const tick = () => new Promise<void>(r => setTimeout(r, 1100));

export function printResult(label: string, res: any) {
  if (res.error) {
    console.log(`  [DENIED] ${label}`);
    console.log(`    Error ${res.error.code}: ${res.error.message}\n`);
  } else {
    console.log(`  [ALLOWED] ${label}`);
    const text = res.result?.content?.[0]?.text ?? JSON.stringify(res.result);
    console.log(`    Response: ${text.slice(0, 120)}\n`);
  }
}
