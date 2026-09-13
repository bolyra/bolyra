/**
 * The complete GatewayConfig the embedded middleware needs (spec §3.1).
 * Nothing is loaded from a gateway YAML. `port` and `target` are placeholders:
 * the middleware is embedded directly and never proxies MCP. validateConfig is
 * not called (it would reject port 0), and buildCredentialRegistry parses the
 * static map without validating closure; closure comes from agents.ts.
 */

import type { GatewayConfig } from '@bolyra/gateway';
import type { DemoAgent } from './agents';

export function buildGatewayConfig(
  actionName: string,
  requiredMask: bigint,
  granted: DemoAgent,
  withheld: DemoAgent,
): GatewayConfig {
  return {
    target: 'http://127.0.0.1:1/unused',
    port: 0,
    network: 'base-sepolia',
    devMode: true,
    credentials: {
      type: 'static',
      map: {
        [granted.commitment.toString()]: { permissionBitmask: granted.permissionBitmask.toString() },
        [withheld.commitment.toString()]: { permissionBitmask: withheld.permissionBitmask.toString() },
      },
    },
    tools: { [actionName]: { requireBitmask: Number(requiredMask) } },
    nonce: { store: 'memory', maxProofAge: 300 },
    // The trial signs its own receipts through createGatewayReceiptSigner,
    // which reads issuer/keyId from here and generates an ephemeral key.
    receipts: { enabled: false, output: 'stdout', issuer: 'operator-trial', keyId: 'trial-k1' },
    health: { enabled: false, path: '/healthz' },
  };
}
