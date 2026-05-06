/**
 * Shared demo state: a single hardcoded human identity + agent credential.
 *
 * In production, the registry is your IdentityRegistry contract or a database
 * mirror of it. Here it's an in-memory Map populated on first lookup with the
 * same credential the legit client uses, so the demo is self-contained.
 */

import * as path from 'path';

// Point the SDK's rapidsnark discovery at the bundled binary BEFORE importing
// @bolyra/sdk. The MCP package nests its own copy of @bolyra/sdk under
// integrations/mcp/node_modules, so the SDK's __dirname-based bundled lookup
// (sdk/../../circuits/build/rapidsnark_prover) lands in the wrong tree and
// silently falls back to snarkjs (~17s vs ~200ms). Env var bypasses that.
const BUNDLED_RAPIDSNARK = path.resolve(__dirname, '../../../circuits/build/rapidsnark_prover');
process.env.BOLYRA_RAPIDSNARK ??= BUNDLED_RAPIDSNARK;

import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  type HumanIdentity,
  type AgentCredential,
  type BolyraConfig,
} from '@bolyra/sdk';

/**
 * SDK config pointing at the local circuits/build artifacts. Both the legit
 * client (proof generation) and the fixed server (vkey-based verification)
 * use this so the demo runs entirely from the local repo.
 */
export const DEMO_SDK_CONFIG: BolyraConfig = {
  circuitDir: path.resolve(__dirname, '../../../circuits/build'),
};

// Stable demo secret (do NOT use anything like this in production).
const DEMO_HUMAN_SECRET =
  0x0001020304050607080900010203040506070809000102030405060708090001n;
const DEMO_OPERATOR_KEY =
  0x0102030405060708090a0b0c0d0e0f1011121314151617181920212223242526n;
const DEMO_MODEL_HASH = 12345n;

let cachedIds: { human: HumanIdentity; credential: AgentCredential } | null = null;

/** Build a stable human identity + agent credential pair for the demo. */
export async function loadDemoIdentities(): Promise<{
  human: HumanIdentity;
  credential: AgentCredential;
}> {
  if (cachedIds) return cachedIds;

  const human = await createHumanIdentity(DEMO_HUMAN_SECRET);
  // Fixed absolute expiry so client and server (separate processes) compute the
  // same credential commitment. Date.now()-based expiry would diverge by ms.
  const expiry = 4_102_444_800n; // 2100-01-01T00:00:00Z
  const credential = await createAgentCredential(
    DEMO_MODEL_HASH,
    DEMO_OPERATOR_KEY,
    [Permission.READ_DATA],
    expiry,
  );

  cachedIds = { human, credential };
  return cachedIds;
}

/** Build the in-memory registry the fixed server consults. */
export function loadDemoCredentialRegistry(): Map<string, AgentCredential> {
  return new Map<string, AgentCredential>();
}

/**
 * Lazy registry population. Called from the server's resolveCredential on
 * first miss so we don't have to await at module load time.
 */
export async function ensureRegistryPopulated(
  registry: Map<string, AgentCredential>,
): Promise<void> {
  if (registry.size > 0) return;
  const { credential } = await loadDemoIdentities();
  registry.set(credential.commitment.toString(), credential);
}
