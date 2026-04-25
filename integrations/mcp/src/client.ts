/**
 * Client-side helper: generate a fresh Bolyra handshake proof and shape it for
 * both transports (HTTP header + stdio _meta) so callers don't have to pick.
 *
 * Lazy SDK import — heavy crypto only loads when the helper is actually used.
 */

import type {
  HumanIdentity,
  AgentCredential,
  BolyraConfig,
  BolyraProofBundle,
  BolyraClientAuth,
} from './types';

/**
 * Generate a fresh handshake and return both transport-ready shapes.
 *
 * For HTTP transports: spread `result.headers` into your fetch headers.
 * For stdio MCP requests: merge `result.meta` into your request's `params`.
 *
 *   const auth = await attachBolyraProof(human, agentCred);
 *   await client.callTool({
 *     name: 'read_file',
 *     arguments: { path: '/etc/hosts' },
 *     _meta: auth.meta.bolyra ? { bolyra: auth.meta.bolyra } : undefined,
 *   });
 *
 * Each call generates a new proof. Cache `result.bundle` if you want to
 * reuse it within `maxProofAge` (default 5 min) instead of re-proving.
 */
export async function attachBolyraProof(
  human: HumanIdentity,
  credential: AgentCredential,
  sdkConfig?: BolyraConfig,
): Promise<BolyraClientAuth> {
  const sdk = await import('@bolyra/sdk');
  const { humanProof, agentProof, nonce } = await sdk.proveHandshake(
    human,
    credential,
    { config: sdkConfig },
  );

  const bundle: BolyraProofBundle = {
    v: 1,
    humanProof,
    agentProof,
    nonce: nonce.toString(),
    credentialCommitment: credential.commitment.toString(),
  };

  const encoded = Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64');
  return {
    headers: { Authorization: `Bolyra ${encoded}` },
    meta: { bolyra: bundle },
    bundle,
  };
}
