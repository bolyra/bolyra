import type { AgentCredential } from './types';

export interface RegistryConfig {
  baseUrl: string;
  apiKey: string;
}

/**
 * Create a resolver function that fetches an AgentCredential from the
 * Bolyra credential registry API by commitment string.
 *
 * JSON decimal strings are converted back to BigInt fields.
 * Returns null if the credential is not found or has been revoked.
 */
export function createRegistryResolver(config: RegistryConfig) {
  return async (commitment: string): Promise<AgentCredential | null> => {
    const res = await fetch(`${config.baseUrl}/v1/credentials/${commitment}`, {
      headers: { Authorization: `Bearer ${config.apiKey}` },
    });
    if (!res.ok) return null;
    const data = (await res.json()) as { credential: Record<string, any> };
    const c = data.credential;
    return {
      modelHash: BigInt(c.modelHash),
      operatorPublicKey: { x: BigInt(c.operatorPublicKey.x), y: BigInt(c.operatorPublicKey.y) },
      permissionBitmask: BigInt(c.permissionBitmask),
      expiryTimestamp: BigInt(c.expiryTimestamp),
      signature: {
        R8: { x: BigInt(c.signature.R8.x), y: BigInt(c.signature.R8.y) },
        S: BigInt(c.signature.S),
      },
      commitment: BigInt(c.commitment),
    };
  };
}
