/**
 * Credential store abstraction.
 *
 * InMemoryCredentialStore is fine for examples and tests.
 * Production: swap for Postgres, DynamoDB, or your credential registry.
 */

import type { AgentCredential } from '@bolyra/sdk';

export interface CredentialStore {
  resolve(commitment: string): Promise<AgentCredential | null>;
}

export class InMemoryCredentialStore implements CredentialStore {
  private credentials = new Map<string, AgentCredential>();

  constructor(seed: AgentCredential[]) {
    for (const cred of seed) {
      this.credentials.set(cred.commitment.toString(), cred);
    }
  }

  async resolve(commitment: string): Promise<AgentCredential | null> {
    return this.credentials.get(commitment) ?? null;
    // Postgres: SELECT credential_json FROM agent_credentials WHERE commitment = $1
  }
}
