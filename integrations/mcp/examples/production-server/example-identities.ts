/**
 * Shared identity fixtures for the production-server example.
 *
 * Uses createDevIdentities() from @bolyra/sdk to produce deterministic
 * human + agent pairs. The server seeds the credential store with the
 * agent credential; the client uses both for proof generation.
 */

import { createDevIdentities } from '@bolyra/sdk';
import type { HumanIdentity, AgentCredential } from '@bolyra/sdk';

export interface ExampleIdentities {
  human: HumanIdentity;
  agent: AgentCredential;
  /** Read-only agent (permissionBitmask: 0b01 = READ_DATA only). */
  readOnlyAgent: AgentCredential;
  readOnlyHuman: HumanIdentity;
}

export async function loadExampleIdentities(): Promise<ExampleIdentities> {
  const { human, agent } = await createDevIdentities();

  // Second pair with restricted permissions for policy-denial demo.
  const { human: readOnlyHuman, agent: readOnlyAgent } =
    await createDevIdentities({ permissionBitmask: 0b01n });

  return { human, agent, readOnlyHuman, readOnlyAgent };
}
