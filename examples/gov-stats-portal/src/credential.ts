/**
 * The demo credential — READ THIS BEFORE TRUSTING ANY OUTPUT.
 *
 * - The Groth16 AgentPolicy proof comes from the repository test vector
 *   `integrations/cli/test/fixtures/verify/allow-agent-only` and is reused UNCHANGED.
 * - The operator-signed binding is re-signed here with the PUBLICLY KNOWN test
 *   private key 42n (the same technique the CLI's own e2e fixtures use in
 *   `deny-mutations.ts`). Anyone can reproduce these signatures.
 * - So this demonstrates ENFORCEMENT by a relying party (what the published
 *   verifier does with a request), not genuine operator identity and not
 *   production issuance.
 *
 * Proof-bound, cannot change without re-proving: `model` ('opus-4.1'), `expiry`
 * (4102444800) and the credential bitmask (3 = READ_DATA|WRITE_DATA). Free to
 * change by re-signing: `agent_name`, `project_key`, `program`, `capabilities`.
 */
import * as fs from 'node:fs';
import { eddsaSign } from '@bolyra/sdk';
import { bindingDigest, type BindingClaim } from '@bolyra/mpp';
import { GOLDEN_REQUEST_PATH } from './paths';

/** Public test operator key; its public key is the one the golden proof attests. */
export const OPERATOR_PRIV = 42n;
export const GOLDEN_OPERATOR_PUBKEY = {
  x: '15617329766995256858590222302430068383949745072531974464084158078905448850943',
  y: '20201653676552407165606319978171745645181779505176156736762229713293662347780',
};

export const AUDIENCE = 'https://stats.example.gov';
const BASE: Omit<BindingClaim, 'capabilities'> = {
  agent_name: 'stats-research-agent',
  project_key: AUDIENCE,
  program: 'demo',
  model: 'opus-4.1', // proof-bound
  expiry: 4102444800, // proof-bound (must equal credential.expiry)
};
/** P1: the agent is authorized for public statistics only. */
export const PUBLIC_STATS_BINDING: BindingClaim = { ...BASE, capabilities: ['read:public-stats'] };
/** P2: the operator signed a binding naming internal files too; the PROVEN bitmask lacks ACCESS_PII. */
export const OVERREACH_BINDING: BindingClaim = { ...BASE, capabilities: ['read:public-stats', 'read:internal-files'] };

export type LooseBundle = Record<string, any>;
export interface Presentation {
  bundle: LooseBundle;
  /** base64url(JSON bundle): the `x-bolyra-authorization` header value. */
  header: string;
  identity: { agent_name: string; program: string; model: string };
}

export function loadGolden(): LooseBundle {
  const req = JSON.parse(fs.readFileSync(GOLDEN_REQUEST_PATH, 'utf8'));
  return JSON.parse(req.bundle);
}

export async function buildPresentation(binding: BindingClaim): Promise<Presentation> {
  const golden = loadGolden();
  const sig = await eddsaSign(OPERATOR_PRIV, bindingDigest(binding));
  const bundle: LooseBundle = {
    bvp: golden.bvp,
    agent: golden.agent, // proof + credential, untouched
    binding: { ...binding, capabilities: [...binding.capabilities] },
    sig: { R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() }, S: sig.S.toString() },
  };
  return {
    bundle,
    header: Buffer.from(JSON.stringify(bundle), 'utf8').toString('base64url'),
    identity: { agent_name: binding.agent_name, program: binding.program, model: binding.model },
  };
}

export function decodeHeader(header: string): LooseBundle {
  return JSON.parse(Buffer.from(header, 'base64url').toString('utf8'));
}
