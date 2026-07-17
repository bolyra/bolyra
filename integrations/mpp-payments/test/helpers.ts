/**
 * Test fixtures: build classical `bvp/1` presentation bundles through the SAME
 * issuance assembler the operator-facing `issueMandate` / `bolyra mandate
 * issue` path uses (`mintPresentation`), so fixtures and real issuance share one
 * minting code path. The load-bearing fact is the real operator EdDSA-Poseidon
 * binding signature; the proof envelope is a structurally-valid placeholder (the
 * classical path never checks proof math).
 *
 * Adversarial fixtures layer explicit tampering (a corrupted signature, an
 * injected zk-only slot) ON TOP of a validly-minted presentation — issue a real
 * mandate, then break it — rather than hand-assembling a second bundle shape.
 */

import { derivePublicKey, Permission } from '@bolyra/sdk';
import { mintPresentation } from '../src/issue';
import type { BindingClaim } from '../src/bundle';
import type { OperatorKey } from '../src/types';

export const OPERATOR_PRIV = 42n;
export const OTHER_OPERATOR_PRIV = 43n;

export const AGENT_NAME = 'shopper-bot';
export const AUDIENCE = 'api.merchant.example';
export const PROGRAM = 'mpp';
export const MODEL = 'opus-4.1';

/** Far-future expiry so fixtures never age out. */
export const EXPIRY = 4102444800; // 2100-01-01T00:00:00Z
/** Fixed test clock, comfortably before EXPIRY. */
export const NOW_UNIX = 1751990400;

export async function operatorKey(priv: bigint = OPERATOR_PRIV): Promise<OperatorKey> {
  const pub = await derivePublicKey(priv);
  return { x: pub.x.toString(), y: pub.y.toString() };
}

export interface MakeBundleOptions {
  operatorPriv?: bigint;
  /** Signed by the binding; defaults to the standard fixture context. */
  binding?: Partial<BindingClaim>;
  /** Permissions revealed in the credential bitmask. */
  permissions?: Permission[];
  /** Credential expiry (unix seconds). */
  expiry?: number;
  /** Corrupt the binding signature (post-issuance tamper). */
  breakSignature?: boolean;
  /** Add zk-only slots to the raw bundle (post-issuance tamper). */
  withHumanSlot?: boolean;
  /** Encode as base64url instead of raw JSON. */
  base64?: boolean;
}

/**
 * Build a serialized `bvp/1` bundle string via {@link mintPresentation}. The
 * scopeCommitment public signal is recomputed from the revealed preimage inside
 * the assembler so classical scope-anchoring passes, then optional tamper
 * options corrupt the valid presentation for negative-path tests.
 */
export async function makeBundle(options: MakeBundleOptions = {}): Promise<string> {
  const {
    operatorPriv = OPERATOR_PRIV,
    permissions = [Permission.READ_DATA, Permission.FINANCIAL_SMALL],
    expiry = EXPIRY,
    breakSignature = false,
    withHumanSlot = false,
    base64 = false,
  } = options;

  const binding: BindingClaim = {
    agent_name: AGENT_NAME,
    project_key: AUDIENCE,
    program: PROGRAM,
    model: MODEL,
    capabilities: ['mpp:financial:small'],
    ...options.binding,
  };

  const json = await mintPresentation({
    operatorPrivateKey: operatorPriv,
    binding,
    permissions,
    expiry,
    encoding: 'json',
  });
  const bundle = JSON.parse(json) as Record<string, unknown> & {
    sig: { S: string };
    agent: { envelope: unknown };
  };

  if (breakSignature) {
    bundle.sig.S = (BigInt(bundle.sig.S) + 1n).toString();
  }
  if (withHumanSlot) {
    const agentEnvelope = bundle.agent.envelope as { circuit: unknown };
    bundle.human = {
      envelope: { ...agentEnvelope, circuit: { name: 'HumanUniqueness', version: '1.0.0' } },
    };
  }

  const out = JSON.stringify(bundle);
  return base64 ? Buffer.from(out, 'utf8').toString('base64url') : out;
}

/** The spec §2.1 request context matching the standard fixture binding. */
export function fixtureRequestContext(overrides: Partial<Record<string, unknown>> = {}) {
  return {
    agent_name: AGENT_NAME,
    project_key: AUDIENCE,
    program: PROGRAM,
    model: MODEL,
    granted_capabilities: ['mpp:financial:small'],
    ...overrides,
  };
}
