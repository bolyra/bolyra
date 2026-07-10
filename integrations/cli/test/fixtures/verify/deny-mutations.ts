/**
 * Deterministic mutation helpers for the `bolyra verify` e2e matrix (Task 16).
 *
 * The 22-case e2e matrix is built by deep-cloning the 3 committed ALLOW goldens
 * and mutating ONE thing per case — no runtime proving, no circuits/build. The
 * agent Groth16 proof stays byte-identical to the golden (so it still verifies
 * against the committed vkeys) unless a case deliberately tampers the proof.
 *
 * `resignBinding` re-signs a mutated binding with the known operator private key
 * (OPERATOR_PRIV = 42n — the same key `generate.ts` used, whose public key the
 * committed proof attests to). This lets cases that must change the SIGNED
 * binding (e.g. an extra capability, a swapped model) still pass the binding
 * signature check so the intended DOWNSTREAM denial code is the one that fires.
 */

import { eddsaSign } from '@bolyra/sdk';
import { bindingDigest, type BindingClaim } from '../../../src/verify/binding';

/** Operator private key the committed goldens were signed/proven under. */
export const OPERATOR_PRIV = 42n;

/** The serialized signature block shape carried by a `bvp/1` bundle. */
export interface BundleSig {
  R8: { x: string; y: string };
  S: string;
}

/** Re-sign a (possibly mutated) binding with the golden operator key. */
export async function resignBinding(binding: BindingClaim): Promise<BundleSig> {
  const sig = await eddsaSign(OPERATOR_PRIV, await bindingDigest(binding));
  return {
    R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
    S: sig.S.toString(),
  };
}

/** A parsed `bvp/1` bundle (loose typing — the e2e only reaches into a few fields). */
export type LooseBundle = Record<string, any>;

/** A parsed VerifierRequest whose `bundle` field is a JSON string. */
export interface LooseRequest {
  version: number;
  bundle: string;
  request: {
    agent_name: string;
    project_key: string;
    program: string;
    model: string;
    granted_capabilities: string[];
  };
  now_unix: number;
  [k: string]: unknown;
}

/** Deep clone via JSON round-trip (all fixture values are JSON-safe). */
export function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}

/** Parse the inner `bvp/1` bundle out of a request's stringified `bundle` field. */
export function decodeBundle(req: LooseRequest): LooseBundle {
  return JSON.parse(req.bundle) as LooseBundle;
}

/** Re-encode a mutated bundle back into the request's `bundle` string field. */
export function encodeBundle(req: LooseRequest, bundle: LooseBundle): void {
  req.bundle = JSON.stringify(bundle);
}
