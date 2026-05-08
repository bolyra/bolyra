// src/verify.ts — temporary shim. Chunk 5 replaces this with the real v0.2 dispatcher.
import { verifyV01 } from "./legacy-v01";
import type { VerifyOptions } from "./types";

export type LegacyVerifyResult =
  | { valid: true; claims: Record<string, unknown> }
  | { valid: false; reason: string };

export async function verify(
  receipt: string,
  opts: VerifyOptions
): Promise<LegacyVerifyResult> {
  // Forward to verifyV01. v0.1 inputs never contain '~' so the tilde gate
  // is a no-op for them; if a v0.2 receipt accidentally lands here, the gate
  // returns `legacy_v01_rejected` which the caller surfaces as a hard reason.
  const r = await verifyV01(receipt, opts);
  if (r.ok) return { valid: true, claims: r.claims as unknown as Record<string, unknown> };
  return { valid: false, reason: r.reason };
}
