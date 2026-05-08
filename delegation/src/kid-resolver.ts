import type { IssuerKeyResolver } from "./types";
export type { IssuerKeyResolver } from "./types";

export class ResolverError extends Error {
  constructor(message: string, public readonly cause?: unknown) {
    super(message);
    this.name = "ResolverError";
  }
}

export function staticIssuerResolver(
  table: Record<string, Record<string, CryptoKey>>
): IssuerKeyResolver {
  return async (iss, kid) => {
    const inner = table[iss];
    if (!inner) return null;
    return inner[kid] ?? null;
  };
}
