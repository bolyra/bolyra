/**
 * Three synthetic tenants for the test suite. Plain data only: this module is
 * imported by vitest.config.mts (Node) AND by the specs (workers pool), so it
 * must not touch `cloudflare:test`.
 *
 *   org-a  trusts the repo conformance-fixture operator key
 *   org-b  trusts ORG_B_OPERATOR_KEY only (so A's bundles are untrusted here)
 *   org-c  trusts the fixture key too (a second tenant sharing A's operator)
 */

export const ORGS = { A: 'org-a', B: 'org-b', C: 'org-c' } as const;

/** Test-only token values (NOT real secrets). */
export const TOKENS = {
  A: { admin: 'org-a-admin-test-token-0000000000', verifier: 'org-a-verifier-test-token-0000000' },
  B: { admin: 'org-b-admin-test-token-0000000000', verifier: 'org-b-verifier-test-token-0000000' },
  C: { admin: 'org-c-admin-test-token-0000000000', verifier: 'org-c-verifier-test-token-0000000' },
} as const;

/**
 * A real BabyJubjub public key: @bolyra/sdk `derivePublicKey(scalar)` with the
 * bigint scalar 0x6f7267622d746573742d6f6e6c792d6f70657261746f722d6b65792d30310000n.
 * It is trusted ONLY by org-b and never signs anything: it exists so org-b
 * can be "a tenant that does not trust the fixture operator".
 */
export const ORG_B_OPERATOR_KEY =
  '5780309220095950943441710225201277741264578273614958887521755782153302045110:' +
  '14077522702613632176467120242135873645024903336295469810913989799816130159769';

export interface TestTenantOptions {
  /** org ids to mark `disabled: true`. */
  disabled?: readonly string[];
}

/** The `TENANTS` JSON for the three orgs; `fixtureOperatorKey` is the conformance fixture's `x:y`. */
export function buildTestTenants(fixtureOperatorKey: string, options: TestTenantOptions = {}): string {
  const disabled = new Set(options.disabled ?? []);
  const tenant = (org: keyof typeof ORGS, operators: string[]) => ({
    admin_token: TOKENS[org].admin,
    verifier_token: TOKENS[org].verifier,
    trusted_operators: operators,
    ...(disabled.has(ORGS[org]) ? { disabled: true } : {}),
  });
  return JSON.stringify({
    [ORGS.A]: tenant('A', [fixtureOperatorKey]),
    [ORGS.B]: tenant('B', [ORG_B_OPERATOR_KEY]),
    [ORGS.C]: tenant('C', [fixtureOperatorKey]),
  });
}
