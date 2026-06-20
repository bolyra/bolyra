/**
 * @bolyra/ai — bolyraAuthMiddleware()
 *
 * Server-side verification middleware for Express/Next.js.
 * Extracts the Authorization header, verifies the Bolyra proof bundle using
 * @bolyra/mcp's verifyBundle(), and checks per-tool policies.
 */

import type {
  BolyraServerConfig,
  BolyraVerifier,
  BolyraVerifyResult,
} from './types';
import { decodeBundleFromHeader } from './utils';

/**
 * Create a server-side Bolyra verifier.
 *
 * Returns a verifier object with `verify()` and `verifyHeader()` methods.
 * Use `verify()` with a Request object (Next.js App Router, Fetch API),
 * or `verifyHeader()` with a raw Authorization header string.
 *
 * @example
 * ```ts
 * const auth = bolyraAuthMiddleware({
 *   toolPolicy: { 'read_file': { requireBitmask: 1 } },
 *   devMode: process.env.NODE_ENV === 'development',
 * });
 *
 * const { verified, context } = await auth.verify(req, 'read_file');
 * ```
 */
export function bolyraAuthMiddleware(config: BolyraServerConfig): BolyraVerifier {
  return {
    async verify(req: Request, toolName?: string): Promise<BolyraVerifyResult> {
      const authHeader = req.headers.get('Authorization') ?? req.headers.get('authorization');
      if (!authHeader) {
        return {
          verified: false,
          reason: 'Missing Authorization header. Expected: Authorization: Bolyra <base64-bundle>',
        };
      }
      return verifyAuthHeader(authHeader, toolName, config);
    },

    async verifyHeader(authHeader: string, toolName?: string): Promise<BolyraVerifyResult> {
      return verifyAuthHeader(authHeader, toolName, config);
    },
  };
}

/**
 * Internal: verify an Authorization header value.
 */
async function verifyAuthHeader(
  authHeader: string,
  toolName: string | undefined,
  config: BolyraServerConfig,
): Promise<BolyraVerifyResult> {
  // Decode the proof bundle from the header
  const bundle = decodeBundleFromHeader(authHeader);
  if (!bundle) {
    return {
      verified: false,
      reason: 'Invalid Authorization header. Expected format: Bolyra <base64-encoded-bundle>',
    };
  }

  // Import verification functions from @bolyra/mcp
  const { verifyBundle, checkToolPolicy } = await import('@bolyra/mcp');

  // Build MCP config from our server config
  const mcpConfig = {
    network: config.network ?? 'base-sepolia',
    devMode: config.devMode,
    resolveCredential: config.resolveCredential,
    nonceStore: config.nonceStore,
    sdkConfig: config.sdkConfig,
    // Map our BolyraToolPolicy to MCP ToolPolicyMap format
    toolPolicy: config.toolPolicy
      ? Object.fromEntries(
          Object.entries(config.toolPolicy).map(([name, policy]) => [
            name,
            {
              requireBitmask: policy.requireBitmask !== undefined
                ? BigInt(policy.requireBitmask)
                : undefined,
              minScore: policy.minScore,
              maxChainDepth: policy.maxChainDepth,
            },
          ]),
        )
      : undefined,
  };

  // Verify the bundle
  const authCtx = await verifyBundle(bundle, mcpConfig);

  if (!authCtx.verified) {
    return {
      verified: false,
      reason: authCtx.reason ?? 'Verification failed',
      context: authCtx,
    };
  }

  // Check per-tool policy if tool name is provided
  if (toolName && config.toolPolicy?.[toolName]) {
    const decision = checkToolPolicy(toolName, authCtx, mcpConfig);
    if (!decision.allowed) {
      return {
        verified: false,
        reason: decision.reason ?? `Tool policy denied for "${toolName}"`,
        context: authCtx,
      };
    }
  }

  return {
    verified: true,
    context: authCtx,
  };
}
