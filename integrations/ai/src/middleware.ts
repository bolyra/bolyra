/**
 * @bolyra/ai — withBolyraAuth()
 *
 * Wraps a Vercel AI SDK LanguageModelV1 using wrapLanguageModel() to inject
 * Bolyra ZKP authentication into tool calls. Supports direct mode (generates
 * proofs inline) and gateway mode (routes through a Bolyra gateway).
 *
 * Dev mode uses createDevIdentities() from @bolyra/sdk for local development
 * without circuit artifacts.
 */

import type { LanguageModelV1, LanguageModelV1CallOptions } from 'ai';
import { wrapLanguageModel } from 'ai';
import type { BolyraAIConfig } from './types';
import type { BolyraProofBundle } from '@bolyra/mcp';
import { encodeBundle, generateNonce, buildDevBundle as buildDevBundleUtil } from './utils';

/**
 * Wrap a language model with Bolyra ZKP authentication.
 *
 * In direct mode, generates a fresh proof bundle before each model call and
 * attaches it to the model's provider metadata. Tool call handlers downstream
 * can read the Bolyra auth context from the metadata.
 *
 * In gateway mode, attaches a gateway bearer token instead.
 *
 * @example
 * ```ts
 * import { withBolyraAuth } from '@bolyra/ai';
 * import { openai } from '@ai-sdk/openai';
 *
 * const model = withBolyraAuth(openai('gpt-4o'), {
 *   credential: agentCredential,
 *   operatorPrivateKey: '0x...',
 *   devMode: true,
 * });
 * ```
 */
export function withBolyraAuth(
  model: LanguageModelV1,
  config: BolyraAIConfig,
): LanguageModelV1 {
  // Validate config: either credential or gateway must be provided
  if (!config.credential && !config.gateway && !config.devMode) {
    throw new Error(
      '@bolyra/ai: withBolyraAuth requires either `credential`, `gateway`, or `devMode: true`.',
    );
  }

  return wrapLanguageModel({
    model,
    middleware: {
      middlewareVersion: 'v1',

      transformParams: async ({ type, params }) => {
        // Build proof bundle or gateway auth
        const authHeader = await buildAuthForConfig(config);

        // Attach auth to provider metadata so downstream tool handlers can access it
        const existingMetadata = params.providerMetadata ?? {};
        const bolyraMetadata = {
          ...(existingMetadata['bolyra'] as Record<string, unknown> ?? {}),
          authHeader,
          mode: config.gateway ? 'gateway' : 'direct',
          devMode: config.devMode ?? false,
        };

        return {
          ...params,
          providerMetadata: {
            ...existingMetadata,
            bolyra: bolyraMetadata,
          },
        } as LanguageModelV1CallOptions;
      },
    },
    modelId: `bolyra:${model.modelId}`,
    providerId: model.provider,
  });
}

/**
 * Build the Authorization header value for the given config.
 * In direct mode, generates a proof bundle. In gateway mode, uses API key.
 * In dev mode, generates a mock bundle.
 */
async function buildAuthForConfig(config: BolyraAIConfig): Promise<string> {
  // Gateway mode: simple bearer token
  if (config.gateway) {
    if (config.gateway.apiKey) {
      return `Bearer ${config.gateway.apiKey}`;
    }
    return `Bearer gateway-anonymous`;
  }

  // Dev mode: generate mock bundle
  if (config.devMode) {
    const bundle = await buildDevBundle(config);
    return `Bolyra ${encodeBundle(bundle)}`;
  }

  // Direct mode: generate real proof bundle
  return buildDirectAuth(config);
}

/**
 * Build a mock proof bundle for dev mode.
 */
async function buildDevBundle(config: BolyraAIConfig): Promise<BolyraProofBundle> {
  let credential = config.credential;

  // If no credential provided in dev mode, create dev identities
  if (!credential) {
    const sdk = await import('@bolyra/sdk');
    const devIds = await sdk.createDevIdentities();
    credential = devIds.agent;
  }

  const nonce = generateNonce();
  return buildDevBundleUtil(credential, nonce);
}

/**
 * Build real proof bundle for direct mode.
 */
async function buildDirectAuth(config: BolyraAIConfig): Promise<string> {
  if (!config.credential) {
    throw new Error('@bolyra/ai: credential is required in direct mode.');
  }
  if (!config.humanIdentity) {
    throw new Error(
      '@bolyra/ai: humanIdentity is required in direct mode for mutual handshake.',
    );
  }

  const { attachBolyraProof } = await import('@bolyra/mcp');
  const auth = await attachBolyraProof(
    config.humanIdentity,
    config.credential,
    { sdkConfig: config.sdkConfig },
  );

  return auth.headers.Authorization;
}
