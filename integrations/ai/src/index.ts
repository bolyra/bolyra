// @bolyra/ai — Bolyra ZKP authentication adapter for Vercel AI SDK.
//
// Three integration surfaces:
//   - withBolyraAuth() — wraps a language model to inject auth into tool calls
//   - bolyraAuthMiddleware() — server-side verification for incoming requests
//   - createBolyraTools() — Vercel AI SDK tool definitions for auth operations

export { withBolyraAuth } from './middleware';
export { bolyraAuthMiddleware } from './server-middleware';
export { createBolyraTools } from './tools';
export {
  encodeBundle,
  decodeBundleFromHeader,
  buildAuthHeader,
  generateNonce,
  buildBolyraHeaders,
} from './utils';

export type {
  BolyraAIConfig,
  BolyraAuthMode,
  BolyraGatewayConfig,
  BolyraServerConfig,
  BolyraToolPolicy,
  BolyraToolsConfig,
  BolyraVerifier,
  BolyraVerifyResult,
  // Re-exports from SDK/MCP
  HumanIdentity,
  AgentCredential,
  BolyraConfig,
  BolyraAuthContext,
  BolyraProofBundle,
  NonceStore,
} from './types';

export { Permission } from './types';
