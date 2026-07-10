// @bolyra/gateway — Bolyra MCP Auth Gateway.
//
// Standalone reverse proxy that verifies Bolyra ZKP proof bundles on
// MCP tools/call requests before forwarding to upstream servers.
//
// Two usage modes:
//   1. CLI: `npx @bolyra/gateway --target http://localhost:3000/mcp`
//   2. Library: import and embed middleware in your own server.

// Middleware — verify Bolyra auth and produce 401/403
export { createGatewayMiddleware, extractToolName } from './middleware';

// Proxy — full reverse proxy server
export { createGatewayProxy } from './proxy';
export type { GatewayProxyOptions } from './proxy';

// Config — load and validate gateway configuration
export { loadConfig, loadConfigFile, loadCredentialsFile, substituteEnvVars, validateConfig, mergeCliFlags, ConfigValidationError } from './config';
export type { CliFlags } from './config';

// Headers — X-Bolyra-* header injection and HMAC signing
export { injectBolyraHeaders, computeHmac, verifyHmac } from './headers';

// Redis nonce store — opt-in for multi-instance deployments
export { RedisNonceStore } from './redis-nonce-store';
export type { RedisNonceStoreOptions } from './redis-nonce-store';

// Receipts — pluggable receipt output
export { createReceiptWriter } from './receipts';

// Receipt signing — ES256K-signed receipt for every allow/deny decision
export {
  createGatewayReceiptSigner,
  buildDecisionReceiptInput,
  buildAuthFailReceiptInput,
  buildAnonymousDenyReceiptInput,
  buildDenialReceiptInput,
  isReceiptableBundle,
} from './receipt-signer';
export type { GatewayReceiptSigner } from './receipt-signer';

// Credential binding — enforce registered credentials in --dev (v0.4.0+),
// static resolveCredential for production
export {
  hasStaticCredentials,
  buildCredentialRegistry,
  checkCredentialBinding,
  createStaticCredentialResolver,
} from './credential-binding';
export type { RegisteredCredential, CredentialBindingResult } from './credential-binding';

// Health — health check endpoint handler
export { createHealthHandler } from './health';

// Types — all gateway-specific types
export type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  ToolPolicyEntry,
  ReceiptOutputConfig,
  CredentialSource,
  StaticCredentialEntry,
  NonceConfig,
  RedisNonceConfig,
  HealthConfig,
  HmacConfig,
  ReceiptWriter,
  GatewayDenial,
  GatewayRequest,
  GatewayHandler,
  JsonRpcRequest,
  JsonRpcError,
} from './types';
