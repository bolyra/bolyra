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
export { loadConfig, loadConfigFile, substituteEnvVars, validateConfig, mergeCliFlags, ConfigValidationError } from './config';
export type { CliFlags } from './config';

// Headers — X-Bolyra-* header injection and HMAC signing
export { injectBolyraHeaders, computeHmac, verifyHmac } from './headers';

// Receipts — pluggable receipt output
export { createReceiptWriter } from './receipts';

// Health — health check endpoint handler
export { createHealthHandler } from './health';

// Types — all gateway-specific types
export type {
  GatewayConfig,
  GatewayMiddlewareOptions,
  ToolPolicyEntry,
  ReceiptOutputConfig,
  CredentialSource,
  NonceConfig,
  HealthConfig,
  HmacConfig,
  ReceiptWriter,
  GatewayRequest,
  GatewayHandler,
  JsonRpcRequest,
  JsonRpcError,
} from './types';
