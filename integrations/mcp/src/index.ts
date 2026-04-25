// @bolyra/mcp — ZKP authentication middleware for Model Context Protocol servers.
//
// Two transports, two right answers (per MCP spec 2025-03-26):
//   - HTTP/SSE/Streamable-HTTP → bolyraAuthMiddleware (spec-aligned, Authorization header)
//   - stdio → withBolyraAuthStdio (proof bundle in _meta, since stdio has no spec'd auth)
//
// Both produce a BolyraAuthContext on the request that downstream handlers can read.

export { withBolyraAuthStdio } from './server-stdio';
export { bolyraAuthMiddleware } from './server-http';
export { attachBolyraProof } from './client';
export { verifyBundle, checkToolPolicy } from './verify';

export type {
  BolyraProofBundle,
  BolyraAuthContext,
  BolyraMcpConfig,
  BolyraMcpHttpConfig,
  BolyraClientAuth,
  ToolPermissionPolicy,
} from './types';
