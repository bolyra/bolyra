/**
 * @bolyra/gateway — types.
 *
 * Gateway-specific configuration and interface types. Reuses
 * BolyraAuthContext, BolyraProofBundle, etc. from @bolyra/mcp.
 */

import type { ToolPolicyMap, NonceStore, BolyraAuthContext } from '@bolyra/mcp';
import type { ReceiptSignerConfig, SignedReceipt } from '@bolyra/receipts';
import type { IncomingMessage, ServerResponse } from 'http';

/** Credential resolution strategy. */
export type CredentialSource =
  | { type: 'registry'; registryAddress: string; rpcUrl: string }
  | { type: 'static'; map: Record<string, { permissionBitmask: string; expiryTimestamp: string; commitment: string }> };

/** Receipt output configuration. */
export interface ReceiptOutputConfig {
  enabled: boolean;
  /** Receipt signing identity. */
  issuer?: string;
  keyId?: string;
  privateKey?: string;
  /** Output mode: file, stdout, or webhook. */
  output: 'file' | 'stdout' | 'webhook';
  /** Directory for file output. */
  dir?: string;
  /** Webhook configuration. */
  webhook?: {
    url: string;
    headers?: Record<string, string>;
  };
}

/** Nonce store configuration. */
export interface NonceConfig {
  store: 'memory';
  maxProofAge?: number;
}

/** Health check configuration. */
export interface HealthConfig {
  enabled: boolean;
  path: string;
}

/** Per-tool policy entry (config file format — bitmasks as numbers, not bigints). */
export interface ToolPolicyEntry {
  requireBitmask?: number;
  minScore?: number;
  maxChainDepth?: number;
}

/** HMAC signing configuration for X-Bolyra-* headers. */
export interface HmacConfig {
  /** Shared secret (hex string). */
  secret: string;
}

/** Full gateway configuration. */
export interface GatewayConfig {
  /** Upstream MCP server URL. */
  target: string;
  /** Gateway listen port. */
  port: number;
  /** Bolyra network identifier. */
  network: string;
  /** Enable dev mode (mock verification, no real ZKP). */
  devMode: boolean;
  /** Credential resolution config. */
  credentials?: CredentialSource;
  /** Per-tool permission policies. */
  tools?: Record<string, ToolPolicyEntry>;
  /** Nonce replay protection config. */
  nonce: NonceConfig;
  /** Receipt output config. */
  receipts: ReceiptOutputConfig;
  /** Health check config. */
  health: HealthConfig;
  /** Optional HMAC config for X-Bolyra-* header signing. */
  hmac?: HmacConfig;
  /** Minimum verification score. */
  minScore?: number;
}

/** Options for creating gateway middleware (library usage). */
export interface GatewayMiddlewareOptions {
  config: GatewayConfig;
  /** Custom credential resolver (overrides config.credentials). */
  resolveCredential?: (commitment: string) => Promise<import('@bolyra/sdk').AgentCredential | null>;
  /** Custom nonce store (overrides config.nonce). */
  nonceStore?: NonceStore;
  /** Custom receipt signer config (overrides config.receipts). */
  receiptSigner?: ReceiptSignerConfig;
}

/** Receipt writer interface. */
export interface ReceiptWriter {
  /** Write a receipt. Non-blocking — returns immediately. */
  write(receipt: SignedReceipt): void;
  /** Write a raw receipt object (for denied requests without signing). */
  writeRaw(data: Record<string, unknown>): void;
}

/** Request with attached Bolyra auth context. */
export interface GatewayRequest extends IncomingMessage {
  bolyra?: BolyraAuthContext;
  /** Parsed JSON-RPC body (set by body parser). */
  jsonRpcBody?: JsonRpcRequest;
  /** Raw body buffer. */
  rawBody?: Buffer;
}

/** Minimal JSON-RPC request shape. */
export interface JsonRpcRequest {
  jsonrpc: string;
  id?: string | number | null;
  method: string;
  params?: Record<string, unknown>;
}

/** JSON-RPC error response shape. */
export interface JsonRpcError {
  jsonrpc: '2.0';
  id: string | number | null;
  error: {
    code: number;
    message: string;
    data?: unknown;
  };
}

/** Gateway request handler type. */
export type GatewayHandler = (req: GatewayRequest, res: ServerResponse) => void | Promise<void>;
