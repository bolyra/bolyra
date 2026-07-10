/**
 * @bolyra/gateway — config loader.
 *
 * Loads gateway configuration from YAML or JSON files with environment
 * variable substitution (${VAR_NAME} syntax). CLI flags override config
 * file values.
 */

import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';
import type { GatewayConfig, ToolPolicyEntry } from './types';

/** Defaults applied when values are missing from config + CLI. */
const DEFAULTS: GatewayConfig = {
  target: '',
  port: 4100,
  network: 'base-sepolia',
  devMode: false,
  nonce: { store: 'memory', maxProofAge: 300 },
  receipts: { enabled: true, output: 'file', dir: './receipts/' },
  health: { enabled: true, path: '/healthz' },
};

/**
 * Recursively substitute ${VAR_NAME} references in string values with
 * the corresponding environment variable. Unset variables remain as-is
 * (the literal `${VAR_NAME}` string is preserved so the user sees what
 * went wrong).
 */
export function substituteEnvVars<T>(obj: T): T {
  if (typeof obj === 'string') {
    return obj.replace(/\$\{([^}]+)\}/g, (_match, varName: string) => {
      return process.env[varName] ?? `\${${varName}}`;
    }) as unknown as T;
  }
  if (Array.isArray(obj)) {
    return obj.map((item) => substituteEnvVars(item)) as unknown as T;
  }
  if (obj !== null && typeof obj === 'object') {
    const result: Record<string, unknown> = {};
    for (const [key, value] of Object.entries(obj as Record<string, unknown>)) {
      result[key] = substituteEnvVars(value);
    }
    return result as T;
  }
  return obj;
}

/**
 * Load and parse a config file. Supports YAML (.yaml, .yml) and JSON (.json).
 * Returns null if the file does not exist (optional config).
 */
export function loadConfigFile(filePath: string): Record<string, unknown> | null {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    return null;
  }

  const raw = fs.readFileSync(resolved, 'utf-8');
  const ext = path.extname(resolved).toLowerCase();

  if (ext === '.json') {
    return JSON.parse(raw) as Record<string, unknown>;
  }
  // Default to YAML for .yaml, .yml, or unknown extensions
  return parseYaml(raw) as Record<string, unknown>;
}

/** Validation errors are descriptive strings. */
export class ConfigValidationError extends Error {
  constructor(public readonly errors: string[]) {
    super(`Gateway config validation failed:\n  - ${errors.join('\n  - ')}`);
    this.name = 'ConfigValidationError';
  }
}

/**
 * Validate a config object. Throws ConfigValidationError if required fields
 * are missing or invalid.
 */
export function validateConfig(config: Partial<GatewayConfig>): asserts config is GatewayConfig {
  const errors: string[] = [];

  if (!config.target || typeof config.target !== 'string') {
    errors.push('"target" is required and must be a non-empty string (upstream MCP server URL)');
  }

  if (config.port !== undefined) {
    if (typeof config.port !== 'number' || config.port < 1 || config.port > 65535) {
      errors.push('"port" must be a number between 1 and 65535');
    }
  }

  if (config.network !== undefined && typeof config.network !== 'string') {
    errors.push('"network" must be a string');
  }

  if (config.receipts?.output !== undefined) {
    const validOutputs = ['file', 'stdout', 'webhook'];
    if (!validOutputs.includes(config.receipts.output)) {
      errors.push(`"receipts.output" must be one of: ${validOutputs.join(', ')}`);
    }
    if (config.receipts.output === 'webhook' && !config.receipts.webhook?.url) {
      errors.push('"receipts.webhook.url" is required when output is "webhook"');
    }
  }

  if (config.receipts?.privateKey !== undefined) {
    if (typeof config.receipts.privateKey !== 'string' || config.receipts.privateKey.length === 0) {
      errors.push('"receipts.privateKey" must be a non-empty string');
    } else if (config.receipts.privateKey.includes('${')) {
      errors.push('"receipts.privateKey" contains unresolved environment variable reference');
    } else if (!/^(0x)?[0-9a-fA-F]{64}$/.test(config.receipts.privateKey)) {
      errors.push('"receipts.privateKey" must be a 32-byte secp256k1 key: 64 hex characters, optional 0x prefix');
    }
  }

  if (config.nonce?.maxProofAge !== undefined) {
    if (typeof config.nonce.maxProofAge !== 'number' || config.nonce.maxProofAge < 30 || config.nonce.maxProofAge > 86400) {
      errors.push('"nonce.maxProofAge" must be between 30 and 86400 seconds');
    }
  }

  if (config.nonce?.store !== undefined) {
    const validStores = ['memory', 'redis'];
    if (!validStores.includes(config.nonce.store)) {
      errors.push(`"nonce.store" must be one of: ${validStores.join(', ')}`);
    }
    if (config.nonce.store === 'redis') {
      if (!config.nonce.redis?.url) {
        errors.push('"nonce.redis.url" is required when nonce.store is "redis"');
      } else if (config.nonce.redis.url.includes('${')) {
        errors.push('"nonce.redis.url" contains unresolved environment variable reference');
      } else if (!config.nonce.redis.url.startsWith('redis://') && !config.nonce.redis.url.startsWith('rediss://')) {
        errors.push('"nonce.redis.url" must use redis:// or rediss:// scheme');
      }
    }
  }

  // HMAC secret validation
  if (config.hmac) {
    if (!config.hmac.secret || typeof config.hmac.secret !== 'string') {
      errors.push('"hmac.secret" is required and must be a non-empty string');
    } else {
      if (config.hmac.secret.includes('${')) {
        errors.push('"hmac.secret" contains unresolved environment variable reference');
      }
      if (config.hmac.secret.replace(/[^0-9a-fA-F]/g, '').length < 32) {
        errors.push('"hmac.secret" must be at least 32 hex characters (16 bytes of entropy)');
      }
    }
  }

  if (errors.length > 0) {
    throw new ConfigValidationError(errors);
  }
}

/** CLI flags that map to config fields. */
export interface CliFlags {
  target?: string;
  port?: number;
  config?: string;
  dev?: boolean;
  receiptDir?: string;
  receiptStdout?: boolean;
  noReceipts?: boolean;
  network?: string;
}

/**
 * Merge CLI flags over a config object. CLI wins for any field it sets.
 */
export function mergeCliFlags(config: Partial<GatewayConfig>, flags: CliFlags): Partial<GatewayConfig> {
  const merged = { ...config };

  if (flags.target !== undefined) merged.target = flags.target;
  if (flags.port !== undefined) merged.port = flags.port;
  if (flags.network !== undefined) merged.network = flags.network;
  if (flags.dev !== undefined) merged.devMode = flags.dev;

  if (flags.noReceipts) {
    merged.receipts = { ...DEFAULTS.receipts, ...merged.receipts, enabled: false };
  } else if (flags.receiptStdout) {
    merged.receipts = { ...DEFAULTS.receipts, ...merged.receipts, output: 'stdout', enabled: true };
  } else if (flags.receiptDir !== undefined) {
    merged.receipts = { ...DEFAULTS.receipts, ...merged.receipts, output: 'file', dir: flags.receiptDir, enabled: true };
  }

  return merged;
}

/**
 * Convert raw config tools (number bitmasks) to the gateway ToolPolicyEntry format.
 */
function normalizeTools(raw: Record<string, unknown> | undefined): Record<string, ToolPolicyEntry> | undefined {
  if (!raw) return undefined;
  const result: Record<string, ToolPolicyEntry> = {};
  for (const [name, policy] of Object.entries(raw)) {
    if (typeof policy === 'number') {
      result[name] = { requireBitmask: policy };
    } else if (policy && typeof policy === 'object') {
      result[name] = policy as ToolPolicyEntry;
    }
  }
  return result;
}

/**
 * Load the full gateway config. Reads config file (if present), substitutes
 * env vars, merges CLI flags, applies defaults, and validates.
 */
export function loadConfig(flags: CliFlags = {}): GatewayConfig {
  const configPath = flags.config ?? './gateway.yaml';

  // Load config file (optional — may not exist)
  const fileConfig = loadConfigFile(configPath);
  const substituted = fileConfig ? substituteEnvVars(fileConfig) : {};

  // Apply defaults
  const base: Partial<GatewayConfig> = {
    ...DEFAULTS,
    ...substituted,
    nonce: { ...DEFAULTS.nonce, ...(substituted.nonce as Record<string, unknown> | undefined) } as GatewayConfig['nonce'],
    receipts: { ...DEFAULTS.receipts, ...(substituted.receipts as Record<string, unknown> | undefined) } as GatewayConfig['receipts'],
    health: { ...DEFAULTS.health, ...(substituted.health as Record<string, unknown> | undefined) } as GatewayConfig['health'],
    tools: normalizeTools(substituted.tools as Record<string, unknown> | undefined),
  };

  // Merge CLI flags (CLI wins)
  const merged = mergeCliFlags(base, flags);

  // Validate
  validateConfig(merged);

  return merged;
}
