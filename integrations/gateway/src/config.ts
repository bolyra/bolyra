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
import type { CredentialSource, GatewayConfig, StaticCredentialEntry, ToolPolicyEntry } from './types';
import { cumulativeMaskError, UINT64_MAX } from './credential-binding';

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

  // Credential binding validation
  if (config.credentials !== undefined) {
    validateCredentials(config.credentials, config.devMode === true, errors);
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

/**
 * True when the value is a non-negative decimal integer (number or decimal
 * string). Numbers must be SAFE integers — YAML/JSON silently rounds values
 * above 2^53-1, which would register a different grant than the one written.
 * Larger values must be decimal strings (exact through BigInt).
 */
function isDecimal(value: unknown): boolean {
  if (typeof value === 'number') return Number.isSafeInteger(value) && value >= 0;
  return typeof value === 'string' && /^\d+$/.test(value);
}

/**
 * Validate the credentials section. Static maps are checked entry-by-entry;
 * `type: registry` is rejected outright — a security-relevant config section
 * the gateway cannot enforce must fail loudly, never be silently ignored.
 */
function validateCredentials(
  credentials: CredentialSource,
  devMode: boolean,
  errors: string[],
): void {
  if (!credentials || typeof credentials !== 'object') {
    errors.push('"credentials" must be an object with type: static');
    return;
  }
  if (credentials.type === 'registry') {
    errors.push(
      '"credentials.type: registry" is not supported by the packaged gateway yet. ' +
      'Use type: static (commitment -> permission map), or embed the middleware ' +
      'with a custom resolveCredential (library API).',
    );
    return;
  }
  if (credentials.type !== 'static') {
    errors.push('"credentials.type" must be "static"');
    return;
  }
  const map = credentials.map;
  if (!map || typeof map !== 'object' || Array.isArray(map)) {
    errors.push('"credentials.map" must be an object mapping commitment -> credential entry');
    return;
  }
  const entries = Object.entries(map);
  if (entries.length === 0) {
    errors.push('"credentials.map" must register at least one credential (an empty map would silently disable binding — omit the section instead)');
    return;
  }
  for (const [commitment, entry] of entries) {
    const label = `"credentials.map[${commitment}]"`;
    // Canonical decimal only (no leading zeros): the runtime registry
    // normalizes keys through BigInt, so "1" and "001" would silently
    // collide after validation if both were accepted.
    if (!/^(0|[1-9]\d*)$/.test(commitment)) {
      errors.push(`${label}: map keys must be credential commitments as canonical decimal strings (no leading zeros)`);
      continue;
    }
    if (!entry || typeof entry !== 'object') {
      errors.push(`${label} must be an object with permissionBitmask`);
      continue;
    }
    const e = entry as StaticCredentialEntry;
    if (!isDecimal(e.permissionBitmask)) {
      errors.push(`${label}.permissionBitmask is required and must be a decimal integer (safe number, or decimal string for values above 2^53-1)`);
    } else {
      // Circuit semantics: AgentPolicy/Delegation masks are uint64 with a
      // cumulative-bit encoding. Registering a mask the circuits could never
      // accept would make production binding permanently unsatisfiable.
      const mask = BigInt(e.permissionBitmask);
      if (mask > UINT64_MAX) {
        errors.push(`${label}.permissionBitmask exceeds uint64 — circuit masks are 64-bit`);
      } else {
        const maskError = cumulativeMaskError(mask);
        if (maskError) {
          errors.push(`${label}.permissionBitmask violates cumulative-bit encoding: ${maskError}`);
        }
      }
    }
    if (e.expiryTimestamp !== undefined && !isDecimal(e.expiryTimestamp)) {
      errors.push(`${label}.expiryTimestamp must be a decimal unix timestamp in seconds (safe number, or decimal string for values above 2^53-1)`);
    } else if (e.expiryTimestamp !== undefined && BigInt(e.expiryTimestamp) > UINT64_MAX) {
      errors.push(`${label}.expiryTimestamp exceeds uint64 — circuit timestamps are 64-bit`);
    }
    if (!devMode && e.expiryTimestamp === undefined) {
      errors.push(`${label}.expiryTimestamp is required in production mode (it is an input to the Poseidon3 scopeCommitment binding)`);
    }
    if (e.commitment !== undefined && e.commitment !== commitment) {
      errors.push(`${label}.commitment ("${e.commitment}") does not match the map key — remove it or fix the mismatch`);
    }
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
  /** Path to a credentials file (--credentials); overrides config.credentials. */
  credentials?: string;
}

/**
 * Load a credentials file referenced by --credentials. Accepts either the
 * full config-section shape ({ type: static, map: {...} }) or a bare
 * commitment -> entry map. Unlike gateway.yaml, the file is NOT optional:
 * an explicit flag pointing at a missing file must fail, not fail open.
 */
export function loadCredentialsFile(filePath: string): CredentialSource {
  const raw = loadConfigFile(filePath);
  if (raw === null) {
    throw new ConfigValidationError([
      `credentials file not found: ${path.resolve(filePath)} (--credentials must point at an existing YAML/JSON file)`,
    ]);
  }
  const substituted = substituteEnvVars(raw);
  if (typeof substituted.type === 'string') {
    return substituted as unknown as CredentialSource;
  }
  return { type: 'static', map: substituted as Record<string, StaticCredentialEntry> };
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

  // --credentials <path> loads a credentials file and wins over the config
  // section (same CLI-over-config precedence as every other flag).
  if (flags.credentials !== undefined) {
    merged.credentials = loadCredentialsFile(flags.credentials);
  }

  // Validate
  validateConfig(merged);

  return merged;
}
