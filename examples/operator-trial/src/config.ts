/**
 * The trial config contract (spec §3.5). Every violation throws
 * TrialConfigError naming the key. ${NAME} substitution is literal
 * replacement from the environment, applies to header values only, and
 * fails on an unset variable. This is deliberately stricter than
 * @bolyra/gateway's substituteEnvVars, which leaves unset references in place.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { parse as parseYaml } from 'yaml';
import { PERMISSION_NAMES } from './agents';
import type { PermissionName } from './agents';

export class TrialConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'TrialConfigError';
  }
}

export const METHODS = ['GET', 'HEAD', 'POST', 'PUT', 'PATCH', 'DELETE'] as const;
export type Method = (typeof METHODS)[number];

const BODYLESS: ReadonlySet<string> = new Set(['GET', 'HEAD', 'DELETE']);
const ACTION_RE = /^[a-z][a-z0-9_-]{0,63}$/;
const HEADER_NAME_RE = /^[!#$%&'*+.^_`|~0-9A-Za-z-]+$/;
const ALLOWED_KEYS: ReadonlySet<string> = new Set([
  'action',
  'method',
  'url',
  'headers',
  'bodyFile',
  'requiredPermission',
]);

export interface TrialConfig {
  action: string;
  method: Method;
  url: URL;
  /** Header values after ${ENV} substitution. Never log these. */
  headers: Record<string, string>;
  /** Literal request body, sent byte for byte. */
  body?: Buffer;
  requiredPermission: PermissionName;
  /**
   * Needles the secret scan must never find in the bundle: every substituted
   * environment value, and every header value that contained a substitution
   * (deduplicated, empty strings dropped). Static header values are not
   * needles; a short one would false-positive against the bundle itself.
   */
  secrets: string[];
}

export function loadTrialConfig(filePath: string, env: NodeJS.ProcessEnv = process.env): TrialConfig {
  const resolved = path.resolve(filePath);
  if (!fs.existsSync(resolved)) {
    throw new TrialConfigError(`config file not found: ${resolved}`);
  }
  let raw: string;
  try {
    raw = fs.readFileSync(resolved, 'utf8');
  } catch (err) {
    throw new TrialConfigError(`config file could not be read: ${(err as NodeJS.ErrnoException).code ?? 'error'}`);
  }
  let parsed: unknown;
  try {
    parsed = resolved.toLowerCase().endsWith('.json') ? JSON.parse(raw) : parseYaml(raw);
  } catch {
    // Parser messages can quote the source, which may contain a secret. Say
    // only that parsing failed.
    throw new TrialConfigError('config file could not be parsed (invalid YAML/JSON); check quoting and indentation');
  }
  return validateTrialConfig(parsed, path.dirname(resolved), env);
}

export function validateTrialConfig(
  input: unknown,
  baseDir: string,
  env: NodeJS.ProcessEnv,
): TrialConfig {
  if (typeof input !== 'object' || input === null || Array.isArray(input)) {
    throw new TrialConfigError('config must be a map of keys');
  }
  const obj = input as Record<string, unknown>;
  for (const key of Object.keys(obj)) {
    if (!ALLOWED_KEYS.has(key)) throw new TrialConfigError(`unknown key: ${key}`);
  }

  const action = obj.action;
  if (typeof action !== 'string' || !ACTION_RE.test(action)) {
    throw new TrialConfigError('action: required; must match ^[a-z][a-z0-9_-]{0,63}$');
  }

  const method = obj.method;
  if (typeof method !== 'string' || !(METHODS as readonly string[]).includes(method)) {
    throw new TrialConfigError(`method: required; one of ${METHODS.join(' ')}`);
  }

  if (typeof obj.url !== 'string') throw new TrialConfigError('url: required string');
  let url: URL;
  try {
    url = new URL(obj.url);
  } catch {
    throw new TrialConfigError('url: not a valid URL');
  }
  if (url.protocol !== 'http:' && url.protocol !== 'https:') {
    throw new TrialConfigError('url: scheme must be http or https');
  }
  if (url.username !== '' || url.password !== '') {
    throw new TrialConfigError('url: credentials in the URL are not allowed');
  }

  const needles: string[] = [];
  const headers: Record<string, string> = {};
  if (obj.headers !== undefined) {
    if (typeof obj.headers !== 'object' || obj.headers === null || Array.isArray(obj.headers)) {
      throw new TrialConfigError('headers: must be a map of header name to value');
    }
    for (const [name, value] of Object.entries(obj.headers as Record<string, unknown>)) {
      if (!HEADER_NAME_RE.test(name)) throw new TrialConfigError(`headers.${name}: invalid header name`);
      if (typeof value !== 'string') throw new TrialConfigError(`headers.${name}: value must be a string`);
      const before = needles.length;
      headers[name] = substituteEnv(value, env, `headers.${name}`, needles);
      if (needles.length > before) needles.push(headers[name]); // the whole resolved value is a needle too
    }
  }

  let body: Buffer | undefined;
  if (obj.bodyFile !== undefined) {
    if (typeof obj.bodyFile !== 'string') throw new TrialConfigError('bodyFile: must be a string path');
    if (BODYLESS.has(method)) throw new TrialConfigError(`bodyFile: not allowed with method ${method}`);
    const bodyPath = path.resolve(baseDir, obj.bodyFile);
    if (!fs.existsSync(bodyPath)) throw new TrialConfigError(`bodyFile: not found: ${bodyPath}`);
    try {
      body = fs.readFileSync(bodyPath);
    } catch (err) {
      throw new TrialConfigError(`bodyFile: could not be read: ${(err as NodeJS.ErrnoException).code ?? 'error'}`);
    }
  }

  const rp = obj.requiredPermission;
  if (typeof rp !== 'string' || !(PERMISSION_NAMES as readonly string[]).includes(rp)) {
    throw new TrialConfigError(`requiredPermission: required; one of ${PERMISSION_NAMES.join(' ')}`);
  }

  const secrets = dedupe(needles).filter((s) => s.length > 0);

  return {
    action,
    method: method as Method,
    url,
    headers,
    body,
    requiredPermission: rp as PermissionName,
    secrets,
  };
}

/** Literal ${NAME} replacement. Throws on an unset variable. */
export function substituteEnv(
  value: string,
  env: NodeJS.ProcessEnv,
  where: string,
  collected: string[],
): string {
  return value.replace(/\$\{([^}]+)\}/g, (_match, name: string) => {
    const v = env[name];
    if (v === undefined) {
      throw new TrialConfigError(`${where}: environment variable ${name} is not set`);
    }
    collected.push(v);
    return v;
  });
}

function dedupe(values: string[]): string[] {
  return Array.from(new Set(values));
}
