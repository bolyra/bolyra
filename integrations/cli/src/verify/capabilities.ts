/**
 * Capability → Bolyra permission-bit mapping for the `bolyra verify` external
 * verifier (spec §6).
 *
 * A calling host describes what a request wants to do with its own *capability*
 * vocabulary (e.g. the `mcp_agent_mail` tool names). The verifier must translate
 * those host capabilities into Bolyra's canonical 8-bit cumulative `Permission`
 * space so it can be compared against the permissions the credential actually
 * carries.
 *
 * Two failure modes both fail CLOSED (deny rather than allow):
 *   - a capability with no mapping  → `unknown_capability`
 *   - a config file naming a permission that isn't a real `Permission` member
 *     → `internal_error` (a misconfiguration, not a request-level fault)
 */

import { readFileSync } from 'fs';
import { Permission } from '@bolyra/sdk';
import { VerifyDenial } from './verdict';

/** A permission name is any key of the `Permission` enum (string members). */
export type PermissionName = keyof typeof Permission;

/** A capability map: host capability token → list of Bolyra permission names. */
export type CapabilityMap = Record<string, string[]>;

/**
 * Built-in mapping for the `mcp_agent_mail` capability vocabulary.
 *
 * Values are permission NAMES (not bits) so the map is human-auditable and
 * round-trips cleanly through the `--capability-map` JSON file format.
 */
export const DEFAULT_CAPABILITY_MAP: CapabilityMap = {
  send_message: ['WRITE_DATA'],
  fetch_inbox: ['READ_DATA'],
  read_message: ['READ_DATA'],
  broadcast: ['WRITE_DATA'],
  list_agents: ['READ_DATA'],
};

/** True when `name` is a valid `Permission` enum member name. */
function isPermissionName(name: string): name is PermissionName {
  // TS numeric enums are bidirectional maps; guard against the reverse
  // (numeric-key) entries so only the string member names are accepted.
  return (
    Object.prototype.hasOwnProperty.call(Permission, name) &&
    typeof Permission[name as PermissionName] === 'number'
  );
}

/**
 * Validate that every value in `map` is an array of valid `Permission` names.
 * A bad name is a configuration error and fails closed with `internal_error`.
 */
function validateMap(map: CapabilityMap): void {
  for (const names of Object.values(map)) {
    for (const name of names) {
      if (!isPermissionName(name)) {
        throw new VerifyDenial(
          'internal_error',
          'capability map has unknown permission name',
          { name }
        );
      }
    }
  }
}

/**
 * Build the effective capability map: start from the built-in default and, when
 * a `--capability-map` file is supplied, merge its entries on top (file entries
 * override or extend defaults). Every value is validated; an unknown permission
 * name fails closed with `internal_error`.
 */
export function loadCapabilityMap(opts: { file?: string }): CapabilityMap {
  const merged: CapabilityMap = { ...DEFAULT_CAPABILITY_MAP };

  if (opts.file !== undefined) {
    const raw = readFileSync(opts.file, 'utf8');
    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch {
      throw new VerifyDenial(
        'internal_error',
        'capability map file is not valid JSON',
        { file: opts.file }
      );
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new VerifyDenial(
        'internal_error',
        'capability map file must be a JSON object',
        { file: opts.file }
      );
    }
    for (const [capability, value] of Object.entries(
      parsed as Record<string, unknown>
    )) {
      if (
        !Array.isArray(value) ||
        !value.every((v): v is string => typeof v === 'string')
      ) {
        throw new VerifyDenial(
          'internal_error',
          'capability map entry must be an array of permission names',
          { capability }
        );
      }
      merged[capability] = value;
    }
  }

  validateMap(merged);
  return merged;
}

/**
 * Compute the union of permission bits required by `capabilities` under `map`.
 *
 * A capability absent from `map` fails closed with `unknown_capability`. Each
 * permission name is converted to its bit via `1n << BigInt(Permission[name])`.
 */
export function requiredBits(map: CapabilityMap, capabilities: string[]): bigint {
  let bits = 0n;
  for (const capability of capabilities) {
    const names = map[capability];
    if (names === undefined) {
      throw new VerifyDenial(
        'unknown_capability',
        'capability has no scope mapping',
        { capability }
      );
    }
    for (const name of names) {
      // `map` is validated on load, so `name` is a known Permission name here.
      bits |= 1n << BigInt(Permission[name as PermissionName]);
    }
  }
  return bits;
}
