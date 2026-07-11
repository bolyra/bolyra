/**
 * Capability → permission-bit mapping (spec §12 `--capability-map` analog).
 *
 * Ported from `integrations/cli/src/verify/capabilities.ts`. The map source is
 * the `CAPABILITY_MAP` Worker var (JSON object) merged over the built-in
 * default, instead of a `--capability-map` file. Both failure modes fail
 * CLOSED: an unmapped capability → `unknown_capability`; a misconfigured map
 * → `internal_error`.
 */

import { Permission } from '@bolyra/sdk/dist/types.js';
import { VerifyDenial } from './verdict';

export type PermissionName = keyof typeof Permission;
export type CapabilityMap = Record<string, string[]>;

/** Built-in mapping (same vocabulary as the CLI reference verifier). */
export const DEFAULT_CAPABILITY_MAP: CapabilityMap = {
  send_message: ['WRITE_DATA'],
  fetch_inbox: ['READ_DATA'],
  read_message: ['READ_DATA'],
  broadcast: ['WRITE_DATA'],
  list_agents: ['READ_DATA'],
};

function isPermissionName(name: string): name is PermissionName {
  return (
    Object.prototype.hasOwnProperty.call(Permission, name) &&
    typeof Permission[name as PermissionName] === 'number'
  );
}

function validateMap(map: CapabilityMap): void {
  for (const names of Object.values(map)) {
    for (const name of names) {
      if (!isPermissionName(name)) {
        throw new VerifyDenial('internal_error', 'capability map has unknown permission name', {
          name,
        });
      }
    }
  }
}

/**
 * Build the effective capability map: the built-in default, with the optional
 * `CAPABILITY_MAP` env JSON merged on top.
 */
export function loadCapabilityMap(envJson: string | undefined): CapabilityMap {
  const merged: CapabilityMap = { ...DEFAULT_CAPABILITY_MAP };

  if (envJson !== undefined && envJson !== '') {
    let parsed: unknown;
    try {
      parsed = JSON.parse(envJson);
    } catch {
      throw new VerifyDenial('internal_error', 'CAPABILITY_MAP is not valid JSON');
    }
    if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
      throw new VerifyDenial('internal_error', 'CAPABILITY_MAP must be a JSON object');
    }
    for (const [capability, value] of Object.entries(parsed as Record<string, unknown>)) {
      if (!Array.isArray(value) || !value.every((v): v is string => typeof v === 'string')) {
        throw new VerifyDenial(
          'internal_error',
          'capability map entry must be an array of permission names',
          { capability },
        );
      }
      merged[capability] = value;
    }
  }

  validateMap(merged);
  return merged;
}

/** Union of permission bits required by `capabilities`; unmapped fails closed. */
export function requiredBits(map: CapabilityMap, capabilities: string[]): bigint {
  let bits = 0n;
  for (const capability of capabilities) {
    const names = map[capability];
    if (names === undefined) {
      throw new VerifyDenial('unknown_capability', 'capability has no scope mapping', {
        capability,
      });
    }
    for (const name of names) {
      bits |= 1n << BigInt(Permission[name as PermissionName]);
    }
  }
  return bits;
}
