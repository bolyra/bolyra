/**
 * @bolyra/ai — createBolyraTools()
 *
 * Creates Vercel AI SDK tool() definitions for common Bolyra auth operations.
 * These tools can be added to any generateText() or streamText() call so the
 * LLM can programmatically authenticate, delegate, or check permissions.
 */

import { tool } from 'ai';
import { z } from 'zod';
import type { BolyraToolsConfig } from './types';
import { encodeBundle, generateNonce, buildDevBundle } from './utils';

/**
 * Create Vercel AI SDK tools for Bolyra auth operations.
 *
 * @example
 * ```ts
 * import { createBolyraTools } from '@bolyra/ai';
 *
 * const bolyraTools = createBolyraTools({
 *   credential: agentCredential,
 *   devMode: true,
 * });
 *
 * const result = await generateText({
 *   model: openai('gpt-4o'),
 *   tools: { ...bolyraTools, ...myAppTools },
 *   prompt: 'Authenticate and then read the file',
 * });
 * ```
 */
export function createBolyraTools(config: BolyraToolsConfig) {
  const { credential, devMode = false } = config;

  // H1: Dev guard — if not devMode, require real credentials
  if (!devMode && (!config.humanIdentity || !credential)) {
    throw new Error(
      '@bolyra/ai: createBolyraTools requires either `devMode: true` or both `credential` and `humanIdentity` for production use.',
    );
  }

  // C2: Internal bundle store — never expose raw bundles to LLM tool output
  let _lastBundle: import('@bolyra/mcp').BolyraProofBundle | null = null;
  let _lastAuthHeader: string | null = null;

  /** Retrieve the last proof bundle for programmatic use. */
  const getLastBundle = () => _lastBundle;
  /** Retrieve the last Authorization header for programmatic use. */
  const getLastAuthHeader = () => _lastAuthHeader;

  const tools = {
    /**
     * Generate a proof bundle for the current agent credential.
     */
    bolyra_authenticate: tool({
      description:
        'Authenticate the current AI agent using Bolyra ZKP credentials. ' +
        'Returns a confirmation with DID and permissions. ' +
        'Use this before making tool calls that require authentication.',
      parameters: z.object({
        nonce: z
          .string()
          .optional()
          .describe('Optional session nonce. If not provided, a fresh one is generated.'),
      }),
      execute: async ({ nonce: nonceStr }) => {
        const nonce = nonceStr ? BigInt(nonceStr) : generateNonce();
        const network = config.network ?? 'base-sepolia';

        if (devMode) {
          const bundle = buildDevBundle(credential, nonce);
          _lastBundle = bundle;
          _lastAuthHeader = `Bolyra ${encodeBundle(bundle)}`;
          const did = `did:bolyra:dev:${credential.commitment.toString(16).padStart(64, '0')}`;
          const permBits = credential.permissionBitmask.toString(2).padStart(8, '0');
          const expiryDate = new Date(Number(credential.expiryTimestamp) * 1000).toISOString();
          return {
            authenticated: true,
            mode: 'dev',
            did,
            permissions: permBits,
            expiresAt: expiryDate,
          };
        }

        // Production mode: generate real proof
        if (!config.humanIdentity) {
          return {
            authenticated: false,
            reason: 'Authentication failed: missing identity configuration.',
          };
        }

        try {
          const { attachBolyraProof } = await import('@bolyra/mcp');
          const auth = await attachBolyraProof(
            config.humanIdentity,
            credential,
            { devMode: false },
          );
          _lastBundle = auth.bundle;
          _lastAuthHeader = auth.headers.Authorization;
          const did = `did:bolyra:${network}:${credential.commitment.toString(16).padStart(64, '0')}`;
          const permBits = credential.permissionBitmask.toString(2).padStart(8, '0');
          const expiryDate = new Date(Number(credential.expiryTimestamp) * 1000).toISOString();
          return {
            authenticated: true,
            mode: 'production',
            did,
            permissions: permBits,
            expiresAt: expiryDate,
          };
        } catch {
          return {
            authenticated: false,
            reason: 'Authentication failed.',
          };
        }
      },
    }),

    /**
     * Create a delegated credential with narrowed permissions.
     */
    bolyra_delegate: tool({
      description:
        'Create a scoped delegation from the current credential. ' +
        'The delegated credential will have narrowed permissions (can only remove, never add). ' +
        'Specify the permission bitmask as a number and TTL in seconds.',
      parameters: z.object({
        permissions: z
          .number()
          .describe(
            'Permission bitmask for the delegated credential. Must be a subset of current permissions.',
          ),
        ttlSeconds: z
          .number()
          .describe('Time-to-live in seconds for the delegated credential.'),
      }),
      execute: async ({ permissions, ttlSeconds }) => {
        const requestedBitmask = BigInt(permissions);
        const currentBitmask = credential.permissionBitmask;

        // Scope narrowing check: delegated permissions must be a subset
        if ((requestedBitmask & currentBitmask) !== requestedBitmask) {
          return {
            status: 'error',
            reason: `Cannot escalate permissions. Requested ${requestedBitmask.toString(2)}b but current credential has ${currentBitmask.toString(2)}b.`,
          };
        }

        const expiry = BigInt(Math.floor(Date.now() / 1000) + ttlSeconds);

        if (devMode) {
          return {
            status: 'delegated',
            mode: 'dev',
            permissions: requestedBitmask.toString(2),
            expiry: expiry.toString(),
            parentDid: `did:bolyra:dev:${credential.commitment.toString(16).padStart(64, '0')}`,
          };
        }

        // Production delegation would require operator key and full SDK call
        if (!config.operatorPrivateKey) {
          return {
            status: 'error',
            reason: 'operatorPrivateKey is required for production delegation.',
          };
        }

        return {
          status: 'delegated',
          mode: 'production',
          permissions: requestedBitmask.toString(2),
          expiry: expiry.toString(),
          note: 'Full delegation proof generation requires circuit artifacts.',
        };
      },
    }),

    /**
     * Check if the current credential has a given permission.
     */
    bolyra_check_permissions: tool({
      description:
        'Check if the current agent credential has a specific permission. ' +
        'Permission names: READ_DATA, WRITE_DATA, FINANCIAL_SMALL, FINANCIAL_MEDIUM, ' +
        'FINANCIAL_UNLIMITED, SIGN_ON_BEHALF, SUB_DELEGATE, ACCESS_PII.',
      parameters: z.object({
        permission: z
          .string()
          .describe('Permission name to check (e.g., "READ_DATA", "FINANCIAL_SMALL").'),
      }),
      execute: async ({ permission }) => {
        const permissionMap: Record<string, number> = {
          READ_DATA: 0,
          WRITE_DATA: 1,
          FINANCIAL_SMALL: 2,
          FINANCIAL_MEDIUM: 3,
          FINANCIAL_UNLIMITED: 4,
          SIGN_ON_BEHALF: 5,
          SUB_DELEGATE: 6,
          ACCESS_PII: 7,
        };

        const bit = permissionMap[permission.toUpperCase()];
        if (bit === undefined) {
          return {
            status: 'error',
            reason: `Unknown permission: "${permission}". Valid values: ${Object.keys(permissionMap).join(', ')}.`,
          };
        }

        const hasPerm = (credential.permissionBitmask >> BigInt(bit) & 1n) === 1n;
        return {
          permission: permission.toUpperCase(),
          granted: hasPerm,
          currentBitmask: credential.permissionBitmask.toString(2).padStart(8, '0'),
        };
      },
    }),

    /**
     * Return metadata about the current credential.
     */
    bolyra_credential_info: tool({
      description:
        'Return metadata about the current Bolyra agent credential, including ' +
        'DID, permission bitmask, expiry timestamp, and available permissions.',
      parameters: z.object({}),
      execute: async () => {
        const bitmask = credential.permissionBitmask;
        const permissionNames: string[] = [];
        const allPerms = [
          'READ_DATA', 'WRITE_DATA', 'FINANCIAL_SMALL', 'FINANCIAL_MEDIUM',
          'FINANCIAL_UNLIMITED', 'SIGN_ON_BEHALF', 'SUB_DELEGATE', 'ACCESS_PII',
        ];
        for (let i = 0; i < 8; i++) {
          if ((bitmask >> BigInt(i) & 1n) === 1n) {
            permissionNames.push(allPerms[i]);
          }
        }

        const network = config.network ?? 'base-sepolia';
        const prefix = devMode ? 'dev' : network;

        return {
          did: `did:bolyra:${prefix}:${credential.commitment.toString(16).padStart(64, '0')}`,
          permissionBitmask: bitmask.toString(2).padStart(8, '0'),
          permissions: permissionNames,
          expiryTimestamp: credential.expiryTimestamp.toString(),
          expiryDate: new Date(Number(credential.expiryTimestamp) * 1000).toISOString(),
          modelHash: credential.modelHash.toString(16),
          devMode,
        };
      },
    }),
  };

  // Attach accessors so callers can retrieve the bundle programmatically
  return Object.assign(tools, { getLastBundle, getLastAuthHeader });
}
