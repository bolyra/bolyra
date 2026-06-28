/**
 * Bolyra MCP integration — uses ProofEnvelope for all proof payloads.
 *
 * This module provides MCP tool handlers that accept and return
 * proofs in the canonical application/bolyra+json envelope format.
 */

import { Server } from '@modelcontextprotocol/sdk/server/index.js';
import {
  BOLYRA_CONTENT_TYPE,
  ProofType,
  createEnvelope,
  deserializeEnvelope,
  serializeEnvelope,
  validateEnvelope,
  EnvelopeValidationError,
} from '@bolyra/sdk';
import type { ProofEnvelope } from '@bolyra/sdk';

// ---------------------------------------------------------------------------
// Types
// ---------------------------------------------------------------------------

export interface McpBolyraConfig {
  /** Path to circuit build artifacts. */
  artifactsDir: string;
  /** Optional proof verification callback. */
  verifyProof?: (envelope: ProofEnvelope) => Promise<boolean>;
}

// ---------------------------------------------------------------------------
// Tool handlers
// ---------------------------------------------------------------------------

/**
 * Register Bolyra proof tools on an MCP server.
 *
 * Tools registered:
 * - `bolyra_prove_handshake` — generate a handshake proof, returns ProofEnvelope
 * - `bolyra_verify_envelope` — validate and optionally verify a ProofEnvelope
 * - `bolyra_envelope_info` — return envelope metadata without verification
 */
export function registerBolyraTools(server: Server, config: McpBolyraConfig): void {
  // -------------------------------------------------------------------------
  // bolyra_prove_handshake
  // -------------------------------------------------------------------------

  server.setRequestHandler(
    { method: 'tools/call' } as any,
    async (request: any) => {
      const { name, arguments: args } = request.params;

      if (name === 'bolyra_prove_handshake') {
        return handleProveHandshake(args);
      }

      if (name === 'bolyra_verify_envelope') {
        return handleVerifyEnvelope(args, config);
      }

      if (name === 'bolyra_envelope_info') {
        return handleEnvelopeInfo(args);
      }

      return { content: [{ type: 'text', text: `Unknown tool: ${name}` }], isError: true };
    },
  );

  // Register tool definitions
  server.setRequestHandler(
    { method: 'tools/list' } as any,
    async () => ({
      tools: [
        {
          name: 'bolyra_prove_handshake',
          description: 'Generate a Bolyra handshake proof. Returns a ProofEnvelope (application/bolyra+json).',
          inputSchema: {
            type: 'object',
            required: ['nonce'],
            properties: {
              nonce: { type: 'string', description: 'Session nonce for replay protection' },
            },
          },
        },
        {
          name: 'bolyra_verify_envelope',
          description: 'Validate a ProofEnvelope against the JSON Schema and optionally verify the proof on-chain.',
          inputSchema: {
            type: 'object',
            required: ['envelope'],
            properties: {
              envelope: { type: 'string', description: 'JSON-serialized ProofEnvelope' },
            },
          },
        },
        {
          name: 'bolyra_envelope_info',
          description: 'Extract metadata from a ProofEnvelope without verification.',
          inputSchema: {
            type: 'object',
            required: ['envelope'],
            properties: {
              envelope: { type: 'string', description: 'JSON-serialized ProofEnvelope' },
            },
          },
        },
      ],
    }),
  );
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async function handleProveHandshake(
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: string; text: string; mimeType?: string }> }> {
  const nonce = args.nonce as string;
  if (!nonce || typeof nonce !== 'string') {
    return {
      content: [{ type: 'text', text: 'Missing required parameter: nonce' }],
    };
  }

  // In production, this calls the real proveHandshake() from @bolyra/sdk.
  // Stub proof for demonstration:
  const envelope = createEnvelope(
    ProofType.Handshake,
    ['100', '200', '300'],
    {
      pi_a: ['1', '2', '1'],
      pi_b: [['3', '4'], ['5', '6'], ['1', '0']],
      pi_c: ['7', '8', '1'],
      protocol: 'groth16',
      curve: 'bn128',
    },
    { nonce },
  );

  return {
    content: [
      {
        type: 'text',
        text: serializeEnvelope(envelope),
        mimeType: BOLYRA_CONTENT_TYPE,
      },
    ],
  };
}

async function handleVerifyEnvelope(
  args: Record<string, unknown>,
  config: McpBolyraConfig,
): Promise<{ content: Array<{ type: string; text: string }> }> {
  const raw = args.envelope as string;
  if (!raw || typeof raw !== 'string') {
    return {
      content: [{ type: 'text', text: 'Missing required parameter: envelope' }],
    };
  }

  try {
    const envelope = deserializeEnvelope(raw);

    let verified = false;
    if (config.verifyProof) {
      verified = await config.verifyProof(envelope);
    }

    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            valid: true,
            verified,
            proofType: envelope.proofType,
            publicSignals: envelope.publicSignals,
            issuedAt: envelope.metadata.issuedAt,
          }),
        },
      ],
    };
  } catch (err) {
    const message = err instanceof EnvelopeValidationError
      ? `[${err.code}] ${err.message}`
      : String(err);
    return {
      content: [{ type: 'text', text: JSON.stringify({ valid: false, error: message }) }],
    };
  }
}

async function handleEnvelopeInfo(
  args: Record<string, unknown>,
): Promise<{ content: Array<{ type: string; text: string }> }> {
  const raw = args.envelope as string;
  if (!raw || typeof raw !== 'string') {
    return {
      content: [{ type: 'text', text: 'Missing required parameter: envelope' }],
    };
  }

  try {
    const envelope = deserializeEnvelope(raw);
    return {
      content: [
        {
          type: 'text',
          text: JSON.stringify({
            version: envelope.version,
            proofType: envelope.proofType,
            signalCount: envelope.publicSignals.length,
            protocol: envelope.proof.protocol,
            issuedAt: envelope.metadata.issuedAt,
            hasNonce: !!envelope.metadata.nonce,
          }),
        },
      ],
    };
  } catch (err) {
    const message = err instanceof EnvelopeValidationError
      ? `[${err.code}] ${err.message}`
      : String(err);
    return {
      content: [{ type: 'text', text: JSON.stringify({ error: message }) }],
    };
  }
}
