/**
 * Tests for verify/core.ts — the §5 orchestrator.
 *
 * Two layers:
 *   1. STEP ORDERING (fast, no real proofs): craft inputs that would fail at
 *      MULTIPLE steps and assert the earliest step's code wins — proving the
 *      §5 order is honored (malformed_input before bundle parse; version before
 *      parse; invalid_proof before scope/expiry).
 *   2. REAL end-to-end (generates genuine Groth16 proofs via the SDK against the
 *      checked-out circuit artifacts): assemble a full `bvp/1` bundle, sign the
 *      binding, and assert `allow` — agent-only, human-present, and host-mode.
 */

import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  proveHandshake,
  envelopeFromSnarkjsProof,
  eddsaSign,
  type AgentCredential,
} from '@bolyra/sdk';
import type { NonceStore } from '@bolyra/mcp';

import { verify, type VerifierRequest, type VerifyFlags } from '../../src/verify/core';
import { computeVkeyHash, resolveVkeyPath } from '../../src/verify/proofs';
import { bindingDigest } from '../../src/verify/binding';
import { hashModel } from '../../src/parse';

const CIRCUITS_DIR =
  process.env.BOLYRA_CIRCUITS_DIR ?? path.resolve(__dirname, '../../../../circuits/build');

/** Operator private key (bigint). The credential pubkey derives from this and
 *  the SAME key signs the binding, so the binding-sig check verifies. */
const OPERATOR_PRIV = 42n;

const AGENT_NAME = 'research-bot';
const PROJECT_KEY = '/work/acme/research';
const PROGRAM = 'crewai';
const MODEL = 'opus-4.1';
/** Granted capabilities map (default map) to READ_DATA | WRITE_DATA = bits {0,1}. */
const GRANTED = ['fetch_inbox', 'send_message'];
/** The signed binding's capability set (superset of GRANTED). */
const CAPS = ['fetch_inbox', 'send_message'];

/** In-memory NonceStore: fresh on first sight of a key, replayed after. */
function memStore(): NonceStore {
  const seen = new Set<string>();
  return {
    markIfFresh: async (key: string): Promise<boolean> => {
      if (seen.has(key)) return false;
      seen.add(key);
      return true;
    },
  };
}

/** Load a circuit vkey object from the resolved build dir. */
function loadVkey(circuit: 'AgentPolicy' | 'HumanUniqueness'): object {
  const p = resolveVkeyPath(circuit, { circuitsDir: CIRCUITS_DIR });
  return JSON.parse(fs.readFileSync(p, 'utf8')) as object;
}

/** Build the revealed credential block for a bundle from an AgentCredential. */
function credentialBlock(agent: AgentCredential) {
  return {
    model_hash: agent.modelHash.toString(),
    operator_pubkey: {
      x: agent.operatorPublicKey.x.toString(),
      y: agent.operatorPublicKey.y.toString(),
    },
    permission_bitmask: agent.permissionBitmask.toString(),
    expiry: Number(agent.expiryTimestamp),
  };
}

describe('verify/core — step ordering (no real proofs)', () => {
  const baseRequest = (): VerifierRequest => ({
    version: 1,
    bundle: '{"bvp":1}',
    request: {
      agent_name: AGENT_NAME,
      project_key: PROJECT_KEY,
      program: PROGRAM,
      model: MODEL,
      granted_capabilities: GRANTED,
    },
    now_unix: Math.floor(Date.now() / 1000),
  });

  const flags = (): VerifyFlags => ({ circuitsDir: CIRCUITS_DIR, nonceStore: memStore() });

  it('malformed request → malformed_input BEFORE any bundle parse', async () => {
    const req = baseRequest();
    // A non-string bundle is ill-formed; if parse ran first it would blow up
    // differently. `malformed_input` proves validation ran first.
    (req as unknown as Record<string, unknown>).bundle = 12345;
    const v = await verify(req, flags());
    expect(v).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
  });

  it('missing nested request field → malformed_input', async () => {
    const req = baseRequest();
    delete (req.request as unknown as Record<string, unknown>).model;
    const v = await verify(req, flags());
    expect(v).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
  });

  it('version:2 → unsupported_version (before bundle parse)', async () => {
    const req = baseRequest();
    req.version = 2;
    // Bundle is a valid string but should never be parsed.
    const v = await verify(req, flags());
    expect(v).toMatchObject({ verdict: 'deny', code: 'unsupported_version' });
  });

  it('bundle that fails groth16 → invalid_proof BEFORE scope/expiry', async () => {
    // A structurally-valid bvp/1 bundle whose agent envelope OMITS vkeyHash, so
    // the mandatory pinning check denies invalid_proof. The credential preimage
    // is bogus and the expiry is in the PAST — proving invalid_proof (step 3)
    // wins over scope-anchor (step 5) and expiry (step 10).
    const fakeEnvelope = {
      version: '1.0.0',
      circuit: { name: 'AgentPolicy', version: '0.4.0' }, // no vkeyHash
      proofType: 'groth16',
      publicSignals: ['1', '2', '3', '4', '5', '6'],
      proof: {
        pi_a: ['1', '2'],
        pi_b: [
          ['1', '2'],
          ['3', '4'],
        ],
        pi_c: ['1', '2'],
      },
    };
    const bundle = {
      bvp: 1,
      agent: {
        envelope: fakeEnvelope,
        credential: {
          model_hash: '999',
          operator_pubkey: { x: '1', y: '2' },
          permission_bitmask: '3',
          expiry: 1, // long past
        },
      },
      binding: {
        agent_name: AGENT_NAME,
        project_key: PROJECT_KEY,
        program: PROGRAM,
        model: MODEL,
        capabilities: CAPS,
      },
      sig: { R8: { x: '1', y: '2' }, S: '3' },
    };
    const req = baseRequest();
    req.bundle = JSON.stringify(bundle);
    const v = await verify(req, flags());
    expect(v).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
  });
});

describe('verify/core — REAL end-to-end (generates proofs via the SDK)', () => {
  jest.setTimeout(180000);

  interface Built {
    bundleString: string;
    rootsFile: string;
    agentNullifier: string;
    operatorKey: string;
    expiry: number;
  }

  let agentOnly: Built;
  let withHuman: Built;
  let tmpDir: string;

  /** Assemble a signed bvp/1 bundle (+ its roots file) from real proofs. */
  async function build(includeHuman: boolean, tag: string): Promise<Built> {
    const nowSec = Math.floor(Date.now() / 1000);
    const expiry = nowSec + 86400;

    const human = await createHumanIdentity(123456789n);
    const agent = await createAgentCredential(
      hashModel(MODEL),
      OPERATOR_PRIV,
      [Permission.READ_DATA, Permission.WRITE_DATA],
      BigInt(expiry),
    );

    const { humanProof, agentProof } = await proveHandshake(human, agent, {
      config: { circuitDir: CIRCUITS_DIR },
      backend: 'snarkjs',
    });

    const agentEnvelope = envelopeFromSnarkjsProof(
      'AgentPolicy',
      agentProof.proof,
      agentProof.publicSignals,
      { vkeyHash: computeVkeyHash(loadVkey('AgentPolicy')) },
    );
    const humanEnvelope = envelopeFromSnarkjsProof(
      'HumanUniqueness',
      humanProof.proof,
      humanProof.publicSignals,
      { vkeyHash: computeVkeyHash(loadVkey('HumanUniqueness')) },
    );

    const binding = {
      agent_name: AGENT_NAME,
      project_key: PROJECT_KEY,
      program: PROGRAM,
      model: MODEL,
      capabilities: CAPS,
    };
    const sig = await eddsaSign(OPERATOR_PRIV, await bindingDigest(binding));

    const bundle: Record<string, unknown> = {
      bvp: 1,
      agent: { envelope: agentEnvelope, credential: credentialBlock(agent) },
      binding,
      sig: {
        R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
        S: sig.S.toString(),
      },
    };
    if (includeHuman) bundle.human = { envelope: humanEnvelope };

    // Namespaced roots file trusting the real agent (and human) merkle roots.
    const roots: Record<string, string[]> = {
      agent: [agentProof.publicSignals[0]],
    };
    if (includeHuman) roots.human = [humanProof.publicSignals[0]];
    const rootsFile = path.join(tmpDir, `roots-${tag}.json`);
    fs.writeFileSync(rootsFile, JSON.stringify(roots));

    return {
      bundleString: JSON.stringify(bundle),
      rootsFile,
      agentNullifier: agentProof.publicSignals[1],
      operatorKey: `${agent.operatorPublicKey.x}:${agent.operatorPublicKey.y}`,
      expiry,
    };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-core-'));
    agentOnly = await build(false, 'agent');
    withHuman = await build(true, 'human');
  });

  const req = (b: Built): VerifierRequest => ({
    version: 1,
    bundle: b.bundleString,
    request: {
      agent_name: AGENT_NAME,
      project_key: PROJECT_KEY,
      program: PROGRAM,
      model: MODEL,
      granted_capabilities: GRANTED,
    },
    now_unix: Math.floor(Date.now() / 1000),
  });

  it('agent-only bundle → allow', async () => {
    const v = await verify(req(agentOnly), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: agentOnly.rootsFile,
      nonceStore: memStore(),
    });
    expect(v).toEqual({ verdict: 'allow' });
  });

  it('human-present bundle → allow', async () => {
    const v = await verify(req(withHuman), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: withHuman.rootsFile,
      nonceStore: memStore(),
    });
    expect(v).toEqual({ verdict: 'allow' });
  });

  it('host mode → allow WITH consume_nonce (issuer_key/nonce/retain_until)', async () => {
    const request = req(agentOnly);
    const v = await verify(request, {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: agentOnly.rootsFile,
      nonceMode: 'host',
      nonceStore: memStore(),
    });
    expect(v).toEqual({
      verdict: 'allow',
      consume_nonce: {
        issuer_key: agentOnly.operatorKey,
        nonce: agentOnly.agentNullifier,
        retain_until: agentOnly.expiry,
      },
    });
  });
});
