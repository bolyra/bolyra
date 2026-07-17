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
import { FileNonceStore } from '../../src/verify/nonce-store';
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
        expiry: 1, // binding v2: == credential expiry (this test fails at groth16 first)
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
    /** HumanUniqueness nullifierHash (publicSignals[1]), when the bundle is human-backed. */
    humanNullifier?: string;
    operatorKey: string;
    expiry: number;
  }

  let agentOnly: Built;
  let withHuman: Built;
  /** A SECOND human handshake for the SAME identity — same human root + nullifier,
   *  but a DIFFERENT (fresh) sessionNonce and a fresh agent nullifier. */
  let withHumanB: Built;
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
      expiry, // binding v2: signature-bound, == credential expiry
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
      ...(includeHuman ? { humanNullifier: humanProof.publicSignals[1] } : {}),
      operatorKey: `${agent.operatorPublicKey.x}:${agent.operatorPublicKey.y}`,
      expiry,
    };
  }

  beforeAll(async () => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-core-'));
    agentOnly = await build(false, 'agent');
    withHuman = await build(true, 'human');
    withHumanB = await build(true, 'humanB');
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

  it('host mode → allow WITH consume_nonces (single agent entry)', async () => {
    const request = req(agentOnly);
    const v = await verify(request, {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: agentOnly.rootsFile,
      nonceMode: 'host',
      nonceStore: memStore(),
    });
    expect(v).toEqual({
      verdict: 'allow',
      consume_nonces: [
        {
          issuer_key: agentOnly.operatorKey,
          nonce: agentOnly.agentNullifier,
          retain_until: agentOnly.expiry,
        },
      ],
    });
  });

  // ── FIX 1: human proof must be bound to the session + consumed ──────────────

  it('human proof from a DIFFERENT session (spliced) → deny invalid_proof (not session-bound)', async () => {
    const a = (JSON.parse(withHuman.bundleString) as { human: { envelope: { publicSignals: string[] } } })
      .human.envelope.publicSignals;
    const b = (JSON.parse(withHumanB.bundleString) as { human: { envelope: { publicSignals: string[] } } })
      .human.envelope.publicSignals;
    // Same identity → identical human merkle root (trust gate passes); only the
    // sessionNonce differs, isolating the §4b session-binding check.
    expect(b[0]).toBe(a[0]);
    expect(b[4]).not.toBe(a[4]);

    const spliced = JSON.parse(withHuman.bundleString) as { human: unknown };
    spliced.human = (JSON.parse(withHumanB.bundleString) as { human: unknown }).human;
    const request = req(withHuman);
    request.bundle = JSON.stringify(spliced);

    const v = await verify(request, {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: withHuman.rootsFile,
      nonceStore: memStore(),
    });
    expect(v).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
  });

  it('reused human nullifier (local mode, fresh agent session) → deny nonce_replayed', async () => {
    // Shared human identity → same human nullifier; distinct sessions → distinct
    // agent nullifiers, so the 2nd verify clears the agent burn and trips ONLY
    // the human-nullifier replay.
    expect(withHumanB.humanNullifier).toBe(withHuman.humanNullifier);
    expect(withHumanB.agentNullifier).not.toBe(withHuman.agentNullifier);

    const store = new FileNonceStore(fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-human-replay-')));
    const first = await verify(req(withHuman), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: withHuman.rootsFile,
      nonceStore: store,
    });
    expect(first).toEqual({ verdict: 'allow' });

    const second = await verify(req(withHumanB), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: withHumanB.rootsFile,
      nonceStore: store,
    });
    expect(second).toMatchObject({ verdict: 'deny', code: 'nonce_replayed' });
    expect((second as { message?: string }).message).toBe('human nullifier replayed');
  });

  it('host mode + human → allow with TWO consume_nonces (agent + human:), NO local nonce state', async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-host-human-'));
    const store = new FileNonceStore(dir);
    const v = await verify(req(withHuman), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: withHuman.rootsFile,
      nonceMode: 'host',
      nonceStore: store,
    });
    expect(v).toMatchObject({ verdict: 'allow' });
    const nonces = (v as { consume_nonces?: Array<{ nonce: string }> }).consume_nonces ?? [];
    expect(nonces).toHaveLength(2);
    expect(nonces[0].nonce).toBe(withHuman.agentNullifier);
    expect(nonces[1].nonce).toBe(`human:${withHuman.humanNullifier}`);
    // Host mode holds NO local state — the store dir stays empty.
    const files = fs.existsSync(dir) ? fs.readdirSync(dir) : [];
    expect(files).toHaveLength(0);
  });

  // ── FIX 3: internal_error must not echo raw exception text on stdout ────────

  it('unexpected fault → generic internal_error verdict; --verbose routes raw detail to stderr', async () => {
    const secretPath = '/private/secret/vkey-abcdef.json';
    const throwingStore: NonceStore = {
      markIfFresh: async (): Promise<boolean> => {
        throw new Error(`ENOENT: no such file or directory, open '${secretPath}'`);
      },
    };

    // Without --verbose: the verdict is generic and carries no path anywhere.
    const v1 = await verify(req(agentOnly), {
      circuitsDir: CIRCUITS_DIR,
      rootsFile: agentOnly.rootsFile,
      nonceStore: throwingStore,
    });
    expect(v1).toEqual({
      verdict: 'deny',
      code: 'internal_error',
      message: 'internal verification error',
    });
    expect(JSON.stringify(v1)).not.toContain(secretPath);

    // With --verbose: the verdict stays generic, but the raw detail hits stderr.
    const writes: string[] = [];
    const spy = jest.spyOn(process.stderr, 'write').mockImplementation(((chunk: unknown): boolean => {
      writes.push(String(chunk));
      return true;
    }) as unknown as typeof process.stderr.write);
    let v2: unknown;
    try {
      v2 = await verify(req(agentOnly), {
        circuitsDir: CIRCUITS_DIR,
        rootsFile: agentOnly.rootsFile,
        nonceStore: throwingStore,
        verbose: true,
      });
    } finally {
      spy.mockRestore();
    }
    expect(v2).toMatchObject({
      verdict: 'deny',
      code: 'internal_error',
      message: 'internal verification error',
    });
    expect(JSON.stringify(v2)).not.toContain(secretPath);
    expect(writes.join('')).toContain(secretPath);
  });
});
