/**
 * Golden-fixture generator for the `bolyra verify` external verifier (Task 15).
 *
 * This is a RUNNABLE DEV SCRIPT — not part of the jest suite. Run it once, with
 * the real proving artifacts on disk, to (re)generate the committed golden
 * `bvp/1` bundles + the small committed vkeys that the drift guard
 * (`test/verify/generate.test.ts`) and the e2e (Task 16) verify against:
 *
 *   cd integrations/cli
 *   BOLYRA_CIRCUITS_DIR=<repo>/circuits/build npx tsx test/fixtures/verify/generate.ts
 *
 * It writes, under `integrations/cli/test/fixtures/verify/`:
 *   - vkeys/{AgentPolicy_groth16,Delegation_groth16,HumanUniqueness}_vkey.json
 *       COPIED VERBATIM from `$BOLYRA_CIRCUITS_DIR`. These small files are
 *       COMMITTED so verification needs no gitignored `circuits/build` artifacts.
 *   - allow-agent-only/{bundle,request}.json   — real agent-only AgentPolicy proof.
 *   - allow-human/{bundle,request}.json         — real proof + HumanUniqueness proof.
 *   - allow-delegation-1hop/{bundle,request}.json — real 1-hop SDK delegation.
 *   - deny-scope-exceeded/{bundle,request}.json — real proof over a READ-only
 *       credential; the request grants a WRITE-requiring capability → the
 *       capability→scope subset check denies `scope_exceeded` (Task 15b).
 *   - deny-model-mismatch/{bundle,request}.json — real proof over a
 *       "model-alpha" credential; binding + request both assert "model-beta"
 *       (equal, so the request-binding check passes) → the model-binding check
 *       denies `model_mismatch` (Task 15b).
 *   - roots.json           — namespaced real merkle roots {agent,human,delegatee}.
 *   - capability-map.json  — capability→permission map covering the requests.
 *
 * The `vkeyHash` stamped into every envelope is `computeVkeyHash(<committed vkey>)`
 * (identical bytes to `$BOLYRA_CIRCUITS_DIR`'s vkey), so a verifier resolving the
 * COMMITTED vkeys agrees byte-for-byte.
 */

import * as fs from 'node:fs';
import * as path from 'node:path';

import {
  createHumanIdentity,
  createAgentCredential,
  Permission,
  proveHandshake,
  delegate,
  envelopeFromSnarkjsProof,
  eddsaSign,
  type AgentCredential,
  type ProofEnvelope,
} from '@bolyra/sdk';

import { computeVkeyHash } from '../../../src/verify/proofs';
import { bindingDigest } from '../../../src/verify/binding';
import { hashModel } from '../../../src/parse';

/** The real proving-artifact directory. REQUIRED — this script proves for real. */
const CIRCUITS_DIR =
  process.env.BOLYRA_CIRCUITS_DIR ?? path.resolve(__dirname, '../../../../../circuits/build');

/** Where the committed goldens live (this file's own directory). */
const FIXTURES_DIR = __dirname;
const VKEYS_DIR = path.join(FIXTURES_DIR, 'vkeys');

/** Operator private key — the credential pubkey derives from it AND it signs the
 *  binding, so the binding-signature check verifies against the proven key. */
const OPERATOR_PRIV = 42n;

/** Fixed request context, shared across goldens (matches the binding). */
const AGENT_NAME = 'research-bot';
const PROJECT_KEY = '/work/acme/research';
const PROGRAM = 'crewai';
const MODEL = 'opus-4.1';

/** A far-future absolute expiry so the committed goldens never age out. */
const EXPIRY = 4102444800; // 2100-01-01T00:00:00Z
/** Fixed verifier clock, comfortably before EXPIRY, committed into each request. */
const NOW_UNIX = 1751990400; // 2025-07-08T16:00:00Z (< EXPIRY, past-stable)

/** vkey filenames per circuit (mirror the SDK/verifier resolver). */
const VKEY_FILES: Record<'AgentPolicy' | 'Delegation' | 'HumanUniqueness', string> = {
  AgentPolicy: 'AgentPolicy_groth16_vkey.json',
  Delegation: 'Delegation_groth16_vkey.json',
  HumanUniqueness: 'HumanUniqueness_vkey.json',
};

/** Load a circuit vkey object from the real build dir. */
function loadBuildVkey(circuit: keyof typeof VKEY_FILES): object {
  const p = path.join(CIRCUITS_DIR, VKEY_FILES[circuit]);
  return JSON.parse(fs.readFileSync(p, 'utf8')) as object;
}

/** Serialize the revealed credential block for a bundle from an AgentCredential. */
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

/** Write a value as pretty JSON, creating parent dirs as needed. */
function writeJson(file: string, value: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(value, null, 2) + '\n');
}

/**
 * The signed binding for a golden (capabilities cover the request). `model`
 * defaults to {@link MODEL}; the `model_mismatch` golden overrides it so the
 * binding claims a model DISTINCT from the one the proof commits to.
 */
function makeBinding(capabilities: string[], model: string = MODEL) {
  return {
    agent_name: AGENT_NAME,
    project_key: PROJECT_KEY,
    program: PROGRAM,
    model,
    capabilities,
    // Binding v2: expiry is signature-bound and MUST equal the credential expiry.
    expiry: EXPIRY,
  };
}

/**
 * Assemble the full VerifierRequest (§2.1 nested shape) around a bundle.
 * `model` defaults to {@link MODEL} and MUST equal the binding's model for the
 * request-binding check to pass (the `model_mismatch` golden sets both to the
 * same distinct value so the failure is the proof↔model check, not the request
 * check).
 */
function makeRequest(bundle: unknown, grantedCapabilities: string[], model: string = MODEL) {
  return {
    version: 1,
    bundle: JSON.stringify(bundle),
    request: {
      agent_name: AGENT_NAME,
      project_key: PROJECT_KEY,
      program: PROGRAM,
      model,
      granted_capabilities: grantedCapabilities,
    },
    now_unix: NOW_UNIX,
  };
}

/** Accumulator for the namespaced roots.json (deduped per tree). */
const roots = {
  agent: new Set<string>(),
  human: new Set<string>(),
  delegatee: new Set<string>(),
};

/** Copy the three vkeys verbatim from the build dir into the committed vkeys/. */
function copyVkeys(): void {
  fs.mkdirSync(VKEYS_DIR, { recursive: true });
  for (const file of Object.values(VKEY_FILES)) {
    fs.copyFileSync(path.join(CIRCUITS_DIR, file), path.join(VKEYS_DIR, file));
  }
  console.log(`  vkeys/ ← ${Object.values(VKEY_FILES).join(', ')}`);
}

/** Build an agent-only (or human-present) golden and write its bundle+request. */
async function buildAgentGolden(includeHuman: boolean, dir: string): Promise<void> {
  const human = await createHumanIdentity(123456789n);
  const agent = await createAgentCredential(
    hashModel(MODEL),
    OPERATOR_PRIV,
    [Permission.READ_DATA, Permission.WRITE_DATA],
    BigInt(EXPIRY),
  );

  const { humanProof, agentProof } = await proveHandshake(human, agent, {
    config: { circuitDir: CIRCUITS_DIR },
    backend: 'snarkjs',
  });

  const agentEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
    'AgentPolicy',
    agentProof.proof,
    agentProof.publicSignals,
    { vkeyHash: computeVkeyHash(loadBuildVkey('AgentPolicy')) },
  );

  const binding = makeBinding(['fetch_inbox', 'send_message']);
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

  roots.agent.add(agentProof.publicSignals[0]);

  if (includeHuman) {
    const humanEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
      'HumanUniqueness',
      humanProof.proof,
      humanProof.publicSignals,
      { vkeyHash: computeVkeyHash(loadBuildVkey('HumanUniqueness')) },
    );
    bundle.human = { envelope: humanEnvelope };
    roots.human.add(humanProof.publicSignals[0]);
  }

  // Both goldens grant READ+WRITE (subset of the credential's own scope = 3).
  const request = makeRequest(bundle, ['fetch_inbox', 'send_message']);

  writeJson(path.join(FIXTURES_DIR, dir, 'bundle.json'), bundle);
  writeJson(path.join(FIXTURES_DIR, dir, 'request.json'), request);
  console.log(`  ${dir}/ ← agent proof${includeHuman ? ' + human proof' : ''}`);
}

/** Build a real 1-hop delegation golden via the SDK `delegate()`. */
async function buildDelegationGolden(dir: string): Promise<void> {
  const human = await createHumanIdentity(123456789n);
  // Delegator carries READ+WRITE; it will delegate a NARROWER (READ-only) scope.
  const delegator = await createAgentCredential(
    hashModel(MODEL),
    OPERATOR_PRIV,
    [Permission.READ_DATA, Permission.WRITE_DATA],
    BigInt(EXPIRY),
  );

  const { agentProof } = await proveHandshake(human, delegator, {
    config: { circuitDir: CIRCUITS_DIR },
    backend: 'snarkjs',
  });

  // AgentPolicy publicSignals: [0]=merkleRoot [1]=nullifier [2]=scopeCommitment
  //   [3]=requiredScopeMask [4]=currentTimestamp [5]=sessionNonce
  const previousScopeCommitment = BigInt(agentProof.publicSignals[2]);
  const currentTimestamp = BigInt(agentProof.publicSignals[4]);
  const sessionNonce = BigInt(agentProof.publicSignals[5]);

  // The delegatee is a distinct credential; only its commitment (identity leaf)
  // matters for the delegation. Scope granted is the narrowed READ-only bitmask.
  const delegatee = await createAgentCredential(
    hashModel('delegatee-model'),
    OPERATOR_PRIV,
    [Permission.READ_DATA],
    BigInt(EXPIRY),
  );
  const delegateeScope = 1n << BigInt(Permission.READ_DATA); // bit 0 = 1

  const { proof: dProof, result } = await delegate({
    delegator,
    delegatorOperatorPrivateKey: OPERATOR_PRIV,
    delegateeCommitment: delegatee.commitment,
    delegateeScope,
    delegateeExpiry: BigInt(EXPIRY), // == delegator expiry (narrowing allows equal)
    previousScopeCommitment,
    sessionNonce,
    currentTimestamp,
    config: { circuitDir: CIRCUITS_DIR },
    backend: 'snarkjs',
  });

  const agentEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
    'AgentPolicy',
    agentProof.proof,
    agentProof.publicSignals,
    { vkeyHash: computeVkeyHash(loadBuildVkey('AgentPolicy')) },
  );
  const delegationEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
    'Delegation',
    dProof.proof,
    dProof.publicSignals,
    { vkeyHash: computeVkeyHash(loadBuildVkey('Delegation')) },
  );

  const leaf = {
    delegatee_scope: delegateeScope.toString(),
    delegatee_commitment: delegatee.commitment.toString(),
    delegatee_expiry: EXPIRY,
  };

  const binding = makeBinding(['fetch_inbox']);
  const sig = await eddsaSign(OPERATOR_PRIV, await bindingDigest(binding));

  const bundle: Record<string, unknown> = {
    bvp: 1,
    agent: { envelope: agentEnvelope, credential: credentialBlock(delegator) },
    delegation: [{ envelope: delegationEnvelope, leaf }],
    binding,
    sig: {
      R8: { x: sig.R8.x.toString(), y: sig.R8.y.toString() },
      S: sig.S.toString(),
    },
  };

  roots.agent.add(agentProof.publicSignals[0]);
  roots.delegatee.add(result.delegateeMerkleRoot.toString());

  // Effective scope = delegatee scope (READ only). Request only READ.
  const request = makeRequest(bundle, ['fetch_inbox']);

  writeJson(path.join(FIXTURES_DIR, dir, 'bundle.json'), bundle);
  writeJson(path.join(FIXTURES_DIR, dir, 'request.json'), request);
  console.log(`  ${dir}/ ← delegator agent proof + 1-hop delegation proof`);
}

/**
 * Build the `deny scope_exceeded` golden (Task 15b): a REAL AgentPolicy proof
 * over a READ_DATA-only credential. The signed binding authorizes BOTH
 * capabilities, but the request grants only `send_message` (→ WRITE_DATA), which
 * the READ-only effective scope does NOT contain. Every earlier §5 check —
 * Groth16, root trust, scope anchor, binding signature, request binding, model
 * binding — PASSES; only the capability→scope subset test (§5 step 9) fails, so
 * the verdict is a genuine `scope_exceeded` (not `untrusted_root` etc.).
 */
async function buildScopeExceededGolden(dir: string): Promise<void> {
  const human = await createHumanIdentity(123456789n);
  // READ_DATA ONLY: the credential cannot satisfy a WRITE_DATA request.
  const agent = await createAgentCredential(
    hashModel(MODEL),
    OPERATOR_PRIV,
    [Permission.READ_DATA],
    BigInt(EXPIRY),
  );

  const { agentProof } = await proveHandshake(human, agent, {
    config: { circuitDir: CIRCUITS_DIR },
    backend: 'snarkjs',
  });

  const agentEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
    'AgentPolicy',
    agentProof.proof,
    agentProof.publicSignals,
    { vkeyHash: computeVkeyHash(loadBuildVkey('AgentPolicy')) },
  );

  // Binding authorizes BOTH capabilities; the operator signs it for real so the
  // binding-signature and request-binding checks both PASS.
  const binding = makeBinding(['fetch_inbox', 'send_message']);
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

  roots.agent.add(agentProof.publicSignals[0]);

  // Grant the WRITE-requiring `send_message` (⊆ binding capabilities, but the
  // required WRITE_DATA bit ⊄ the READ-only effective scope → scope_exceeded).
  const request = makeRequest(bundle, ['send_message']);

  writeJson(path.join(FIXTURES_DIR, dir, 'bundle.json'), bundle);
  writeJson(path.join(FIXTURES_DIR, dir, 'request.json'), request);
  console.log(`  ${dir}/ ← READ-only agent proof (deny: scope_exceeded)`);
}

/**
 * Build the `deny model_mismatch` golden (Task 15b): a REAL AgentPolicy proof
 * over a credential minted with model "model-alpha" (so the proven `model_hash`
 * = `hashModel("model-alpha")`). The signed binding AND the request BOTH assert
 * model "model-beta" — they are EQUAL, so §5's `checkRequestBinding` passes —
 * and the credential carries READ+WRITE so the requested capabilities are in
 * scope. The subsequent model-binding check (§5 step 8b) then fails because the
 * proven `model_hash` for "model-alpha" ≠ `hashModel("model-beta")`, yielding a
 * genuine `model_mismatch`. The beta-binding is signed by the real operator key,
 * so the binding signature still verifies.
 */
async function buildModelMismatchGolden(dir: string): Promise<void> {
  const human = await createHumanIdentity(123456789n);
  // Credential commits to "model-alpha"; scope READ+WRITE covers the request.
  const agent = await createAgentCredential(
    hashModel('model-alpha'),
    OPERATOR_PRIV,
    [Permission.READ_DATA, Permission.WRITE_DATA],
    BigInt(EXPIRY),
  );

  const { agentProof } = await proveHandshake(human, agent, {
    config: { circuitDir: CIRCUITS_DIR },
    backend: 'snarkjs',
  });

  const agentEnvelope: ProofEnvelope = envelopeFromSnarkjsProof(
    'AgentPolicy',
    agentProof.proof,
    agentProof.publicSignals,
    { vkeyHash: computeVkeyHash(loadBuildVkey('AgentPolicy')) },
  );

  // Binding (and request) both claim "model-beta" — equal to each other but
  // DISTINCT from the proven "model-alpha". Signing the beta-binding with the
  // real operator key keeps the binding signature valid.
  const binding = makeBinding(['fetch_inbox', 'send_message'], 'model-beta');
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

  roots.agent.add(agentProof.publicSignals[0]);

  // Request asserts "model-beta" (== binding.model) and stays within scope, so
  // the ONLY failing check is proof modelHash(alpha) ≠ hashModel("model-beta").
  const request = makeRequest(bundle, ['fetch_inbox', 'send_message'], 'model-beta');

  writeJson(path.join(FIXTURES_DIR, dir, 'bundle.json'), bundle);
  writeJson(path.join(FIXTURES_DIR, dir, 'request.json'), request);
  console.log(`  ${dir}/ ← model-alpha agent proof, model-beta binding (deny: model_mismatch)`);
}

async function main(): Promise<void> {
  if (!fs.existsSync(CIRCUITS_DIR)) {
    throw new Error(
      `BOLYRA_CIRCUITS_DIR does not exist: ${CIRCUITS_DIR}\n` +
        'Point it at a built circuits/build with AgentPolicy/Delegation/HumanUniqueness artifacts.',
    );
  }
  console.log(`Generating verify goldens from ${CIRCUITS_DIR}`);

  copyVkeys();
  await buildAgentGolden(false, 'allow-agent-only');
  await buildAgentGolden(true, 'allow-human');
  await buildDelegationGolden('allow-delegation-1hop');
  await buildScopeExceededGolden('deny-scope-exceeded');
  await buildModelMismatchGolden('deny-model-mismatch');

  writeJson(path.join(FIXTURES_DIR, 'roots.json'), {
    agent: [...roots.agent],
    human: [...roots.human],
    delegatee: [...roots.delegatee],
  });
  console.log('  roots.json ← namespaced {agent,human,delegatee} real merkle roots');

  writeJson(path.join(FIXTURES_DIR, 'capability-map.json'), {
    fetch_inbox: ['READ_DATA'],
    send_message: ['WRITE_DATA'],
  });
  console.log('  capability-map.json ← fetch_inbox→READ_DATA, send_message→WRITE_DATA');

  console.log('Done.');
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
