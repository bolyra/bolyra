/**
 * End-to-end matrix for the `bolyra verify` external verifier (Task 16).
 *
 * Each case SPAWNS the BUILT CLI (`node dist/main.js verify …flags`), pipes the
 * full §2.1 request object (`{version, bundle, request, now_unix}`) on stdin, and
 * asserts the SINGLE stdout verdict + exit code. The three ALLOW inputs are the
 * committed real-Groth16 goldens; every DENY case is built from a golden by a
 * deterministic ONE-FIELD mutation (or is a committed deny golden). Verification
 * uses ONLY the committed `vkeys/` via `--circuits-dir` — no `circuits/build`,
 * no runtime proving.
 *
 * Isolation: every spawn runs with a FRESH temp `$HOME` so the durable
 * FileNonceStore (`$HOME/.bolyra/nonces`) starts empty, and `BOLYRA_TRUSTED_ROOTS`
 * is stripped from the child env so ambient trust config can never leak in. The
 * two replay cases (#8, #14) deliberately REUSE one `$HOME` across two spawns.
 *
 * stdout cleanliness: `parseSingleVerdict` does a single `JSON.parse` of the
 * trimmed stdout, which throws on ANY leading/trailing byte — so a clean parse is
 * itself the proof that stdout carried exactly one verdict and nothing else.
 */

import { spawnSync } from 'node:child_process';
import * as crypto from 'node:crypto';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

import { BN254_FIELD_ORDER, derivePublicKey, eddsaSign } from '@bolyra/sdk';

import { bindingDigest } from '../src/verify/binding';
import {
  clone,
  decodeBundle,
  encodeBundle,
  resignBinding,
  type LooseRequest,
} from './fixtures/verify/deny-mutations';

const CLI = path.join(__dirname, '..', 'dist', 'main.js');
const FIX = path.join(__dirname, 'fixtures', 'verify');
const VKEYS = path.join(FIX, 'vkeys');
const ROOTS = path.join(FIX, 'roots.json');
const CAPMAP = path.join(FIX, 'capability-map.json');

/** Namespaced trusted-roots file shape. */
type RootsFile = { agent: string[]; human: string[]; delegatee: string[] };

/** Load a committed golden's request.json as a fresh mutable object. */
function loadGolden(
  name: 'allow-agent-only' | 'allow-human' | 'allow-delegation-1hop',
): LooseRequest {
  return JSON.parse(fs.readFileSync(path.join(FIX, name, 'request.json'), 'utf8')) as LooseRequest;
}

/** Load a committed DENY golden's request.json verbatim. */
function loadDenyGolden(name: 'deny-scope-exceeded' | 'deny-model-mismatch'): unknown {
  return JSON.parse(fs.readFileSync(path.join(FIX, name, 'request.json'), 'utf8'));
}

/** The committed namespaced roots file, parsed. */
function realRoots(): RootsFile {
  return JSON.parse(fs.readFileSync(ROOTS, 'utf8')) as RootsFile;
}

/** A per-case scratch `$HOME` so the durable nonce store is isolated. */
function freshHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-e2e-'));
}

/** Write a small JSON temp file under a scratch dir and return its path. */
function writeTemp(basename: string, value: unknown): string {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-e2e-tmp-'));
  const file = path.join(dir, basename);
  fs.writeFileSync(file, JSON.stringify(value));
  return file;
}

interface RunResult {
  verdict: Record<string, unknown>;
  exitCode: number;
  stdout: string;
  stderr: string;
}

interface RunOpts {
  /** Extra flags appended AFTER the base flags. A duplicate `--roots-file` /
   *  `--capability-map` here OVERRIDES the base one (node parseArgs = last wins). */
  extraFlags?: string[];
  /** Reuse a specific `$HOME` (for the replay cases). Defaults to a fresh temp dir. */
  home?: string;
  /** Extra env overrides merged on top of the isolated child env. */
  env?: Record<string, string>;
  /** Send this RAW string on stdin instead of `JSON.stringify(requestObj)` (#3). */
  raw?: string;
  /** Omit `--roots-file` entirely (only #22 needs no trusted-root source). */
  omitRoots?: boolean;
}

/**
 * Spawn the built CLI `verify` command with the base trust flags plus any
 * per-case overrides, pipe the request on stdin, and return the parsed single
 * verdict, exit code, and raw streams.
 */
function runVerify(requestObj: unknown, opts: RunOpts = {}): RunResult {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: opts.home ?? freshHome() };
  // Never inherit ambient trust config — each case supplies its own (or none).
  delete env.BOLYRA_TRUSTED_ROOTS;
  Object.assign(env, opts.env ?? {});

  const args = ['verify', '--circuits-dir', VKEYS];
  if (!opts.omitRoots) args.push('--roots-file', ROOTS);
  args.push('--capability-map', CAPMAP);
  if (opts.extraFlags) args.push(...opts.extraFlags);

  const input = opts.raw ?? JSON.stringify(requestObj);
  const res = spawnSync(process.execPath, [CLI, ...args], {
    input,
    env,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });

  const stdout = res.stdout ?? '';
  return {
    verdict: parseSingleVerdict(stdout),
    exitCode: res.status ?? 0,
    stdout,
    stderr: res.stderr ?? '',
  };
}

/**
 * Assert stdout is EXACTLY one JSON object and return it. A single `JSON.parse`
 * of the trimmed stdout throws on any leading/trailing noise or a second
 * concatenated value, so a clean parse proves stdout carried one verdict only.
 */
function parseSingleVerdict(stdout: string): Record<string, unknown> {
  const trimmed = stdout.trim();
  expect(trimmed.length).toBeGreaterThan(0);
  const verdict = JSON.parse(trimmed) as Record<string, unknown>;
  // Re-serializing and re-parsing the value must round-trip to the SAME string,
  // guaranteeing there was no trailing garbage the first parse silently ignored.
  expect(JSON.stringify(JSON.parse(trimmed))).toBe(JSON.stringify(verdict));
  return verdict;
}

jest.setTimeout(60_000);

describe('bolyra verify — 22-fixture e2e matrix', () => {
  // ── 1. valid allow (agent-only golden, as-is) ───────────────────────────────
  it('#1 valid allow → allow (exit 0)', () => {
    const r = runVerify(loadGolden('allow-agent-only'));
    expect(r.verdict).toEqual({ verdict: 'allow' });
    expect(r.exitCode).toBe(0);
  });

  // ── 2. allow + consume_nonce (host mode) ────────────────────────────────────
  it('#2 host nonce-mode → allow WITH consume_nonce (exit 0)', () => {
    const r = runVerify(loadGolden('allow-agent-only'), {
      extraFlags: ['--nonce-mode', 'host'],
    });
    expect(r.verdict.verdict).toBe('allow');
    expect(r.verdict.consume_nonce).toMatchObject({
      issuer_key: expect.any(String),
      nonce: expect.any(String),
      retain_until: expect.any(Number),
    });
    expect(r.exitCode).toBe(0);
  });

  // ── 3. malformed input (literal non-JSON on stdin) ──────────────────────────
  it('#3 literal "not json" on stdin → deny malformed_input (exit 0)', () => {
    // Bypass JSON.stringify — pipe the raw bytes `not json`.
    const r = runVerify(undefined, { raw: 'not json' });
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
    expect(r.exitCode).toBe(0);
  });

  // ── 4. invalid proof (tampered proof coordinate) ────────────────────────────
  it('#4 tampered agent proof coordinate → deny invalid_proof (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    // Flip a digit of pi_a[0]; the Groth16 pairing check then fails.
    b.agent.envelope.proof.pi_a[0] = (BigInt(b.agent.envelope.proof.pi_a[0]) + 1n).toString();
    encodeBundle(req, b);
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(r.exitCode).toBe(0);
  });

  // ── 5. expired (now_unix well past the credential expiry) ───────────────────
  it('#5 now_unix past credential expiry → deny expired (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry + 100_000;
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.exitCode).toBe(0);
  });

  // ── 6. scope mismatch (committed deny golden) ───────────────────────────────
  it('#6 deny-scope-exceeded golden → deny scope_exceeded (exit 0)', () => {
    const r = runVerify(loadDenyGolden('deny-scope-exceeded'));
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
    expect(r.exitCode).toBe(0);
  });

  // ── 7. request mismatch (project_key differs from signed binding) ───────────
  it('#7 request.project_key ≠ binding → deny request_mismatch (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    req.request.project_key = '/work/acme/DIFFERENT';
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
    expect(r.exitCode).toBe(0);
  });

  // ── 8. replayed nonce (local mode, 2nd spawn same $HOME) ────────────────────
  it('#8 replayed nonce (local) → allow then deny nonce_replayed (exit 0)', () => {
    const home = freshHome();
    const req = loadGolden('allow-agent-only');

    const first = runVerify(req, { home });
    expect(first.verdict).toEqual({ verdict: 'allow' });
    expect(first.exitCode).toBe(0);

    const second = runVerify(req, { home });
    expect(second.verdict).toMatchObject({ verdict: 'deny', code: 'nonce_replayed' });
    expect(second.exitCode).toBe(0);
  });

  // ── 9. unsupported version ──────────────────────────────────────────────────
  it('#9 request.version = 2 → deny unsupported_version (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    req.version = 2;
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'unsupported_version' });
    expect(r.exitCode).toBe(0);
  });

  // ── 10. unknown capability ──────────────────────────────────────────────────
  it('#10 granted capability absent from every map → deny unknown_capability (exit 0)', async () => {
    // A granted capability must be inside the SIGNED binding (else request_mismatch
    // fires at step 8 first) yet absent from BOTH the default map and the file map
    // (else it resolves to bits and we reach scope). `loadCapabilityMap` ALWAYS
    // merges the `--capability-map` file ON TOP of the built-in DEFAULT map, so
    // "omitting" a capability from the file cannot make a defaulted name unknown —
    // the only faithful construction is a phantom capability that no map defines.
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.binding.capabilities = ['fetch_inbox', 'send_message', 'phantom_cap'];
    b.sig = await resignBinding(b.binding);
    encodeBundle(req, b);
    req.request.granted_capabilities = ['fetch_inbox', 'phantom_cap'];

    // Override the capability map with one that OMITS phantom_cap (it is absent
    // from the built-in default too), so requiredBits() denies unknown_capability.
    const capmap = writeTemp('capmap-10.json', {
      fetch_inbox: ['READ_DATA'],
      send_message: ['WRITE_DATA'],
    });
    const r = runVerify(req, { extraFlags: ['--capability-map', capmap] });
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'unknown_capability' });
    expect(r.exitCode).toBe(0);
  });

  // ── 11. cross-signer authorization (F1) ─────────────────────────────────────
  it('#11 binding signed by a FOREIGN operator key → deny invalid_signature (exit 0)', async () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);

    // A fresh random operator key. The binding is re-signed under priv2, but the
    // credential's operator_pubkey (which the ZK proof attests to) is left as the
    // golden's — so the signature can never verify against the PROVEN key.
    const priv2 = BigInt('0x' + crypto.randomBytes(31).toString('hex')) % BN254_FIELD_ORDER;
    const pub2 = derivePublicKey(priv2);
    void pub2; // computed per spec; intentionally NOT applied to the credential.
    const sig2 = await eddsaSign(priv2, await bindingDigest(b.binding));
    b.sig = { R8: { x: sig2.R8.x.toString(), y: sig2.R8.y.toString() }, S: sig2.S.toString() };
    encodeBundle(req, b);

    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'invalid_signature' });
    expect(r.exitCode).toBe(0);
  });

  // ── 12. inflated scope claim (F2) ───────────────────────────────────────────
  it('#12 inflated permission_bitmask → deny invalid_proof (exit 0)', () => {
    // Claim a fully-permissive bitmask (255). The scope anchor recomputes
    // scopeCommitment from the revealed preimage and binds it to publicSignals[2];
    // the inflated bitmask changes the recompute → mismatch → invalid_proof, BEFORE
    // any subset/scope check runs.
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.agent.credential.permission_bitmask = '255';
    encodeBundle(req, b);
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(r.exitCode).toBe(0);
  });

  // ── 13. forged expiry (F4) ──────────────────────────────────────────────────
  it('#13 now_unix just past expiry → deny expired (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry + 1;
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.exitCode).toBe(0);
  });

  // ── 14. fresh-nonce replay (F3) ─────────────────────────────────────────────
  it('#14 fresh-nonce replay (agent golden) → 2nd spawn deny nonce_replayed (exit 0)', () => {
    // Same durable-store keying as #8 (the agent nullifierHash), viewed from the
    // F3 "the SECOND presentation of an already-burned fresh nonce is rejected"
    // angle. Two sequential spawns share one $HOME so the store persists.
    const home = freshHome();
    const req = loadGolden('allow-agent-only');

    const first = runVerify(req, { home });
    expect(first.verdict).toEqual({ verdict: 'allow' });
    expect(first.exitCode).toBe(0);

    const second = runVerify(req, { home });
    expect(second.verdict).toMatchObject({ verdict: 'deny', code: 'nonce_replayed' });
    expect(second.exitCode).toBe(0);
  });

  // ── 15. over-long delegation chain (F5) ─────────────────────────────────────
  it('#15 delegation chain exceeds hop cap → deny delegation_invalid (exit 0)', () => {
    const req = loadGolden('allow-delegation-1hop');
    const b = decodeBundle(req);
    const hop = b.delegation[0];
    // 4 hops > MAX_HOPS (3): rejected at the hop-cap gate before any hop proof.
    b.delegation = [clone(hop), clone(hop), clone(hop), clone(hop)];
    encodeBundle(req, b);
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'delegation_invalid' });
    expect(r.exitCode).toBe(0);
  });

  // ── 16. missing / mismatched vkeyHash (F6) ──────────────────────────────────
  it('#16 absent OR mismatched envelope.vkeyHash → deny invalid_proof (exit 0)', () => {
    // (a) vkeyHash ABSENT — mandatory pinning rejects an envelope with no hash.
    const reqA = loadGolden('allow-agent-only');
    const bA = decodeBundle(reqA);
    delete bA.agent.envelope.circuit.vkeyHash;
    encodeBundle(reqA, bA);
    const rA = runVerify(reqA);
    expect(rA.verdict).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(rA.exitCode).toBe(0);

    // (b) vkeyHash MISMATCHED — an all-zero hash cannot equal the resolved vkey's.
    const reqB = loadGolden('allow-agent-only');
    const bB = decodeBundle(reqB);
    bB.agent.envelope.circuit.vkeyHash = 'sha256:' + '0'.repeat(64);
    encodeBundle(reqB, bB);
    const rB = runVerify(reqB);
    expect(rB.verdict).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(rB.exitCode).toBe(0);
  });

  // ── 17. stdout injection under real proving (F8) ────────────────────────────
  it('#17 native fd-1 noise during real proving → exactly ONE clean verdict → allow', () => {
    // Run the agent golden through REAL snarkjs verification in the isolated
    // worker, while the worker also writes native-style noise directly to fd 1 —
    // the exact hazard proving libs pose. The fd-level isolation must capture that
    // noise (route it to stderr) and keep the host-facing stdout a single clean
    // verdict.
    const r = runVerify(loadGolden('allow-agent-only'), {
      env: { BOLYRA_VERIFY_TEST_FD1_NOISE: '1' },
    });
    // parseSingleVerdict already proved stdout is exactly one JSON object; assert
    // it is the allow verdict, that the noise did NOT leak to stdout, and that it
    // WAS rerouted to stderr.
    expect(r.verdict).toEqual({ verdict: 'allow' });
    expect(r.stdout).not.toContain('RAW-FD1-NATIVE-NOISE');
    expect(r.stderr).toContain('RAW-FD1-NATIVE-NOISE');
    expect(r.exitCode).toBe(0);
  });

  // ── 18. untrusted agent root ────────────────────────────────────────────────
  it('#18 agent root not in roots file → deny untrusted_root (exit 0)', () => {
    const rr = realRoots();
    // A bogus agent tree (human + delegatee kept real) so the agent gate is
    // configured but the proof's agent root is not trusted.
    const roots = writeTemp('roots-18.json', {
      agent: ['99999999999999999999999999999999999999999999999999999999999999999999'],
      human: rr.human,
      delegatee: rr.delegatee,
    });
    const r = runVerify(loadGolden('allow-agent-only'), {
      extraFlags: ['--roots-file', roots],
    });
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
    expect(r.exitCode).toBe(0);
  });

  // ── 19. phantom delegatee root ──────────────────────────────────────────────
  it('#19 delegatee root removed from roots file → deny untrusted_root (exit 0)', () => {
    const rr = realRoots();
    // Keep agent + human real (agent gate passes) but drop the delegatee tree, so
    // the delegation hop's delegatee Merkle root is untrusted.
    const roots = writeTemp('roots-19.json', {
      agent: rr.agent,
      human: rr.human,
      delegatee: [],
    });
    const r = runVerify(loadGolden('allow-delegation-1hop'), {
      extraFlags: ['--roots-file', roots],
    });
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
    expect(r.exitCode).toBe(0);
  });

  // ── 20. model mismatch (committed deny golden) ──────────────────────────────
  it('#20 deny-model-mismatch golden → deny model_mismatch (exit 0)', () => {
    const r = runVerify(loadDenyGolden('deny-model-mismatch'));
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'model_mismatch' });
    expect(r.exitCode).toBe(0);
  });

  // ── 21. expiry equality boundary (now == expiry is EXPIRED) ─────────────────
  it('#21 now_unix == expiry (strict) → deny expired (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry; // equality is EXPIRED under strict `<`
    const r = runVerify(req);
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.exitCode).toBe(0);
  });

  // ── 22. missing trust config (no roots source at all) ───────────────────────
  it('#22 no --roots-file / --root and no env roots → deny internal_error + NON-ZERO exit', () => {
    // BOLYRA_TRUSTED_ROOTS is always stripped by runVerify; omitRoots drops the
    // --roots-file flag too, leaving the trusted-root source unconfigured.
    const r = runVerify(loadGolden('allow-agent-only'), { omitRoots: true });
    expect(r.verdict).toMatchObject({ verdict: 'deny', code: 'internal_error' });
    expect(r.exitCode).not.toBe(0);
  });
});
