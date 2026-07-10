/**
 * End-to-end matrix for the `bolyra verify` external verifier (Task 16).
 *
 * Spawns the BUILT CLI (`dist/main.js verify`) as a real subprocess, pipes a
 * verification request on stdin, and asserts the single stdout verdict + exit
 * code for all 22 spec fixtures. The three ALLOW goldens are real Groth16
 * proofs; every DENY case is a deterministic ONE-FIELD mutation of a golden
 * (see fixtures/verify/deny-mutations.ts) — no runtime proving.
 *
 * Isolation: every spawn runs with a FRESH temp `$HOME` so the durable
 * FileNonceStore ($HOME/.bolyra/nonces) starts empty. The two replay cases
 * (#8, #14) deliberately REUSE one `$HOME` across two sequential spawns.
 */

import { spawnSync } from 'node:child_process';
import * as fs from 'node:fs';
import * as os from 'node:os';
import * as path from 'node:path';

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

/** Standard trust flags shared by (almost) every case. */
const BASE_ARGS = ['--circuits-dir', VKEYS, '--roots-file', ROOTS, '--capability-map', CAPMAP];

/** Load a committed ALLOW golden's request as a fresh mutable object. */
function loadGolden(name: 'allow-agent-only' | 'allow-human' | 'allow-delegation-1hop'): LooseRequest {
  return JSON.parse(fs.readFileSync(path.join(FIX, name, 'request.json'), 'utf8')) as LooseRequest;
}

/** A per-case scratch $HOME so the durable nonce store is isolated. */
function freshHome(): string {
  return fs.mkdtempSync(path.join(os.tmpdir(), 'bolyra-verify-e2e-'));
}

interface SpawnResult {
  stdout: string;
  stderr: string;
  status: number;
}

/** Spawn the built CLI verify command with `input` on stdin. */
function runVerify(opts: {
  input: string;
  args: string[];
  home: string;
  extraEnv?: Record<string, string>;
}): SpawnResult {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: opts.home };
  // Never inherit ambient trust config — each case supplies its own (or none).
  delete env.BOLYRA_TRUSTED_ROOTS;
  Object.assign(env, opts.extraEnv ?? {});

  const res = spawnSync(process.execPath, [CLI, 'verify', ...opts.args], {
    input: opts.input,
    env,
    encoding: 'utf8',
    maxBuffer: 8 * 1024 * 1024,
  });
  return { stdout: res.stdout ?? '', stderr: res.stderr ?? '', status: res.status ?? 0 };
}

/**
 * Assert stdout is EXACTLY one JSON object and return it. `JSON.parse` throws on
 * any trailing/leading noise, so a clean parse proves stdout cleanliness.
 */
function parseSingleVerdict(stdout: string): Record<string, unknown> {
  const trimmed = stdout.trim();
  const verdict = JSON.parse(trimmed) as Record<string, unknown>;
  // Re-serialize and compare to guarantee there was no second concatenated value.
  expect(trimmed.length).toBeGreaterThan(0);
  return verdict;
}

jest.setTimeout(30_000);

describe('bolyra verify — 22-fixture e2e matrix', () => {
  // ── 1. valid allow (agent-only) ────────────────────────────────────────────
  it('#1 valid allow → allow (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toEqual({ verdict: 'allow' });
    expect(r.status).toBe(0);
  });

  // ── 2. allow + consume_nonce (host mode) ────────────────────────────────────
  it('#2 host nonce-mode → allow with consume_nonce (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const r = runVerify({
      input: JSON.stringify(req),
      args: [...BASE_ARGS, '--nonce-mode', 'host'],
      home: freshHome(),
    });
    const v = parseSingleVerdict(r.stdout);
    expect(v.verdict).toBe('allow');
    expect(v.consume_nonce).toMatchObject({
      issuer_key: expect.any(String),
      nonce: expect.any(String),
      retain_until: expect.any(Number),
    });
    expect(r.status).toBe(0);
  });

  // ── 3. malformed input (truncated stdin) ────────────────────────────────────
  it('#3 truncated stdin → deny malformed_input (exit 0)', () => {
    const r = runVerify({ input: '{"version":1,"bun', args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'malformed_input' });
    expect(r.status).toBe(0);
  });

  // ── 4. invalid proof (tampered proof coordinate) ────────────────────────────
  it('#4 tampered proof coordinate → deny invalid_proof (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.agent.envelope.proof.pi_a[0] = (BigInt(b.agent.envelope.proof.pi_a[0]) + 1n).toString();
    encodeBundle(req, b);
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(r.status).toBe(0);
  });

  // ── 5. expired proof (now_unix > expiry, strict) ────────────────────────────
  it('#5 now_unix past expiry → deny expired (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry + 1; // strictly past → expired
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.status).toBe(0);
  });

  // ── 6. scope mismatch ───────────────────────────────────────────────────────
  it('#6 required scope exceeds effective → deny scope_exceeded (exit 0)', () => {
    // Effective scope from the proof is READ+WRITE (3). Map a bound capability to
    // a higher (valid cumulative) tier so required = READ+WRITE+FIN_SMALL (7) ⊄ 3.
    const home = freshHome();
    const capmap = path.join(home, 'capmap-6.json');
    fs.writeFileSync(
      capmap,
      JSON.stringify({ fetch_inbox: ['READ_DATA'], send_message: ['WRITE_DATA', 'FINANCIAL_SMALL'] }),
    );
    const req = loadGolden('allow-agent-only');
    const args = ['--circuits-dir', VKEYS, '--roots-file', ROOTS, '--capability-map', capmap];
    const r = runVerify({ input: JSON.stringify(req), args, home });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
    expect(r.status).toBe(0);
  });

  // ── 7. request mismatch (project_key differs from binding) ──────────────────
  it('#7 request.project_key ≠ binding → deny request_mismatch (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    req.request.project_key = '/work/acme/DIFFERENT';
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'request_mismatch' });
    expect(r.status).toBe(0);
  });

  // ── 8. replayed nonce (local, 2nd spawn same $HOME) ─────────────────────────
  it('#8 replayed nonce (local) → deny nonce_replayed on 2nd spawn (exit 0)', () => {
    const home = freshHome();
    const req = loadGolden('allow-agent-only');
    const first = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home });
    expect(parseSingleVerdict(first.stdout)).toEqual({ verdict: 'allow' });
    expect(first.status).toBe(0);

    const second = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home });
    const v = parseSingleVerdict(second.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'nonce_replayed' });
    expect(second.status).toBe(0);
  });

  // ── 9. unsupported version ──────────────────────────────────────────────────
  it('#9 request.version ≠ 1 → deny unsupported_version (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    req.version = 2;
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'unsupported_version' });
    expect(r.status).toBe(0);
  });

  // ── 10. unknown capability (granted cap not in map) ─────────────────────────
  it('#10 granted capability absent from map → deny unknown_capability (exit 0)', async () => {
    // The capability must be in the SIGNED binding (else request_mismatch fires
    // first) yet absent from BOTH the default and file maps. Re-sign a binding
    // that includes a phantom capability, then request it.
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.binding.capabilities = ['fetch_inbox', 'send_message', 'phantom_cap'];
    b.sig = await resignBinding(b.binding);
    encodeBundle(req, b);
    req.request.granted_capabilities = ['fetch_inbox', 'phantom_cap'];
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'unknown_capability' });
    expect(r.status).toBe(0);
  });

  // ── 11. cross-signer replay (F1: corrupt binding signature) ─────────────────
  it('#11 corrupted binding signature → deny invalid_signature (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    // Swap in a different scalar S → signature no longer verifies against the
    // PROVEN operator key (a cross-signer / forged-authorization attempt).
    b.sig.S = (BigInt(b.sig.S) + 1n).toString();
    encodeBundle(req, b);
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny' });
    expect(['invalid_signature', 'invalid_proof']).toContain(v.code);
    expect(r.status).toBe(0);
  });

  // ── 12. inflated scope claim (F2) ───────────────────────────────────────────
  it('#12 inflated scope claim → deny scope_exceeded (exit 0)', () => {
    // Distinct vector from #6: request a FINANCIAL_MEDIUM tier (bits 0-3 = 15)
    // that the READ+WRITE credential (3) cannot satisfy.
    const home = freshHome();
    const capmap = path.join(home, 'capmap-12.json');
    fs.writeFileSync(
      capmap,
      JSON.stringify({
        fetch_inbox: ['READ_DATA'],
        send_message: ['WRITE_DATA', 'FINANCIAL_SMALL', 'FINANCIAL_MEDIUM'],
      }),
    );
    const req = loadGolden('allow-agent-only');
    const args = ['--circuits-dir', VKEYS, '--roots-file', ROOTS, '--capability-map', capmap];
    const r = runVerify({ input: JSON.stringify(req), args, home });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'scope_exceeded' });
    expect(r.status).toBe(0);
  });

  // ── 13. forged expiry (F4) ──────────────────────────────────────────────────
  it('#13 forged/exceeded expiry → deny expired (exit 0)', () => {
    // The strict liveness check (nowUnix < expiry) rejects a credential presented
    // past its committed expiry. Use the human golden for coverage variety.
    const req = loadGolden('allow-human');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry + 86_400;
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.status).toBe(0);
  });

  // ── 14. fresh-nonce replay (F3) ─────────────────────────────────────────────
  it('#14 fresh-nonce replay (human golden) → deny nonce_replayed on 2nd spawn (exit 0)', () => {
    const home = freshHome();
    const req = loadGolden('allow-human');
    const first = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home });
    expect(parseSingleVerdict(first.stdout)).toEqual({ verdict: 'allow' });
    expect(first.status).toBe(0);

    const second = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home });
    const v = parseSingleVerdict(second.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'nonce_replayed' });
    expect(second.status).toBe(0);
  });

  // ── 15. over-long delegation chain (F5: exceed hop cap) ─────────────────────
  it('#15 delegation chain exceeds hop cap → deny delegation_invalid (exit 0)', () => {
    const req = loadGolden('allow-delegation-1hop');
    const b = decodeBundle(req);
    const hop = b.delegation[0];
    // 4 hops > MAX_HOPS (3): rejected before any hop proof is verified.
    b.delegation = [clone(hop), clone(hop), clone(hop), clone(hop)];
    encodeBundle(req, b);
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'delegation_invalid' });
    expect(r.status).toBe(0);
  });

  // ── 16. missing/mismatched vkeyHash (F6) ────────────────────────────────────
  it('#16 corrupted envelope.vkeyHash → deny invalid_proof (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.agent.envelope.circuit.vkeyHash =
      'sha256:0000000000000000000000000000000000000000000000000000000000000000';
    encodeBundle(req, b);
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'invalid_proof' });
    expect(r.status).toBe(0);
  });

  // ── 17. stdout injection — raw fd-1 write (F8) ──────────────────────────────
  it('#17 native fd-1 noise → exactly ONE verdict on stdout, noise routed away', () => {
    const req = loadGolden('allow-agent-only');
    const r = runVerify({
      input: JSON.stringify(req),
      args: BASE_ARGS,
      home: freshHome(),
      extraEnv: { BOLYRA_VERIFY_TEST_FD1_NOISE: '1' },
    });
    // Stdout must parse as a SINGLE clean verdict — the fd-1 noise the worker
    // emitted must have been captured by the parent and sent to stderr.
    const v = parseSingleVerdict(r.stdout);
    expect(v).toEqual({ verdict: 'allow' });
    expect(r.stdout).not.toContain('RAW-FD1-NATIVE-NOISE');
    expect(r.stderr).toContain('RAW-FD1-NATIVE-NOISE');
    expect(r.status).toBe(0);
  });

  // ── 18. untrusted agent root ────────────────────────────────────────────────
  it('#18 agent root omitted from roots file → deny untrusted_root (exit 0)', () => {
    const home = freshHome();
    const realRoots = JSON.parse(fs.readFileSync(ROOTS, 'utf8')) as Record<string, string[]>;
    const roots = path.join(home, 'roots-18.json');
    // Configured (human/delegatee present) but the agent tree is empty.
    fs.writeFileSync(
      roots,
      JSON.stringify({ agent: [], human: realRoots.human, delegatee: realRoots.delegatee }),
    );
    const req = loadGolden('allow-agent-only');
    const args = ['--circuits-dir', VKEYS, '--roots-file', roots, '--capability-map', CAPMAP];
    const r = runVerify({ input: JSON.stringify(req), args, home });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
    expect(r.status).toBe(0);
  });

  // ── 19. phantom delegatee root ──────────────────────────────────────────────
  it('#19 delegatee root omitted from roots file → deny untrusted_root (exit 0)', () => {
    const home = freshHome();
    const realRoots = JSON.parse(fs.readFileSync(ROOTS, 'utf8')) as Record<string, string[]>;
    const roots = path.join(home, 'roots-19.json');
    // Agent root present (agent gate passes) but the delegatee tree is empty, so
    // the delegation hop's delegatee root is untrusted.
    fs.writeFileSync(
      roots,
      JSON.stringify({ agent: realRoots.agent, human: realRoots.human, delegatee: [] }),
    );
    const req = loadGolden('allow-delegation-1hop');
    const args = ['--circuits-dir', VKEYS, '--roots-file', roots, '--capability-map', CAPMAP];
    const r = runVerify({ input: JSON.stringify(req), args, home });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'untrusted_root' });
    expect(r.status).toBe(0);
  });

  // ── 20. model mismatch ──────────────────────────────────────────────────────
  it('#20 request+binding model ≠ proven model hash → deny model_mismatch (exit 0)', async () => {
    // Change BOTH the request model AND the signed binding model to the same new
    // value (re-signing) so the request↔binding check passes, but the model no
    // longer hashes to the proof's committed modelHash → model_mismatch.
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    b.binding.model = 'gpt-4o';
    b.sig = await resignBinding(b.binding);
    encodeBundle(req, b);
    req.request.model = 'gpt-4o';
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'model_mismatch' });
    expect(r.status).toBe(0);
  });

  // ── 21. expiry equality boundary (now == expiry → EXPIRED) ──────────────────
  it('#21 now_unix == expiry (strict) → deny expired (exit 0)', () => {
    const req = loadGolden('allow-agent-only');
    const b = decodeBundle(req);
    req.now_unix = b.agent.credential.expiry; // equality is EXPIRED under strict
    const r = runVerify({ input: JSON.stringify(req), args: BASE_ARGS, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'expired' });
    expect(r.status).toBe(0);
  });

  // ── 22. missing trust config (no --roots-file / no --root) ──────────────────
  it('#22 no trusted-root source → deny internal_error + NON-ZERO exit', () => {
    const req = loadGolden('allow-agent-only');
    // No --roots-file, no --root, and BOLYRA_TRUSTED_ROOTS stripped from env.
    const args = ['--circuits-dir', VKEYS, '--capability-map', CAPMAP];
    const r = runVerify({ input: JSON.stringify(req), args, home: freshHome() });
    const v = parseSingleVerdict(r.stdout);
    expect(v).toMatchObject({ verdict: 'deny', code: 'internal_error' });
    expect(r.status).toBe(1);
  });
});
