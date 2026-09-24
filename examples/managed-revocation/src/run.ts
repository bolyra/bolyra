/**
 * The revocation demonstration, end to end, against a running hosted verifier:
 *
 *   /health ─► issue ─► register ─► spend (allow, counter 1) ─► spend again with a fresh
 *   presentation (allow, counter 2) ─► REVOKE ─► spend with a fresh presentation
 *   (deny untrusted_root / credential_not_active, counter still 2) ─► an independent
 *   credential under the same operator (allow, counter 3).
 *
 * Two evidence sources, labelled in the output:
 *   [gate]     what the published @bolyra/mpp gate proves — the counter and the Problem
 *              Details `code`; plus the in-process verdict the gate threw.
 *   [verifier] what only the hosted verifier shows — the `x-bolyra-credential-id` header,
 *              the signed receipt (checked with `bolyra receipt verify`), and the deny
 *              `detail` (`reason`, `credential_id`); plus the registered id checked against
 *              one derived in-process from the mandate (`credentialId(operator key,
 *              bindingDigest(binding))` with this example's installed @bolyra/mpp and
 *              src/credential-id.ts, a node:crypto mirror of the Worker's derivation), so a
 *              digest or id drift between the Worker and the published package is caught.
 *
 * Environment: VERIFY_URL (default http://127.0.0.1:8787), ADMIN_TOKEN and VERIFIER_TOKEN
 * (default: the placeholder tenant of integrations/hosted-verify/.dev.vars.example — not
 * secrets). Exit code 0 only when every check passed. Nothing prints a token: every value
 * shown comes from an allowlist, and anything a verifier returns outside it is withheld.
 * Runs are independent: each issues bindings under a per-run agent name.
 */
import { randomBytes } from 'node:crypto';
import { Receipt } from 'mppx';
import { bindingDigest, issueMandate, type BindingClaim, type IssuedMandate } from '@bolyra/mpp';
import { paidCall } from './client.js';
import { credentialId } from './credential-id.js';
import { AUDIENCE, MODEL, createServer } from './server.js';
import { DiagnosticError, health, register, registrationOf, revoke, verify, verifyReceiptWithCli, type HostedVerifier } from './verifier.js';
import { CLI_VERSION, PACKAGES } from './versions.js';

/** The repo's documented test-only operator scalar; the placeholder tenant trusts its public key. */
const OPERATOR_PRIVATE_KEY = 42n;
const EXPIRY = Math.floor(Date.now() / 1000) + 3600;
/**
 * `wrangler dev` keeps the registry's SQLite under .wrangler/state across restarts, so a
 * run must not reuse a binding an earlier run revoked: the agent name carries a per-run
 * suffix (a different binding ⇒ a different credential id).
 */
const RUN = randomBytes(4).toString('hex');
const AGENT = `managed-revocation-agent-${RUN}`;
const OTHER_AGENT = `${AGENT}-2`;

const hosted: HostedVerifier = {
  url: (process.env.VERIFY_URL ?? 'http://127.0.0.1:8787').replace(/\/+$/, ''),
  adminToken: process.env.ADMIN_TOKEN ?? 'local-admin-token-000000000000000000',
  verifierToken: process.env.VERIFIER_TOKEN ?? 'local-verifier-token-0000000000000000',
};
/** A bearer token is printable ASCII without spaces; anything else would make a header library quote it in an error. */
const TOKEN_SHAPE = /^[\x21-\x7e]{1,256}$/;

// ─── What may be printed. Anything else a server sends back is withheld. ───────────────
const WITHHELD = '<unexpected value withheld>';
const VERDICTS = ['allow', 'deny'] as const;
const DENY_CODES = [
  'missing_authorization', 'malformed_input', 'unsupported_version', 'invalid_bundle', 'invalid_proof',
  'invalid_signature', 'untrusted_root', 'delegation_invalid', 'request_mismatch', 'model_mismatch',
  'unknown_capability', 'scope_exceeded', 'expired', 'nonce_missing', 'nonce_replayed', 'internal_error',
] as const;
const REASONS = ['credential_not_active'] as const;
const REGISTRY_ERRORS = ['credential_revoked', 'binding_expired', 'untrusted_operator', 'not_found', 'internal_error'] as const;
const TENANT_STATES = ['ok', 'invalid'] as const;
const VERIFIER_KINDS = ['url', 'classical', 'command'] as const;
const TIERS = ['small', 'medium', 'unlimited'] as const;

/** Show `value` only if it is one of `allowed`; booleans, numbers, and absence are shown as such. */
function shown(value: unknown, allowed: readonly string[]): string {
  if (value === undefined || value === null) return 'absent';
  if (typeof value === 'boolean' || typeof value === 'number') return String(value);
  return typeof value === 'string' && allowed.includes(value) ? value : WITHHELD;
}

/** A credential id is shown truncated, and only when it has the id's exact shape. */
function shownId(value: unknown): string {
  return typeof value === 'string' && /^[0-9a-f]{64}$/.test(value) ? `${value.slice(0, 16)}…` : WITHHELD;
}

interface Row { source: '[gate]' | '[verifier]'; step: string; expected: string; observed: string; ok: boolean }
const rows: Row[] = [];
function check(source: Row['source'], step: string, ok: boolean, expected: string, observed: string): void {
  rows.push({ source, step, expected, observed, ok });
  console.log(`${ok ? '  ok ' : ' FAIL'} ${source} ${step}: ${observed}${ok ? '' : ` (expected ${expected})`}`);
}

/** One presentation of a mandate. Every presentation of the same input shares the signed binding and gets a fresh nullifier. */
function issue(agentName: string): Promise<IssuedMandate> {
  return issueMandate({ operatorPrivateKey: OPERATOR_PRIVATE_KEY, agentName, audience: AUDIENCE, model: MODEL, tier: 'small', expiry: EXPIRY });
}

function detailOf(verdict: { detail?: unknown } | undefined): { reason?: unknown; credential_id?: unknown } {
  const d = verdict?.detail;
  return typeof d === 'object' && d !== null ? (d as { reason?: unknown; credential_id?: unknown }) : {};
}

async function main(): Promise<void> {
  if (!TOKEN_SHAPE.test(hosted.adminToken) || !TOKEN_SHAPE.test(hosted.verifierToken)) {
    throw new DiagnosticError('ADMIN_TOKEN and VERIFIER_TOKEN must be printable ASCII without spaces (values withheld)');
  }
  console.log(`managed revocation — @bolyra/mpp ${PACKAGES.mpp}, mppx ${PACKAGES.mppx}, @bolyra/cli ${CLI_VERSION}, verifier ${hosted.url}\n`);

  // 0. The verifier is a registry-enforcing build with a parsed tenant config and receipts on.
  const h = await health(hosted);
  check('[verifier]', 'GET /health registry_enforced + tenants', h.registry_enforced === true && h.tenants === 'ok', 'registry_enforced true, tenants ok', `registry_enforced ${shown(h.registry_enforced, [])}, tenants ${shown(h.tenants, TENANT_STATES)}`);
  check('[verifier]', 'GET /health receipts_enabled', h.receipts_enabled === true, 'true — scripts/dev-vars.mjs writes the signing key the Worker needs (demo:local runs it)', shown(h.receipts_enabled, []));

  const server = createServer({ url: hosted.url, token: hosted.verifierToken });

  // 1. Issue and register. The registration is the signed binding lifted from the presentation.
  const mandate = await issue(AGENT);
  const reg = await register(hosted, mandate);
  const id = reg.credential_id ?? '';
  check('[verifier]', 'POST /v1/credentials (new binding)', reg.status === 201 && id !== '', '201 + credential_id', `${reg.status} ${shownId(id)}`);
  // The same object register() sends: the signed binding lifted from the presentation.
  const registration = registrationOf(mandate);
  const localId = credentialId(
    { x: BigInt(registration.operator_pubkey.x), y: BigInt(registration.operator_pubkey.y) },
    bindingDigest(registration.binding as BindingClaim),
  );
  check('[verifier]', 'credential_id equals the id derived in-process from the mandate', id === localId, 'same id', id === localId ? 'same id' : 'DIFFERENT id');
  const again = await register(hosted, await issue(AGENT));
  check('[verifier]', 'POST /v1/credentials (same binding, fresh presentation)', again.status === 200 && again.credential_id === id, '200, same id', `${again.status} ${again.credential_id === id ? 'same id' : 'DIFFERENT id'}`);

  // 2. Spend: one 402→pay handshake, two fresh presentations, the action runs once.
  const paid1 = await paidCall(server.handler, (await issue(AGENT)).presentation, (await issue(AGENT)).presentation);
  check('[gate]', 'paid call #1', paid1.status === 200 && server.state.counter === 1, '200, counter 1', `${paid1.status}, counter ${server.state.counter}`);
  const encoded1 = paid1.headers.get('Payment-Receipt');
  const receipt1 = (encoded1 === null ? {} : Receipt.deserialize(encoded1)) as { bolyraAuthorization?: { verifier?: unknown; tier?: unknown } };
  check('[gate]', 'Payment-Receipt.bolyraAuthorization', encoded1 !== null && receipt1.bolyraAuthorization?.verifier === 'url' && receipt1.bolyraAuthorization?.tier === 'small', 'verifier url, tier small', encoded1 === null ? 'no Payment-Receipt header' : `verifier ${shown(receipt1.bolyraAuthorization?.verifier, VERIFIER_KINDS)}, tier ${shown(receipt1.bolyraAuthorization?.tier, TIERS)}`);

  // 3. What the verifier adds on an allow: the credential id header and a signed receipt.
  const v1 = await verify(hosted, await issue(AGENT));
  check('[verifier]', 'POST /v1/verify verdict', v1.status === 200 && v1.verdict.verdict === 'allow', '200 allow', `${v1.status} ${shown(v1.verdict.verdict, VERDICTS)}`);
  check('[verifier]', 'x-bolyra-credential-id equals the registered id', v1.credentialIdHeader === id, 'the registered id', v1.credentialIdHeader === null ? 'absent' : v1.credentialIdHeader === id ? 'the registered id' : 'a DIFFERENT id');
  let receiptOk = false;
  let receiptLine = 'no receipt header';
  if (v1.receiptHeader !== null) {
    try {
      receiptOk = verifyReceiptWithCli(hosted, v1.receiptHeader).startsWith('PASS');
      receiptLine = receiptOk ? 'PASS: receipt signature valid' : 'the CLI did not report PASS (output withheld)';
    } catch {
      receiptLine = 'bolyra receipt verify exited non-zero (output withheld)';
    }
  }
  check('[verifier]', 'x-bolyra-receipt → bolyra receipt verify --signer-from', receiptOk, 'PASS', receiptLine);

  // 4. Spend again with fresh presentations: still allowed, counter 2.
  const paid2 = await paidCall(server.handler, (await issue(AGENT)).presentation, (await issue(AGENT)).presentation);
  check('[gate]', 'paid call #2 (fresh presentations)', paid2.status === 200 && server.state.counter === 2, '200, counter 2', `${paid2.status}, counter ${server.state.counter}`);

  // 5. REVOKE. From here every fresh presentation of this binding must deny.
  const revoked = await revoke(hosted, id);
  check('[verifier]', 'POST /v1/credentials/{id}/revoke', revoked === 204, '204', String(revoked));
  const revokedAgain = await revoke(hosted, id);
  check('[verifier]', 'revoke again (idempotent)', revokedAgain === 204, '204', String(revokedAgain));
  const reRegister = await register(hosted, await issue(AGENT));
  check('[verifier]', 'POST /v1/credentials after revoke (terminal)', reRegister.status === 409 && reRegister.error === 'credential_revoked', '409 credential_revoked', `${reRegister.status} ${shown(reRegister.error, REGISTRY_ERRORS)}`);

  // 6. The gate denies before any 402; the paid action does not run.
  const denied = await paidCall(server.handler, (await issue(AGENT)).presentation, (await issue(AGENT)).presentation);
  const problem = (await denied.json()) as { code?: unknown; detail?: unknown };
  check('[gate]', 'paid call #3 after revoke', denied.status === 401 && problem.code === 'untrusted_root' && server.state.counter === 2, '401 untrusted_root, counter 2', `${denied.status} ${shown(problem.code, DENY_CODES)}, counter ${server.state.counter}`);
  const thrown = detailOf(server.state.lastDenial);
  check('[gate]', 'in-process verdict.detail (the wire body carries only the message; the id is cross-checked against the registration)', thrown.reason === 'credential_not_active' && thrown.credential_id === id, 'credential_not_active, registered id', `${shown(thrown.reason, REASONS)}, ${thrown.credential_id === id ? 'registered id' : 'a DIFFERENT id'}`);

  // 7. The verifier's own words for the same presentation.
  const v2 = await verify(hosted, await issue(AGENT));
  const d2 = detailOf(v2.verdict);
  check('[verifier]', 'POST /v1/verify after revoke', v2.status === 200 && v2.verdict.verdict === 'deny' && v2.verdict.code === 'untrusted_root', '200 deny untrusted_root', `${v2.status} ${shown(v2.verdict.verdict, VERDICTS)} ${shown(v2.verdict.code, DENY_CODES)}`);
  check('[verifier]', 'deny detail', d2.reason === 'credential_not_active' && d2.credential_id === id, 'credential_not_active, registered id', `${shown(d2.reason, REASONS)}, ${d2.credential_id === id ? 'registered id' : 'a DIFFERENT id'}`);
  check('[verifier]', 'no x-bolyra-credential-id on a deny', v2.credentialIdHeader === null, 'absent', v2.credentialIdHeader === null ? 'absent' : 'present');

  // 8. An independent credential under the same operator is unaffected.
  const other = await issue(OTHER_AGENT);
  const regOther = await register(hosted, other);
  check('[verifier]', 'register an independent binding (same operator)', regOther.status === 201 && regOther.credential_id !== undefined && regOther.credential_id !== id, '201, a different id', `${regOther.status} ${regOther.credential_id === undefined ? 'no id' : regOther.credential_id === id ? 'the SAME id' : 'a different id'}`);
  const paid3 = await paidCall(server.handler, (await issue(OTHER_AGENT)).presentation, (await issue(OTHER_AGENT)).presentation);
  check('[gate]', 'paid call #4 with the independent credential', paid3.status === 200 && server.state.counter === 3, '200, counter 3', `${paid3.status}, counter ${server.state.counter}`);

  const failed = rows.filter((r) => !r.ok);
  console.log(`\n${rows.length - failed.length}/${rows.length} checks passed; counter ended at ${server.state.counter} (expected trajectory 1 → 2 → revoke → 2 → 3).`);
  if (failed.length > 0) {
    console.error(`\n${failed.length} check(s) failed:`);
    for (const r of failed) console.error(`  ${r.source} ${r.step}: expected ${r.expected}, observed ${r.observed}`);
    process.exitCode = 1;
  }
}

main().catch((e: unknown) => {
  // Only our own diagnostics are printed: they name a route, a status, and a byte count.
  // Any other error may quote server- or environment-supplied text, so only its class is shown.
  console.error(e instanceof DiagnosticError ? e.message : `unexpected ${e instanceof Error ? e.name : typeof e} (details withheld)`);
  process.exitCode = 1;
});
