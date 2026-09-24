#!/usr/bin/env node
/**
 * Post-deploy verification of a hosted-verify Worker (backlog E14). The logic and its
 * tests live in scripts/lib/verify-deploy-core.mjs and test-node/verify-deploy.test.mjs;
 * this file wires real `fetch`, the macOS keychain, the pending store and @bolyra/mpp.
 *
 *   node scripts/verify-deploy.mjs [<url>] [--version <id> | --from-wrangler]
 *        [--env production|staging|local] [--tenant <org>] [--allow-missing-tenant]
 *        [--pending-dir <path>] [--secrets-from-dev-vars]
 *
 *   <url>                the Worker's origin; defaults to $VERIFY_URL (scripts/with-worker.sh sets it)
 *   --from-wrangler      read `wrangler deploy` output on stdin and require its
 *                        "Current Version ID: <uuid>" (absent → exit 1: a failed deploy never passes)
 *   --env                keychain service bolyra-hosted-verify (production, the default) or
 *                        bolyra-hosted-verify-staging; `local` is a loopback `wrangler dev`
 *   --tenant <org>       run the behavioral leg with the keychain accounts
 *                        tenant-<org>-admin, tenant-<org>-verifier, operator-<org>-scalar
 *   --allow-missing-tenant   if any of the three is missing, say enforcement was NOT verified
 *                        and exit on the auth-boundary leg alone
 *   --pending-dir <path> default ~/.bolyra/canary-pending-<env>/ (one <credential_id>.pending file per canary)
 *   --secrets-from-dev-vars  LOCAL ONLY (refused for production and staging): the tenant's
 *                        placeholder tokens from .dev.vars.example and the repo's documented
 *                        test operator scalar 42
 *
 * The procedure (what it proves, the keychain accounts, resolving pending records) is
 * pilot/RUNBOOK.md §7, "Post-deploy verification". Secrets are never printed.
 */
import { execFileSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { homedir } from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { pendingStore } from './lib/pending-store.mjs';
import { AUDIENCE, DiagnosticError, MODEL, parseCliArgs, verifyDeploy } from './lib/verify-deploy-core.mjs';

const require = createRequire(import.meta.url);
const here = path.dirname(fileURLToPath(import.meta.url));

/** The repo's documented test-only operator scalar; the placeholder tenant trusts its public key. */
const LOCAL_TEST_SCALAR = 42n;

async function readStdin() {
  const chunks = [];
  for await (const chunk of process.stdin) chunks.push(chunk);
  return Buffer.concat(chunks).toString('utf8');
}

/** A keychain generic password, or null when the account is absent (or there is no keychain). */
function keychainReader(service) {
  return (account) => {
    try {
      const out = execFileSync('security', ['find-generic-password', '-s', service, '-a', account, '-w'], {
        encoding: 'utf8',
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return out.replace(/\n$/, '');
    } catch (e) {
      if (e?.status === 44) return null; // errSecItemNotFound
      if (e?.code === 'ENOENT') return null; // no security(1): not macOS
      throw new DiagnosticError(`keychain read of account ${account} in service ${service} failed (security exit ${e?.status ?? 'unknown'})`);
    }
  };
}

/** The placeholder tenant of .dev.vars.example — the tokens `wrangler dev` runs with (not secrets). */
function devVarsSecrets(org) {
  const example = readFileSync(path.join(here, '..', '.dev.vars.example'), 'utf8');
  const line = example.split(/\r?\n/).find((l) => l.startsWith('TENANTS='));
  if (line === undefined) throw new DiagnosticError('.dev.vars.example has no TENANTS line');
  const tenant = JSON.parse(line.slice('TENANTS='.length))[org];
  if (tenant === undefined) throw new DiagnosticError(`.dev.vars.example has no tenant ${org}`);
  return { adminToken: tenant.admin_token, verifierToken: tenant.verifier_token, scalar: LOCAL_TEST_SCALAR };
}

async function main() {
  let opts;
  try {
    opts = parseCliArgs(process.argv.slice(2), { fallbackUrl: process.env.VERIFY_URL });
  } catch (e) {
    console.error(e instanceof DiagnosticError ? e.message : 'bad arguments');
    return 2;
  }
  if (opts.fromWrangler && process.stdin.isTTY) {
    console.error('--from-wrangler reads `wrangler deploy` output on stdin, and stdin is a terminal: pipe the deploy into it (npm run deploy:staging / deploy:prod)');
    return 2;
  }
  const mpp = require('@bolyra/mpp');
  const pendingDir = opts.pendingDir ?? path.join(homedir(), '.bolyra', `canary-pending-${opts.env}`);
  return verifyDeploy(opts, {
    fetch: globalThis.fetch,
    print: (l) => console.log(l),
    printErr: (l) => console.error(l),
    readSecret: keychainReader(opts.keychainService),
    devVarsSecrets,
    log: pendingStore(pendingDir),
    makeIssuer: (scalar) => (agentName, expiry) =>
      mpp.issueMandate({ operatorPrivateKey: scalar, agentName, audience: AUDIENCE, model: MODEL, tier: 'small', expiry }),
    now: () => Date.now(),
    sleep: (ms) => new Promise((resolve) => setTimeout(resolve, ms)),
    wranglerOutput: opts.fromWrangler ? await readStdin() : undefined,
  });
}

main().then(
  (code) => {
    process.exitCode = code;
  },
  (e) => {
    // Our own diagnostics name an account, a route or a status; anything else may quote
    // environment- or server-supplied text, so only its class is shown.
    console.error(e instanceof DiagnosticError ? e.message : `unexpected ${e instanceof Error ? e.name : typeof e} (details withheld)`);
    process.exitCode = 1;
  },
);
