/**
 * External verifier transports: EVC v1 command spawn and hosted verifier URL.
 *
 * Both delegate the DECISION and keep the host obligations local
 * (spec/external-verifier-contract-v1.md §5–§7, mirroring spec/reference-host.js):
 *   - host-owned timeout (RECOMMENDED 10 000 ms) → kill + fail closed
 *   - stdout / response-body cap → fail closed
 *   - strict single-JSON-object parse of the verdict
 *   - strict §3.4 closed-schema verdict validation
 *   - non-zero exit, signal death, transport errors → fail closed
 *
 * Every failure class resolves to `deny code=internal_error`: the caller
 * never treats a broken verifier as an allow.
 */

import { spawn } from 'node:child_process';
import {
  deny,
  type ConsumeNonce,
  type EvcDenyCode,
  type Verdict,
  type VerifierRequest,
} from './types';

const DEFAULT_TIMEOUT_MS = 10_000;
const DEFAULT_MAX_STDOUT_BYTES = 1024 * 1024; // 1 MiB, spec §6
const DEFAULT_MAX_BODY_BYTES = 1024 * 1024; // response-body cap for URL mode

/** Spec §3.5: the closed three-member `kind` vocabulary. */
const VERDICT_KINDS: ReadonlySet<string> = new Set(['classical', 'zk', 'external']);

const EVC_DENY_CODES: ReadonlySet<string> = new Set([
  'malformed_input',
  'unsupported_version',
  'invalid_bundle',
  'invalid_proof',
  'untrusted_root',
  'delegation_invalid',
  'invalid_signature',
  'request_mismatch',
  'model_mismatch',
  'unknown_capability',
  'scope_exceeded',
  'expired',
  'nonce_missing',
  'nonce_replayed',
  'internal_error',
]);

function isPlainObject(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isConsumeNonce(value: unknown): value is ConsumeNonce {
  return (
    isPlainObject(value) &&
    typeof value.issuer_key === 'string' &&
    typeof value.nonce === 'string' &&
    typeof value.retain_until === 'number' &&
    Number.isInteger(value.retain_until) &&
    Object.keys(value).every((k) => ['issuer_key', 'nonce', 'retain_until'].includes(k))
  );
}

/**
 * Validate a spec §3.4 verdict object — CLOSED schemas: unknown members,
 * unrecognized `kind` values (§3.5), empty `consume_nonces` (minItems 1),
 * and non-integer `retain_until` all reject. Returns the typed verdict or
 * `null` when invalid (caller fails closed).
 */
export function validateVerdict(value: unknown): Verdict | null {
  if (!isPlainObject(value)) return null;
  if (value.kind !== undefined && (typeof value.kind !== 'string' || !VERDICT_KINDS.has(value.kind))) {
    return null;
  }

  if (value.verdict === 'allow') {
    for (const key of Object.keys(value)) {
      if (!['verdict', 'consume_nonces', 'kind'].includes(key)) return null;
    }
    if (value.consume_nonces !== undefined) {
      if (
        !Array.isArray(value.consume_nonces) ||
        value.consume_nonces.length === 0 || // minItems 1: "omitted, never []"
        !value.consume_nonces.every(isConsumeNonce)
      ) {
        return null;
      }
    }
    return value as unknown as Verdict;
  }

  if (value.verdict === 'deny') {
    for (const key of Object.keys(value)) {
      if (!['verdict', 'code', 'message', 'kind', 'detail'].includes(key)) return null;
    }
    if (typeof value.code !== 'string' || !EVC_DENY_CODES.has(value.code)) return null;
    if (typeof value.message !== 'string') return null;
    if (value.detail !== undefined && !isPlainObject(value.detail)) return null;
    return {
      verdict: 'deny',
      code: value.code as EvcDenyCode,
      message: value.message,
      ...(value.kind !== undefined ? { kind: value.kind } : {}),
      ...(value.detail !== undefined ? { detail: value.detail as Record<string, unknown> } : {}),
    };
  }

  return null;
}

/** Parse verifier output as exactly one JSON object, else `null`. */
function parseSingleVerdict(text: string): Verdict | null {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return null;
  }
  return validateVerdict(parsed);
}

/**
 * Spawn an EVC v1 verifier command: one JSON request on stdin, one verdict on
 * stdout. Fail-closed on timeout, oversized stdout, signal death, unparseable
 * output, and non-zero exit (a non-zero exit is honored only as
 * `deny code=internal_error`, per spec §7.1).
 */
export function runCommandVerifier(
  config: { command: string; args?: string[]; timeoutMs?: number; maxStdoutBytes?: number },
  request: VerifierRequest,
): Promise<Verdict> {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxStdoutBytes = config.maxStdoutBytes ?? DEFAULT_MAX_STDOUT_BYTES;

  return new Promise<Verdict>((resolve) => {
    let settled = false;
    const settle = (verdict: Verdict) => {
      if (settled) return;
      settled = true;
      resolve(verdict);
    };

    let child: ReturnType<typeof spawn>;
    try {
      child = spawn(config.command, config.args ?? [], {
        stdio: ['pipe', 'pipe', 'inherit'],
      });
    } catch (err) {
      settle(deny('internal_error', 'verifier spawn failed'));
      return;
    }

    const chunks: Buffer[] = [];
    let stdoutBytes = 0;

    const timer = setTimeout(() => {
      child.kill('SIGKILL');
      settle(deny('internal_error', `verifier timed out after ${timeoutMs}ms`));
    }, timeoutMs);

    child.on('error', () => {
      clearTimeout(timer);
      settle(deny('internal_error', 'verifier spawn failed'));
    });

    child.stdout?.on('data', (chunk: Buffer) => {
      stdoutBytes += chunk.length;
      if (stdoutBytes > maxStdoutBytes) {
        clearTimeout(timer);
        child.kill('SIGKILL');
        settle(deny('internal_error', 'verifier stdout exceeded the output cap'));
        return;
      }
      chunks.push(chunk);
    });

    child.on('close', (code, signal) => {
      clearTimeout(timer);
      if (settled) return;
      if (signal !== null) {
        settle(deny('internal_error', `verifier died with signal ${signal}`));
        return;
      }
      const verdict = parseSingleVerdict(Buffer.concat(chunks).toString('utf8').trim());
      if (verdict === null) {
        settle(deny('internal_error', 'verifier produced no valid verdict'));
        return;
      }
      if (code !== 0) {
        // Spec §7.1: only `internal_error` may pair with a non-zero exit.
        if (verdict.verdict === 'deny' && verdict.code === 'internal_error') {
          settle(verdict);
        } else {
          settle(deny('internal_error', `verifier exited non-zero (${code})`));
        }
        return;
      }
      settle(verdict);
    });

    child.stdin?.on('error', () => {
      // EPIPE when the verifier exits early; `close` decides the outcome.
    });
    child.stdin?.end(JSON.stringify(request));
  });
}

/** Read a response body as text, failing closed past `maxBytes`. */
async function readBodyCapped(response: Response, maxBytes: number): Promise<string | null> {
  const reader = response.body?.getReader();
  if (!reader) {
    const text = await response.text();
    return new TextEncoder().encode(text).byteLength > maxBytes ? null : text;
  }
  const chunks: Uint8Array[] = [];
  let received = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    received += value.byteLength;
    if (received > maxBytes) {
      await reader.cancel().catch(() => undefined);
      return null;
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString('utf8');
}

/** The hosted verifier's verify route, appended to a bare-origin `url`. */
const DEFAULT_VERIFY_PATH = '/v1/verify';

/**
 * Verifier URL convention: `url` is the verifier's origin, or a full URL to
 * its verify route. ONLY a bare origin is rewritten: when the path portion
 * of the string AS WRITTEN is `''` or `/`, it becomes `/v1/verify`, keeping
 * any query string and fragment. Dot segments such as `/..` or `/%2e` are
 * not roots. Every other URL, including a custom path with a trailing slash
 * and any query, is returned byte-for-byte. Throws `TypeError` when `url` is
 * not an absolute `scheme://authority` URL or has leading/trailing whitespace
 * (never trimmed).
 *
 * Exported as a helper for pre-validating a configured verifier URL (e.g. at
 * startup, or to log the exact endpoint the gate will POST to).
 */
export function normalizeVerifierUrl(url: string): string {
  // URL parsing silently trims surrounding whitespace, which would make the
  // string-as-written root check below disagree with the endpoint used.
  if (/^\s|\s$/.test(url)) {
    throw new TypeError('verifier url must not have leading or trailing whitespace');
  }
  const parsed = new URL(url); // validation only: URL parsing collapses dot segments
  // Rewrite eligibility comes from the ORIGINAL string's path portion (after
  // the authority, before `?` / `#`), never from `parsed.pathname`:
  // `/custom/..` and `/%2e` parse to `/` but are not bare origins.
  const authority = /^[A-Za-z][A-Za-z0-9+.-]*:\/\/[^/\\?#]*/.exec(url);
  if (authority === null) {
    throw new TypeError('verifier url must have the form scheme://authority[/path]');
  }
  const rest = url.slice(authority[0].length);
  const pathEnd = rest.search(/[?#]/);
  const path = pathEnd === -1 ? rest : rest.slice(0, pathEnd);
  if (path !== '' && path !== '/') return url;
  parsed.pathname = DEFAULT_VERIFY_PATH;
  return parsed.href;
}

/** Configuration for a hosted verifier endpoint (URL mode). */
export interface UrlVerifierConfig {
  /** Verifier origin (→ `/v1/verify`) or full verify-route URL; see {@link normalizeVerifierUrl}. */
  url: string;
  /** Bearer token sent as `Authorization: Bearer <token>`. */
  token?: string;
  /** Host-owned timeout. Default 10 000 ms. */
  timeoutMs?: number;
  /** Cap on the verdict response body; overflow fails closed. Default 1 MiB. */
  maxBodyBytes?: number;
}

/**
 * What a hosted verifier call produced, beyond the verdict: the HTTP status
 * (absent when no HTTP response was received — unreachable, timed out) and
 * the raw `x-bolyra-credential-id` / `x-bolyra-receipt` response headers
 * (absent when the response did not carry them; never decoded or verified
 * here). The verdict carries the same fail-closed semantics as
 * {@link callUrlVerifier}; evidence never turns a deny into an allow.
 */
export interface UrlVerifierEvidence {
  verdict: Verdict;
  status?: number;
  credentialId?: string;
  receipt?: string;
}

/** Hosted-verifier response headers surfaced as evidence. */
const CREDENTIAL_ID_HEADER = 'x-bolyra-credential-id';
const RECEIPT_HEADER = 'x-bolyra-receipt';

/**
 * POST the spec §2.1 request to a hosted verifier and return the verdict
 * plus the call's evidence (HTTP status, raw credential-id and receipt
 * headers). Decision semantics are identical to {@link callUrlVerifier}:
 * 200 = decision; 500 may carry only `deny internal_error`; any other
 * status, transport failure, non-verdict or oversized body, timeout, or an
 * invalid `url` fails closed with `deny internal_error`. A bare-origin `url`
 * is POSTed to `/v1/verify` ({@link normalizeVerifierUrl}).
 */
export async function callUrlVerifierWithEvidence(
  config: UrlVerifierConfig,
  request: VerifierRequest,
): Promise<UrlVerifierEvidence> {
  const timeoutMs = config.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  const maxBodyBytes = config.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let evidence: Omit<UrlVerifierEvidence, 'verdict'> = {};
  try {
    // Inside the try: an invalid URL fails closed like any transport fault.
    const url = normalizeVerifierUrl(config.url);
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        ...(config.token !== undefined ? { authorization: `Bearer ${config.token}` } : {}),
      },
      body: JSON.stringify(request),
      signal: controller.signal,
    });
    const credentialId = response.headers.get(CREDENTIAL_ID_HEADER);
    const receipt = response.headers.get(RECEIPT_HEADER);
    evidence = {
      status: response.status,
      ...(credentialId !== null ? { credentialId } : {}),
      ...(receipt !== null ? { receipt } : {}),
    };
    const withVerdict = (verdict: Verdict): UrlVerifierEvidence => ({ verdict, ...evidence });

    // 200 = decision (allow or policy/crypto deny); 500 may carry a
    // deny internal_error verdict. Anything else is a transport fault.
    if (response.status !== 200 && response.status !== 500) {
      return withVerdict(deny('internal_error', `verifier endpoint returned HTTP ${response.status}`));
    }
    const text = await readBodyCapped(response, maxBodyBytes);
    if (text === null) {
      return withVerdict(deny('internal_error', 'verifier endpoint response exceeded the body cap'));
    }
    let body: unknown;
    try {
      body = JSON.parse(text);
    } catch {
      return withVerdict(deny('internal_error', 'verifier endpoint returned a non-JSON body'));
    }
    const verdict = validateVerdict(body);
    if (verdict === null) {
      return withVerdict(deny('internal_error', 'verifier endpoint returned an invalid verdict'));
    }
    if (response.status === 500 && !(verdict.verdict === 'deny' && verdict.code === 'internal_error')) {
      return withVerdict(deny('internal_error', 'verifier endpoint returned HTTP 500'));
    }
    return withVerdict(verdict);
  } catch {
    return { verdict: deny('internal_error', 'verifier endpoint unreachable or timed out'), ...evidence };
  } finally {
    clearTimeout(timer);
  }
}

/**
 * POST the spec §2.1 request to a hosted verifier (e.g. the Bolyra
 * hosted-verify preview's `POST /v1/verify`). Any decision — allow or deny —
 * arrives as a verdict body; transport failures, non-verdict bodies,
 * oversized bodies, and timeouts fail closed. Returns the verdict only; use
 * {@link callUrlVerifierWithEvidence} for the HTTP status and headers.
 */
export async function callUrlVerifier(
  config: UrlVerifierConfig,
  request: VerifierRequest,
): Promise<Verdict> {
  return (await callUrlVerifierWithEvidence(config, request)).verdict;
}
