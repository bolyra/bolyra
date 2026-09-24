// Validate a TENANTS map the way the Worker does (src/tenants.ts), before it is ever put:
// any defect in any entry makes the Worker fail EVERY tenant closed. Pure module: no
// imports, no I/O — test/tenants-check.spec.ts proves it agrees with the Worker's own
// loader. Error strings name org ids, the four known field names, and indexes; never a
// token, a key, or an unknown field name (an unknown key may itself be a pasted secret).
//
// CLI (used by tenant.sh):
//   node tenants-check.mjs < map.json           validate; print "ok: <n> tenants, <b> bytes"
//                                               (plus a warning at >= 80% of the ceiling)
//   node tenants-check.mjs --pass < map.json    same, then copy the validated map to stdout
//                                               so it can be piped on (into wrangler secret
//                                               put). The byte count reported is the count
//                                               of what --pass emits (trailing newlines
//                                               stripped); pipe --pass, never re-read the
//                                               file, so the Worker measures the same bytes.

export const ORG_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;
export const TOKEN_PATTERN = /^[A-Za-z0-9._~+\/-]{32,256}$/;
export const MAX_TENANTS_BYTES = 4096;
// Warn from 80% of the ceiling (3277 bytes) up to it: one more tenant is roughly 300–750
// bytes, so this is the last point at which growth can be planned rather than hit.
const WARN_TENANTS_BYTES = Math.ceil(MAX_TENANTS_BYTES * 0.8);
const TENANT_FIELDS = ['admin_token', 'verifier_token', 'trusted_operators', 'disabled'];
const OPERATOR_KEY = /^[0-9]+:[0-9]+$/;

/** True when any JSON object in `text` repeats a key (JSON.parse would silently keep the last). */
export function hasDuplicateKey(text) {
  const stack = []; // per open container: a Set of decoded keys for an object, null for an array
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      const start = i;
      let j = i + 1;
      while (j < text.length && text[j] !== '"') j += text[j] === '\\' ? 2 : 1;
      if (j >= text.length) return false; // unterminated string: JSON.parse rejects it anyway
      const quoted = text.slice(start, j + 1);
      let k = j + 1;
      while (k < text.length && (text[k] === ' ' || text[k] === '\n' || text[k] === '\r' || text[k] === '\t')) k += 1;
      if (text[k] === ':' && stack.length > 0 && stack[stack.length - 1] !== null) {
        // Compare DECODED keys, as JSON.parse does: "acme" and "acm\u0065" are the same key.
        let key;
        try {
          key = JSON.parse(quoted);
        } catch {
          return false; // malformed escape: JSON.parse rejects it anyway
        }
        const keys = stack[stack.length - 1];
        if (keys.has(key)) return true;
        keys.add(key);
      }
      i = j + 1;
      continue;
    }
    if (c === '{') stack.push(new Set());
    else if (c === '[') stack.push(null);
    else if (c === '}' || c === ']') stack.pop();
    i += 1;
  }
  return false;
}

/**
 * `warnings` never affect `ok`: they flag a map the Worker accepts today but that is close to
 * a limit (the size ceiling). They carry byte counts only.
 * @returns {{ ok: boolean, errors: string[], warnings: string[], bytes: number, orgs: string[] }}
 */
export function checkTenants(raw) {
  const errors = [];
  const warnings = [];
  const orgs = [];
  if (raw === undefined || raw === '') return { ok: false, errors: ['TENANTS is not configured (empty)'], warnings, bytes: 0, orgs };
  const bytes = new TextEncoder().encode(raw).byteLength;
  if (bytes >= MAX_TENANTS_BYTES) errors.push(`serialized size must be under ${MAX_TENANTS_BYTES} bytes (is ${bytes})`);
  else if (bytes >= WARN_TENANTS_BYTES) {
    warnings.push(`warning: ${bytes}/${MAX_TENANTS_BYTES} bytes (${MAX_TENANTS_BYTES - bytes} left) — plan tenant growth or raise the ceiling`);
  }
  if (hasDuplicateKey(raw)) errors.push('a JSON object repeats a key');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, errors: [...errors, 'not valid JSON'], warnings, bytes, orgs };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, errors: [...errors, 'must be a JSON object keyed by org_id'], warnings, bytes, orgs };
  }
  const entries = Object.entries(parsed);
  if (entries.length === 0) errors.push('no tenants configured (the Worker rejects an empty map)');
  const seenTokens = new Map(); // token -> where it was first seen (org/field), for a message without the value
  for (const [index, [orgId, value]] of entries.entries()) {
    const validOrg = ORG_ID_PATTERN.test(orgId);
    const where = validOrg ? `tenant "${orgId}"` : `entry #${index}`;
    if (!validOrg) errors.push(`${where}: org_id must match ^[a-z0-9][a-z0-9-]{1,62}$`);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      errors.push(`${where}: must be an object`);
      continue;
    }
    for (const field of Object.keys(value)) {
      // An unknown key may itself be a misplaced secret — name the tenant, never the key.
      if (!TENANT_FIELDS.includes(field)) errors.push(`${where}: has an unknown field (only ${TENANT_FIELDS.join(', ')} are allowed)`);
    }
    for (const field of ['admin_token', 'verifier_token']) {
      const token = value[field];
      if (typeof token !== 'string' || !TOKEN_PATTERN.test(token)) {
        errors.push(`${where}: ${field} must be 32–256 characters of [A-Za-z0-9._~+/-]`);
        continue;
      }
      const first = seenTokens.get(token);
      if (first !== undefined) errors.push(`${where}: ${field} repeats the token of ${first} (a repeated token grants nothing)`);
      else seenTokens.set(token, `${where} ${field}`);
    }
    const ops = value.trusted_operators;
    if (!Array.isArray(ops) || ops.length === 0) errors.push(`${where}: trusted_operators must be a non-empty array`);
    else {
      for (const [i, op] of ops.entries()) {
        // The Worker trims each entry before parsing it; match that.
        if (typeof op !== 'string' || !OPERATOR_KEY.test(op.trim())) errors.push(`${where}: trusted_operators[${i}] must be an x:y decimal pair`);
      }
    }
    if ('disabled' in value && typeof value.disabled !== 'boolean') errors.push(`${where}: disabled must be a boolean`);
    if (validOrg) orgs.push(orgId);
  }
  return { ok: errors.length === 0, errors, warnings, bytes, orgs };
}

// CLI entry (only when run directly under Node; the module is also imported by the tests).
if (typeof process !== 'undefined' && process.argv?.[1] && /tenants-check\.mjs$/.test(process.argv[1])) {
  const args = process.argv.slice(2);
  const pass = args.includes('--pass');
  const unknown = args.filter((a) => a !== '--pass');
  if (unknown.length > 0) {
    // A misspelled flag must not validate-and-emit-nothing: downstream that is an empty secret.
    process.stderr.write(`tenants-check: unknown argument ${JSON.stringify(unknown[0])} (only --pass is accepted)\n`);
    process.exit(2);
  }
  if (process.stdin.isTTY) {
    process.stderr.write('tenants-check: reads the TENANTS map on stdin: node tenants-check.mjs [--pass] < map.json\n');
    process.exit(2);
  }
  const chunks = [];
  process.stdin.on('error', (e) => {
    process.stderr.write(`tenants-check: could not read stdin (${e.code ?? 'error'})\n`);
    process.exit(2);
  });
  process.stdin.on('data', (d) => chunks.push(d));
  process.stdin.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8').replace(/[\r\n]+$/, '');
    const result = checkTenants(raw);
    // process.exit after synchronous writes is safe here: Node flushes pipe writes to
    // stdout/stderr synchronously on POSIX.
    if (!result.ok) {
      for (const e of result.errors) process.stderr.write(`tenants-check: ${e}\n`);
      process.stderr.write('tenants-check: REFUSED — this map would fail every tenant closed; nothing was pushed\n');
      process.exit(1);
    }
    for (const w of result.warnings) process.stderr.write(`tenants-check: ${w}\n`);
    process.stderr.write(`tenants-check: ok: ${result.orgs.length} tenant(s) [${result.orgs.join(', ')}], ${result.bytes} bytes\n`);
    if (pass) process.stdout.write(raw);
  });
}
