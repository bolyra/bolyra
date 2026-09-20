// Validate a TENANTS map the way the Worker does (src/tenants.ts), before it is ever put:
// any defect in any entry makes the Worker fail EVERY tenant closed. Pure module: no
// imports, no I/O — test/tenants-check.spec.ts proves it agrees with the Worker's own
// loader. Error strings name org ids, field names, and indexes; never a token or a key.
//
// CLI (used by tenant.sh):
//   node tenants-check.mjs < map.json           validate; print "ok: <n> tenants, <b> bytes"
//   node tenants-check.mjs --pass < map.json    same, then copy the input to stdout so it
//                                               can be piped on (into wrangler secret put)

export const ORG_ID_PATTERN = /^[a-z0-9][a-z0-9-]{1,62}$/;
export const TOKEN_PATTERN = /^[A-Za-z0-9._~+\/-]{32,256}$/;
export const MAX_TENANTS_BYTES = 4096;
const TENANT_FIELDS = ['admin_token', 'verifier_token', 'trusted_operators', 'disabled'];
const OPERATOR_KEY = /^[0-9]+:[0-9]+$/;

/** True when any JSON object in `text` repeats a key (JSON.parse would silently keep the last). */
export function hasDuplicateKey(text) {
  const stack = []; // per open container: a Set of keys for an object, null for an array
  let i = 0;
  while (i < text.length) {
    const c = text[i];
    if (c === '"') {
      let j = i + 1;
      let raw = '';
      while (j < text.length && text[j] !== '"') {
        if (text[j] === '\\') {
          raw += text[j] + (text[j + 1] ?? '');
          j += 2;
        } else {
          raw += text[j];
          j += 1;
        }
      }
      let k = j + 1;
      while (k < text.length && /\s/.test(text[k])) k += 1;
      if (text[k] === ':' && stack.length > 0 && stack[stack.length - 1] !== null) {
        const keys = stack[stack.length - 1];
        if (keys.has(raw)) return true;
        keys.add(raw);
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

/** @returns {{ ok: boolean, errors: string[], bytes: number, orgs: string[] }} */
export function checkTenants(raw) {
  const errors = [];
  const orgs = [];
  if (raw === undefined || raw === '') return { ok: false, errors: ['TENANTS is not configured (empty)'], bytes: 0, orgs };
  const bytes = new TextEncoder().encode(raw).byteLength;
  if (bytes >= MAX_TENANTS_BYTES) errors.push(`serialized size must be under ${MAX_TENANTS_BYTES} bytes (is ${bytes})`);
  if (hasDuplicateKey(raw)) errors.push('a JSON object repeats a key');
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { ok: false, errors: [...errors, 'not valid JSON'], bytes, orgs };
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed)) {
    return { ok: false, errors: [...errors, 'must be a JSON object keyed by org_id'], bytes, orgs };
  }
  const entries = Object.entries(parsed);
  if (entries.length === 0) errors.push('no tenants configured (the Worker rejects an empty map)');
  const seenTokens = new Map(); // token -> where it was first seen (org/field), for a message without the value
  for (const [index, [orgId, value]] of entries.entries()) {
    const where = ORG_ID_PATTERN.test(orgId) ? `tenant "${orgId}"` : `entry #${index}`;
    if (!ORG_ID_PATTERN.test(orgId)) errors.push(`${where}: org_id must match ${ORG_ID_PATTERN}`);
    if (typeof value !== 'object' || value === null || Array.isArray(value)) {
      errors.push(`${where}: must be an object`);
      continue;
    }
    for (const field of Object.keys(value)) {
      if (!TENANT_FIELDS.includes(field)) errors.push(`${where}: unknown field "${field}"`);
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
        if (typeof op !== 'string' || !OPERATOR_KEY.test(op)) errors.push(`${where}: trusted_operators[${i}] must be an x:y decimal pair`);
      }
    }
    if ('disabled' in value && typeof value.disabled !== 'boolean') errors.push(`${where}: disabled must be a boolean`);
    if (ORG_ID_PATTERN.test(orgId)) orgs.push(orgId);
  }
  return { ok: errors.length === 0, errors, bytes, orgs };
}

// CLI entry (only when run directly under Node; the module is also imported by the tests).
if (typeof process !== 'undefined' && process.argv?.[1] && /tenants-check\.mjs$/.test(process.argv[1])) {
  const pass = process.argv.includes('--pass');
  const chunks = [];
  process.stdin.on('data', (d) => chunks.push(d));
  process.stdin.on('end', () => {
    const raw = Buffer.concat(chunks).toString('utf8').replace(/\r?\n$/, '');
    const result = checkTenants(raw);
    if (!result.ok) {
      for (const e of result.errors) process.stderr.write(`tenants-check: ${e}\n`);
      process.stderr.write('tenants-check: REFUSED — this map would fail every tenant closed; nothing was pushed\n');
      process.exit(1);
    }
    process.stderr.write(`tenants-check: ok: ${result.orgs.length} tenant(s) [${result.orgs.join(', ')}], ${result.bytes} bytes\n`);
    if (pass) process.stdout.write(raw);
  });
}
