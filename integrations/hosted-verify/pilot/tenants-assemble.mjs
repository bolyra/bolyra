// Assemble the TENANTS map for `tenant.sh sync`: one entry per registry file in the
// directory given as argv[2] whose status is active or disabled, tokens read from stdin
// as lines "<org_id> <admin|verifier> <token>". The map is written to stdout and nowhere
// else; nothing is logged. Registry files hold no secrets.
//
// `assemble(dir, tokenText)` is the whole of the logic and is exported for
// test-node/tenants-assemble.test.mjs; the CLI below is a thin wrapper. Every refusal is an
// AssembleError whose message names the file, the org, or the token LINE NUMBER an operator
// has to fix — never a token.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const ROLES = ['admin', 'verifier'];

export class AssembleError extends Error {
  constructor(message) {
    super(message);
    this.name = 'AssembleError';
  }
}

const isPlainObject = (v) => typeof v === 'object' && v !== null && !Array.isArray(v);

/** Parse "<org> <role> <token>" lines into a Map keyed "org role". */
function parseTokens(tokenText) {
  const tokens = new Map(); // "org role" -> token
  const rows = tokenText.split('\n');
  for (const [i, line] of rows.entries()) {
    if (line === '') continue;
    const first = line.indexOf(' ');
    const second = first < 0 ? -1 : line.indexOf(' ', first + 1);
    const org = first < 0 ? '' : line.slice(0, first);
    const role = second < 0 ? '' : line.slice(first + 1, second);
    const token = second < 0 ? '' : line.slice(second + 1);
    if (!org || !role || !token) throw new AssembleError(`token line ${i + 1}: malformed (expected "<org_id> <role> <token>")`);
    if (!ROLES.includes(role)) throw new AssembleError(`token line ${i + 1}: role must be admin or verifier`);
    const key = `${org} ${role}`;
    // A second line for the same pair used to overwrite the first silently: which token went
    // live would then depend on line order, not on anything an operator decided.
    if (tokens.has(key)) throw new AssembleError(`token line ${i + 1}: a second token for ${key}`);
    tokens.set(key, token);
  }
  return tokens;
}

/**
 * @param {string} dir the registry directory
 * @param {string} tokenText "<org_id> <role> <token>" lines
 * @returns {Record<string, {admin_token: string, verifier_token: string, trusted_operators: unknown[], disabled?: true}>}
 */
export function assemble(dir, tokenText) {
  const tokens = parseTokens(tokenText);
  const map = {};
  // A dot-file (an AppleDouble ._acme.json copied off a USB stick) and anything that is not
  // a regular file (a directory named x.json) are not registry records — skipping them keeps
  // one stray entry from blocking every tenant's sync.
  const files = readdirSync(dir)
    .filter((f) => !f.startsWith('.') && f.endsWith('.json') && !f.endsWith('.policy.json'))
    .filter((f) => {
      try {
        return statSync(path.join(dir, f)).isFile();
      } catch {
        return false;
      }
    })
    .sort();
  for (const f of files) {
    const org = path.basename(f, '.json');
    let record;
    try {
      record = JSON.parse(readFileSync(path.join(dir, f), 'utf8'));
    } catch {
      // Name the file. A Node stack trace here tells an operator nothing they can act on.
      throw new AssembleError(`${f}: not valid JSON`);
    }
    // `null`, an array or a scalar parses fine and would otherwise die on `record.org_id`
    // with a TypeError that names no file.
    if (!isPlainObject(record)) throw new AssembleError(`${f}: record must be a JSON object`);
    if (record.org_id !== org) throw new AssembleError(`${f}: org_id must equal the file name`);
    if (record.status === 'removed') continue;
    if (record.status !== 'active' && record.status !== 'disabled') {
      throw new AssembleError(`${f}: status must be active, disabled, or removed`);
    }
    const admin = tokens.get(`${org} admin`);
    const verifier = tokens.get(`${org} verifier`);
    if (admin === undefined || verifier === undefined) throw new AssembleError(`${org}: missing a token for admin or verifier`);
    if (!Array.isArray(record.trustedOperators)) {
      // Refuse rather than pass it through: the validator would reject it downstream with a
      // message about the map, not about the file an operator has to fix.
      throw new AssembleError(`${f}: trustedOperators must be an array`);
    }
    // Dedupe, first-seen order preserved: a repeated key grants nothing and spends the
    // 4096-byte TENANTS budget that every other tenant shares.
    const trusted = [...new Set(record.trustedOperators)];
    const entry = { admin_token: admin, verifier_token: verifier, trusted_operators: trusted };
    if (record.status === 'disabled') entry.disabled = true;
    map[org] = entry;
  }
  return map;
}

// CLI entry (only when run directly under Node; the module is also imported by the tests).
if (typeof process !== 'undefined' && process.argv?.[1] && /tenants-assemble\.mjs$/.test(process.argv[1])) {
  const dir = process.argv[2];
  if (!dir) {
    process.stderr.write('usage: tenants-assemble.mjs <registry-dir> < tokens\n');
    process.exit(2);
  }
  const chunks = [];
  process.stdin.on('error', (e) => {
    process.stderr.write(`tenants-assemble: could not read stdin (${e.code ?? 'error'})\n`);
    process.exit(1);
  });
  process.stdin.on('data', (d) => chunks.push(d));
  process.stdin.on('end', () => {
    let map;
    try {
      map = assemble(dir, Buffer.concat(chunks).toString('utf8'));
    } catch (e) {
      // An AssembleError message is written for the operator; anything else (the directory
      // unreadable, say) is reported by its code alone — never a stack trace.
      process.stderr.write(`tenants-assemble: ${e instanceof AssembleError ? e.message : `could not assemble (${e?.code ?? e?.name ?? 'error'})`}\n`);
      process.exit(1);
    }
    process.stdout.write(JSON.stringify(map));
  });
}
