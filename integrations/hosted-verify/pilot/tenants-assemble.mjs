// Assemble the TENANTS map for `tenant.sh sync`: one entry per registry file in the
// directory given as argv[2] whose status is active or disabled, tokens read from stdin
// as lines "<org_id> <admin|verifier> <token>". The map is written to stdout and nowhere
// else; nothing is logged. Registry files hold no secrets.
import { readdirSync, readFileSync, statSync } from 'node:fs';
import path from 'node:path';

const dir = process.argv[2];
if (!dir) {
  process.stderr.write('usage: tenants-assemble.mjs <registry-dir> < tokens\n');
  process.exit(2);
}

const chunks = [];
process.stdin.on('data', (d) => chunks.push(d));
process.stdin.on('end', () => {
  const tokens = new Map(); // "org role" -> token
  for (const line of Buffer.concat(chunks).toString('utf8').split('\n')) {
    if (line === '') continue;
    const first = line.indexOf(' ');
    const second = first < 0 ? -1 : line.indexOf(' ', first + 1);
    const org = first < 0 ? '' : line.slice(0, first);
    const role = second < 0 ? '' : line.slice(first + 1, second);
    const token = second < 0 ? '' : line.slice(second + 1);
    if (!org || !role || !token) {
      process.stderr.write('tenants-assemble: malformed token line (expected "<org_id> <role> <token>")\n');
      process.exit(1);
    }
    tokens.set(`${org} ${role}`, token);
  }
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
      process.stderr.write(`tenants-assemble: ${f}: not valid JSON\n`);
      process.exit(1);
    }
    if (record.org_id !== org) {
      process.stderr.write(`tenants-assemble: ${f}: org_id must equal the file name\n`);
      process.exit(1);
    }
    if (record.status === 'removed') continue;
    if (record.status !== 'active' && record.status !== 'disabled') {
      process.stderr.write(`tenants-assemble: ${f}: status must be active, disabled, or removed\n`);
      process.exit(1);
    }
    const admin = tokens.get(`${org} admin`);
    const verifier = tokens.get(`${org} verifier`);
    if (admin === undefined || verifier === undefined) {
      process.stderr.write(`tenants-assemble: ${org}: missing a token for admin or verifier\n`);
      process.exit(1);
    }
    if (!Array.isArray(record.trustedOperators)) {
      // Refuse rather than pass it through: the validator would reject it downstream with a
      // message about the map, not about the file an operator has to fix.
      process.stderr.write(`tenants-assemble: ${f}: trustedOperators must be an array\n`);
      process.exit(1);
    }
    // Dedupe, first-seen order preserved: a repeated key grants nothing and spends the
    // 4096-byte TENANTS budget that every other tenant shares.
    const trusted = [...new Set(record.trustedOperators)];
    const entry = { admin_token: admin, verifier_token: verifier, trusted_operators: trusted };
    if (record.status === 'disabled') entry.disabled = true;
    map[org] = entry;
  }
  process.stdout.write(JSON.stringify(map));
});
