// Docs drift: the fenced shell blocks a partner pastes must keep working as the repo moves.
// For every ```sh / ```bash block in the four integration docs this checks, statically:
//   (a) every `--data @<path>` file exists, resolved against the current directory, unless
//       the block itself writes it. The current directory is modelled the way a reader pastes:
//       the repo root at the top of the doc, changed by each `cd`, and CARRIED INTO THE NEXT
//       BLOCK — so a block that relies on a relative path must `cd` first;
//   (b) every /v1/… and /health path is a route the Worker serves — the 404 `routes` list in
//       src/index.ts is the source of truth;
//   (c) every `npm run <script>` names a script in the nearest package.json at or above the
//       block's current directory;
// and every `cd` lands on a directory that exists. Nothing is executed.
//
// A `cd` this checker cannot model (`$VAR`, `~`, `"$(mktemp -d)"`, `-`) makes the current
// directory UNKNOWN: the relative checks (a, c) are skipped until the next modellable `cd`
// rather than run against a stale directory. Quoting is not parsed as shell: text inside
// quotes in a fenced block (a URL in "…", a --data argument in '…') is checked like any
// other text, with the quote characters themselves stripped from route tokens.
//
// Plain `node --test` (npm run test:agreement), not the vitest workers pool: this reads
// repo files at test time, which the workerd sandbox cannot.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { existsSync, readFileSync, statSync } from 'node:fs';
import { dirname, join, relative, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const WORKER = resolve(HERE, '..');
const ROOT = resolve(WORKER, '../..');

const DOCS = [
  'integrations/hosted-verify/README.md',
  'pilot/INTEGRATION.md',
  'examples/managed-revocation/README.md',
  'integrations/mpp-payments/README.md',
];

/** Fenced ```sh / ```bash / ```shell blocks: [{ line, body }]. */
export function shellBlocks(markdown) {
  const blocks = [];
  const lines = markdown.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const open = /^\s*```(sh|bash|shell)\s*$/.exec(lines[i]);
    if (!open) continue;
    const start = i + 1;
    let j = start;
    while (j < lines.length && !/^\s*```\s*$/.test(lines[j])) j++;
    blocks.push({ line: start + 1, body: lines.slice(start, j) });
    i = j;
  }
  return blocks;
}

/** The Worker's route paths, from the 404 `routes` list in src/index.ts. */
export function workerRoutes(indexSource) {
  const m = /routes:\s*\[([\s\S]*?)\]/.exec(indexSource);
  assert.ok(m, 'src/index.ts has no `routes: [...]` list');
  const routes = [...m[1].matchAll(/'(?:GET|POST|PUT|DELETE|PATCH) ([^']+)'/g)].map((r) => r[1]);
  assert.ok(routes.length > 0, 'src/index.ts `routes` list is empty');
  return new Set(routes);
}

/** Normalise a path seen in a doc to route-table form: quotes and any query string go, an id segment becomes {id}. */
function normaliseRoute(path) {
  return path
    .replace(/["']/g, '')
    .replace(/\?.*$/, '')
    .replace(/[)`,.;]+$/, '')
    .replace(/^(\/v1\/credentials\/)(\$\{?\w+\}?|<[^>]*>|\{id\}|[0-9a-f]{64})(?=\/|$)/, '$1{id}');
}

function nearestPackageJson(dir) {
  for (let d = dir; ; d = dirname(d)) {
    const p = join(d, 'package.json');
    if (existsSync(p)) return p;
    if (d === ROOT || d === dirname(d)) return null;
  }
}

/** Resolve a `cd` argument against cwd. Returns null for a target this checker cannot model. */
function cdTarget(arg, cwd, cloned) {
  let a = arg.trim().replace(/^["']|["']$/g, '');
  const top = /^\$\(git rev-parse --show-toplevel\)(\/.*)?$/.exec(a.replace(/"/g, ''));
  if (top) return join(ROOT, top[1] ?? '');
  if (a.includes('$') || a.startsWith('~') || a === '-') return null;
  if (cwd === null && !a.startsWith('/')) return null; // relative to an unknown directory
  // `git clone …/bolyra` then `cd bolyra/…`: the clone is this checkout.
  if (cloned && (a === 'bolyra' || a.startsWith('bolyra/'))) return join(ROOT, a.slice('bolyra'.length));
  return resolve(cwd, a);
}

/**
 * Split a shell line into simple commands on && / || / ; / |, tracking ( subshell ) depth.
 * `$( … )` and `$(( … ))` are command/arithmetic substitutions, copied into the current
 * command whole (balanced parentheses) so they never open or close a subshell.
 */
function commands(line) {
  const out = [];
  const code = line.replace(/(^|\s)#.*$/, ''); // strip trailing comments
  let depth = 0;
  let cur = '';
  const flush = () => {
    if (cur.trim()) out.push({ text: cur.trim(), subshell: depth > 0 });
    cur = '';
  };
  for (let i = 0; i < code.length; i++) {
    const c = code[i];
    if (c === '$' && code[i + 1] === '(') {
      let j = i + 1;
      for (let open = 0; j < code.length; j++) {
        if (code[j] === '(') open++;
        else if (code[j] === ')' && --open === 0) break;
      }
      cur += code.slice(i, j + 1);
      i = j;
      continue;
    }
    if (c === '(') {
      flush();
      depth++;
      continue;
    }
    if (c === ')' && depth > 0) {
      flush();
      depth--;
      out.push({ text: '', subshell: false, close: true });
      continue;
    }
    if ((c === '&' && code[i + 1] === '&') || (c === '|' && code[i + 1] === '|')) {
      flush();
      i++;
      continue;
    }
    if (c === ';' || c === '|') {
      flush();
      continue;
    }
    cur += c;
  }
  flush();
  return out;
}

/** Check one document's text; returns { problems: string[], counts }. */
export function checkDoc(docPath, markdown, routes) {
  const problems = [];
  const counts = { blocks: 0, dataRefs: 0, routeRefs: 0, npmRuns: 0 };
  let cwd = ROOT; // one reader's shell for the whole doc: a cd carries into later blocks
  for (const block of shellBlocks(markdown)) {
    counts.blocks++;
    let saved; // cwd outside the current ( subshell ); undefined when not in one (cwd itself may be null)
    let cloned = false;
    // Files the block itself writes (`> f`, `--out f`, `-o f`) need not pre-exist.
    const written = new Set();
    // Join backslash continuations so a flag and its value sit on one logical line,
    // remembering the physical line each logical line starts on.
    const logical = [];
    block.body.forEach((raw, k) => {
      const prev = logical[logical.length - 1];
      if (prev && prev.text.endsWith('\\')) prev.text = prev.text.slice(0, -1) + ' ' + raw;
      else logical.push({ text: raw, at: block.line + k });
    });
    logical.forEach(({ text: line, at }) => {
      const where = `${docPath}:${at}`;
      for (const cmd of commands(line)) {
        if (cmd.close) {
          if (saved !== undefined) cwd = saved;
          saved = undefined;
          continue;
        }
        if (cmd.subshell && saved === undefined) saved = cwd;
        const text = cmd.text;
        if (/^git clone\b/.test(text)) cloned = true;
        if (cwd !== null) {
          for (const w of text.matchAll(/(?:>\s*|--out\s+|-o\s+)([\w./-]+)/g)) written.add(resolve(cwd, w[1]));
        }
        const cd = /^cd\s+(.+)$/.exec(text);
        if (cd) {
          const target = cdTarget(cd[1], cwd, cloned);
          if (target === null) {
            cwd = null; // unknown until the next modellable cd
            continue;
          }
          if (!existsSync(target) || !statSync(target).isDirectory()) {
            problems.push(`${where}: cd ${cd[1].trim()} → ${relative(ROOT, target) || '.'} is not a directory`);
          } else cwd = target;
          continue;
        }
        if (cwd === null) continue; // relative checks need a known directory
        for (const d of text.matchAll(/(?:--data(?:-binary|-raw)?|-d)\s+@([^\s'"]+)/g)) {
          counts.dataRefs++;
          if (d[1].includes('$')) continue;
          const file = resolve(cwd, d[1]);
          if (!written.has(file) && !existsSync(file)) {
            problems.push(`${where}: @${d[1]} resolves to ${relative(ROOT, file)} (cwd ${relative(ROOT, cwd) || '<repo root>'}), which does not exist`);
          }
        }
        for (const n of text.matchAll(/\bnpm run ([\w:.-]+)/g)) {
          counts.npmRuns++;
          const pkgPath = nearestPackageJson(cwd);
          const scripts = pkgPath ? JSON.parse(readFileSync(pkgPath, 'utf8')).scripts ?? {} : {};
          if (!(n[1] in scripts)) {
            problems.push(`${where}: npm run ${n[1]} — no such script in ${pkgPath ? relative(ROOT, pkgPath) : 'any package.json'} (cwd ${relative(ROOT, cwd) || '<repo root>'})`);
          }
        }
      }
      // Routes: anywhere on the line, comments included (a comment naming a route is a claim too).
      for (const r of line.matchAll(/(?:\$\{?BASE\}?|https?:\/\/[^\s/'"]+|\s|^)(\/v1\/[^\s|]*|\/health\b|\/\.well-known\/[^\s|]*)/g)) {
        counts.routeRefs++;
        const route = normaliseRoute(r[1]);
        if (!routes.has(route)) problems.push(`${where}: ${r[1]} (as ${route}) is not in the Worker's routes list`);
      }
    });
  }
  return { problems, counts };
}

const routes = workerRoutes(readFileSync(join(WORKER, 'src/index.ts'), 'utf8'));

test('the checker catches the drift classes it claims to (self-test)', () => {
  const bad = [
    '```bash',
    'curl -s -X POST $BASE/v1/credentials --data @examples/registration.allow.json | jq',
    'curl -s $BASE/v1/nope | jq',
    'npm run no-such-script',
    'cd no/such/dir',
    '```',
  ].join('\n');
  const { problems } = checkDoc('synthetic.md', bad, routes);
  const all = problems.join('\n');
  for (const [cls, needle] of [
    ['missing @file', '@examples/registration.allow.json resolves to examples/registration.allow.json'],
    ['unknown route', "/v1/nope (as /v1/nope) is not in the Worker's routes list"],
    ['missing npm script', 'npm run no-such-script — no such script'],
    ['missing cd target', 'cd no/such/dir → no/such/dir is not a directory'],
  ]) {
    assert.ok(all.includes(needle), `${cls} not reported; got:\n${all}`);
  }
  const good = [
    '```bash',
    'cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"',
    'curl -s -X POST $BASE/v1/credentials --data @examples/registration.allow.json | jq',
    'ID=$(curl -s -X POST $BASE/v1/credentials --data @examples/registration.allow.json | jq -r .credential_id)',
    'curl -s -X POST $BASE/v1/credentials/$ID/revoke',
    'jq . x.json > out.json; curl --data @out.json $BASE/v1/verify',
    '(cd ../cli && npm run build)',
    'npm run smoke:dev',
    '```',
  ].join('\n');
  assert.deepEqual(checkDoc('synthetic.md', good, routes).problems, []);
});

for (const doc of DOCS) {
  test(`${doc}: every shell block's files, routes, scripts and cd targets exist`, () => {
    const { problems, counts } = checkDoc(doc, readFileSync(join(ROOT, doc), 'utf8'), routes);
    assert.ok(counts.blocks > 0, `${doc} has no shell blocks — did the fence language change?`);
    assert.deepEqual(problems, [], `\n${problems.join('\n')}`);
  });
}

const block = (...lines) => ['```bash', ...lines, '```'].join('\n');
const TOP = 'cd "$(git rev-parse --show-toplevel)/integrations/hosted-verify"';

test('route tokens: shell quotes and query strings are not part of the route', () => {
  const doc = block(
    TOP,
    'curl -s -X POST $BASE/v1/credentials/"$ID"/revoke',
    "curl -s -X POST \"$BASE/v1/credentials/$ID/repair-history\"",
    "curl -s '$BASE/v1/verify?trace=1'",
    'curl -s $BASE/health?x=1',
  );
  assert.deepEqual(checkDoc('synthetic.md', doc, routes).problems, []);
  // …while a wrong route inside quotes is still caught.
  const bad = block(TOP, 'curl -s -X POST "$BASE/v1/credentials/$ID/unrevoke"');
  assert.match(checkDoc('synthetic.md', bad, routes).problems.join('\n'), /unrevoke/);
});

test('an unmodellable cd suspends relative checks until the next modellable cd', () => {
  const doc = [
    block(TOP, 'cd "$(mktemp -d)"   # scratch', 'npm run not-a-script', 'curl --data @nowhere.json $BASE/v1/verify'),
    // the reader's shell is still in the temp dir in the next block
    block('curl --data @still-nowhere.json $BASE/v1/verify', 'cd ~/somewhere', 'npm run also-not'),
    block(TOP, 'curl --data @missing-after-cd.json $BASE/v1/verify'),
  ].join('\n\n');
  const problems = checkDoc('synthetic.md', doc, routes).problems;
  assert.equal(problems.length, 1, problems.join('\n'));
  assert.match(problems[0], /@missing-after-cd\.json/);
  for (const arg of ['"$DIR"', '~', '"$(mktemp -d)"', '$HOME/x']) {
    const p = checkDoc('synthetic.md', block(TOP, `cd ${arg}`, 'npm run nope'), routes).problems;
    assert.deepEqual(p, [], `cd ${arg}`);
  }
});

test('$(( arithmetic )) does not open a subshell', () => {
  const doc = block(
    'EXPIRY=$(( $(date +%s) + 30*24*3600 )) && ' + TOP,
    '(cd ../cli && npm run build)',
    'npm run smoke:dev',
  );
  assert.deepEqual(checkDoc('synthetic.md', doc, routes).problems, []);
  // a subshell entered while the directory is unknown still restores on exit
  const nested = block('cd "$(mktemp -d)"', '(' + TOP + ' && npm run smoke:dev)', 'npm run not-checked-here');
  assert.deepEqual(checkDoc('synthetic.md', nested, routes).problems, []);
});
