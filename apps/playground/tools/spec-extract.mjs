/**
 * Build-time extraction of EVC wire shapes from the committed spec markdown.
 * Pure functions over text; every contract violation throws `spec drift: …`.
 *
 * Guarantee (stated narrowly): the extraction CONTRACTS below are checked at
 * build time and `build.mjs --check` rejects stale generated output. A spec
 * edit that keeps the contracts intact changes the page on the next build.
 */
import { assertSupportedSchema, validate } from './mini-schema.mjs';

const drift = (what) => new Error(`spec drift: ${what}`);
/** Strip markdown emphasis and backticks for display; text otherwise verbatim. */
export const plain = (s) => s.replace(/\*\*([^*]+)\*\*/g, '$1').replace(/\*([^*]+)\*/g, '$1').replace(/`([^`]*)`/g, '$1').replace(/\s+/g, ' ').trim();

/** All headings with their section number (leading token like `2.1`) and body line range. */
export function sections(md) {
  const lines = md.split('\n');
  const heads = [];
  let inFence = false;
  lines.forEach((line, i) => {
    if (/^```/.test(line)) inFence = !inFence;
    if (inFence) return;
    const m = /^(#{1,6})\s+(.*)$/.exec(line);
    if (m) heads.push({ level: m[1].length, text: plain(m[2]), line: i + 1, start: i + 1 });
  });
  if (inFence) throw drift('unterminated fence');
  heads.forEach((h, i) => { h.end = i + 1 < heads.length ? heads[i + 1].start - 1 : lines.length; h.body = lines.slice(h.start, h.end); h.number = (/^(\d+(?:\.\d+)*)\.?\s/.exec(h.text) || [])[1] ?? null; });
  const seen = new Map();
  for (const h of heads) { if (seen.has(h.text)) throw drift(`duplicate section heading "${h.text}"`); seen.set(h.text, h); }
  return heads;
}
function sectionByNumber(heads, number) {
  const hits = heads.filter((h) => h.number === number);
  if (hits.length !== 1) throw drift(`expected exactly one section ${number}, found ${hits.length}`);
  return hits[0];
}

/** Every ```json fence with the nearest preceding heading; each must terminate and parse. */
export function fencedJsonBlocks(md) {
  const lines = md.split('\n');
  const out = [];
  let heading = null, open = null, buf = [], openLine = 0;
  lines.forEach((line, i) => {
    if (open === null) {
      const h = /^(#{1,6})\s+(.*)$/.exec(line);
      if (h) { heading = plain(h[2]); return; }
      const f = /^```(\w*)\s*$/.exec(line);
      if (f) { open = f[1]; buf = []; openLine = i + 1; }
    } else if (/^```\s*$/.test(line)) {
      if (open === 'json') {
        const text = buf.join('\n');
        let json; try { json = JSON.parse(text); } catch (e) { throw drift(`json fence at line ${openLine} does not parse: ${e.message}`); }
        out.push({ heading, line: openLine, text, json });
      }
      open = null;
    } else buf.push(line);
  });
  if (open !== null) throw drift(`unterminated fence opened at line ${openLine}`);
  return out;
}

/** Contract: json fences per section number. */
export const EXPECTED_FENCES = Object.freeze({ '2.1': 1, '2.2': 1, '3.1': 1, '3.2': 1, '3.3': 1, '3.4': 1, '13.1': 2, '13.2': 1, '13.3': 1, '13.4': 1, '13.5': 1, '13.6': 1, '13.7': 1, '13.8': 1 });

function parseTable(body, headerRe, what) {
  const start = body.findIndex((l) => headerRe.test(l));
  if (start === -1) throw drift(`${what} table header not found`);
  const rows = [];
  for (let i = start + 2; i < body.length; i++) {
    const l = body[i];
    if (l.trim() === '') break;
    if (!/^\|/.test(l)) throw drift(`${what} table row malformed at "${l.slice(0, 40)}"`);
    rows.push(l.split('|').slice(1, -1).map((c) => c.trim()));
  }
  if (rows.length === 0) throw drift(`${what} table has no rows`);
  return rows;
}

export function extractEvcSpec(md) {
  const heads = sections(md);
  const fences = fencedJsonBlocks(md);
  const byNumber = (n) => { const s = sectionByNumber(heads, n); return fences.filter((f) => f.line > s.start && f.line <= s.end); };
  for (const [n, count] of Object.entries(EXPECTED_FENCES)) { const got = byNumber(n).length; if (got !== count) throw drift(`section ${n}: expected ${count} json fence(s), found ${got}`); }
  const total = Object.values(EXPECTED_FENCES).reduce((a, b) => a + b, 0);
  if (fences.length !== total) throw drift(`expected ${total} json fences in the document, found ${fences.length}`);

  const revision = (/^- \*\*Document revision:\*\* (\d{4}-\d{2}-\d{2})/m.exec(md) || [])[1];
  if (!revision) throw drift('document revision line not found');

  const request = { example: byNumber('2.1')[0].json, schema: byNumber('2.2')[0].json };
  const verdict = { allow: byNumber('3.1')[0].json, allowConsume: byNumber('3.2')[0].json, deny: byNumber('3.3')[0].json, schema: byNumber('3.4')[0].json };
  assertSupportedSchema(request.schema); assertSupportedSchema(verdict.schema);

  const codeEnum = verdict.schema?.oneOf?.[1]?.properties?.code?.enum;
  if (!Array.isArray(codeEnum)) throw drift('verdict schema deny-branch code enum not found');
  const kindAllow = verdict.schema?.oneOf?.[0]?.properties?.kind?.enum, kindDeny = verdict.schema?.oneOf?.[1]?.properties?.kind?.enum;
  if (!Array.isArray(kindAllow) || JSON.stringify(kindAllow) !== JSON.stringify(kindDeny)) throw drift('kind enum differs between the allow and deny branches');

  const s9 = sectionByNumber(heads, '9');
  const registry = parseTable(s9.body, /^\|\s*`code`\s*\|\s*Meaning\s*\|/, 'registry').map(([code, meaning]) => ({ code: plain(code), meaning: plain(meaning) }));
  if (JSON.stringify(registry.map((r) => r.code)) !== JSON.stringify(codeEnum)) throw drift(`registry table codes ${JSON.stringify(registry.map((r) => r.code))} != schema enum ${JSON.stringify(codeEnum)}`);

  const s35 = sectionByNumber(heads, '3.5');
  const kinds = parseTable(s35.body, /^\|\s*`kind`\s*\|/, 'kind').map(([kind, cls, productLine, examples]) => ({ kind: plain(kind), class: plain(cls), productLine: plain(productLine), examples: plain(examples) }));
  if (JSON.stringify(kinds.map((k) => k.kind)) !== JSON.stringify(kindAllow)) throw drift('kind table != schema kind enum');
  const omitted = /absen(?:t|ce)[^.]*?as `zk`/.exec(md);
  if (!omitted) throw drift('rule "absent kind is read as zk" not found');

  const examples = [];
  for (const n of ['13.1', '13.2', '13.3', '13.4', '13.5', '13.6', '13.7', '13.8']) {
    const s = sectionByNumber(heads, n);
    const f = byNumber(n);
    const prose = plain(s.body.filter((l) => !/^```/.test(l)).join(' ').replace(/\{[\s\S]*?\}/g, ' '));
    const notes = plain(s.body.join('\n').replace(/```[\s\S]*?```/g, ' '));
    const ex = { id: n, heading: s.text.replace(/^\S+\s+/, ''), verdict: f[f.length - 1].json, notes };
    if (f.length === 2) ex.request = f[0].json;
    void prose;
    examples.push(ex);
  }

  const results = [];
  const v = (schema, inst, what) => { const r = validate(schema, inst); if (!r.ok) throw drift(`${what} fails its schema: ${r.errors.join('; ')}`); results.push(what); };
  v(request.schema, request.example, '§2.1 example');
  v(verdict.schema, verdict.allow, '§3.1'); v(verdict.schema, verdict.allowConsume, '§3.2'); v(verdict.schema, verdict.deny, '§3.3');
  for (const e of examples) { v(verdict.schema, e.verdict, `§${e.id} verdict`); if (e.request) v(request.schema, e.request, `§${e.id} request`); }

  return { revision, request, verdict, registry, kinds, omittedKindMeans: 'zk', examples, validated: results };
}

const LABELS = { applicability: 'Applicability.', role: 'Role.', localContext: 'Local challenge context.', hostMusts: 'Host MUSTs.', mustNotClaim: 'MUST NOT claim.' };
export function extractProfile42(md) {
  const heads = sections(md);
  const s = sectionByNumber(heads, '4.2');
  const paragraphs = s.body.join('\n').split(/\n\s*\n/).map((p) => p.replace(/\s*\n\s*/g, ' ').trim()).filter(Boolean);
  const out = {};
  for (const [key, label] of Object.entries(LABELS)) {
    const hits = paragraphs.filter((p) => p.startsWith(`**${label}**`));
    if (hits.length !== 1) throw drift(`§4.2 paragraph "${label}" expected once, found ${hits.length}`);
    out[key] = plain(hits[0].slice(`**${label}**`.length));
  }
  const ex = paragraphs.filter((p) => p.startsWith('**Non-normative example'));
  if (ex.length !== 1) throw drift(`§4.2 non-normative example paragraph expected once, found ${ex.length}`);
  out.example = plain(ex[0]);
  const parts = out.hostMusts.split(/\s*\((\d)\)\s*/);
  // parts: ['', '1', text1, '2', text2, ...]
  if (parts[0] !== '' || parts.length !== 19) throw drift(`§4.2 Host MUSTs: expected (1)…(9), parsed ${(parts.length - 1) / 2} items`);
  const musts = [];
  for (let i = 1; i < parts.length; i += 2) { if (Number(parts[i]) !== musts.length + 1) throw drift(`§4.2 Host MUST numbering broken at (${parts[i]})`); musts.push(parts[i + 1].trim()); }
  out.hostMusts = musts;
  if (!/does NOT establish/.test(out.mustNotClaim)) throw drift('§4.2 MUST NOT claim paragraph lost its "does NOT establish" statement');
  return out;
}
