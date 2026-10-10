/**
 * Findings → one self-contained HTML page (spec §6). No scripts, no external
 * resources, every bundle-derived string escaped. The JSON report is the
 * source of truth; this file only lays it out.
 */

import type { Finding, Report } from './classify';
import { ANCHORS_WORDING, CLAIM_TITLES, DEV_MODE_DISCLOSURE, STATUS_LEGEND, TAMPER_INSTRUCTION } from './claims';

export interface RenderOptions {
  /** Path to receipts.jsonl as the reviewer should type it, relative to where they will run the command. */
  receiptsPath: string;
}

export function esc(s: unknown): string {
  return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}

/** POSIX single-quote shell escaping: safe for any byte sequence except NUL. */
export function shellQuote(s: string): string {
  return /^[A-Za-z0-9_./-]+$/.test(s) ? s : `'${s.replace(/'/g, `'\\''`)}'`;
}

/** The exact command, pinned to the trial's CLI version, built from the validated anchors only. */
export function buildVerifyCommand(report: Report, receiptsPath: string): string {
  const parts = [`npx @bolyra/cli@${report.tool.cli} receipt verify-chain ${shellQuote(receiptsPath)}`, `--signer ${report.anchors.signer}`];
  if (report.anchors.expectCount !== undefined) parts.push(`--expect-count ${report.anchors.expectCount}`);
  if (report.anchors.expectHead !== undefined) parts.push(`--expect-head ${report.anchors.expectHead}`);
  return parts.join(' ');
}

const CSS = `
body{font:14px/1.45 -apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;color:#111;margin:2rem auto;max-width:60rem;padding:0 1rem}
h1{font-size:1.5rem;margin:0 0 .25rem}h2{font-size:1.15rem;margin:2rem 0 .5rem;border-bottom:1px solid #ccc;padding-bottom:.2rem}
p.lede{margin:.25rem 0 1rem;color:#333}.box{border:1px solid #999;padding:.75rem 1rem;margin:1rem 0;background:#fafafa}
table{border-collapse:collapse;width:100%;margin:.5rem 0 1rem}th,td{border:1px solid #ccc;padding:.35rem .5rem;vertical-align:top;text-align:left}
th{background:#eee}td.s{white-space:nowrap;font-weight:600}code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.92em}
pre{background:#f4f4f4;padding:.6rem .8rem;overflow-x:auto;white-space:pre-wrap;word-break:break-all}
.SIGNED{color:#1b5e20}.OBSERVED{color:#4e342e}.DERIVED{color:#0d47a1}.ABSENT{color:#616161}.FAILED{color:#b71c1c}
dl dt{font-weight:700;margin-top:.5rem}dl dd{margin:0 0 .25rem 0}small{color:#555}
@media print{body{margin:0;max-width:none}h2{break-after:avoid}tr{break-inside:avoid}}
`;

export function render(report: Report, opts: RenderOptions): string {
  const cmd = buildVerifyCommand(report, opts.receiptsPath);
  const bundleLevel = report.findings.filter((f) => f.attempt === undefined && f.receiptLine === undefined);
  const receiptLevel = report.findings.filter((f) => f.attempt === undefined && f.receiptLine !== undefined && /^B/.test(f.claim));
  const unattributed = report.findings.filter((f) => f.attempt === undefined && f.receiptLine !== undefined && /^A/.test(f.claim));
  const counts: Record<string, number> = {};
  for (const f of report.findings) counts[f.status] = (counts[f.status] ?? 0) + 1;

  const out: string[] = [];
  out.push('<!doctype html>', '<html lang="en"><head><meta charset="utf-8">', `<title>Reviewer evidence report: ${esc(report.bundle)}</title>`, `<style>${CSS}</style></head><body>`);
  out.push(`<h1>Reviewer evidence report</h1>`);
  out.push(`<p class="lede">Bundle <code>${esc(report.bundle)}</code>, generated ${esc(report.generatedAt)} by ${esc(report.tool.name)} ${esc(report.tool.version)} using @bolyra/receipts ${esc(report.tool.receipts)}.</p>`);

  out.push('<div class="box"><p><strong>What this report is.</strong> For each claim a reviewer might make about this bundle, it says whether the bundle supports it, by which artifact and field, and with what kind of evidence. It makes no judgement beyond that: no score, no verdict, no certification.</p>');
  out.push(`<p><strong>What produced the bundle.</strong> ${esc(DEV_MODE_DISCLOSURE)}</p>`);
  out.push('<p><strong>What this report never claims.</strong> That the endpoint executed anything, that a human consented, who receives funds or controls a settlement address, that a spend limit applied, that any subject was authenticated, or that production credentials were used. Where such a claim appears below, its status is ABSENT.</p></div>');

  out.push('<h2>Anchors</h2>');
  out.push('<table><tr><th>Anchor</th><th>Value</th><th>Source</th></tr>');
  out.push(`<tr><td>signer</td><td><code>${esc(report.anchors.signer)}</code></td><td>command line (--signer)</td></tr>`);
  out.push(`<tr><td>receipt count</td><td>${report.anchors.expectCount === undefined ? '<em>not supplied</em>' : esc(report.anchors.expectCount)}</td><td>${report.anchors.expectCount === undefined ? '(--expect-count omitted)' : 'command line (--expect-count)'}</td></tr>`);
  out.push(`<tr><td>head hash</td><td>${report.anchors.expectHead === undefined ? '<em>not supplied</em>' : `<code>${esc(report.anchors.expectHead)}</code>`}</td><td>${report.anchors.expectHead === undefined ? '(--expect-head omitted)' : 'command line (--expect-head)'}</td></tr>`);
  out.push('</table>');
  out.push(`<p>${esc(ANCHORS_WORDING)}</p>`);

  out.push('<h2>Summary of statuses</h2>');
  out.push('<p>' + (['SIGNED', 'OBSERVED', 'DERIVED', 'ABSENT', 'FAILED'] as const).map((s) => `<span class="${s}">${s}: ${counts[s] ?? 0}</span>`).join(' &middot; ') + '</p>');

  out.push('<h2 id="bundle">Bundle-level findings</h2>');
  out.push(table(bundleLevel));
  out.push('<h3>Per receipt line</h3>');
  out.push(table(receiptLevel, true));

  for (const n of report.attempts) {
    const rows = report.findings.filter((f) => f.attempt === n);
    out.push(`<h2 id="attempt-${n}">Attempt ${n}</h2>`);
    out.push(table(rows));
  }

  if (report.unattributedLines.length > 0) {
    out.push('<h2 id="unattributed">Unattributed receipts</h2>');
    out.push(`<p>Receipt lines ${esc(report.unattributedLines.join(', '))} are not attributed to any attempt (see A1). Their own findings follow; nothing is attributed by position.</p>`);
    out.push(table(unattributed, true));
  }

  out.push('<h2 id="reverify">Re-verify yourself</h2>');
  out.push('<p>From the bundle directory, with Node 20 or newer (the first run downloads the pinned CLI):</p>');
  out.push(`<pre>${esc(cmd)}</pre>`);
  out.push(`<p>${esc(TAMPER_INSTRUCTION)}</p>`);

  out.push('<h2 id="legend">Status legend</h2><dl>');
  for (const [k, v] of Object.entries(STATUS_LEGEND)) out.push(`<dt>${k}</dt><dd>${esc(v)}</dd>`);
  out.push('</dl>');
  out.push('<p><small>Claim titles are fixed in the generating tool (claims.ts); the bundle cannot add or remove a claim.</small></p>');
  out.push('</body></html>');
  return out.join('\n');
}

function table(rows: Finding[], withLine = false): string {
  if (rows.length === 0) return '<p><em>none</em></p>';
  const o: string[] = [`<table><tr><th>#</th>${withLine ? '<th>line</th>' : ''}<th>Claim</th><th>Status</th><th>Evidence</th><th>Note</th></tr>`];
  for (const f of rows) {
    const ev = f.evidence.map((e) => `<code>${esc(e.file)}${e.line !== undefined ? ` line ${e.line}` : ''}${e.path ? ` ${esc(e.path)}` : ''}</code>`).join('<br>');
    const inputs = f.inputs && f.inputs.length ? `<br><small>inputs: ${f.inputs.map((i) => esc(i)).join('; ')}</small>` : '';
    o.push(
      `<tr id="f-${esc(f.id)}"><td>${esc(f.claim)}</td>${withLine ? `<td>${esc(f.receiptLine ?? '')}</td>` : ''}<td>${esc(CLAIM_TITLES[f.claim] ?? f.title)}</td><td class="s ${esc(f.status)}">${esc(f.status)}</td><td>${ev || '<em>none</em>'}${inputs}</td><td>${esc(f.note ?? '')}</td></tr>`,
    );
  }
  o.push('</table>');
  return o.join('\n');
}
