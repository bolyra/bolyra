import * as core from '@actions/core';
import * as github from '@actions/github';
import * as fs from 'fs';
import * as path from 'path';
import { parse as parseYaml } from 'yaml';

// ── Types ──────────────────────────────────────────────────────

interface Receipt {
  decision: 'allow' | 'deny';
  toolName?: string;
  did?: string;
  score?: number;
  reason?: string;
  timestamp?: string;
}

interface PolicyEntry {
  requireBitmask?: number;
  minScore?: number;
}

interface ReplayResult {
  tool: string;
  original: 'allow' | 'deny';
  replayed: 'allow' | 'deny';
  reason: string;
  changed: boolean;
  regression: boolean; // allow → deny
  relaxation: boolean; // deny → allow
}

// ── Receipt loading ────────────────────────────────────────────

function loadReceipts(receiptPath: string): Receipt[] {
  const resolved = path.resolve(receiptPath);
  const receipts: Receipt[] = [];

  if (!fs.existsSync(resolved)) {
    core.warning(`Receipt path not found: ${resolved}`);
    return [];
  }

  const stat = fs.statSync(resolved);

  if (stat.isFile()) {
    return parseReceiptFile(resolved);
  }

  if (stat.isDirectory()) {
    const files = fs.readdirSync(resolved)
      .filter(f => f.endsWith('.ndjson') || f.endsWith('.jsonl'))
      .sort();

    for (const file of files) {
      receipts.push(...parseReceiptFile(path.join(resolved, file)));
    }
  }

  return receipts;
}

function parseReceiptFile(filePath: string): Receipt[] {
  const content = fs.readFileSync(filePath, 'utf-8');
  const receipts: Receipt[] = [];
  for (const line of content.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    try {
      const obj = JSON.parse(trimmed);
      if (obj.decision) receipts.push(obj as Receipt);
    } catch { /* skip non-JSON lines */ }
  }
  return receipts;
}

// ── Policy loading ─────────────────────────────────────────────

function loadPolicy(policyPath: string): Map<string, PolicyEntry> {
  const resolved = path.resolve(policyPath);
  const policy = new Map<string, PolicyEntry>();

  if (!fs.existsSync(resolved)) {
    core.warning(`Policy file not found: ${resolved}. Replaying without policy (all pass).`);
    return policy;
  }

  const raw = fs.readFileSync(resolved, 'utf-8');
  const config = parseYaml(raw);

  if (config?.tools) {
    for (const [name, pol] of Object.entries(config.tools as Record<string, any>)) {
      policy.set(name, {
        requireBitmask: pol.requireBitmask,
        minScore: pol.minScore,
      });
    }
  }

  return policy;
}

// ── Replay engine ──────────────────────────────────────────────

function replayReceipt(receipt: Receipt, policy: Map<string, PolicyEntry>): ReplayResult {
  const tool = receipt.toolName ?? '(unknown)';

  // No policy = all pass
  if (policy.size === 0) {
    const changed = receipt.decision !== 'allow';
    return {
      tool,
      original: receipt.decision,
      replayed: 'allow',
      reason: 'no policy (all pass)',
      changed,
      regression: false,
      relaxation: changed && receipt.decision === 'deny',
    };
  }

  const toolPolicy = policy.get(tool);

  // No policy for this tool = pass
  if (!toolPolicy) {
    const changed = receipt.decision !== 'allow';
    return {
      tool,
      original: receipt.decision,
      replayed: 'allow',
      reason: 'no tool policy',
      changed,
      regression: false,
      relaxation: changed && receipt.decision === 'deny',
    };
  }

  // For denied receipts: assume still denied under new policy
  if (receipt.decision === 'deny') {
    return {
      tool,
      original: 'deny',
      replayed: 'deny',
      reason: receipt.reason ?? 'original denial preserved',
      changed: false,
      regression: false,
      relaxation: false,
    };
  }

  // For allowed receipts: check if new policy would deny
  if (toolPolicy.minScore && (receipt.score ?? 0) < toolPolicy.minScore) {
    return {
      tool,
      original: 'allow',
      replayed: 'deny',
      reason: `score ${receipt.score} < required ${toolPolicy.minScore}`,
      changed: true,
      regression: true,
      relaxation: false,
    };
  }

  return {
    tool,
    original: 'allow',
    replayed: 'allow',
    reason: 'passes current policy',
    changed: false,
    regression: false,
    relaxation: false,
  };
}

// ── PR comment ─────────────────────────────────────────────────

function buildComment(results: ReplayResult[], policyPath: string): string {
  const total = results.length;
  const changed = results.filter(r => r.changed).length;
  const regressions = results.filter(r => r.regression);
  const relaxations = results.filter(r => r.relaxation);

  const lines: string[] = [];
  lines.push('## 🛡️ Bolyra Replay Check\n');
  lines.push(`Replayed **${total}** agent receipts against \`${path.basename(policyPath)}\`.\n`);

  if (changed === 0) {
    lines.push('✅ **No regressions.** All decisions match the current policy.\n');
    return lines.join('\n');
  }

  lines.push(`**${changed}** decision(s) would change:\n`);

  if (regressions.length > 0) {
    lines.push(`### 🚫 Regressions (${regressions.length} allow → deny)\n`);
    lines.push('| Tool | Reason |');
    lines.push('|------|--------|');
    for (const r of regressions) {
      lines.push(`| \`${r.tool}\` | ${r.reason} |`);
    }
    lines.push('');
  }

  if (relaxations.length > 0) {
    lines.push(`### ✅ Relaxations (${relaxations.length} deny → allow)\n`);
    lines.push('| Tool | Reason |');
    lines.push('|------|--------|');
    for (const r of relaxations) {
      lines.push(`| \`${r.tool}\` | ${r.reason} |`);
    }
    lines.push('');
  }

  lines.push('---');
  lines.push('*Generated by [Bolyra Replay Check](https://bolyra.ai)*');

  return lines.join('\n');
}

// ── Main ───────────────────────────────────────────────────────

async function main(): Promise<void> {
  try {
    const receiptPath = core.getInput('receipt-path') || '.bolyra/receipts';
    const policyPath = core.getInput('policy') || 'shield.yaml';
    const failOnRegression = core.getInput('fail-on-regression') !== 'false';
    const shouldComment = core.getInput('comment') !== 'false';
    const token = core.getInput('github-token');

    core.info(`Receipt path: ${receiptPath}`);
    core.info(`Policy: ${policyPath}`);

    // Load
    const receipts = loadReceipts(receiptPath);
    const policy = loadPolicy(policyPath);

    if (receipts.length === 0) {
      core.info('No receipts found. Nothing to replay.');
      core.setOutput('total', '0');
      core.setOutput('changed', '0');
      core.setOutput('regressions', '0');
      core.setOutput('relaxations', '0');
      return;
    }

    core.info(`Loaded ${receipts.length} receipts, ${policy.size} tool policies`);

    // Replay
    const results = receipts.map(r => replayReceipt(r, policy));

    const total = results.length;
    const changed = results.filter(r => r.changed).length;
    const regressions = results.filter(r => r.regression).length;
    const relaxations = results.filter(r => r.relaxation).length;

    core.setOutput('total', String(total));
    core.setOutput('changed', String(changed));
    core.setOutput('regressions', String(regressions));
    core.setOutput('relaxations', String(relaxations));

    // Log results
    for (const r of results) {
      if (r.regression) {
        core.error(`REGRESSION: ${r.tool} — ${r.reason}`);
      } else if (r.relaxation) {
        core.warning(`RELAXATION: ${r.tool} — ${r.reason}`);
      } else if (r.changed) {
        core.warning(`CHANGED: ${r.tool} — ${r.reason}`);
      }
    }

    core.info(`Replay complete: ${total} receipts, ${changed} changed, ${regressions} regressions, ${relaxations} relaxations`);

    // Post PR comment
    if (shouldComment && github.context.payload.pull_request) {
      const octokit = github.getOctokit(token);
      const comment = buildComment(results, policyPath);

      // Find existing Bolyra comment to update
      const { data: comments } = await octokit.rest.issues.listComments({
        owner: github.context.repo.owner,
        repo: github.context.repo.repo,
        issue_number: github.context.payload.pull_request.number,
      });

      const existing = comments.find(c =>
        c.body?.includes('Bolyra Replay Check') && c.user?.type === 'Bot'
      );

      if (existing) {
        await octokit.rest.issues.updateComment({
          owner: github.context.repo.owner,
          repo: github.context.repo.repo,
          comment_id: existing.id,
          body: comment,
        });
        core.info('Updated existing PR comment');
      } else {
        await octokit.rest.issues.createComment({
          owner: github.context.repo.owner,
          repo: github.context.repo.repo,
          issue_number: github.context.payload.pull_request.number,
          body: comment,
        });
        core.info('Posted PR comment');
      }
    }

    // Fail if regressions found
    if (failOnRegression && regressions > 0) {
      core.setFailed(`${regressions} regression(s) found: agent behavior that was previously allowed would now be denied.`);
    }

  } catch (error) {
    core.setFailed(`Bolyra Replay Check failed: ${error instanceof Error ? error.message : String(error)}`);
  }
}

main();
