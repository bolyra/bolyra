/**
 * bolyra inspect vectors — read-only conformance vector inspector.
 *
 * Validates test vectors against the schema, checks field completeness,
 * and prints a structured report. No crypto, no proving, no mutations.
 *
 * Usage:
 *   bolyra inspect vectors
 *   bolyra inspect vectors --path ./spec/test-vectors.json
 *   bolyra inspect vectors --format json
 */

import * as fs from 'fs';
import * as path from 'path';
import { parseArgs } from 'node:util';

const HELP = `
bolyra inspect vectors — conformance vector inspector

Usage:
  bolyra inspect vectors [options]

Options:
  --path <file>    Path to test-vectors.json (default: spec/test-vectors.json)
  --format <fmt>   Output: table (default), json
  --strict         Exit nonzero on any warning
  --help           Show this help
`.trim();

interface Vector {
  id: string;
  description: string;
  type: string;
  inputs: Record<string, any>;
  expected: Record<string, any>;
}

interface Issue {
  severity: 'error' | 'warn' | 'info';
  vectorId: string;
  field: string;
  message: string;
}

const REQUIRED_FIELDS = ['id', 'description', 'type', 'inputs', 'expected'];
const REQUIRED_EXPECTED = ['result'];

const KNOWN_TYPES = [
  'handshake', 'signature_verification', 'merkle_inclusion',
  'delegation', 'enrollment', 'delegation_chain',
  'sd_jwt', 'proof_envelope', 'session_token',
];

// Fields that financial/handshake vectors should have
const TYPE_EXPECTED_INPUTS: Record<string, string[]> = {
  handshake: ['agentPermissions', 'sessionNonce'],
  delegation: ['delegatorScope', 'delegateeScope'],
  enrollment: ['credentialCommitment'],
  sd_jwt: ['claims'],
  proof_envelope: ['contentType'],
};

export async function run(argv: string[]): Promise<void> {
  let parsed;
  try {
    parsed = parseArgs({
      args: argv,
      options: {
        path: { type: 'string', default: 'spec/test-vectors.json' },
        format: { type: 'string', default: 'table' },
        strict: { type: 'boolean', default: false },
        help: { type: 'boolean', default: false },
      },
      strict: true,
    });
  } catch (err) {
    console.error(`Error: ${(err as Error).message}`);
    process.exit(1);
  }

  if (parsed.values.help) { console.log(HELP); process.exit(0); }

  const vectorPath = path.resolve(parsed.values.path as string);
  const format = parsed.values.format as string;
  const strict = parsed.values.strict as boolean;

  // Load vectors
  if (!fs.existsSync(vectorPath)) {
    console.error(`File not found: ${vectorPath}`);
    process.exit(1);
  }

  let data: { version: string; vectors: Vector[] };
  try {
    data = JSON.parse(fs.readFileSync(vectorPath, 'utf-8'));
  } catch (err) {
    console.error(`Failed to parse: ${(err as Error).message}`);
    process.exit(1);
  }

  const issues: Issue[] = [];

  // Check version
  if (!data.version) {
    issues.push({ severity: 'error', vectorId: '(root)', field: 'version', message: 'Missing version field' });
  }

  // Check each vector
  const ids = new Set<string>();
  const typeCounts: Record<string, number> = {};
  const resultCounts = { PASS: 0, FAIL: 0 };

  for (const v of data.vectors) {
    // Required fields
    for (const f of REQUIRED_FIELDS) {
      if (!(f in v)) {
        issues.push({ severity: 'error', vectorId: v.id ?? '(unknown)', field: f, message: `Missing required field: ${f}` });
      }
    }

    // Duplicate ID
    if (ids.has(v.id)) {
      issues.push({ severity: 'error', vectorId: v.id, field: 'id', message: 'Duplicate vector ID' });
    }
    ids.add(v.id);

    // ID format
    if (v.id && !/^[a-z0-9-]+$/.test(v.id)) {
      issues.push({ severity: 'warn', vectorId: v.id, field: 'id', message: 'ID should be kebab-case (a-z, 0-9, hyphens)' });
    }

    // Known type
    if (v.type && !KNOWN_TYPES.includes(v.type)) {
      issues.push({ severity: 'warn', vectorId: v.id, field: 'type', message: `Unknown vector type: ${v.type}` });
    }
    typeCounts[v.type] = (typeCounts[v.type] || 0) + 1;

    // Expected result
    if (v.expected) {
      if (!v.expected.result) {
        issues.push({ severity: 'error', vectorId: v.id, field: 'expected.result', message: 'Missing expected.result (PASS or FAIL)' });
      } else if (!['PASS', 'FAIL'].includes(v.expected.result)) {
        issues.push({ severity: 'warn', vectorId: v.id, field: 'expected.result', message: `Unexpected result value: ${v.expected.result}` });
      } else {
        resultCounts[v.expected.result as 'PASS' | 'FAIL']++;
      }

      // FAIL vectors should have a reason
      if (v.expected.result === 'FAIL' && !v.expected.reason) {
        issues.push({ severity: 'warn', vectorId: v.id, field: 'expected.reason', message: 'FAIL vector missing expected.reason' });
      }
    }

    // Type-specific input checks
    const expectedInputs = TYPE_EXPECTED_INPUTS[v.type];
    if (expectedInputs && v.inputs) {
      for (const field of expectedInputs) {
        if (!(field in v.inputs)) {
          issues.push({ severity: 'info', vectorId: v.id, field: `inputs.${field}`, message: `${v.type} vector typically has ${field}` });
        }
      }
    }

    // Empty description
    if (v.description && v.description.length < 10) {
      issues.push({ severity: 'warn', vectorId: v.id, field: 'description', message: 'Description too short (< 10 chars)' });
    }
  }

  // Output
  const errors = issues.filter(i => i.severity === 'error').length;
  const warnings = issues.filter(i => i.severity === 'warn').length;
  const infos = issues.filter(i => i.severity === 'info').length;

  if (format === 'json') {
    console.log(JSON.stringify({
      version: data.version,
      totalVectors: data.vectors.length,
      typeCounts,
      resultCounts,
      issues,
      summary: { errors, warnings, infos },
    }, null, 2));
  } else {
    console.log('Bolyra Conformance Vector Inspector\n');
    console.log(`  Version:  ${data.version}`);
    console.log(`  Vectors:  ${data.vectors.length}`);
    console.log(`  Types:    ${Object.entries(typeCounts).map(([k, v]) => `${k}(${v})`).join(', ')}`);
    console.log(`  Results:  ${resultCounts.PASS} PASS, ${resultCounts.FAIL} FAIL`);
    console.log('');

    if (issues.length === 0) {
      console.log('\x1b[32mAll vectors valid. No issues found.\x1b[0m');
    } else {
      for (const issue of issues) {
        const icon = issue.severity === 'error' ? '\x1b[31mERROR\x1b[0m' :
                     issue.severity === 'warn' ? '\x1b[33mWARN \x1b[0m' :
                     '\x1b[36mINFO \x1b[0m';
        console.log(`${icon}  ${issue.vectorId} → ${issue.field}: ${issue.message}`);
      }
      console.log(`\nSummary: ${errors} errors, ${warnings} warnings, ${infos} info`);
    }
  }

  if (errors > 0 || (strict && warnings > 0)) {
    process.exitCode = 1;
  }
}
