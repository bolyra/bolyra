#!/usr/bin/env node
/**
 * @bolyra/evc-conformance - prove an EVC v1 host conforms, in one command.
 *
 *   npx @bolyra/evc-conformance --host "/path/to/your-host --flags"
 *   npx @bolyra/evc-conformance --host "..." --json
 *   npx @bolyra/evc-conformance            # self-test against the bundled reference host
 *
 * This is a thin launcher over the vendored spec runner (see MANIFEST.json
 * for the checksummed provenance of every vendored file). It always runs the
 * host_behavior vector class - the class that tests YOUR host, in any
 * language, with no npm install. The full 104-vector suite lives in the
 * bolyra monorepo; the normative contract is
 * spec/external-verifier-contract-v1.md there.
 *
 * Exit codes: 0 all pass, 1 any failure - drops straight into CI.
 */

const { spawnSync } = require('child_process');
const path = require('path');

const args = process.argv.slice(2);

if (args.includes('--help') || args.includes('-h')) {
  console.log(`@bolyra/evc-conformance - EVC v1 host conformance (host_behavior vectors)

Usage:
  evc-conformance --host "/path/to/your-host --flags"   test YOUR host
  evc-conformance --host "..." --json                   machine-readable result on stdout
  evc-conformance                                       self-test the bundled reference host
  evc-conformance --vector <id>                         run a single vector

Your host must honor the Host-Under-Test convention (HUT_* env, one request
on stdin, one decision object on stdout). Full pass path:
https://github.com/bolyra/bolyra/blob/main/spec/IMPLEMENTER.md`);
  process.exit(0);
}

const runner = path.join(__dirname, 'vendor', 'conformance-runner.js');
const res = spawnSync(
  process.execPath,
  [runner, '--type', 'host_behavior', ...args],
  { stdio: 'inherit' },
);
process.exit(res.status === null ? 1 : res.status);
