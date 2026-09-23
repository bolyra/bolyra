#!/usr/bin/env node
// Stub verifier: under a config fault it emits deny code=internal_error but
// exits NON-ZERO, as §7.1 requires. The required vector must PASS this.
// The fault is modelled as a marker file so the stub carries no trust-store
// semantics of its own -- it exercises the runner, not a real trust store.
const fs = require('fs');
const FAULT = process.env.STUB_FAULT_FILE;
let raw = '';
process.stdin.on('data', d => { raw += d; });
process.stdin.on('end', () => {
  if (FAULT && fs.existsSync(FAULT)) {
    process.stdout.write(JSON.stringify({
      verdict: 'deny', code: 'internal_error',
      message: 'trust store present but unreadable — refusing to fail open',
    }));
    process.exitCode = 1;
    return;
  }
  process.stdout.write(JSON.stringify({ verdict: 'allow', kind: 'classical' }));
});
