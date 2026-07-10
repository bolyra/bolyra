'use strict';

/**
 * Stub verification worker for isolation.test.ts.
 *
 * Dispatches on the first CLI arg (the "mode"), which the test injects via
 * IsolationOptions.workerArgs. Each mode is a faithful analog of a real
 * verification worker behavior:
 *
 *   noise   — performs a GENUINE raw fd-1 write (fs.writeSync(1, ...)) — the
 *             faithful analog of a native/WASM library writing to stdout — and
 *             then emits a valid verdict on fd 3. The raw fd-1 bytes must be
 *             routed to the parent's stderr, NOT into the fd-3 verdict channel.
 *   crash   — exits non-zero WITHOUT writing fd 3 (fail-closed path).
 *   garbage — writes non-JSON bytes to fd 3 (fail-closed path).
 *   echo    — reads the request JSON from stdin and echoes it back as the
 *             verdict on fd 3 (proves the request reaches the worker).
 *
 * Uses raw fs.writeSync on the numeric fds so nothing depends on the CLI
 * package build; this is intentionally a plain .js file.
 */

const fs = require('fs');

const mode = process.argv[2];

function emitVerdict(verdict) {
  fs.writeSync(3, JSON.stringify(verdict));
}

switch (mode) {
  case 'noise': {
    // Genuine raw native-style write directly to fd 1 (stdout). This is the
    // exact hazard the isolation mechanism must contain.
    fs.writeSync(1, 'RAW-NATIVE-NOISE');
    emitVerdict({ verdict: 'allow' });
    break;
  }
  case 'crash': {
    // Exit non-zero without ever writing the verdict channel.
    process.exit(1);
    break;
  }
  case 'garbage': {
    // Non-JSON bytes on the verdict channel.
    fs.writeSync(3, 'this-is-not-json{{{');
    break;
  }
  case 'hang': {
    // Emit a valid verdict on fd 3, then stay alive forever. This is the
    // faithful analog of snarkjs/bn128 leaving open handles/worker threads
    // that keep the worker PROCESS alive after the verdict is flushed. The
    // parent MUST time out and fail closed rather than wait on 'close'.
    emitVerdict({ verdict: 'allow' });
    setInterval(() => {}, 1e9);
    break;
  }
  case 'echo': {
    let input = '';
    process.stdin.setEncoding('utf8');
    process.stdin.on('data', (chunk) => {
      input += chunk;
    });
    process.stdin.on('end', () => {
      let parsed;
      try {
        parsed = JSON.parse(input);
      } catch {
        parsed = { received: input };
      }
      emitVerdict({ verdict: 'allow', echoed: parsed });
    });
    break;
  }
  default: {
    fs.writeSync(2, `unknown worker mode: ${String(mode)}\n`);
    process.exit(2);
  }
}
