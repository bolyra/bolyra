// Start `wrangler secret put TENANTS` only once a non-empty validated map has arrived on
// stdin. `wrangler secret put` has no empty-value guard, so it must not be the last stage
// of the assembly pipeline: on a validator refusal it would read EOF and put an empty
// secret, which fails EVERY tenant closed. The map is held in memory and never written
// anywhere. Extra arguments (`--env=staging`, or `--env=` for production) are passed
// through to wrangler.
import { spawn } from 'node:child_process';
import { renameSync, writeFileSync } from 'node:fs';
import path from 'node:path';

// wrangler's own confirmation, and the ONLY thing that counts as one. The process spawned
// here is the launcher (`npx` → wrangler's bin script), which forwards a signal to the
// process it runs and then reports that child's signal death as exit 0 — so an exit code by
// itself cannot tell a finished upload from a killed one. The line is looked for on both
// streams because which one carries it is wrangler's choice, not ours.
const SUCCESS_LINE = /Success! Uploaded secret TENANTS/;

// Writing to a reader that has already gone (a `| grep -q` upstream of this stage) must not
// turn into an uncaught EPIPE on top of wrangler's own output.
process.stdout.on('error', () => {});
process.stderr.on('error', () => {});

// An interrupt is DEFERRED here exactly as it is in tenant.sh: recorded, reported once, and
// acted on only after the upload has finished. Forwarding it to the launcher would be worse
// than useless — the launcher converts its child's signal death into exit 0, so a forwarded
// interrupt reads as a clean upload while the map that reached Cloudflare is unknown.
// Installed FIRST, before a byte of the map has been read: until a handler is attached the
// default disposition applies, so a TERM that arrives while the map is still on its way down
// the pipe kills this stage outright — no marker, no upload, and a shell upstream left to
// explain an exit code for something that never started.
let interrupted = null;
for (const sig of ['SIGINT', 'SIGTERM']) {
  process.on(sig, () => {
    if (interrupted !== null) return;
    interrupted = sig;
    process.stderr.write(`tenants-put: ${sig} received; the upload in flight runs to completion first\n`);
  });
}

const chunks = [];
process.stdin.on('data', (d) => chunks.push(d));
process.stdin.on('end', () => {
  const body = Buffer.concat(chunks);
  if (body.length === 0) {
    process.stderr.write('tenants-put: nothing validated upstream; wrangler was NOT started and the live map was NOT changed\n');
    process.exit(1);
  }
  // Last line of defence before the live map: whatever reaches here must parse as a
  // non-empty JSON object. This guard costs one parse and is the only thing standing
  // between a future upstream change and a TENANTS that fails every tenant closed.
  let parsed;
  try {
    parsed = JSON.parse(body.toString('utf8'));
  } catch {
    parsed = undefined;
  }
  if (typeof parsed !== 'object' || parsed === null || Array.isArray(parsed) || Object.keys(parsed).length === 0) {
    process.stderr.write('tenants-put: refusing to push a map that is not a non-empty JSON object; wrangler was NOT started and the live map was NOT changed\n');
    process.exit(1);
  }

  // tenant.sh exports TENANT_LOCK_DIR for as long as it holds the per-environment lock, and
  // release_lock refuses to release the lock while this marker is there. It is written BEFORE
  // wrangler starts and renamed to upload.confirmed only on a confirmed upload, so every way
  // this process can die between the two — including SIGKILL — leaves the lock held. A lock released while an
  // upload is still in flight is exactly the interleaving the lock exists to prevent: a second
  // operator's sync lands first and this older map overwrites it, silently undoing a
  // quarantine. If the marker cannot be written, the upload does not start at all.
  // Without TENANT_LOCK_DIR (direct CLI use, CI) there is no lock and no marker: the lock
  // semantics below exist only under tenant.sh.
  const pendingFile = process.env.TENANT_LOCK_DIR
    ? path.join(process.env.TENANT_LOCK_DIR, 'upload.pending')
    : undefined;
  // The same marker under its confirmed name. tenant.sh reads which of the two names exists to
  // decide what to tell the operator, because neither an exit code nor the live secret can:
  // the launcher reports a signalled child as exit 0, a confirmation lost with the terminal
  // looks exactly like a failure, and `wrangler secret put` is write-only.
  const confirmedFile = process.env.TENANT_LOCK_DIR
    ? path.join(process.env.TENANT_LOCK_DIR, 'upload.confirmed')
    : undefined;
  if (pendingFile !== undefined) {
    try {
      writeFileSync(pendingFile, 'starting\n');
    } catch (err) {
      process.stderr.write(`tenants-put: cannot record the upload under the lock (${err.code ?? err}); wrangler was NOT started and the live map was NOT changed\n`);
      process.exit(1);
    }
  }

  // The map goes to wrangler on stdin, so wrangler's own logging decides whether the secret
  // ever reaches disk. WRANGLER_LOG_SANITIZE=false or WRANGLER_WRITE_LOGS=true in the
  // operator's shell would be inherited here and write the full token map into wrangler's
  // debug log; they are pinned on the child so the environment cannot opt into that.
  // Both output streams are piped rather than inherited so the success line can be read on
  // the way past; every chunk is passed through unchanged.
  const child = spawn('npx', ['--no-install', 'wrangler', 'secret', 'put', 'TENANTS', ...process.argv.slice(2)], {
    stdio: ['pipe', 'pipe', 'pipe'],
    env: {
      ...process.env,
      WRANGLER_LOG_SANITIZE: 'true',
      WRANGLER_WRITE_LOGS: 'false',
      WRANGLER_SEND_METRICS: 'false',
      // The confirmation protocol below needs wrangler's success line, and every level above
      // `log` suppresses it: at warn/error/none the upload still happens and still lands, and
      // the only thing an inherited WRANGLER_LOG changes is that this stage can no longer tell
      // that it did. Pinned, not read.
      WRANGLER_LOG: 'log',
    },
  });
  child.on('error', (e) => {
    process.stderr.write(`tenants-put: ${e.message}\n`);
    process.exit(1);
  });
  // A wrangler that exits before draining stdin makes this write fail with EPIPE. Unhandled
  // that is an uncaught exception and a stack trace on top of wrangler's real error; handled,
  // the exit path below still forwards wrangler's own exit code.
  child.stdin.on('error', (e) => {
    process.stderr.write(`tenants-put: could not send the map to wrangler (${e.code ?? 'error'}); wrangler's own error is above\n`);
  });
  child.stdin.end(body);
  if (pendingFile !== undefined) {
    try {
      // Both pids, one per line: `pid` is the launcher this started, `put` is this process —
      // the one that still has to confirm the upload. An operator reading a leftover marker
      // wants the first; anything that has to signal the upload wants the second, and reading
      // it here is the only way to get it right (a name matched against a process list picks
      // up ancestors and bystanders that merely mention this file).
      writeFileSync(pendingFile, `pid ${child.pid}\nput ${process.pid}\n`);
    } catch {
      // Best effort: the marker written before the spawn is what holds the lock; naming the
      // pids only makes the leftover easier to read and to act on.
    }
  }

  let sawSuccessLine = false;
  const passThrough = (sink) => {
    // A chunk boundary can fall inside the success line, so each stream keeps a short tail of
    // what came before. The match is made over the tail AND the whole chunk: searching only
    // the last bytes of the pair would miss a success line that a single write already carried
    // past — wrangler's debug/metrics notices follow it in the same write, and a confirmation
    // that scrolled out of a 256-byte window would retain the lock over a good upload.
    let tail = '';
    return (chunk) => {
      if (!sawSuccessLine) {
        const text = tail + chunk.toString('utf8');
        if (SUCCESS_LINE.test(text)) sawSuccessLine = true;
        tail = text.slice(-256);
      }
      // Read the confirmation off the chunk BEFORE passing it on: a reader that has already
      // gone must not cost us wrangler's own answer.
      try {
        sink.write(chunk);
      } catch {
        // The stream is gone; wrangler's exit and its success line still decide.
      }
    };
  };
  child.stdout.on('data', passThrough(process.stdout));
  child.stderr.on('data', passThrough(process.stderr));

  // `close`, not `exit`: `exit` can fire while the output pipes still hold unread bytes, and
  // the success line is read off those pipes. By `close` both have ended.
  child.on('close', (code, signal) => {
    if (code === 0 && signal === null && sawSuccessLine) {
      // Confirmed: no upload is in flight any more, so release_lock is free to release. The
      // marker is RENAMED rather than removed — same directory, so the rename is atomic and
      // there is no instant in which neither name exists — and that rename is the only record
      // tenant.sh has that this upload landed. A confirmation that cannot be recorded is
      // reported as unknown: an unnecessary re-sync costs a minute, while claiming a map is
      // live when nothing can show it is sends an operator away from a quarantine that isn't.
      if (pendingFile !== undefined) {
        try {
          renameSync(pendingFile, confirmedFile);
        } catch (err) {
          process.stderr.write(`tenants-put: the upload was confirmed but could not be recorded (${err.code ?? err}); treating the outcome as unknown\n`);
          process.exit(1);
        }
      }
      if (interrupted !== null) {
        const rc = interrupted === 'SIGINT' ? 130 : 143;
        process.stderr.write(`tenants-put: the upload completed; exiting with ${rc} because of the earlier ${interrupted}\n`);
        process.exit(rc);
      }
      process.exit(0);
    }
    // Not confirmed: the marker stays under its pending name, so the lock stays with it. What
    // reached Cloudflare is unknown from here and nothing can look it up — the secret is
    // write-only, and a dry run would only re-validate the map this run INTENDED to push.
    process.stderr.write(`tenants-put: upload NOT confirmed (exit ${code}, signal ${signal}, success line ${sawSuccessLine ? 'seen' : 'not seen'}); the lock is retained and what is live is unknown — recover with: pilot/tenant.sh unlock, then pilot/tenant.sh sync\n`);
    process.exit(code === 0 || code === null || code === undefined ? 1 : code);
  });
});
