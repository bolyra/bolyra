// Start `wrangler secret put TENANTS` only once a non-empty validated map has arrived on
// stdin. `wrangler secret put` has no empty-value guard, so it must not be the last stage
// of the assembly pipeline: on a validator refusal it would read EOF and put an empty
// secret, which fails EVERY tenant closed. The map is held in memory and never written
// anywhere. Extra arguments (`--env=staging`, or `--env=` for production) are passed
// through to wrangler.
import { spawn } from 'node:child_process';
import { unlinkSync, writeFileSync } from 'node:fs';
import path from 'node:path';

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
  // The map goes to wrangler on stdin, so wrangler's own logging decides whether the secret
  // ever reaches disk. WRANGLER_LOG_SANITIZE=false or WRANGLER_WRITE_LOGS=true in the
  // operator's shell would be inherited here and write the full token map into wrangler's
  // debug log; the three are pinned on the child so the environment cannot opt into that.
  const child = spawn('npx', ['--no-install', 'wrangler', 'secret', 'put', 'TENANTS', ...process.argv.slice(2)], {
    stdio: ['pipe', 'inherit', 'inherit'],
    env: {
      ...process.env,
      WRANGLER_LOG_SANITIZE: 'true',
      WRANGLER_WRITE_LOGS: 'false',
      WRANGLER_SEND_METRICS: 'false',
    },
  });
  // tenant.sh exports TENANT_LOCK_DIR for as long as it holds the per-environment lock.
  // Recording wrangler's pid there is what lets the lock outlive an interrupted shell: without
  // it, a lock released while this upload is still in flight would let a second operator's sync
  // land first and be overwritten by this older map — a quarantine silently undone.
  // Best effort in both directions: an unwritable lock directory must never stop a push that is
  // otherwise fine, and a pid file that is already gone must never fail the exit path.
  const uploadPidFile = process.env.TENANT_LOCK_DIR
    ? path.join(process.env.TENANT_LOCK_DIR, 'upload.pid')
    : undefined;
  if (uploadPidFile !== undefined) {
    try {
      writeFileSync(uploadPidFile, String(child.pid));
    } catch {
      // The lock is advisory from here; tenant.sh still holds it for this whole process.
    }
  }
  // Forward an interrupt to wrangler rather than dying under it. This process must outlive the
  // child: it is what removes the upload pid file at the moment the upload is really over, and
  // what keeps the pipeline stage that tenant.sh is waiting on running until then, so tenant.sh
  // sees a finished put before its own deferred handler runs. The `exit` listener below is the
  // only way out; on a signal death `code` is null and it exits non-zero.
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => {
      try {
        child.kill(sig);
      } catch {
        // Already gone — the `exit` listener has fired or is about to.
      }
    });
  }
  child.on('error', (e) => {
    process.stderr.write(`tenants-put: ${e.message}\n`);
    process.exit(1);
  });
  // A wrangler that exits before draining stdin makes this write fail with EPIPE. Unhandled
  // that is an uncaught exception and a stack trace on top of wrangler's real error; handled,
  // the `exit` listener below still forwards wrangler's own exit code.
  child.stdin.on('error', (e) => {
    process.stderr.write(`tenants-put: could not send the map to wrangler (${e.code ?? 'error'}); wrangler's own error is above\n`);
  });
  child.stdin.end(body);
  child.on('exit', (code) => {
    // Clear the pid BEFORE exiting: after this point no upload is in flight, so tenant.sh's
    // release_lock must be free to remove the lock directory.
    if (uploadPidFile !== undefined) {
      try {
        unlinkSync(uploadPidFile);
      } catch {
        // Already removed, or the lock directory is gone; nothing to undo.
      }
    }
    process.exit(code ?? 1);
  });
});
