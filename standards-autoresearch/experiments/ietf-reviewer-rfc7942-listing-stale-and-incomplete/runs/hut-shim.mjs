// hut-shim.mjs — Host-Under-Test (HUT) adapter for khandrew1/mcp-use-evc-example
// at commit 17642a5efd5e1c42991ab8aa399cd6138f64f635.
//
// The pinned commit exposes its EVC host boundary as a library function,
// askExternalVerifier() in src/evc-host.ts, wired into mcp-use middleware in
// src/demo.ts. It has no stdin/stdout Host-Under-Test entry point, so the
// @bolyra/evc-conformance harness cannot drive it directly. This shim is the
// smallest adapter that lets the harness drive that function unchanged:
//
//   HUT env  -> askExternalVerifier() options      (this file)
//   spawn, timeout, output bound, exit/signal handling, single-object parse,
//   closed verdict schema, reserve-before-resolve nonce ordering
//                                                  (src/evc-host.ts, UNCHANGED)
//   EvcHostError message -> §16.3 failure_class    (this file, table below)
//   file-backed nonce store for HUT_NONCE_MODE=host (this file; src/demo.ts uses
//                                                  an in-memory Set with the same
//                                                  any-conflict-rejects rule)
//   HUT_ACTION_LOG marker after allow resolves     (this file)
//
// Nothing in the cloned repo is modified. The shim lives OUTSIDE the clone.
import fs from "node:fs";
import { askExternalVerifier, EvcHostError } from "./mcp-use-evc-example/src/evc-host.ts";

const CLASS_BY_MESSAGE = {
  "EVC verifier spawn error": "spawn_error",
  "EVC verifier timeout": "timeout",
  "EVC verifier output exceeded limit": "oversize_stdout",
  "EVC verifier killed by signal": "signal_death",
  "EVC verifier exited unsuccessfully": "nonzero_exit",
  "EVC verifier returned malformed JSON": "unparseable_stdout",
  "EVC verifier returned an invalid verdict": "schema_invalid",
  "EVC replay detected": "replay",
  "EVC nonce reservation failed": "replay",
  "EVC nonce reservation is not configured": "replay",
};

function emit(d) { process.stdout.write(JSON.stringify(d), () => process.exit(0)); }

let cmd;
try { cmd = JSON.parse(process.env.HUT_VERIFIER_CMD || "[]"); } catch { cmd = []; }
const timeoutMs = Number(process.env.HUT_TIMEOUT_MS || 10000);
const maxStdoutBytes = Number(process.env.HUT_MAX_STDOUT_BYTES || 1048576);
const nonceMode = process.env.HUT_NONCE_MODE || "local";
const store = process.env.HUT_NONCE_STORE || null;
const actionLog = process.env.HUT_ACTION_LOG || null;

if (!Array.isArray(cmd) || cmd.length === 0) {
  emit({ decision: "deny", failure_class: "spawn_error" });
} else {
  const chunks = [];
  process.stdin.on("data", (c) => chunks.push(c));
  process.stdin.on("end", () => run(Buffer.concat(chunks)));
}

async function run(raw) {
  let request;
  try { request = JSON.parse(raw.toString("utf8")); }
  catch { return emit({ decision: "deny", failure_class: "spawn_error" }); } // not exercised by the suite
  const consumeNonces = nonceMode === "host" ? reserveAll : undefined;
  try {
    const verdict = await askExternalVerifier({
      command: cmd[0], args: cmd.slice(1), request, timeoutMs, maxStdoutBytes, consumeNonces,
    });
    if (verdict.verdict === "deny") return emit({ decision: "deny", code: verdict.code }); // relayed unchanged
    if (actionLog) fs.appendFileSync(actionLog, "acted\n"); // allow resolved only after reservation succeeded
    return emit({ decision: "allow" });
  } catch (e) {
    const cls = (e instanceof EvcHostError && CLASS_BY_MESSAGE[e.message]) || "spawn_error";
    return emit({ decision: "deny", failure_class: cls });
  }
}

// Durable, any-conflict-rejects reservation (mirrors src/demo.ts's Set rule on a file).
function reserveAll(entries) {
  if (!store) return false;
  const existing = new Set();
  try { for (const l of fs.readFileSync(store, "utf8").split("\n")) if (l.trim()) existing.add(l.trim()); } catch {}
  if (entries.some((e) => existing.has(e.nonce))) return false;
  for (const e of entries) existing.add(e.nonce);
  fs.writeFileSync(store, [...existing].join("\n") + "\n");
  return true;
}
