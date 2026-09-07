// Host-Under-Test adapter for khandrew1/mcp-use-evc-example @17642a5.
// Test-only shim (spec/IMPLEMENTER.md §3): maps the HUT_* convention onto the
// implementation's askExternalVerifier() and maps its EvcHostError messages
// 1:1 onto §16.3 failure classes. It adds NO contract logic: verdict codes are
// relayed unchanged, timeout/output-bound/schema/replay decisions are the
// implementation's own.
import { appendFileSync, existsSync, readFileSync } from "node:fs";

import { askExternalVerifier, EvcHostError, type EvcNonce } from "/tmp/evc-ext/src/evc-host.ts";

const CLASS_BY_MESSAGE: Record<string, string> = {
  "EVC verifier timeout": "timeout",
  "EVC verifier spawn error": "spawn_error",
  "EVC verifier output exceeded limit": "oversize_stdout",
  "EVC verifier killed by signal": "signal_death",
  "EVC verifier exited unsuccessfully": "nonzero_exit",
  "EVC verifier returned malformed JSON": "unparseable_stdout",
  "EVC verifier returned an invalid verdict": "schema_invalid",
  "EVC replay detected": "replay",
  "EVC nonce reservation failed": "replay",
  "EVC nonce reservation is not configured": "replay",
};

function emit(decision: Record<string, unknown>): void {
  process.stdout.write(JSON.stringify(decision), () => process.exit(0));
}

async function main(): Promise<void> {
  const chunks: Buffer[] = [];
  for await (const c of process.stdin) chunks.push(c as Buffer);
  const request = JSON.parse(Buffer.concat(chunks).toString("utf8"));

  const argv: string[] = JSON.parse(process.env.HUT_VERIFIER_CMD ?? "[]");
  const store = process.env.HUT_NONCE_STORE;
  const hostMode = process.env.HUT_NONCE_MODE === "host";
  const local = new Set<string>();

  const consumeNonces = (nonces: EvcNonce[]): boolean => {
    const reserved = new Set<string>(local);
    if (hostMode && store && existsSync(store)) {
      for (const line of readFileSync(store, "utf8").split("\n")) if (line.trim()) reserved.add(line.trim());
    }
    if (nonces.some((n) => reserved.has(n.nonce))) return false; // ANY conflict -> reserve nothing
    for (const n of nonces) {
      local.add(n.nonce);
      if (hostMode && store) appendFileSync(store, n.nonce + "\n");
    }
    return true;
  };

  try {
    const verdict = await askExternalVerifier({
      command: argv[0],
      args: argv.slice(1),
      request,
      timeoutMs: Number(process.env.HUT_TIMEOUT_MS ?? 1000),
      maxStdoutBytes: Number(process.env.HUT_MAX_STDOUT_BYTES ?? 65536),
      consumeNonces,
    });
    if (verdict.verdict === "allow") {
      if (process.env.HUT_ACTION_LOG) appendFileSync(process.env.HUT_ACTION_LOG, "authorized\n");
      emit({ decision: "allow" });
    } else {
      emit({ decision: "deny", code: verdict.code }); // relayed unchanged
    }
  } catch (err) {
    const msg = err instanceof EvcHostError ? err.message : String(err);
    emit({ decision: "deny", failure_class: CLASS_BY_MESSAGE[msg] ?? "spawn_error" });
  }
}

main();
