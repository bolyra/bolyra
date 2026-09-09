/**
 * HUT shim (§16.2) for khandrew1/mcp-use-evc-example.
 *
 * Boundary under test: the implementer's askExternalVerifier, imported
 * unmodified from the cloned repo at its pinned commit (EVC_IMPL_DIR),
 * COMPOSED WITH the harness-provided file nonce store below. The library
 * delegates nonce reservation through its consumeNonces callback, so
 * conflict detection and persistence in the three nonce vectors are
 * observable behavior of this test store, not of the example's own storage
 * or middleware — the claim registry scopes the evidence accordingly. The
 * shim additionally:
 *   1. reads the HUT env + the §2.1 request on stdin,
 *   2. maps the library's distinct error messages onto §16.3 failure
 *      classes 1:1.
 * It never overrides a decision. An error message with no mapping exits
 * non-zero, which the runner records as a loud vector FAIL — a shim that
 * guessed a class there would be testing itself, not the implementer.
 *
 * Run under the implementer's own tsx (from its pinned lockfile), so the
 * TypeScript execution path is also the implementer's, not ours.
 */
import fs from "node:fs";

const implDir = process.env.EVC_IMPL_DIR;
if (!implDir) {
  process.stderr.write("EVC_IMPL_DIR not set\n");
  process.exit(1);
}

// The library's EvcHostError messages, mapped 1:1 to §16.3 classes. Exact
// strings from src/evc-host.ts at the pinned commit; a drifted message on a
// future pin fails loudly instead of silently reclassifying.
const MESSAGE_TO_CLASS: Record<string, string> = {
  "EVC verifier timeout": "timeout",
  "EVC verifier spawn error": "spawn_error",
  "EVC verifier output exceeded limit": "oversize_stdout",
  "EVC verifier killed by signal": "signal_death",
  "EVC verifier exited unsuccessfully": "nonzero_exit",
  "EVC verifier returned malformed JSON": "unparseable_stdout",
  "EVC verifier returned an invalid verdict": "schema_invalid",
  "EVC replay detected": "replay",
};

type Nonce = { issuer_key: string; nonce: string; retain_until: number };

// Durable-store convention from spec/reference-host.js: one reserved nonce
// per line. On mixed novel/conflicting input this store persists nothing
// (the reference host persists the novel entries before denying); either
// behavior satisfies the vectors, which assert nonce_reserved only after an
// allow.
function makeConsumeNonces(mode: string, store: string | null) {
  if (mode !== "host") return async () => true; // local mode: verifier owns reservation
  return async (nonces: Nonce[]) => {
    if (!store) return false; // host mode without a store: fail closed
    const existing = new Set<string>();
    try {
      for (const line of fs.readFileSync(store, "utf8").split("\n")) {
        if (line.trim()) existing.add(line.trim());
      }
    } catch {
      /* missing store == empty */
    }
    for (const n of nonces) {
      if (existing.has(n.nonce)) return false;
    }
    for (const n of nonces) existing.add(n.nonce);
    fs.writeFileSync(store, Array.from(existing).join("\n") + "\n");
    return true;
  };
}

function emit(decision: unknown): never {
  process.stdout.write(JSON.stringify(decision));
  process.exit(0);
}

async function main() {
  const { askExternalVerifier } = await import(`${implDir}/src/evc-host.ts`);

  const verifierCmd = JSON.parse(process.env.HUT_VERIFIER_CMD || "[]");
  const timeoutMs = Number(process.env.HUT_TIMEOUT_MS || 10000);
  const maxStdoutBytes = Number(process.env.HUT_MAX_STDOUT_BYTES || 1048576);
  const nonceMode = process.env.HUT_NONCE_MODE || "local";
  const nonceStore = process.env.HUT_NONCE_STORE || null;
  const actionLog = process.env.HUT_ACTION_LOG || null;

  const stdin = fs.readFileSync(0, "utf8");
  const request = JSON.parse(stdin);

  try {
    const verdict = await askExternalVerifier({
      command: verifierCmd[0],
      args: verifierCmd.slice(1),
      request,
      timeoutMs,
      maxStdoutBytes,
      consumeNonces: makeConsumeNonces(nonceMode, nonceStore),
    });
    if (verdict.verdict === "deny") {
      emit({ decision: "deny", code: verdict.code });
    }
    // §16.5 reserve-before-act observability: mark the action only after the
    // library resolved allow (its reservation already succeeded by then).
    if (actionLog) {
      try {
        fs.appendFileSync(actionLog, "acted\n");
      } catch {
        /* best effort */
      }
    }
    emit({ decision: "allow" });
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    const failureClass = MESSAGE_TO_CLASS[message];
    if (!failureClass) {
      process.stderr.write(`unmapped host error: ${message}\n`);
      process.exit(1);
    }
    emit({ decision: "deny", failure_class: failureClass });
  }
}

main();
