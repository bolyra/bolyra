"""Objective check for vector_gap artifacts.

Validates a candidate host-conformance vector by:
1. Schema-shape validation of the vector entry (+ fixture source sanity).
2. Building a MERGED temp copy of spec/ (existing vectors + candidate,
   fixture written in) and running `node spec/conformance-runner.js --type
   host_behavior` against the reference host.
3. Asserting the merged run passes (existing 28 stay green AND the new
   vector passes against the conforming reference host).

The spec/ tree itself is NEVER touched (program.md rule 2a).
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
SPEC = REPO / "spec"

REQUIRED_VECTOR_FIELDS = {"id", "description", "type", "inputs", "expected"}
FAILURE_CLASSES = {
    "timeout", "signal_death", "nonzero_exit", "oversize_stdout",
    "schema_invalid", "parse_error", "replay", "trailing_garbage",
}


def validate_shape(artifact: dict[str, Any]) -> list[str]:
    errors: list[str] = []
    vector = artifact.get("vector")
    if not isinstance(vector, dict):
        return ["artifact.vector missing or not an object"]
    missing = REQUIRED_VECTOR_FIELDS - vector.keys()
    if missing:
        errors.append(f"vector missing fields: {sorted(missing)}")
    if vector.get("type") != "host_behavior":
        errors.append("vector.type must be host_behavior")
    vid = vector.get("id", "")
    if not re.fullmatch(r"host-[a-z0-9-]+", str(vid)):
        errors.append(f"vector.id must be kebab-case with host- prefix: {vid!r}")
    inputs = vector.get("inputs", {})
    if not isinstance(inputs, dict) or "fixture" not in inputs:
        errors.append("vector.inputs.fixture required")
    expected = vector.get("expected", {})
    if not isinstance(expected, dict):
        errors.append("vector.expected must be an object")
        expected = {}
    if expected.get("result") not in ("PASS",):
        errors.append("vector.expected.result must be PASS")
    if "host_decision" not in expected and "failure_class" not in expected:
        errors.append("vector.expected needs host_decision or failure_class")
    fc = expected.get("failure_class")
    if fc is not None and fc not in FAILURE_CLASSES:
        errors.append(f"unknown failure_class: {fc}")
    # inputs.fixture is used as a filename by the runner: bare basename only,
    # validated UNCONDITIONALLY before any existence check (Codex finding).
    fx_ref = str(inputs.get("fixture", "")) if isinstance(inputs, dict) else ""
    if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,64}\.js", fx_ref):
        errors.append(f"vector.inputs.fixture must be a bare kebab-case *.js basename: {fx_ref!r}")
    fixture_js = artifact.get("fixture_js")
    fixture_name = artifact.get("fixture_name")
    if fixture_js is not None:
        # bare basename only, and it must be the fixture the vector references
        # (Codex review finding: unvalidated names allow traversal or an
        # unused staged fixture)
        if not re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,64}\.js", str(fixture_name or "")):
            errors.append(f"fixture_name must be a bare kebab-case *.js basename: {fixture_name!r}")
        elif fixture_name != fx_ref:
            errors.append(
                f"fixture_name {fixture_name!r} != vector.inputs.fixture {fx_ref!r}")
        if "process.stdin" not in fixture_js:
            errors.append("fixture must read stdin (host writes one request)")
    elif re.fullmatch(r"[a-z0-9][a-z0-9_-]{1,64}\.js", fx_ref):
        # must reuse an existing fixture (only checked once the name is safe)
        if not (SPEC / "fixtures" / "host-conformance" / fx_ref).exists():
            errors.append(f"no fixture_js given and {fx_ref} does not exist")
    return errors


def _docker_available() -> bool:
    return shutil.which("docker") is not None and subprocess.run(
        ["docker", "info"], capture_output=True, timeout=20).returncode == 0


def run_merged(artifact: dict[str, Any], *, timeout: int = 300) -> dict[str, Any]:
    """Copy spec/ to a temp dir, merge the candidate, run the host suite.

    The merged run EXECUTES the model-generated fixture script, so it runs
    inside `docker run --network none` (Codex review finding: arbitrary node
    code must not run with host filesystem/network access). No docker = the
    check fails loudly; there is no unsandboxed fallback.
    """
    if not _docker_available():
        return {"ok": False, "stage": "sandbox",
                "error": "docker unavailable; refusing to execute a "
                         "model-generated fixture outside a sandbox"}
    with tempfile.TemporaryDirectory(prefix="sar-vectors-") as td:
        tmp_spec = Path(td) / "spec"
        shutil.copytree(SPEC, tmp_spec, symlinks=True,
                        ignore=shutil.ignore_patterns("reference-host-rs", "*.md"))
        vectors_path = tmp_spec / "test-vectors.json"
        doc = json.loads(vectors_path.read_text())
        existing_ids = {v["id"] for v in doc["vectors"]}
        vector = artifact["vector"]
        if vector["id"] in existing_ids:
            return {"ok": False, "stage": "merge",
                    "error": f"vector id collides with published set: {vector['id']}"}
        doc["vectors"].append(vector)
        vectors_path.write_text(json.dumps(doc, indent=2))
        if artifact.get("fixture_js"):
            fx = tmp_spec / "fixtures" / "host-conformance" / artifact["fixture_name"]
            fx.write_text(artifact["fixture_js"])
            fx.chmod(0o755)
        try:
            p = subprocess.run(
                ["docker", "run", "--rm", "--network", "none",
                 "-v", f"{td}:/work", "-w", "/work", "node:20",
                 "node", "spec/conformance-runner.js", "--type", "host_behavior"],
                capture_output=True, text=True, timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            return {"ok": False, "stage": "run", "error": f"runner timeout after {timeout}s"}
        tail = "\n".join(p.stdout.splitlines()[-15:])
        return {"ok": p.returncode == 0, "stage": "run", "exit": p.returncode,
                "stdout_tail": tail, "stderr_tail": p.stderr[-800:]}


def check(artifact: dict[str, Any]) -> dict[str, Any]:
    shape_errors = validate_shape(artifact)
    if shape_errors:
        return {"ok": False, "stage": "shape", "errors": shape_errors}
    return run_merged(artifact)


def main() -> int:
    import argparse, sys
    ap = argparse.ArgumentParser()
    ap.add_argument("artifact", help="Path to the vector artifact JSON")
    args = ap.parse_args()
    result = check(json.loads(Path(args.artifact).read_text()))
    print(json.dumps(result, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    import sys
    sys.exit(main())
