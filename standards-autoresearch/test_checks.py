"""Shape-level tests for the objective check scripts (no subprocesses)."""
from __future__ import annotations

import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

sys.path.insert(0, str(Path(__file__).resolve().parent / "checks"))
import check_vectors  # noqa: E402
import check_spec_diff  # noqa: E402


def _vector_artifact(**overrides):
    art = {
        "vector": {
            "id": "host-new-edge",
            "description": "Host must fail closed on X (§7.2).",
            "type": "host_behavior",
            "inputs": {"fixture": "new-edge.js", "timeout_ms": 5000},
            "expected": {"result": "PASS", "failure_class": "schema_invalid"},
        },
        "fixture_js": "#!/usr/bin/env node\nprocess.stdin.resume();\n",
        "fixture_name": "new-edge.js",
    }
    art.update(overrides)
    return art


class VectorShapeTests(unittest.TestCase):
    def test_valid_shape(self):
        self.assertEqual(check_vectors.validate_shape(_vector_artifact()), [])

    def test_missing_vector(self):
        errs = check_vectors.validate_shape({"fixture_js": "x"})
        self.assertIn("artifact.vector missing or not an object", errs)

    def test_wrong_type_and_id(self):
        art = _vector_artifact()
        art["vector"]["type"] = "delegation"
        art["vector"]["id"] = "NotKebab"
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("host_behavior" in e for e in errs))
        self.assertTrue(any("kebab-case" in e for e in errs))

    def test_unknown_failure_class(self):
        art = _vector_artifact()
        art["vector"]["expected"] = {"result": "PASS", "failure_class": "explodes"}
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("unknown failure_class" in e for e in errs))

    def test_fixture_must_read_stdin(self):
        art = _vector_artifact(fixture_js="#!/usr/bin/env node\n")
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("stdin" in e for e in errs))

    def test_missing_fixture_reference(self):
        art = _vector_artifact(fixture_js=None, fixture_name=None)
        art["vector"]["inputs"]["fixture"] = "does-not-exist-anywhere.js"
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("does not exist" in e for e in errs))


SPEC_DIFF_OK = """Base-Commit: {commit}
Target-File: {target}
Finding: hostile-implementer-x

```diff
-{needle}
+{needle} (clarified: the host MUST fail closed here)
```

## Rationale
...
"""


class SpecDiffTests(unittest.TestCase):
    def _write(self, text: str) -> Path:
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "spec-diff.md"
        p.write_text(text)
        return p

    def test_missing_headers(self):
        result = check_spec_diff.check(self._write("no headers\n```diff\n-x\n```\n"))
        self.assertFalse(result["ok"])
        self.assertTrue(any("Base-Commit" in e for e in result["errors"]))

    def test_stale_base_detected(self):
        with mock.patch.object(check_spec_diff, "_spec_head",
                               return_value="a" * 40):
            text = SPEC_DIFF_OK.format(commit="b" * 12,
                                       target="spec/external-verifier-contract-v1.md",
                                       needle="anything")
            result = check_spec_diff.check(self._write(text))
        self.assertFalse(result["ok"])
        self.assertTrue(any("stale base" in e for e in result["errors"]))

    def test_removal_line_must_exist(self):
        head = check_spec_diff._spec_head()
        target = "spec/external-verifier-contract-v1.md"
        text = SPEC_DIFF_OK.format(commit=head[:12], target=target,
                                   needle="THIS LINE IS NOT IN THE SPEC FILE 12345")
        result = check_spec_diff.check(self._write(text))
        self.assertFalse(result["ok"])
        self.assertTrue(any("removal line not found" in e for e in result["errors"]))



class ContainmentTests(unittest.TestCase):
    def test_target_file_allowlist(self):
        import tempfile as _tf
        td = _tf.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        p = Path(td.name) / "spec-diff.md"
        p.write_text(SPEC_DIFF_OK.format(commit="a" * 12,
                                         target="integrations/cli/src/index.ts",
                                         needle="x"))
        result = check_spec_diff.check(p)
        self.assertFalse(result["ok"])
        self.assertTrue(any("allowlist" in e for e in result["errors"]))

    def test_fixture_name_traversal_rejected(self):
        art = _vector_artifact(fixture_name="../../evil.js")
        art["vector"]["inputs"]["fixture"] = "../../evil.js"
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("bare kebab-case" in e for e in errs))

    def test_fixture_name_must_match_vector(self):
        art = _vector_artifact(fixture_name="other-name.js")
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("!=" in e for e in errs))

    def test_safe_experiment_dir(self):
        import run_tier2_build as t2
        for bad in ("../../spec", "/tmp/x", "UPPER", "a", "x" * 80):
            with self.assertRaises(ValueError):
                t2.safe_experiment_dir(bad)
        self.assertTrue(str(t2.safe_experiment_dir("hostile-implementer-edge-1"))
                        .endswith("experiments/hostile-implementer-edge-1"))


class FixtureRefTests(unittest.TestCase):
    def test_inputs_fixture_traversal_rejected_even_on_reuse(self):
        art = _vector_artifact(fixture_js=None, fixture_name=None)
        art["vector"]["inputs"]["fixture"] = "../../../etc/passwd.js"
        errs = check_vectors.validate_shape(art)
        self.assertTrue(any("vector.inputs.fixture" in e for e in errs))

class MalformedInputsTests(unittest.TestCase):
    def test_inputs_as_string_records_error_not_crash(self):
        art = _vector_artifact()
        art["vector"]["inputs"] = "not-a-dict"
        errs = check_vectors.validate_shape(art)  # must not raise
        self.assertTrue(any("inputs.fixture" in e or "inputs" in e for e in errs))

    def test_expected_as_string_records_error_not_crash(self):
        art = _vector_artifact()
        art["vector"]["expected"] = "not-a-dict"
        errs = check_vectors.validate_shape(art)  # must not raise
        self.assertTrue(any("expected must be an object" in e for e in errs))

if __name__ == "__main__":
    unittest.main()
