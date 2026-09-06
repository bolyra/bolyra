"""Unit tests for drought detection, reconcile stubs, and hold parsing."""
from __future__ import annotations

import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent / "history"))
from drought_detector import should_stop  # noqa: E402
import reconcile  # noqa: E402
from run_tier1_attack import held_entities  # noqa: E402


def _t(i, cards=0, staged=0):
    return {"iter": i, "total": 50.0, "new_cards": cards, "staged": staged}


class DroughtTests(unittest.TestCase):
    def test_no_stop_when_productive(self):
        traj = [_t(0), _t(1, cards=2), _t(2, staged=1), _t(3, cards=1)]
        stop, _ = should_stop(traj)
        self.assertFalse(stop)

    def test_drought_after_three_dry(self):
        traj = [_t(0), _t(1, cards=1), _t(2), _t(3), _t(4)]
        stop, reason = should_stop(traj)
        self.assertTrue(stop)
        self.assertIn("drought", reason)

    def test_baseline_not_counted(self):
        traj = [_t(0)]  # iteration 0 only
        stop, _ = should_stop(traj)
        self.assertFalse(stop)

    def test_max_iters(self):
        traj = [_t(0), _t(1, cards=1), _t(2, cards=1)]
        stop, reason = should_stop(traj, max_iters=2)
        self.assertTrue(stop)
        self.assertIn("max iterations", reason)


class ReconcileStubTests(unittest.TestCase):
    def test_unknown_method_is_stub_not_crash(self):
        checker = reconcile.CHECKERS.get("nonexistent-method")
        self.assertIsNone(checker)  # reconcile_entities turns this into an error stub

    def test_run_helper_handles_missing_binary(self):
        code, _, err = reconcile._run(["definitely-not-a-binary-xyz"])
        self.assertEqual(code, -1)
        self.assertIn("not found", err)


class HeldEntitiesTests(unittest.TestCase):
    def test_returns_list(self):
        held = held_entities()
        self.assertIsInstance(held, list)



class DatatrackerClassificationTests(unittest.TestCase):
    def _with_response(self, payload):
        from unittest import mock
        import json as _json
        with mock.patch.object(reconcile, "_run",
                               return_value=(0, _json.dumps(payload), "")):
            return reconcile.check_datatracker({"name": "draft-x"})

    def test_expired_draft_is_terminal(self):
        out = self._with_response({"rev": "02", "expires": "2020-01-01T00:00:00Z"})
        self.assertEqual(out["state"], "terminal")
        self.assertEqual(out["detail"], "expired")

    def test_live_draft_is_active(self):
        out = self._with_response({"rev": "01", "expires": "2099-01-01T00:00:00Z"})
        self.assertEqual(out["state"], "active")

    def test_published_rfc_is_terminal(self):
        out = self._with_response({"rev": "05", "expires": "2099-01-01T00:00:00Z",
                                   "rfc": "9999"})
        self.assertEqual(out["state"], "terminal")
        self.assertEqual(out["detail"], "replaced_or_published")

if __name__ == "__main__":
    unittest.main()
