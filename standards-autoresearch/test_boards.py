"""Board mutation invariants: create / rescore-if-higher / hold-cap / terminal."""
from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

import boards


def _candidate(cid="scout-x", ctype="adoption_target", name="ExampleCo"):
    return {"id": cid, "type": ctype, "title": f"{name} target",
            "claim": "would outsource verification",
            "evidence": ["https://example.com/repo"],
            "entity": {"name": name, "repo": "example/repo", "tracked_id": None}}


def _score(**dims):
    base = {"incentive_fit": 20, "technical_fit": 20, "channel_state": 20, "effort": 15}
    base.update(dims)
    return {"dims": base}


class BoardTests(unittest.TestCase):
    def setUp(self):
        td = tempfile.TemporaryDirectory()
        self.addCleanup(td.cleanup)
        patcher = mock.patch.object(boards, "OUTPUT", Path(td.name))
        patcher.start()
        self.addCleanup(patcher.stop)
        (boards.OUTPUT / "adoption_board.json").write_text("[]")
        (boards.OUTPUT / "threat_board.json").write_text("[]")

    def _cards(self):
        return json.loads((boards.OUTPUT / "adoption_board.json").read_text())

    def test_create(self):
        action = boards.apply_candidate(_candidate(), _score(), iter_num=1, held_names=[])
        self.assertEqual(action, "created")
        cards = self._cards()
        self.assertEqual(len(cards), 1)
        self.assertEqual(cards[0]["state"], "active")
        self.assertEqual(cards[0]["scores"]["total"], 75)

    def test_hold_caps_channel_state(self):
        action = boards.apply_candidate(_candidate(name="HeldCo"), _score(),
                                        iter_num=1, held_names=["HeldCo"])
        self.assertEqual(action, "created")
        card = self._cards()[0]
        self.assertEqual(card["state"], "hold")
        self.assertEqual(card["scores"]["dims"]["channel_state"], 5)

    def test_rescore_only_if_higher(self):
        boards.apply_candidate(_candidate(), _score(), iter_num=1, held_names=[])
        low = boards.apply_candidate(_candidate(), _score(incentive_fit=1),
                                     iter_num=2, held_names=[])
        self.assertEqual(low, "unchanged_lower_score")
        high = boards.apply_candidate(_candidate(), _score(effort=25),
                                      iter_num=2, held_names=[])
        self.assertEqual(high, "rescored")
        card = self._cards()[0]
        self.assertEqual(card["scores"]["total"], 85)
        self.assertTrue(any("rescored" in h["event"] for h in card["history"]))

    def test_terminal_is_terminal(self):
        boards.apply_candidate(_candidate(), _score(), iter_num=1, held_names=[])
        cards = self._cards()
        cards[0]["state"] = "terminal"
        (boards.OUTPUT / "adoption_board.json").write_text(json.dumps(cards))
        action = boards.apply_candidate(_candidate(), _score(effort=25),
                                        iter_num=3, held_names=[])
        self.assertEqual(action, "skipped_terminal")

    def test_new_cards_since(self):
        boards.apply_candidate(_candidate("a1"), _score(), iter_num=4, held_names=[])
        boards.apply_candidate(_candidate("a2", ctype="threat_update"), _score(),
                               iter_num=4, held_names=[])
        self.assertEqual(boards.new_cards_since(4), 2)
        self.assertEqual(boards.new_cards_since(5), 0)


if __name__ == "__main__":
    unittest.main()
