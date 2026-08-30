from __future__ import annotations

import json
import unittest
from pathlib import Path

from gawsl.analyzer import Analyzer
from gawsl.config import ScanConfig
from gawsl.lab import verify_pairs

ROOT = Path(__file__).resolve().parents[1]


class HardenedExamplesTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.payload = json.loads((ROOT / "examples" / "pairs.json").read_text(encoding="utf-8"))
        cls.analyzer = Analyzer(config=ScanConfig(include=[], exclude=[], waivers_path=None), root=ROOT)

    def test_pair_count(self) -> None:
        self.assertEqual(10, len(self.payload["pairs"]))

    def test_all_pairs_pass(self) -> None:
        results = verify_pairs(ROOT)
        self.assertTrue(all(result.passed for result in results), [result.to_dict() for result in results])

    def test_vulnerable_examples_are_outside_workflow_directory(self) -> None:
        for pair in self.payload["pairs"]:
            self.assertNotIn(".github/workflows", pair["vulnerable"])

    def test_hardened_examples_have_no_high_or_critical_findings(self) -> None:
        for pair in self.payload["pairs"]:
            with self.subTest(pair=pair["name"]):
                result = self.analyzer.scan([ROOT / pair["hardened"]])
                blocking = [f.rule.id for f in result.active_findings if f.severity in {"critical", "high"}]
                self.assertEqual([], blocking)

    def test_vulnerable_examples_cover_expected_rules(self) -> None:
        for pair in self.payload["pairs"]:
            with self.subTest(pair=pair["name"]):
                result = self.analyzer.scan([ROOT / pair["vulnerable"]])
                observed = {f.rule.id for f in result.active_findings}
                self.assertTrue(set(pair["expected_rules"]).issubset(observed), (pair["name"], observed))
