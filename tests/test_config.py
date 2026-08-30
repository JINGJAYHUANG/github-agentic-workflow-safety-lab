from __future__ import annotations

import json
import unittest
from datetime import datetime, timezone
from pathlib import Path
from tempfile import TemporaryDirectory

from gawsl.analyzer import Analyzer
from gawsl.config import ScanConfig, Waiver

WORKFLOW = """
name: mutable action
on: push
permissions: {contents: read}
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
"""


class ConfigTests(unittest.TestCase):
    def test_default_fail_threshold(self) -> None:
        self.assertEqual("high", ScanConfig().fail_on)

    def test_waiver_matches_rule_and_path(self) -> None:
        waiver = Waiver(rule_id="GH003", path="*.yml", reason="Temporary migration exception")
        self.assertTrue(waiver.matches("GH003", "workflow.yml", "0" * 64))

    def test_waiver_rejects_other_rule(self) -> None:
        waiver = Waiver(rule_id="GH003", path="*.yml", reason="Temporary migration exception")
        self.assertFalse(waiver.matches("GH004", "workflow.yml", "0" * 64))

    def test_expired_waiver_is_reported_not_applied(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workflow.yml").write_text(WORKFLOW, encoding="utf-8")
            (root / "waivers.json").write_text(json.dumps({"waivers": [{
                "rule_id": "GH003",
                "path": "workflow.yml",
                "reason": "Migration exception with an owner",
                "expires_at": "2025-01-01T00:00:00Z"
            }]}), encoding="utf-8")
            config = ScanConfig(include=[], exclude=[], waivers_path="waivers.json")
            result = Analyzer(config=config, root=root, now=datetime(2026, 1, 1, tzinfo=timezone.utc)).scan([root / "workflow.yml"])
            self.assertEqual(1, len(result.expired_waivers))
            self.assertIn("GH003", {f.rule.id for f in result.active_findings})

    def test_active_waiver_suppresses_matching_finding(self) -> None:
        with TemporaryDirectory() as temporary:
            root = Path(temporary)
            (root / "workflow.yml").write_text(WORKFLOW, encoding="utf-8")
            (root / "waivers.json").write_text(json.dumps({"waivers": [{
                "rule_id": "GH003",
                "path": "workflow.yml",
                "reason": "Migration exception with an owner",
                "expires_at": "2027-01-01T00:00:00Z"
            }]}), encoding="utf-8")
            config = ScanConfig(include=[], exclude=[], waivers_path="waivers.json")
            result = Analyzer(config=config, root=root, now=datetime(2026, 1, 1, tzinfo=timezone.utc)).scan([root / "workflow.yml"])
            self.assertNotIn("GH003", {f.rule.id for f in result.active_findings})
            self.assertIn("GH003", {f.rule.id for f in result.suppressed_findings})
