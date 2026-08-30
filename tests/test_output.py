from __future__ import annotations

import json
import unittest

from gawsl.output import render_json, render_sarif, render_text

from helpers import scan_text

WORKFLOW = """
name: vulnerable
on: push
permissions: write-all
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
"""


class OutputTests(unittest.TestCase):
    def test_text_contains_rule_and_summary(self) -> None:
        with scan_text(WORKFLOW) as result:
            text = render_text(result)
            self.assertIn("GH002", text)
            self.assertIn("Summary:", text)

    def test_json_is_machine_readable(self) -> None:
        with scan_text(WORKFLOW) as result:
            payload = json.loads(render_json(result))
            self.assertEqual("1.0", payload["schema_version"])
            self.assertGreater(payload["active_findings"], 0)

    def test_sarif_is_version_2_1_0(self) -> None:
        with scan_text(WORKFLOW) as result:
            payload = json.loads(render_sarif(result))
            self.assertEqual("2.1.0", payload["version"])

    def test_sarif_contains_fingerprints(self) -> None:
        with scan_text(WORKFLOW) as result:
            payload = json.loads(render_sarif(result))
            self.assertTrue(payload["runs"][0]["results"][0]["partialFingerprints"])

    def test_fail_threshold_high(self) -> None:
        with scan_text(WORKFLOW) as result:
            self.assertTrue(result.fails("high"))

    def test_fail_threshold_none(self) -> None:
        with scan_text(WORKFLOW) as result:
            self.assertFalse(result.fails("none"))
