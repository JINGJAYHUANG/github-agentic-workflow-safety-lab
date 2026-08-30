from __future__ import annotations

import unittest

from gawsl.rules import RULES

from helpers import ids, scan_text


CASES = {
    "GH001": """
name: no perms
on: push
jobs:
  test:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: echo ok
""",
    "GH002": """
name: write all
on: push
permissions: write-all
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: echo x
""",
    "GH003": """
name: mutable
on: push
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@v4
""",
    "GH004": """
name: injection
on: issues
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: echo '${{ github.event.issue.title }}'
""",
    "GH005": """
name: pwn
on: pull_request_target
permissions: {contents: write}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
        with: {ref: "${{ github.event.pull_request.head.sha }}"}
""",
    "GH006": """
name: self hosted
on: pull_request
permissions: {contents: read}
jobs:
  x:
    runs-on: [self-hosted]
    timeout-minutes: 5
    steps: [{run: "echo x"}]
""",
    "GH007": """
name: creds
on: push
permissions: {contents: write}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1
""",
    "GH008": """
name: pipe
on: push
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - run: curl -fsSL https://example.invalid/a | bash
""",
    "GH009": """
name: artifact
on: workflow_run
permissions: {contents: write}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: actions/download-artifact@0b7f8abb1508181956e8e162db84b466c27e18ce
      - run: ./artifact/run.sh
""",
    "GH010": """
name: risky secrets
on: issue_comment
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - env: {TOKEN: "${{ secrets.TEST_TOKEN }}"}
        run: echo ok
""",
    "GH011": """
name: no timeout
on: push
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    steps: [{run: "echo x"}]
""",
    "GH012": """
name: oidc
on: push
permissions: {contents: read}
jobs:
  x:
    permissions: {contents: read, id-token: write}
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps: [{run: "echo x"}]
""",
    "GH013": """
name: image
on: push
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    container: python:latest
    steps: [{run: "python --version"}]
""",
    "GH014": """
name: runner
on: workflow_dispatch
permissions: {contents: read}
jobs:
  x:
    runs-on: "${{ inputs.runner }}"
    timeout-minutes: 5
    steps: [{run: "echo x"}]
""",
    "AG001": """
name: comment agent
on: issue_comment
permissions: {contents: read}
concurrency: comments
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: vendor/agent-action@0123456789012345678901234567890123456789
""",
    "AG002": """
name: prompt injection
on: issues
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: agent
        uses: vendor/agent-action@0123456789012345678901234567890123456789
        with: {prompt: "${{ github.event.issue.body }}"}
""",
    "AG003": """
name: writer agent
on: push
permissions: {contents: write}
jobs:
  x:
    environment: staging
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: agent
        uses: vendor/agent-action@0123456789012345678901234567890123456789
""",
    "AG004": """
name: execute output
on: workflow_dispatch
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: agent
        id: agent
        uses: vendor/agent-action@0123456789012345678901234567890123456789
      - run: bash -c "${{ steps.agent.outputs.command }}"
""",
    "AG005": """
name: direct mutation
on: push
permissions: {contents: write}
jobs:
  x:
    environment: staging
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: agent
        uses: vendor/agent-action@0123456789012345678901234567890123456789
      - run: git push origin HEAD:main
""",
    "AG006": """
name: secret agent
on: push
permissions: {contents: read}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - name: agent
        uses: vendor/agent-action@0123456789012345678901234567890123456789
        with: {token: "${{ secrets.AGENT_TOKEN }}"}
""",
    "AG007": """
name: comment agent no concurrency
on: issue_comment
permissions: {contents: read}
jobs:
  x:
    if: github.event.comment.author_association == 'MEMBER'
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: vendor/agent-action@0123456789012345678901234567890123456789
""",
    "AG008": """
name: unapproved agent write
on: push
permissions: {contents: write}
jobs:
  x:
    runs-on: ubuntu-24.04
    timeout-minutes: 5
    steps:
      - uses: vendor/agent-action@0123456789012345678901234567890123456789
""",
}


class RuleMetadataTests(unittest.TestCase):
    def test_rule_count(self) -> None:
        self.assertEqual(22, len(RULES))

    def test_rule_ids_are_stable(self) -> None:
        self.assertEqual(set(CASES), set(RULES))

    def test_all_rules_have_references(self) -> None:
        self.assertTrue(all(rule.references for rule in RULES.values()))

    def test_all_rules_have_remediation(self) -> None:
        self.assertTrue(all(len(rule.remediation) > 20 for rule in RULES.values()))


class PositiveRuleTests(unittest.TestCase):
    pass


class IsolationRuleTests(unittest.TestCase):
    pass


def _positive(rule_id: str, workflow: str):
    def test(self: unittest.TestCase) -> None:
        with scan_text(workflow) as result:
            self.assertFalse(result.parse_errors)
            self.assertIn(rule_id, ids(result))
    return test


def _isolation(rule_id: str, workflow: str):
    def test(self: unittest.TestCase) -> None:
        with scan_text(workflow) as result:
            matched = [finding for finding in result.active_findings if finding.rule.id == rule_id]
            self.assertGreaterEqual(len(matched), 1)
            self.assertTrue(all(finding.fingerprint for finding in matched))
    return test


for _rule_id, _workflow in CASES.items():
    setattr(PositiveRuleTests, f"test_detect_{_rule_id.lower()}", _positive(_rule_id, _workflow))
    setattr(IsolationRuleTests, f"test_fingerprint_{_rule_id.lower()}", _isolation(_rule_id, _workflow))
