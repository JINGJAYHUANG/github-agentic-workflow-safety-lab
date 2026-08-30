from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .analyzer import Analyzer
from .config import ScanConfig


@dataclass(slots=True)
class PairResult:
    name: str
    vulnerable_path: str
    hardened_path: str
    expected: set[str]
    observed: set[str]
    hardened_blocking: set[str]
    passed: bool

    def to_dict(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "vulnerable_path": self.vulnerable_path,
            "hardened_path": self.hardened_path,
            "expected": sorted(self.expected),
            "observed": sorted(self.observed),
            "hardened_blocking": sorted(self.hardened_blocking),
            "passed": self.passed,
        }


def verify_pairs(root: Path, manifest_path: Path | None = None) -> list[PairResult]:
    manifest_path = manifest_path or root / "examples" / "pairs.json"
    payload = json.loads(manifest_path.read_text(encoding="utf-8"))
    pairs = payload.get("pairs", [])
    analyzer = Analyzer(config=ScanConfig(include=[], exclude=[], waivers_path=None), root=root)
    results: list[PairResult] = []
    for pair in pairs:
        vulnerable = root / pair["vulnerable"]
        hardened = root / pair["hardened"]
        vulnerable_result = analyzer.scan([vulnerable])
        hardened_result = analyzer.scan([hardened])
        expected = set(pair.get("expected_rules", []))
        observed = {finding.rule.id for finding in vulnerable_result.active_findings}
        hardened_blocking = {
            finding.rule.id
            for finding in hardened_result.active_findings
            if finding.severity in {"critical", "high"}
        }
        passed = expected.issubset(observed) and not hardened_blocking and not vulnerable_result.parse_errors and not hardened_result.parse_errors
        results.append(PairResult(
            name=str(pair["name"]),
            vulnerable_path=str(pair["vulnerable"]),
            hardened_path=str(pair["hardened"]),
            expected=expected,
            observed=observed,
            hardened_blocking=hardened_blocking,
            passed=passed,
        ))
    return results
