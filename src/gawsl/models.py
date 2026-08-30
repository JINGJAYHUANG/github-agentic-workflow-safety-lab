from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

SEVERITY_ORDER = {"none": 99, "critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


@dataclass(frozen=True, slots=True)
class Rule:
    id: str
    title: str
    severity: str
    category: str
    description: str
    remediation: str
    references: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "title": self.title,
            "severity": self.severity,
            "category": self.category,
            "description": self.description,
            "remediation": self.remediation,
            "references": list(self.references),
        }


@dataclass(slots=True)
class Finding:
    rule: Rule
    path: str
    line: int
    column: int
    message: str
    evidence: str
    job: str | None = None
    step: str | None = None
    suppressed: bool = False
    waiver_reason: str | None = None
    fingerprint: str = field(init=False)

    def __post_init__(self) -> None:
        payload = {
            "rule": self.rule.id,
            "path": self.path.replace("\\", "/"),
            "message": " ".join(self.message.split()),
            "evidence": " ".join(self.evidence.strip().split())[:240],
            "job": self.job or "",
            "step": self.step or "",
        }
        self.fingerprint = hashlib.sha256(
            json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()

    @property
    def severity(self) -> str:
        return self.rule.severity

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule.id,
            "title": self.rule.title,
            "severity": self.rule.severity,
            "category": self.rule.category,
            "path": self.path,
            "line": self.line,
            "column": self.column,
            "message": self.message,
            "evidence": self.evidence,
            "job": self.job,
            "step": self.step,
            "fingerprint": self.fingerprint,
            "suppressed": self.suppressed,
            "waiver_reason": self.waiver_reason,
            "remediation": self.rule.remediation,
            "references": list(self.rule.references),
        }


@dataclass(slots=True)
class ScanResult:
    files_scanned: int
    findings: list[Finding]
    parse_errors: list[dict[str, Any]]
    expired_waivers: list[dict[str, Any]]

    @property
    def active_findings(self) -> list[Finding]:
        return [f for f in self.findings if not f.suppressed]

    @property
    def suppressed_findings(self) -> list[Finding]:
        return [f for f in self.findings if f.suppressed]

    def counts(self) -> dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for finding in self.active_findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def fails(self, threshold: str) -> bool:
        if threshold == "none":
            return False
        cutoff = SEVERITY_ORDER[threshold]
        return any(SEVERITY_ORDER.get(f.severity, 99) <= cutoff for f in self.active_findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "1.0",
            "files_scanned": self.files_scanned,
            "counts": self.counts(),
            "active_findings": len(self.active_findings),
            "suppressed_findings": len(self.suppressed_findings),
            "parse_errors": self.parse_errors,
            "expired_waivers": self.expired_waivers,
            "findings": [finding.to_dict() for finding in self.findings],
        }


def normalize_path(path: str | Path) -> str:
    return Path(path).as_posix()
