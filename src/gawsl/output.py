from __future__ import annotations

import json
from typing import Any

from .models import ScanResult
from .rules import RULES


def render_text(result: ScanResult) -> str:
    lines: list[str] = []
    for finding in result.active_findings:
        location = f"{finding.path}:{finding.line}:{finding.column}"
        context = ""
        if finding.job:
            context += f" job={finding.job}"
        if finding.step:
            context += f" step={finding.step}"
        lines.append(
            f"{finding.severity.upper():8} {finding.rule.id} {location}{context}\n"
            f"  {finding.message}\n"
            f"  Fix: {finding.rule.remediation}"
        )
    counts = result.counts()
    lines.append(
        "Summary: "
        f"files={result.files_scanned} "
        f"critical={counts['critical']} high={counts['high']} "
        f"medium={counts['medium']} low={counts['low']} "
        f"suppressed={len(result.suppressed_findings)} "
        f"parse_errors={len(result.parse_errors)} expired_waivers={len(result.expired_waivers)}"
    )
    if result.parse_errors:
        for error in result.parse_errors:
            lines.append(f"PARSE    {error['path']}: {error['error']}")
    return "\n".join(lines) + "\n"


def render_json(result: ScanResult) -> str:
    return json.dumps(result.to_dict(), indent=2, sort_keys=True) + "\n"


def render_sarif(result: ScanResult) -> str:
    active_rule_ids = sorted({finding.rule.id for finding in result.active_findings})
    rules = []
    for rule_id in active_rule_ids:
        rule = RULES[rule_id]
        rules.append({
            "id": rule.id,
            "name": rule.title,
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "help": {"text": rule.remediation, "markdown": rule.remediation},
            "properties": {
                "category": rule.category,
                "security-severity": _sarif_security_severity(rule.severity),
                "tags": ["security", "github-actions", rule.category],
            },
            "helpUri": rule.references[0] if rule.references else None,
        })
    sarif_results: list[dict[str, Any]] = []
    for finding in result.active_findings:
        sarif_results.append({
            "ruleId": finding.rule.id,
            "level": _sarif_level(finding.severity),
            "message": {"text": finding.message},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.path},
                    "region": {
                        "startLine": max(1, finding.line),
                        "startColumn": max(1, finding.column),
                    },
                }
            }],
            "partialFingerprints": {"primaryLocationLineHash": finding.fingerprint},
            "properties": {
                "severity": finding.severity,
                "job": finding.job,
                "step": finding.step,
                "evidence": finding.evidence,
            },
        })
    payload = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GitHub Agentic Workflow Safety Lab",
                    "informationUri": "https://github.com/JINGJAYHUANG/github-agentic-workflow-safety-lab",
                    "semanticVersion": "0.1.0",
                    "rules": rules,
                }
            },
            "results": sarif_results,
        }],
    }
    return json.dumps(payload, indent=2, sort_keys=True) + "\n"


def _sarif_level(severity: str) -> str:
    return {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "note"}[severity]


def _sarif_security_severity(severity: str) -> str:
    return {"critical": "9.0", "high": "8.0", "medium": "5.0", "low": "2.0", "info": "0.1"}[severity]
