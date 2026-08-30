from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable

import yaml

from .config import ScanConfig, Waiver, load_waivers, match_any
from .models import ScanResult
from .parser import WorkflowDocument
from .rules import analyze_document

SUPPORTED_SUFFIXES = (".yml", ".yaml")


class Analyzer:
    def __init__(
        self,
        *,
        config: ScanConfig | None = None,
        root: Path | None = None,
        now: datetime | None = None,
    ) -> None:
        self.config = config or ScanConfig()
        self.root = (root or Path.cwd()).resolve()
        self.now = now or datetime.now(timezone.utc)
        self.waivers = load_waivers(self.config, self.root)

    def discover(self, targets: Iterable[Path]) -> list[Path]:
        target_list = [target.resolve() for target in targets]
        explicit_files = {target for target in target_list if target.is_file()}
        found: set[Path] = set()
        for target in target_list:
            if target.is_file():
                if target.suffix.lower() in SUPPORTED_SUFFIXES:
                    found.add(target)
                continue
            if not target.exists():
                continue
            for suffix in SUPPORTED_SUFFIXES:
                found.update(path.resolve() for path in target.rglob(f"*{suffix}") if path.is_file())
        result: list[Path] = []
        for path in sorted(found):
            rel = self._relative(path)
            if path not in explicit_files:
                if self.config.include and not match_any(rel, self.config.include):
                    continue
                if match_any(rel, self.config.exclude):
                    continue
            result.append(path)
        return result

    def scan(self, targets: Iterable[Path]) -> ScanResult:
        target_list = list(targets)
        paths = self.discover(target_list)
        findings = []
        parse_errors = []
        expired = []
        expired_seen: set[tuple[str, str, str]] = set()
        for path in paths:
            try:
                doc = WorkflowDocument.load(path)
                doc.path = Path(self._relative(path))
                file_findings = analyze_document(doc)
            except (OSError, UnicodeError, ValueError, yaml.YAMLError) as exc:
                parse_errors.append({"path": self._relative(path), "error": str(exc)})
                continue
            for item in file_findings:
                for waiver in self.waivers:
                    if waiver.matches(item.rule.id, item.path, item.fingerprint):
                        if waiver.is_expired(self.now):
                            key = (waiver.rule_id, waiver.path, waiver.reason)
                            if key not in expired_seen:
                                expired_seen.add(key)
                                expired.append({
                                    "rule_id": waiver.rule_id,
                                    "path": waiver.path,
                                    "reason": waiver.reason,
                                    "expires_at": waiver.expires_at.isoformat() if waiver.expires_at else None,
                                })
                        else:
                            item.suppressed = True
                            item.waiver_reason = waiver.reason
                        break
                findings.append(item)
        return ScanResult(
            files_scanned=len(paths),
            findings=findings,
            parse_errors=parse_errors,
            expired_waivers=expired,
        )

    def _relative(self, path: Path) -> str:
        try:
            return path.resolve().relative_to(self.root).as_posix()
        except ValueError:
            return path.as_posix()
