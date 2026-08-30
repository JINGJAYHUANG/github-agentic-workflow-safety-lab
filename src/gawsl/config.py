from __future__ import annotations

import fnmatch
import json
import tomllib
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(slots=True)
class Waiver:
    rule_id: str
    path: str = "*"
    fingerprint: str | None = None
    reason: str = ""
    expires_at: datetime | None = None

    @classmethod
    def from_dict(cls, raw: dict[str, Any]) -> "Waiver":
        expires_at = None
        if raw.get("expires_at"):
            value = str(raw["expires_at"]).replace("Z", "+00:00")
            expires_at = datetime.fromisoformat(value)
            if expires_at.tzinfo is None:
                expires_at = expires_at.replace(tzinfo=timezone.utc)
        return cls(
            rule_id=str(raw["rule_id"]),
            path=str(raw.get("path", "*")),
            fingerprint=raw.get("fingerprint"),
            reason=str(raw.get("reason", "")),
            expires_at=expires_at,
        )

    def is_expired(self, now: datetime) -> bool:
        return self.expires_at is not None and self.expires_at <= now

    def matches(self, rule_id: str, path: str, fingerprint: str) -> bool:
        return (
            self.rule_id == rule_id
            and fnmatch.fnmatch(path, self.path)
            and (self.fingerprint is None or self.fingerprint == fingerprint)
        )


@dataclass(slots=True)
class ScanConfig:
    include: list[str] = field(default_factory=lambda: [
        ".github/workflows/*.yml",
        ".github/workflows/*.yaml",
        ".github/workflows/**/*.yml",
        ".github/workflows/**/*.yaml",
        "examples/**/hardened.yml",
        "examples/**/hardened.yaml",
    ])
    exclude: list[str] = field(default_factory=lambda: [
        "examples/**/vulnerable.yml",
        "examples/**/vulnerable.yaml",
    ])
    fail_on: str = "high"
    waivers_path: str | None = "policy/waivers.json"

    @classmethod
    def load(cls, path: Path | None) -> "ScanConfig":
        if path is None or not path.exists():
            return cls()
        with path.open("rb") as handle:
            raw = tomllib.load(handle)
        scan = raw.get("scan", {})
        return cls(
            include=[str(item) for item in scan.get("include", cls().include)],
            exclude=[str(item) for item in scan.get("exclude", cls().exclude)],
            fail_on=str(scan.get("fail_on", "high")),
            waivers_path=scan.get("waivers"),
        )


def load_waivers(config: ScanConfig, root: Path) -> list[Waiver]:
    if not config.waivers_path:
        return []
    path = root / config.waivers_path
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    entries = raw.get("waivers", raw if isinstance(raw, list) else [])
    if not isinstance(entries, list):
        raise ValueError("waiver file must contain a list or a `waivers` list")
    return [Waiver.from_dict(item) for item in entries]


def match_any(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatch(path, pattern) for pattern in patterns)
