from __future__ import annotations

import re
import sys
from pathlib import Path

ROOT = Path(sys.argv[1] if len(sys.argv) > 1 else ".").resolve()
SKIP_PARTS = {".git", ".venv", "dist", "build", "__pycache__", ".pytest_cache"}
TEXT_SUFFIXES = {".py", ".md", ".toml", ".json", ".yml", ".yaml", ".txt", ".cff"}
PATTERNS = {
    "private-key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    "github-token": re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{30,}\b"),
    "aws-key": re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    "generic-secret": re.compile(r"(?i)\b(?:api[_-]?key|token|password|secret)\s*[:=]\s*['\"][A-Za-z0-9_./+=-]{20,}['\"]"),
    "windows-user-path": re.compile(r"(?i)[A-Z]:\\Users\\[^\\\s]+"),
    "unix-user-path": re.compile(r"/(?:home|Users)/[^/\s]+"),
    "email": re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I),
}
ALLOWED_EMAILS = {"security@example.invalid", "41898282+github-actions[bot]@users.noreply.github.com"}
findings = []
scanned = 0
for path in sorted(ROOT.rglob("*")):
    if not path.is_file() or path.suffix.lower() not in TEXT_SUFFIXES:
        continue
    if any(part in SKIP_PARTS for part in path.parts):
        continue
    text = path.read_text(encoding="utf-8")
    scanned += 1
    for name, pattern in PATTERNS.items():
        for match in pattern.finditer(text):
            value = match.group(0)
            if name == "email" and value in ALLOWED_EMAILS:
                continue
            # Examples intentionally refer to symbolic secret names but never values.
            if name == "generic-secret" and "${{ secrets." in value:
                continue
            findings.append((path.relative_to(ROOT).as_posix(), name, value[:80]))
if findings:
    for item in findings:
        print(f"public-audit finding: {item}", file=sys.stderr)
    raise SystemExit(1)
print(f"public audit passed: {scanned} text files scanned")
