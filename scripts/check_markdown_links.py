from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
pattern = re.compile(r"\[[^\]]+\]\((?!https?://|mailto:|#)([^)]+)\)")
missing = []
for path in ROOT.rglob("*.md"):
    if ".git" in path.parts:
        continue
    text = path.read_text(encoding="utf-8")
    for target in pattern.findall(text):
        clean = target.split("#", 1)[0]
        if not clean:
            continue
        candidate = (path.parent / clean).resolve()
        if not candidate.exists():
            missing.append((path.relative_to(ROOT).as_posix(), target))
if missing:
    for item in missing:
        print(f"missing markdown link: {item}")
    raise SystemExit(1)
print("markdown links passed")
