from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
manifest = json.loads((ROOT / "examples" / "pairs.json").read_text(encoding="utf-8"))
for pair in manifest["pairs"]:
    vulnerable = Path(pair["vulnerable"])
    hardened = Path(pair["hardened"])
    assert vulnerable.parts[:2] != (".github", "workflows")
    assert hardened.parts[:2] != (".github", "workflows")
    assert (ROOT / vulnerable).is_file()
    assert (ROOT / hardened).is_file()
print(f"fixture safety passed: {len(manifest['pairs'])} pairs are non-executable examples")
