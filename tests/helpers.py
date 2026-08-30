from __future__ import annotations

from contextlib import contextmanager
from pathlib import Path
from tempfile import TemporaryDirectory

from gawsl.analyzer import Analyzer
from gawsl.config import ScanConfig


@contextmanager
def scan_text(text: str, filename: str = "workflow.yml"):
    with TemporaryDirectory() as temporary:
        root = Path(temporary)
        path = root / filename
        path.write_text(text, encoding="utf-8")
        analyzer = Analyzer(config=ScanConfig(include=[], exclude=[], waivers_path=None), root=root)
        yield analyzer.scan([path])


def ids(result) -> set[str]:
    return {finding.rule.id for finding in result.active_findings}
