from __future__ import annotations

import unittest
from pathlib import Path

from gawsl.analyzer import Analyzer
from gawsl.config import ScanConfig

ROOT = Path(__file__).resolve().parents[1]


class DiscoveryTests(unittest.TestCase):
    def test_repository_scan_includes_live_workflows(self) -> None:
        analyzer = Analyzer(config=ScanConfig.load(ROOT / "gawsl.toml"), root=ROOT)
        paths = {path.relative_to(ROOT).as_posix() for path in analyzer.discover([ROOT])}
        self.assertIn(".github/workflows/ci.yml", paths)
        self.assertIn(".github/workflows/release.yml", paths)

    def test_repository_scan_excludes_vulnerable_fixtures(self) -> None:
        analyzer = Analyzer(config=ScanConfig.load(ROOT / "gawsl.toml"), root=ROOT)
        paths = {path.relative_to(ROOT).as_posix() for path in analyzer.discover([ROOT])}
        self.assertFalse(any(path.endswith("/vulnerable.yml") for path in paths))

    def test_repository_scan_includes_hardened_fixtures(self) -> None:
        analyzer = Analyzer(config=ScanConfig.load(ROOT / "gawsl.toml"), root=ROOT)
        paths = {path.relative_to(ROOT).as_posix() for path in analyzer.discover([ROOT])}
        self.assertTrue(any(path.endswith("/hardened.yml") for path in paths))
