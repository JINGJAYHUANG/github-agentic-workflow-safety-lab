from __future__ import annotations

import json
import subprocess
import sys
import unittest
from pathlib import Path
from tempfile import TemporaryDirectory

ROOT = Path(__file__).resolve().parents[1]


class CliTests(unittest.TestCase):
    def run_cli(self, *args: str, cwd: Path | None = None) -> subprocess.CompletedProcess[str]:
        return subprocess.run(
            [sys.executable, "-m", "gawsl", *args],
            cwd=cwd or ROOT,
            text=True,
            capture_output=True,
            check=False,
        )

    def test_version(self) -> None:
        result = self.run_cli("--version")
        self.assertEqual(0, result.returncode)
        self.assertIn("0.1.0", result.stdout)

    def test_list_rules(self) -> None:
        result = self.run_cli("list-rules")
        self.assertEqual(0, result.returncode)
        self.assertIn("AG006", result.stdout)

    def test_list_rules_json(self) -> None:
        result = self.run_cli("list-rules", "--json")
        self.assertEqual(22, len(json.loads(result.stdout)))

    def test_explain_known_rule(self) -> None:
        result = self.run_cli("explain", "GH005")
        self.assertEqual(0, result.returncode)
        self.assertIn("pwn-request", result.stdout)

    def test_explain_unknown_rule(self) -> None:
        result = self.run_cli("explain", "UNKNOWN")
        self.assertEqual(2, result.returncode)

    def test_scan_vulnerable_fails(self) -> None:
        result = self.run_cli(
            "scan", "examples/pwn-request/vulnerable.yml",
            "--root", ".", "--format", "json", "--fail-on", "high"
        )
        self.assertEqual(1, result.returncode)
        self.assertIn("GH005", result.stdout)

    def test_scan_hardened_passes_high_gate(self) -> None:
        result = self.run_cli(
            "scan", "examples/pwn-request/hardened.yml",
            "--root", ".", "--format", "json", "--fail-on", "high"
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)

    def test_scan_writes_sarif(self) -> None:
        with TemporaryDirectory() as temporary:
            output = Path(temporary) / "result.sarif"
            result = self.run_cli(
                "scan", "examples/script-injection/vulnerable.yml",
                "--root", ".", "--format", "sarif", "--output", str(output), "--fail-on", "none"
            )
            self.assertEqual(0, result.returncode)
            self.assertEqual("2.1.0", json.loads(output.read_text())["version"])

    def test_verify_lab(self) -> None:
        result = self.run_cli("verify-lab", "--root", ".")
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)
        self.assertIn("10/10", result.stdout)

    def test_verify_lab_json(self) -> None:
        result = self.run_cli("verify-lab", "--root", ".", "--json")
        self.assertTrue(json.loads(result.stdout)["passed"])

    def test_init_config_refuses_overwrite(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "gawsl.toml"
            path.write_text("existing", encoding="utf-8")
            result = self.run_cli("init-config", "--path", str(path))
            self.assertEqual(2, result.returncode)

    def test_init_config_creates_file(self) -> None:
        with TemporaryDirectory() as temporary:
            path = Path(temporary) / "gawsl.toml"
            result = self.run_cli("init-config", "--path", str(path))
            self.assertEqual(0, result.returncode)
            self.assertIn("fail_on", path.read_text())
