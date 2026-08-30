from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from . import __version__
from .analyzer import Analyzer
from .config import ScanConfig
from .lab import verify_pairs
from .output import render_json, render_sarif, render_text
from .rules import RULES, rules_as_dicts


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gawsl",
        description="Scan GitHub Actions workflows for conventional and agentic security risks.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="Scan workflow files or a repository tree")
    scan.add_argument("targets", nargs="*", default=["."], type=Path)
    scan.add_argument("--config", type=Path, default=Path("gawsl.toml"))
    scan.add_argument("--format", choices=["text", "json", "sarif"], default="text")
    scan.add_argument("--output", type=Path)
    scan.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "none"])
    scan.add_argument("--root", type=Path, default=Path("."))

    rules = sub.add_parser("list-rules", help="List available rules")
    rules.add_argument("--json", action="store_true")

    explain = sub.add_parser("explain", help="Explain one rule")
    explain.add_argument("rule_id")
    explain.add_argument("--json", action="store_true")

    lab = sub.add_parser("verify-lab", help="Verify vulnerable/hardened example pairs")
    lab.add_argument("--root", type=Path, default=Path("."))
    lab.add_argument("--manifest", type=Path)
    lab.add_argument("--json", action="store_true")

    init = sub.add_parser("init-config", help="Write a conservative starter configuration")
    init.add_argument("--path", type=Path, default=Path("gawsl.toml"))
    init.add_argument("--force", action="store_true")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scan":
        return _scan(args)
    if args.command == "list-rules":
        return _list_rules(args)
    if args.command == "explain":
        return _explain(args)
    if args.command == "verify-lab":
        return _verify_lab(args)
    if args.command == "init-config":
        return _init_config(args)
    parser.error("unknown command")
    return 2


def _scan(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    config_path = args.config if args.config.is_absolute() else root / args.config
    config = ScanConfig.load(config_path)
    threshold = args.fail_on or config.fail_on
    analyzer = Analyzer(config=config, root=root)
    result = analyzer.scan(args.targets)
    rendered = {
        "text": render_text,
        "json": render_json,
        "sarif": render_sarif,
    }[args.format](result)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(rendered, encoding="utf-8", newline="\n")
    else:
        sys.stdout.write(rendered)
    if result.parse_errors or result.expired_waivers:
        return 2
    return 1 if result.fails(threshold) else 0


def _list_rules(args: argparse.Namespace) -> int:
    if args.json:
        print(json.dumps(rules_as_dicts(), indent=2, sort_keys=True))
    else:
        for rule_id in sorted(RULES):
            rule = RULES[rule_id]
            print(f"{rule.id:5} {rule.severity.upper():8} {rule.title}")
    return 0


def _explain(args: argparse.Namespace) -> int:
    rule = RULES.get(args.rule_id.upper())
    if rule is None:
        print(f"unknown rule: {args.rule_id}", file=sys.stderr)
        return 2
    if args.json:
        print(json.dumps(rule.to_dict(), indent=2, sort_keys=True))
    else:
        print(f"{rule.id} — {rule.title}")
        print(f"Severity: {rule.severity}")
        print(f"Category: {rule.category}")
        print(f"\n{rule.description}\n\nRemediation:\n{rule.remediation}")
        if rule.references:
            print("\nReferences:")
            for reference in rule.references:
                print(f"- {reference}")
    return 0


def _verify_lab(args: argparse.Namespace) -> int:
    root = args.root.resolve()
    manifest = args.manifest
    if manifest is not None and not manifest.is_absolute():
        manifest = root / manifest
    results = verify_pairs(root, manifest)
    passed = all(result.passed for result in results)
    if args.json:
        print(json.dumps({
            "schema_version": "1.0",
            "passed": passed,
            "pairs": [result.to_dict() for result in results],
        }, indent=2, sort_keys=True))
    else:
        for result in results:
            status = "PASS" if result.passed else "FAIL"
            print(f"{status:4} {result.name}")
            if not result.passed:
                print(f"  expected: {sorted(result.expected)}")
                print(f"  observed: {sorted(result.observed)}")
                print(f"  hardened blocking: {sorted(result.hardened_blocking)}")
        print(f"Summary: {sum(result.passed for result in results)}/{len(results)} pairs passed")
    return 0 if passed else 1


def _init_config(args: argparse.Namespace) -> int:
    path: Path = args.path
    if path.exists() and not args.force:
        print(f"refusing to overwrite existing file: {path}", file=sys.stderr)
        return 2
    content = """[scan]\ninclude = [\n  \".github/workflows/*.yml\",\n  \".github/workflows/*.yaml\",\n  \".github/workflows/**/*.yml\",\n  \".github/workflows/**/*.yaml\",\n]\nexclude = []\nfail_on = \"high\"\nwaivers = \"policy/waivers.json\"\n"""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content, encoding="utf-8", newline="\n")
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
