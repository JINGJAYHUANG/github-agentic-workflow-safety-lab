# Contributing

## Rule changes

A new or changed rule requires:

1. a stable ID, severity, category, description, remediation, and primary reference;
2. at least one positive regression test;
3. a hardened negative example or explicit false-positive discussion;
4. no real credentials, private logs, or production exploit payloads;
5. updated rule reference and changelog.

## Example safety

Never place an intentionally vulnerable example under `.github/workflows`. All teaching fixtures must remain inert files under `examples/`.

## Validation

```bash
python -m compileall -q src scripts tests
python scripts/verify_test_count.py
python -m unittest discover -s tests -v
python scripts/check_fixture_safety.py
python scripts/public_audit.py .
python scripts/check_markdown_links.py
gawsl verify-lab --root .
gawsl scan . --config gawsl.toml --fail-on high
```
