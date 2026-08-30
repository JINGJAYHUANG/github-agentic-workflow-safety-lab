# Roadmap

## 0.2

- reusable-workflow and composite-action resolution;
- richer expression taint tracking across `env`, `with`, outputs, and artifacts;
- repository ruleset inspection report;
- JSON Schema validation for configuration and scan output;
- GitHub code-scanning upload example that remains opt-in.

## 0.3

- action metadata and container provenance checks;
- organization policy bundles;
- OIDC claim-policy inspection adapters;
- signed waiver records;
- differential scans between workflow revisions.

## Not planned as a silent default

- automatic mutation of user workflows;
- automatic upload of source code or SARIF to external services;
- scanning private repositories without explicit access;
- executing vulnerable teaching fixtures;
- granting agents secrets or write permissions for convenience.
