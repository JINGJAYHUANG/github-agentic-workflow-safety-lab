# Architecture

## Components

```text
Workflow files
    │
    ▼
Safe YAML loader
    │
    ├── parsed structure
    └── original lines
          │
          ▼
22 deterministic heuristic rules
          │
          ▼
Stable Finding model + fingerprint
          │
          ├── expiring waiver matching
          ├── text output
          ├── JSON output
          └── SARIF 2.1.0 output
```

The analyzer deliberately combines parsed structure and raw-line inspection:

- parsed structure finds jobs, steps, triggers, permissions, runners, actions, services, and agent-shaped steps;
- raw-line inspection retains approximate line locations and catches dangerous expressions inside multiline script bodies.

## Why heuristic

Full GitHub Actions security analysis requires expression evaluation, event-specific defaults, reusable workflow resolution, action implementation analysis, permission inheritance, and data flow across steps. GAWSL v0.1.0 does not pretend to solve that entire problem.

Its scope is narrower:

- deterministic review signals;
- high-value anti-patterns;
- explicit evidence and remediation;
- regression-tested fixtures;
- no network access required during analysis.

## Stable fingerprints

A finding fingerprint hashes:

```text
rule ID
relative path
normalized message
normalized evidence
job
step
```

Line numbers are intentionally excluded so a harmless earlier edit does not invalidate a narrowly scoped waiver. Path, evidence, and semantic context still bind the waiver to a specific finding shape.

## Waiver lifecycle

```text
finding
→ exact rule/path/fingerprint match
→ expiry check
→ suppressed with reason
```

An expired waiver remains visible and makes the command exit with code `2`. It never silently converts into a permanent exception.

## Fail-closed CI boundary

CI separately checks:

1. Python compilation;
2. minimum test count;
3. unit and integration tests;
4. example directory safety;
5. all vulnerable/hardened pairs;
6. the repository's active workflows and hardened examples;
7. public repository privacy patterns;
8. Markdown links;
9. reproducible wheel output.
