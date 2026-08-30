# Lab guide

## 1. Verify the paired examples

```bash
gawsl verify-lab --root .
```

Each pair declares a minimum expected finding set for its vulnerable file. The hardened file must have no high or critical finding.

## 2. Compare one pair

```bash
gawsl scan examples/comment-agent/vulnerable.yml --root . --format text --fail-on none
gawsl scan examples/comment-agent/hardened.yml --root . --format text --fail-on none
```

Questions to review:

1. Which text is attacker-controlled?
2. Which token, secret, runner, or external system is reachable?
3. Does one job both interpret and mutate?
4. Is model output data or executable code?
5. What approval survives between analysis and mutation?
6. Can an artifact or cache cross from an untrusted stage into a privileged stage?

## 3. Scan a repository

From the target repository root:

```bash
gawsl init-config
gawsl scan . --config gawsl.toml --fail-on high
```

The generated configuration scans active workflows only. Expand `include` deliberately if you store reusable workflows elsewhere.

## 4. Produce SARIF

```bash
gawsl scan . \
  --config gawsl.toml \
  --format sarif \
  --output gawsl.sarif \
  --fail-on none
```

SARIF is emitted for integration with code-scanning pipelines. Uploading SARIF requires repository settings and token permissions that this lab does not silently request.

## 5. Record a temporary exception

Generate JSON output, copy the finding fingerprint, and add a waiver with:

- exact rule;
- narrow path;
- preferably an exact fingerprint;
- owner and technical reason;
- expiration date.

Do not waive a critical finding merely to make CI green.

## 6. Harden the real control plane

The scanner cannot configure repository settings. Maintainers should separately review:

- default workflow token permissions;
- allowed Actions and SHA pinning policy;
- branch protection or rulesets;
- CODEOWNERS for `.github/workflows/**`;
- environment required reviewers;
- fork approval policy;
- self-hosted runner groups and network isolation;
- OIDC subject conditions;
- secret scope and rotation;
- artifact provenance and attestations;
- CodeQL for GitHub Actions where available.
