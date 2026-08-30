# Threat model

## Protected assets

- repository contents and branch history;
- GitHub Actions secrets and environment secrets;
- `GITHUB_TOKEN` and OIDC-issued credentials;
- release artifacts and provenance;
- self-hosted runner files, credentials, and network access;
- maintainer trust and review integrity;
- external systems reachable from an agent or workflow.

## Adversaries

1. An external contributor controlling a fork or pull-request branch.
2. A user able to create issues, comments, reviews, or discussions.
3. A compromised third-party action, container, package, or artifact.
4. A malicious or misleading document embedded in repository content.
5. A prompted agent that makes an unsafe inference or exceeds its intended scope.
6. An insider or automation account with excessive permissions.

## Trust boundaries

| Boundary | Untrusted side | Trusted side |
|---|---|---|
| Event content | Issues, PRs, reviews, comments | Workflow instructions |
| Repository code | Fork or PR head | Base repository workflow |
| Workflow stage | Read-only analysis | Write-capable mutation |
| Agent output | Free-form model text | Typed approved operation |
| Artifact | Untrusted producer workflow | Privileged consumer workflow |
| Runner | Ephemeral public workload | Persistent internal infrastructure |
| Identity | Generic workflow token | Environment-approved scoped credential |

## Primary attack paths

### Pwn request

A privileged event checks out fork-controlled code and runs it while secrets or a write token are available.

### Script injection

Untrusted event text is interpolated into Shell or JavaScript source instead of being passed as data.

### Prompt injection to mutation

Issue, PR, comment, repository, or artifact text instructs an agent to disclose secrets or perform an unauthorized operation.

### Model-output execution

An agent produces a command, script, workflow, or expression that a later step executes without a typed schema and policy check.

### Artifact confusion

A privileged workflow downloads an artifact without binding it to an expected repository, commit, workflow, and digest, then executes it.

### Runner persistence

Untrusted code runs on a persistent self-hosted runner and steals credentials or alters state for later jobs.

## Out of scope

- vulnerabilities inside GitHub's hosted service;
- malware analysis of third-party actions or containers;
- semantic correctness of an LLM's answer;
- cloud IAM policy verification;
- organization-level GitHub settings enforcement;
- runtime containment or network sandboxing;
- proof that a reviewed workflow has no vulnerability.
