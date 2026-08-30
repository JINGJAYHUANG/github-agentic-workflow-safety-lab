# Rule reference

GAWSL v0.1.0 contains 22 deterministic heuristic rules.

| Rule | Severity | Category | Title |
|---|---|---|---|
| `AG001` | critical | agent-authorization | Comment-triggered agent lacks an actor authorization gate |
| `AG002` | critical | prompt-injection | Untrusted event text is passed to an agent |
| `AG003` | high | agent-privilege | Agent step runs with write-capable token permissions |
| `AG004` | critical | agent-output | Agent output is executed as code |
| `AG005` | high | agent-change-control | Agent workflow directly pushes, merges, or mutates repository state |
| `AG006` | critical | agent-secrets | Secret is passed directly to an agent step |
| `AG007` | medium | agent-availability | Comment-driven agent workflow has no concurrency control |
| `AG008` | high | agent-approval | Write-capable agent job has no protected environment |
| `GH001` | medium | permissions | Explicit token permissions are missing |
| `GH002` | critical | permissions | Write-all token permissions |
| `GH003` | high | supply-chain | Action or reusable workflow is not pinned to a full commit SHA |
| `GH004` | high | injection | Untrusted expression is interpolated directly into executable script |
| `GH005` | critical | privilege-boundary | Privileged pull_request_target workflow checks out PR-controlled code |
| `GH006` | critical | runner | Untrusted contribution can run on a self-hosted runner |
| `GH007` | high | credentials | Checkout credentials persist in a write-capable job |
| `GH008` | critical | supply-chain | Network download is piped directly to a shell |
| `GH009` | critical | artifact-boundary | Privileged workflow_run job executes downloaded artifacts |
| `GH010` | high | secrets | Secrets are referenced from an externally triggerable privileged workflow |
| `GH011` | low | availability | Job has no timeout-minutes |
| `GH012` | high | identity | OIDC token permission lacks a trusted deployment boundary |
| `GH013` | medium | supply-chain | Container image is referenced by a mutable tag |
| `GH014` | high | injection | Runner or matrix topology depends directly on untrusted input |

## Rule details
## AG001 — Comment-triggered agent lacks an actor authorization gate

**Severity:** `critical`  
**Category:** `agent-authorization`

A public comment command can become an execution API unless the actor and repository relationship are checked before any agent or write-capable step runs.

**Remediation**

Require an explicit command and allowlisted actor, team, or trusted author association before routing to the agent.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## AG002 — Untrusted event text is passed to an agent

**Severity:** `critical`  
**Category:** `prompt-injection`

Issue, pull-request, review, or comment text is attacker-controlled. Giving it to an agent that can access tools or secrets creates a prompt-injection path.

**Remediation**

Separate untrusted content from instructions, use a read-only analysis stage, validate structured output, and require approval before privileged actions.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## AG003 — Agent step runs with write-capable token permissions

**Severity:** `high`  
**Category:** `agent-privilege`

An agent can be manipulated or make mistakes. Combining interpretation and repository write authority removes an important control boundary.

**Remediation**

Run the agent read-only, emit a bounded proposal artifact, and apply changes in a separate reviewed job with minimal write scope.

**References**

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication

## AG004 — Agent output is executed as code

**Severity:** `critical`  
**Category:** `agent-output`

Model output is untrusted data. Substituting it into a shell, eval, source, interpreter, or generated workflow turns model text into code execution.

**Remediation**

Require a typed schema, allowlisted operations, static validation, and human approval. Never execute free-form model output directly.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## AG005 — Agent workflow directly pushes, merges, or mutates repository state

**Severity:** `high`  
**Category:** `agent-change-control`

Direct mutation removes the independent review boundary and can amplify prompt injection or model error.

**Remediation**

Have the agent create a patch or draft pull request. Require branch protection, code review, and separate merge authority.

**References**

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication

## AG006 — Secret is passed directly to an agent step

**Severity:** `critical`  
**Category:** `agent-secrets`

Prompted agents and their dependencies may log, transmit, or accidentally disclose credentials.

**Remediation**

Keep secrets outside the reasoning context. Use a narrow broker or post-approval step that exposes only the exact operation required.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## AG007 — Comment-driven agent workflow has no concurrency control

**Severity:** `medium`  
**Category:** `agent-availability`

Repeated comments can create parallel agent runs, duplicate changes, race conditions, and avoidable cost.

**Remediation**

Add a stable concurrency group derived from the issue or pull request and choose an explicit cancellation policy.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## AG008 — Write-capable agent job has no protected environment

**Severity:** `high`  
**Category:** `agent-approval`

A write-capable agent job without an environment cannot use environment-level required reviewers or scoped environment secrets.

**Remediation**

Move mutation into a separate job protected by a GitHub environment with required reviewers and narrow secrets.

**References**

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication

## GH001 — Explicit token permissions are missing

**Severity:** `medium`  
**Category:** `permissions`

A workflow without an explicit permissions block relies on repository defaults, which are harder to review and may drift.

**Remediation**

Add a top-level `permissions: contents: read` block, then grant narrower job-level write scopes only where required.

**References**

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication

## GH002 — Write-all token permissions

**Severity:** `critical`  
**Category:** `permissions`

`write-all` grants every available GITHUB_TOKEN write scope to the workflow or job.

**Remediation**

Replace `write-all` with an explicit allowlist of the smallest required scopes.

**References**

- https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication

## GH003 — Action or reusable workflow is not pinned to a full commit SHA

**Severity:** `high`  
**Category:** `supply-chain`

Mutable tags and branches can change after review and therefore do not provide immutable dependency identity.

**Remediation**

Pin every third-party action and reusable workflow to a full 40-character commit SHA and record the human-readable release in a comment.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH004 — Untrusted expression is interpolated directly into executable script

**Severity:** `high`  
**Category:** `injection`

Event-controlled text embedded in a `run` or `github-script` body can change the program that the runner executes.

**Remediation**

Move the expression into an environment variable or action input and treat it strictly as data; validate it before use.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH005 — Privileged pull_request_target workflow checks out PR-controlled code

**Severity:** `critical`  
**Category:** `privilege-boundary`

A pull_request_target workflow can have base-repository secrets and write permissions. Checking out and executing PR-controlled code creates a pwn-request path.

**Remediation**

Use `pull_request` for untrusted build/test code. Keep pull_request_target limited to metadata-only operations and never execute PR-controlled content.

**References**

- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target

## GH006 — Untrusted contribution can run on a self-hosted runner

**Severity:** `critical`  
**Category:** `runner`

Self-hosted runners can retain credentials, files, network access, or state and are not guaranteed to be clean or ephemeral.

**Remediation**

Use GitHub-hosted runners for public or fork-controlled pull requests, or isolate ephemeral runners in tightly restricted groups.

**References**

- https://docs.github.com/en/actions/reference/runners/self-hosted-runners

## GH007 — Checkout credentials persist in a write-capable job

**Severity:** `high`  
**Category:** `credentials`

actions/checkout persists the workflow token by default. Later tools or untrusted code in the job can reuse those credentials.

**Remediation**

Set `persist-credentials: false` and provide a narrowly scoped credential only to the exact step that needs it.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH008 — Network download is piped directly to a shell

**Severity:** `critical`  
**Category:** `supply-chain`

Download-and-execute pipelines provide no stable identity, integrity check, or review point for remote code.

**Remediation**

Download to a file, verify a pinned digest or signature, inspect provenance, and execute only after verification.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH009 — Privileged workflow_run job executes downloaded artifacts

**Severity:** `critical`  
**Category:** `artifact-boundary`

Artifacts produced by a different workflow may contain fork-controlled content. A privileged workflow must treat them as untrusted data.

**Remediation**

Bind artifacts to an expected workflow, repository, commit, and digest; parse them as data instead of executing them.

**References**

- https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target

## GH010 — Secrets are referenced from an externally triggerable privileged workflow

**Severity:** `high`  
**Category:** `secrets`

Secrets in pull_request_target, issue_comment, discussion_comment, or workflow_run workflows raise the impact of prompt, script, checkout, and artifact attacks.

**Remediation**

Remove secrets from the untrusted stage. Split the workflow and use an approved environment or narrowly scoped short-lived credential in a trusted stage.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH011 — Job has no timeout-minutes

**Severity:** `low`  
**Category:** `availability`

A missing timeout allows stuck, adversarial, or unexpectedly expensive jobs to consume runner time indefinitely up to platform limits.

**Remediation**

Set a job-level timeout-minutes appropriate to the expected workload.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH012 — OIDC token permission lacks a trusted deployment boundary

**Severity:** `high`  
**Category:** `identity`

`id-token: write` allows the job to request an OIDC token. On risky triggers or without an environment boundary, the trust policy may be too broad.

**Remediation**

Issue OIDC tokens only in a trusted deployment job protected by an environment and restrictive cloud-side subject claims.

**References**

- https://docs.github.com/en/actions/concepts/security/openid-connect

## GH013 — Container image is referenced by a mutable tag

**Severity:** `medium`  
**Category:** `supply-chain`

A mutable container or service tag can resolve to different code after review.

**Remediation**

Pin container and service images by immutable digest, for example `image@sha256:...`.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

## GH014 — Runner or matrix topology depends directly on untrusted input

**Severity:** `high`  
**Category:** `injection`

Allowing event-controlled text to choose runners or matrix values can redirect execution to privileged infrastructure or expand workload unexpectedly.

**Remediation**

Map untrusted input through a fixed allowlist before using it in `runs-on`, `container`, or `strategy.matrix`.

**References**

- https://docs.github.com/en/actions/reference/security/secure-use

