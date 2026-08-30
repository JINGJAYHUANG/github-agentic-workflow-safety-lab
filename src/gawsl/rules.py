from __future__ import annotations

import re
from typing import Any, Callable

from .models import Finding, Rule
from .parser import (
    WorkflowDocument,
    effective_permissions,
    extract_action_ref,
    is_agent_step,
    is_full_commit_sha,
    permission_has,
    permission_has_write,
    serialize_value,
    step_label,
)

GITHUB_SECURE_USE = "https://docs.github.com/en/actions/reference/security/secure-use"
PULL_REQUEST_TARGET = "https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target"
TOKEN_PERMISSIONS = "https://docs.github.com/en/actions/security-for-github-actions/security-guides/automatic-token-authentication"
OIDC = "https://docs.github.com/en/actions/concepts/security/openid-connect"
SELF_HOSTED = "https://docs.github.com/en/actions/reference/runners/self-hosted-runners"


def rule(
    rule_id: str,
    title: str,
    severity: str,
    category: str,
    description: str,
    remediation: str,
    *references: str,
) -> Rule:
    return Rule(rule_id, title, severity, category, description, remediation, tuple(references))


RULES: dict[str, Rule] = {
    "GH001": rule(
        "GH001", "Explicit token permissions are missing", "medium", "permissions",
        "A workflow without an explicit permissions block relies on repository defaults, which are harder to review and may drift.",
        "Add a top-level `permissions: contents: read` block, then grant narrower job-level write scopes only where required.",
        TOKEN_PERMISSIONS,
    ),
    "GH002": rule(
        "GH002", "Write-all token permissions", "critical", "permissions",
        "`write-all` grants every available GITHUB_TOKEN write scope to the workflow or job.",
        "Replace `write-all` with an explicit allowlist of the smallest required scopes.",
        TOKEN_PERMISSIONS,
    ),
    "GH003": rule(
        "GH003", "Action or reusable workflow is not pinned to a full commit SHA", "high", "supply-chain",
        "Mutable tags and branches can change after review and therefore do not provide immutable dependency identity.",
        "Pin every third-party action and reusable workflow to a full 40-character commit SHA and record the human-readable release in a comment.",
        GITHUB_SECURE_USE,
    ),
    "GH004": rule(
        "GH004", "Untrusted expression is interpolated directly into executable script", "high", "injection",
        "Event-controlled text embedded in a `run` or `github-script` body can change the program that the runner executes.",
        "Move the expression into an environment variable or action input and treat it strictly as data; validate it before use.",
        GITHUB_SECURE_USE,
    ),
    "GH005": rule(
        "GH005", "Privileged pull_request_target workflow checks out PR-controlled code", "critical", "privilege-boundary",
        "A pull_request_target workflow can have base-repository secrets and write permissions. Checking out and executing PR-controlled code creates a pwn-request path.",
        "Use `pull_request` for untrusted build/test code. Keep pull_request_target limited to metadata-only operations and never execute PR-controlled content.",
        PULL_REQUEST_TARGET,
    ),
    "GH006": rule(
        "GH006", "Untrusted contribution can run on a self-hosted runner", "critical", "runner",
        "Self-hosted runners can retain credentials, files, network access, or state and are not guaranteed to be clean or ephemeral.",
        "Use GitHub-hosted runners for public or fork-controlled pull requests, or isolate ephemeral runners in tightly restricted groups.",
        SELF_HOSTED,
    ),
    "GH007": rule(
        "GH007", "Checkout credentials persist in a write-capable job", "high", "credentials",
        "actions/checkout persists the workflow token by default. Later tools or untrusted code in the job can reuse those credentials.",
        "Set `persist-credentials: false` and provide a narrowly scoped credential only to the exact step that needs it.",
        GITHUB_SECURE_USE,
    ),
    "GH008": rule(
        "GH008", "Network download is piped directly to a shell", "critical", "supply-chain",
        "Download-and-execute pipelines provide no stable identity, integrity check, or review point for remote code.",
        "Download to a file, verify a pinned digest or signature, inspect provenance, and execute only after verification.",
        GITHUB_SECURE_USE,
    ),
    "GH009": rule(
        "GH009", "Privileged workflow_run job executes downloaded artifacts", "critical", "artifact-boundary",
        "Artifacts produced by a different workflow may contain fork-controlled content. A privileged workflow must treat them as untrusted data.",
        "Bind artifacts to an expected workflow, repository, commit, and digest; parse them as data instead of executing them.",
        PULL_REQUEST_TARGET,
    ),
    "GH010": rule(
        "GH010", "Secrets are referenced from an externally triggerable privileged workflow", "high", "secrets",
        "Secrets in pull_request_target, issue_comment, discussion_comment, or workflow_run workflows raise the impact of prompt, script, checkout, and artifact attacks.",
        "Remove secrets from the untrusted stage. Split the workflow and use an approved environment or narrowly scoped short-lived credential in a trusted stage.",
        GITHUB_SECURE_USE,
    ),
    "GH011": rule(
        "GH011", "Job has no timeout-minutes", "low", "availability",
        "A missing timeout allows stuck, adversarial, or unexpectedly expensive jobs to consume runner time indefinitely up to platform limits.",
        "Set a job-level timeout-minutes appropriate to the expected workload.",
        GITHUB_SECURE_USE,
    ),
    "GH012": rule(
        "GH012", "OIDC token permission lacks a trusted deployment boundary", "high", "identity",
        "`id-token: write` allows the job to request an OIDC token. On risky triggers or without an environment boundary, the trust policy may be too broad.",
        "Issue OIDC tokens only in a trusted deployment job protected by an environment and restrictive cloud-side subject claims.",
        OIDC,
    ),
    "GH013": rule(
        "GH013", "Container image is referenced by a mutable tag", "medium", "supply-chain",
        "A mutable container or service tag can resolve to different code after review.",
        "Pin container and service images by immutable digest, for example `image@sha256:...`.",
        GITHUB_SECURE_USE,
    ),
    "GH014": rule(
        "GH014", "Runner or matrix topology depends directly on untrusted input", "high", "injection",
        "Allowing event-controlled text to choose runners or matrix values can redirect execution to privileged infrastructure or expand workload unexpectedly.",
        "Map untrusted input through a fixed allowlist before using it in `runs-on`, `container`, or `strategy.matrix`.",
        GITHUB_SECURE_USE,
    ),
    "AG001": rule(
        "AG001", "Comment-triggered agent lacks an actor authorization gate", "critical", "agent-authorization",
        "A public comment command can become an execution API unless the actor and repository relationship are checked before any agent or write-capable step runs.",
        "Require an explicit command and allowlisted actor, team, or trusted author association before routing to the agent.",
        GITHUB_SECURE_USE,
    ),
    "AG002": rule(
        "AG002", "Untrusted event text is passed to an agent", "critical", "prompt-injection",
        "Issue, pull-request, review, or comment text is attacker-controlled. Giving it to an agent that can access tools or secrets creates a prompt-injection path.",
        "Separate untrusted content from instructions, use a read-only analysis stage, validate structured output, and require approval before privileged actions.",
        GITHUB_SECURE_USE,
    ),
    "AG003": rule(
        "AG003", "Agent step runs with write-capable token permissions", "high", "agent-privilege",
        "An agent can be manipulated or make mistakes. Combining interpretation and repository write authority removes an important control boundary.",
        "Run the agent read-only, emit a bounded proposal artifact, and apply changes in a separate reviewed job with minimal write scope.",
        TOKEN_PERMISSIONS,
    ),
    "AG004": rule(
        "AG004", "Agent output is executed as code", "critical", "agent-output",
        "Model output is untrusted data. Substituting it into a shell, eval, source, interpreter, or generated workflow turns model text into code execution.",
        "Require a typed schema, allowlisted operations, static validation, and human approval. Never execute free-form model output directly.",
        GITHUB_SECURE_USE,
    ),
    "AG005": rule(
        "AG005", "Agent workflow directly pushes, merges, or mutates repository state", "high", "agent-change-control",
        "Direct mutation removes the independent review boundary and can amplify prompt injection or model error.",
        "Have the agent create a patch or draft pull request. Require branch protection, code review, and separate merge authority.",
        TOKEN_PERMISSIONS,
    ),
    "AG006": rule(
        "AG006", "Secret is passed directly to an agent step", "critical", "agent-secrets",
        "Prompted agents and their dependencies may log, transmit, or accidentally disclose credentials.",
        "Keep secrets outside the reasoning context. Use a narrow broker or post-approval step that exposes only the exact operation required.",
        GITHUB_SECURE_USE,
    ),
    "AG007": rule(
        "AG007", "Comment-driven agent workflow has no concurrency control", "medium", "agent-availability",
        "Repeated comments can create parallel agent runs, duplicate changes, race conditions, and avoidable cost.",
        "Add a stable concurrency group derived from the issue or pull request and choose an explicit cancellation policy.",
        GITHUB_SECURE_USE,
    ),
    "AG008": rule(
        "AG008", "Write-capable agent job has no protected environment", "high", "agent-approval",
        "A write-capable agent job without an environment cannot use environment-level required reviewers or scoped environment secrets.",
        "Move mutation into a separate job protected by a GitHub environment with required reviewers and narrow secrets.",
        TOKEN_PERMISSIONS,
    ),
}

RISKY_TRIGGERS = {
    "pull_request_target",
    "issue_comment",
    "pull_request_review_comment",
    "discussion_comment",
    "workflow_run",
}
UNTRUSTED_PR_TRIGGERS = {"pull_request", "pull_request_target"}
UNTRUSTED_EXPR = re.compile(
    r"\$\{\{\s*(?:github\.(?:event|head_ref|actor)|inputs\.)[^}]*\}\}",
    re.IGNORECASE,
)
PR_REF_EXPR = re.compile(
    r"github\.event\.pull_request\.(?:head\.(?:sha|ref|repo\.full_name)|merge_commit_sha)|refs/pull/",
    re.IGNORECASE,
)
SCRIPT_EXEC = re.compile(
    r"(?i)(?:^|[;&|\n])\s*(?:bash|sh|zsh|pwsh|powershell|python(?:3)?\s+-c|node\s+-e|eval|source|\.\s+)"
)
DOWNLOAD_EXECUTE = re.compile(
    r"(?is)(?:curl|wget)\b[^\n|]*(?:\|\s*(?:sudo\s+)?(?:bash|sh|zsh)|\|\s*python|\|\s*node)"
)
DIRECT_MUTATION = re.compile(
    r"(?i)\b(?:git\s+push|gh\s+pr\s+merge|gh\s+api\b[^\n]*(?:/contents|/git/refs)|git\s+merge\b[^\n]*\bmain\b)"
)
EXEC_ARTIFACT = re.compile(
    r"(?i)(?:chmod\s+\+x|\./[\w./-]+|bash\s+[\w./-]+|sh\s+[\w./-]+|python(?:3)?\s+[\w./-]+|node\s+[\w./-]+|source\s+[\w./-]+|pip\s+install\s+[\w./-]+)"
)
AUTH_MARKERS = (
    "author_association",
    "github.actor ==",
    "github.actor !=",
    "github.event.comment.user.login",
    "allowed_actors",
    "trusted_actors",
)


def finding(
    doc: WorkflowDocument,
    rule_id: str,
    message: str,
    evidence: str,
    *,
    line: int | None = None,
    job: str | None = None,
    step: str | None = None,
) -> Finding:
    evidence_line = line or doc.line_for(evidence.strip().splitlines()[0].strip(), 1)
    return Finding(
        rule=RULES[rule_id],
        path=doc.path.as_posix(),
        line=evidence_line,
        column=1,
        message=message,
        evidence=evidence.strip()[:500],
        job=job,
        step=step,
    )


def analyze_document(doc: WorkflowDocument) -> list[Finding]:
    findings: list[Finding] = []
    triggers = doc.triggers()
    workflow_permissions = doc.workflow_permissions()

    if workflow_permissions is None:
        findings.append(finding(doc, "GH001", "Workflow does not declare explicit GITHUB_TOKEN permissions.", "permissions:"))
    elif isinstance(workflow_permissions, str) and workflow_permissions.lower() == "write-all":
        findings.append(finding(doc, "GH002", "Workflow grants write-all permissions.", "permissions: write-all"))

    for job_name, job in doc.jobs():
        permissions = effective_permissions(workflow_permissions, job)
        write_capable = permission_has_write(permissions)
        if isinstance(job.get("permissions"), str) and str(job["permissions"]).lower() == "write-all":
            findings.append(finding(doc, "GH002", f"Job `{job_name}` grants write-all permissions.", "permissions: write-all", job=job_name))

        if "timeout-minutes" not in job:
            findings.append(finding(doc, "GH011", f"Job `{job_name}` has no timeout-minutes.", f"{job_name}:", job=job_name))

        runs_on_text = serialize_value(job.get("runs-on"))
        matrix_text = serialize_value(job.get("strategy", {}).get("matrix") if isinstance(job.get("strategy"), dict) else "")
        if UNTRUSTED_EXPR.search(runs_on_text + "\n" + matrix_text):
            findings.append(finding(
                doc,
                "GH014",
                f"Job `{job_name}` derives runner or matrix topology from event-controlled input.",
                runs_on_text or matrix_text,
                job=job_name,
            ))

        if "self-hosted" in runs_on_text.lower() and triggers & UNTRUSTED_PR_TRIGGERS:
            findings.append(finding(
                doc,
                "GH006",
                f"Job `{job_name}` can run untrusted pull-request code on a self-hosted runner.",
                runs_on_text,
                job=job_name,
            ))

        if permission_has(permissions, "id-token", "write") and (
            triggers & RISKY_TRIGGERS or "environment" not in job
        ):
            findings.append(finding(
                doc,
                "GH012",
                f"Job `{job_name}` can mint an OIDC token without a clearly trusted environment boundary.",
                "id-token: write",
                job=job_name,
            ))

        container = job.get("container")
        images: list[str] = []
        if isinstance(container, str):
            images.append(container)
        elif isinstance(container, dict) and container.get("image"):
            images.append(str(container["image"]))
        services = job.get("services", {})
        if isinstance(services, dict):
            for service in services.values():
                if isinstance(service, str):
                    images.append(service)
                elif isinstance(service, dict) and service.get("image"):
                    images.append(str(service["image"]))
        for image in images:
            if "@sha256:" not in image:
                findings.append(finding(
                    doc,
                    "GH013",
                    f"Job `{job_name}` uses mutable container image `{image}`.",
                    image,
                    job=job_name,
                ))

        steps = doc.steps(job)
        agent_steps: list[tuple[int, dict[str, Any]]] = [
            (idx, step) for idx, step in enumerate(steps, start=1) if is_agent_step(step)
        ]
        agent_ids = {str(step.get("id")) for _, step in agent_steps if step.get("id")}
        downloaded_artifact = False

        for idx, step in enumerate(steps, start=1):
            label = step_label(step, idx)
            uses = str(step.get("uses", ""))
            run_text = str(step.get("run", ""))
            step_text = serialize_value(step)

            script_text = run_text
            if "github-script" in uses.lower():
                with_block_for_script = step.get("with", {})
                if isinstance(with_block_for_script, dict):
                    script_text += "\n" + str(with_block_for_script.get("script", ""))
            if UNTRUSTED_EXPR.search(script_text):
                findings.append(finding(
                    doc,
                    "GH004",
                    f"Step `{label}` embeds event-controlled input directly in executable script text.",
                    script_text,
                    job=job_name,
                    step=label,
                ))

            if uses:
                action, ref = extract_action_ref(uses)
                if not uses.startswith("./") and not is_full_commit_sha(ref):
                    findings.append(finding(
                        doc,
                        "GH003",
                        f"Step `{label}` uses `{uses}` without a full immutable commit SHA.",
                        uses,
                        job=job_name,
                        step=label,
                    ))
                if action.lower().endswith("actions/download-artifact") or "download-artifact" in action.lower():
                    downloaded_artifact = True

            if uses.lower().startswith("actions/checkout@"):
                with_block = step.get("with", {})
                if not isinstance(with_block, dict):
                    with_block = {}
                ref_text = serialize_value(with_block.get("ref"))
                repository_text = serialize_value(with_block.get("repository"))
                if "pull_request_target" in triggers and PR_REF_EXPR.search(ref_text + "\n" + repository_text):
                    findings.append(finding(
                        doc,
                        "GH005",
                        f"Step `{label}` checks out pull-request-controlled code in a pull_request_target workflow.",
                        ref_text or repository_text or uses,
                        job=job_name,
                        step=label,
                    ))
                persist = with_block.get("persist-credentials")
                persist_is_false = persist is False or str(persist).lower() == "false"
                if write_capable and not persist_is_false:
                    findings.append(finding(
                        doc,
                        "GH007",
                        f"Step `{label}` leaves checkout credentials available in a write-capable job.",
                        uses,
                        job=job_name,
                        step=label,
                    ))

            if DOWNLOAD_EXECUTE.search(run_text):
                findings.append(finding(
                    doc,
                    "GH008",
                    f"Step `{label}` downloads network content and pipes it directly to an interpreter.",
                    run_text,
                    job=job_name,
                    step=label,
                ))

            if downloaded_artifact and "workflow_run" in triggers and EXEC_ARTIFACT.search(run_text):
                findings.append(finding(
                    doc,
                    "GH009",
                    f"Step `{label}` executes content after downloading an artifact in a workflow_run workflow.",
                    run_text,
                    job=job_name,
                    step=label,
                ))

            if is_agent_step(step):
                if write_capable:
                    findings.append(finding(
                        doc,
                        "AG003",
                        f"Agent step `{label}` runs in a write-capable job.",
                        step_text,
                        job=job_name,
                        step=label,
                    ))
                    if "environment" not in job:
                        findings.append(finding(
                            doc,
                            "AG008",
                            f"Write-capable agent job `{job_name}` has no protected environment.",
                            f"{job_name}:",
                            job=job_name,
                            step=label,
                        ))
                if UNTRUSTED_EXPR.search(step_text):
                    findings.append(finding(
                        doc,
                        "AG002",
                        f"Agent step `{label}` receives event-controlled text.",
                        step_text,
                        job=job_name,
                        step=label,
                    ))
                if "secrets." in step_text:
                    findings.append(finding(
                        doc,
                        "AG006",
                        f"Agent step `{label}` receives a repository or environment secret directly.",
                        step_text,
                        job=job_name,
                        step=label,
                    ))

            if DIRECT_MUTATION.search(run_text) and agent_steps:
                findings.append(finding(
                    doc,
                    "AG005",
                    f"Agent-enabled job `{job_name}` directly mutates repository state in step `{label}`.",
                    run_text,
                    job=job_name,
                    step=label,
                ))

            if agent_ids and run_text:
                for agent_id in agent_ids:
                    output_pattern = re.compile(rf"steps\.{re.escape(agent_id)}\.outputs\.[A-Za-z0-9_-]+")
                    if output_pattern.search(run_text) and (SCRIPT_EXEC.search(run_text) or re.search(r"(?i)\beval\b", run_text)):
                        findings.append(finding(
                            doc,
                            "AG004",
                            f"Step `{label}` executes output produced by agent step `{agent_id}`.",
                            run_text,
                            job=job_name,
                            step=label,
                        ))

        if agent_steps and "issue_comment" in triggers:
            lower_text = doc.text.lower()
            if not any(marker.lower() in lower_text for marker in AUTH_MARKERS):
                findings.append(finding(
                    doc,
                    "AG001",
                    f"Comment-triggered agent job `{job_name}` has no visible actor or author-association gate.",
                    "issue_comment:",
                    job=job_name,
                ))
            if "concurrency:" not in doc.text:
                findings.append(finding(
                    doc,
                    "AG007",
                    "Comment-driven agent workflow has no top-level concurrency control.",
                    "issue_comment:",
                    job=job_name,
                ))

    if triggers & RISKY_TRIGGERS and "secrets." in doc.text:
        findings.append(finding(
            doc,
            "GH010",
            "Workflow references secrets while using an externally triggerable privileged event.",
            "secrets.",
        ))

    # Deduplicate identical findings caused by combined structural and line-based checks.
    unique: dict[tuple[str, str, str | None, str | None], Finding] = {}
    for item in findings:
        key = (item.rule.id, item.evidence, item.job, item.step)
        unique.setdefault(key, item)
    return sorted(
        unique.values(),
        key=lambda item: (item.path, item.line, item.rule.id, item.job or "", item.step or ""),
    )


def rules_as_dicts() -> list[dict[str, Any]]:
    return [RULES[key].to_dict() for key in sorted(RULES)]
