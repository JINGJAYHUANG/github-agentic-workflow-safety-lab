# GitHub settings checklist

GAWSL analyzes files. The following controls live in repository, organization, runner, environment, and cloud settings and therefore require separate verification.

## Repository

- Set the default `GITHUB_TOKEN` permission to read-only.
- Require approval for workflows from first-time or outside contributors.
- Restrict allowed actions and require full commit SHA pinning where supported.
- Protect the default branch with required checks and review.
- Require CODEOWNERS review for `.github/workflows/**`, actions, and policy files.
- Prevent force pushes and branch deletion on protected branches.

## Environments

- Put deployment and mutation secrets in environments rather than general repository secrets.
- Require reviewers for production environments.
- Restrict deployment branches and tags.
- Use environment-specific credentials.

## Runners

- Do not expose persistent self-hosted runners to untrusted pull requests.
- Prefer ephemeral runners with isolated network access.
- Use runner groups and repository allowlists.
- Remove long-lived credentials from runner disks.

## Identity and cloud

- Prefer OIDC short-lived credentials to stored cloud keys.
- Restrict cloud trust policies by repository, ref, workflow, and environment claims.
- Do not grant an agent general cloud administration access.

## Artifacts and releases

- Bind privileged consumption to expected producer workflow, repository, commit, and digest.
- Generate provenance or attestations for release artifacts.
- Verify immutable tags and release assets before downstream use.
