# Repository operating rules

1. Treat every intentionally vulnerable example as inert teaching data. Never move it under `.github/workflows`.
2. Preserve rule IDs once released. Breaking semantic changes require a major version.
3. A rule must include a positive test, remediation, and a hardened counterexample or documented limitation.
4. Do not claim that a clean GAWSL scan proves safety.
5. Do not add real tokens, private logs, user paths, account details, or production prompts.
6. Pin every live GitHub Action in this repository to a full commit SHA.
7. Keep live workflows read-only except the narrowly scoped release job.
8. Do not suppress a finding with a non-expiring waiver.
9. Update `docs/rule-reference.md` when rule metadata changes.
10. Run the complete validation sequence before merge.
