from __future__ import annotations

import copy
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

import yaml


class ActionsLoader(yaml.SafeLoader):
    """SafeLoader adjusted so YAML 1.1 does not coerce the key `on` to True."""


ActionsLoader.yaml_implicit_resolvers = copy.deepcopy(yaml.SafeLoader.yaml_implicit_resolvers)
for first_char, resolvers in list(ActionsLoader.yaml_implicit_resolvers.items()):
    ActionsLoader.yaml_implicit_resolvers[first_char] = [
        (tag, regexp)
        for tag, regexp in resolvers
        if tag != "tag:yaml.org,2002:bool"
    ]
ActionsLoader.add_implicit_resolver(
    "tag:yaml.org,2002:bool",
    re.compile(r"^(?:true|True|TRUE|false|False|FALSE)$"),
    list("tTfF"),
)


@dataclass(slots=True)
class WorkflowDocument:
    path: Path
    text: str
    data: dict[str, Any]

    @classmethod
    def load(cls, path: Path) -> "WorkflowDocument":
        text = path.read_text(encoding="utf-8")
        loaded = yaml.load(text, Loader=ActionsLoader)
        if loaded is None:
            loaded = {}
        if not isinstance(loaded, dict):
            raise ValueError("workflow root must be a mapping")
        return cls(path=path, text=text, data=loaded)

    @property
    def lines(self) -> list[str]:
        return self.text.splitlines()

    def line_for(self, fragment: str, default: int = 1) -> int:
        if not fragment:
            return default
        for index, line in enumerate(self.lines, start=1):
            if fragment in line:
                return index
        return default

    def line_for_regex(self, pattern: str, default: int = 1) -> int:
        regex = re.compile(pattern)
        for index, line in enumerate(self.lines, start=1):
            if regex.search(line):
                return index
        return default

    def triggers(self) -> set[str]:
        raw = self.data.get("on", {})
        if isinstance(raw, str):
            return {raw}
        if isinstance(raw, list):
            return {str(item) for item in raw}
        if isinstance(raw, dict):
            return {str(key) for key in raw}
        return set()

    def workflow_permissions(self) -> Any:
        return self.data.get("permissions")

    def jobs(self) -> Iterable[tuple[str, dict[str, Any]]]:
        jobs = self.data.get("jobs", {})
        if not isinstance(jobs, dict):
            return []
        return [
            (str(name), value)
            for name, value in jobs.items()
            if isinstance(value, dict)
        ]

    def steps(self, job: dict[str, Any]) -> list[dict[str, Any]]:
        steps = job.get("steps", [])
        if not isinstance(steps, list):
            return []
        return [step for step in steps if isinstance(step, dict)]


def serialize_value(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, (str, int, float, bool)):
        return str(value)
    if isinstance(value, list):
        return "\n".join(serialize_value(item) for item in value)
    if isinstance(value, dict):
        return "\n".join(f"{key}: {serialize_value(item)}" for key, item in value.items())
    return repr(value)


def effective_permissions(workflow_permissions: Any, job: dict[str, Any]) -> Any:
    return job.get("permissions", workflow_permissions)


def permission_has_write(permissions: Any) -> bool:
    if isinstance(permissions, str):
        return permissions.strip().lower() == "write-all"
    if isinstance(permissions, dict):
        return any(str(value).lower() == "write" for value in permissions.values())
    return False


def permission_has(permissions: Any, scope: str, level: str) -> bool:
    if isinstance(permissions, str):
        if permissions == "write-all":
            return level == "write"
        if permissions == "read-all":
            return level == "read"
        return False
    if isinstance(permissions, dict):
        return str(permissions.get(scope, "none")).lower() == level
    return False


def extract_action_ref(uses: str) -> tuple[str, str | None]:
    if uses.startswith("./"):
        return uses, None
    if uses.startswith("docker://"):
        if "@sha256:" in uses:
            return uses, uses.rsplit("@", 1)[1]
        return uses, None
    if "@" not in uses:
        return uses, None
    action, ref = uses.rsplit("@", 1)
    return action, ref


def is_full_commit_sha(ref: str | None) -> bool:
    return bool(ref and re.fullmatch(r"[0-9a-fA-F]{40}", ref))


AGENT_MARKERS = re.compile(
    r"(?i)(?:^|[^a-z0-9])(?:agent|llm|codex|claude|anthropic|openai|gemini|qwen|aider|copilot|sweep)(?:[^a-z0-9]|$)"
)


def is_agent_step(step: dict[str, Any]) -> bool:
    identity = "\n".join(serialize_value(step.get(key)) for key in ("name", "id", "uses"))
    if AGENT_MARKERS.search(identity):
        return True
    run_text = str(step.get("run", ""))
    return bool(re.search(
        r"(?im)(?:^|[;&|]\s*)(?:codex|claude|gemini|qwen|aider)(?:\s|$)",
        run_text,
    ))


def step_label(step: dict[str, Any], index: int) -> str:
    return str(step.get("name") or step.get("id") or f"step-{index}")
