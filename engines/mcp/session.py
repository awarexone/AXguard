"""Per-session MCP workspace state."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from engines.mcp.limits import ContextLimits, ToolCallBudget, limits_for_mode
from engines.mcp.security.sandbox import ProjectSandbox


@dataclass
class McpSession:
    """Holds project root, budgets, and cached analysis artifacts."""

    project_root: Path
    sandbox: ProjectSandbox
    budget: ToolCallBudget = field(default_factory=ToolCallBudget)
    limits: ContextLimits = field(default_factory=ContextLimits)
    cache: dict[str, Any] = field(default_factory=dict)
    last_findings: list[dict[str, Any]] = field(default_factory=list)
    last_review: dict[str, Any] | None = None
    last_investigation: dict[str, Any] | None = None
    last_attack_graph: dict[str, Any] | None = None
    last_evidence: dict[str, Any] | None = None
    last_twin: dict[str, Any] | None = None
    last_predict: dict[str, Any] | None = None

    @classmethod
    def create(
        cls,
        project_root: str | Path | None = None,
        *,
        mode: str = "BALANCED",
    ) -> McpSession:
        root = Path(project_root or Path.cwd()).expanduser().resolve()
        sandbox = ProjectSandbox(root)
        return cls(
            project_root=sandbox.root,
            sandbox=sandbox,
            limits=limits_for_mode(mode),
        )

    def resolve(self, path: str | Path | None = None) -> Path:
        return self.sandbox.resolve(path)

    def findings_dir(self) -> Path:
        out = self.project_root / ".findings" / "axguard"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def memory_dir(self) -> Path:
        out = self.findings_dir() / "memory"
        out.mkdir(parents=True, exist_ok=True)
        return out

    def begin_tool(self) -> None:
        self.budget.record_call()


# Process-local default session (stdio server is single-workspace)
_SESSION: McpSession | None = None


def get_session() -> McpSession:
    global _SESSION
    if _SESSION is None:
        _SESSION = McpSession.create()
    return _SESSION


def set_session(session: McpSession) -> McpSession:
    global _SESSION
    _SESSION = session
    return _SESSION


def reset_session(project_root: str | Path | None = None, *, mode: str = "BALANCED") -> McpSession:
    return set_session(McpSession.create(project_root, mode=mode))
