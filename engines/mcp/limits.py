"""Context and tool-call budgets for MCP sessions."""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any

from engines.mcp.schemas.errors import McpError


@dataclass
class ContextLimits:
    max_files: int = 200
    max_source_lines: int = 4000
    max_findings: int = 50
    max_evidence_items: int = 40
    max_attack_paths: int = 25
    max_output_bytes: int = 48_000
    max_analysis_depth: int = 4
    max_list_items: int = 50


@dataclass
class ToolCallBudget:
    max_tool_calls: int = 40
    max_investigation_steps: int = 12
    max_total_runtime_sec: float = 300.0
    max_recursion_depth: int = 3
    calls: int = 0
    investigation_steps: int = 0
    started_at: float = field(default_factory=time.monotonic)
    recursion_depth: int = 0

    def check(self, *, kind: str = "tool") -> None:
        elapsed = time.monotonic() - self.started_at
        if elapsed > self.max_total_runtime_sec:
            raise McpError(
                "TOOL_BUDGET_EXCEEDED",
                "Session runtime budget exhausted.",
                details={
                    "elapsed_sec": round(elapsed, 2),
                    "max_total_runtime_sec": self.max_total_runtime_sec,
                },
            )
        if kind == "tool":
            if self.calls >= self.max_tool_calls:
                raise McpError(
                    "TOOL_BUDGET_EXCEEDED",
                    "Tool-call budget exhausted for this session.",
                    details={
                        "calls": self.calls,
                        "max_tool_calls": self.max_tool_calls,
                    },
                )
        if kind == "investigation":
            if self.investigation_steps >= self.max_investigation_steps:
                raise McpError(
                    "TOOL_BUDGET_EXCEEDED",
                    "Investigation step budget exhausted.",
                    details={
                        "steps": self.investigation_steps,
                        "max_investigation_steps": self.max_investigation_steps,
                    },
                )
        if self.recursion_depth > self.max_recursion_depth:
            raise McpError(
                "TOOL_BUDGET_EXCEEDED",
                "Recursion depth budget exceeded.",
                details={
                    "depth": self.recursion_depth,
                    "max_recursion_depth": self.max_recursion_depth,
                },
            )

    def record_call(self) -> None:
        self.check(kind="tool")
        self.calls += 1

    def record_investigation_step(self) -> None:
        self.check(kind="investigation")
        self.investigation_steps += 1

    def snapshot(self) -> dict[str, Any]:
        return {
            "calls": self.calls,
            "max_tool_calls": self.max_tool_calls,
            "investigation_steps": self.investigation_steps,
            "max_investigation_steps": self.max_investigation_steps,
            "elapsed_sec": round(time.monotonic() - self.started_at, 2),
            "max_total_runtime_sec": self.max_total_runtime_sec,
            "recursion_depth": self.recursion_depth,
            "max_recursion_depth": self.max_recursion_depth,
        }


MODE_LIMITS: dict[str, ContextLimits] = {
    "LITE": ContextLimits(
        max_files=40,
        max_source_lines=800,
        max_findings=15,
        max_evidence_items=10,
        max_attack_paths=5,
        max_output_bytes=16_000,
        max_analysis_depth=2,
    ),
    "BALANCED": ContextLimits(),
    "DEEP": ContextLimits(
        max_files=400,
        max_source_lines=12_000,
        max_findings=100,
        max_evidence_items=80,
        max_attack_paths=50,
        max_output_bytes=96_000,
        max_analysis_depth=6,
    ),
    "MAX": ContextLimits(
        max_files=800,
        max_source_lines=24_000,
        max_findings=200,
        max_evidence_items=120,
        max_attack_paths=80,
        max_output_bytes=160_000,
        max_analysis_depth=8,
    ),
}


def limits_for_mode(mode: str | None) -> ContextLimits:
    return MODE_LIMITS.get((mode or "BALANCED").upper(), MODE_LIMITS["BALANCED"])
