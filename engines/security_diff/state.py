"""Build comparable security states by orchestrating existing engines."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any


def _load_json(path: Path) -> dict[str, Any] | None:
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    return data if isinstance(data, dict) else None


def _artifacts_dir(target: Path) -> Path:
    return target / ".findings" / "axguard"


def build_security_state(
    target: Path | str,
    *,
    changed_files: list[str] | None = None,
    incremental: bool = True,
    options: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a comparable Application Security State for one tree.

    Soft-imports existing engines. Never invents missing analysis.
    """
    opts = dict(options or {})
    root = Path(target).resolve()
    unknowns: list[dict[str, Any]] = []
    state: dict[str, Any] = {
        "target": str(root),
        "application_model": None,
        "dataflow": None,
        "attack_graph": None,
        "twin": None,
        "predictive": None,
        "changed_files": list(changed_files or []),
        "incremental": bool(incremental),
        "unknowns": unknowns,
        "scope": {
            "changed_files": list(changed_files or []),
            "incremental": bool(incremental),
        },
    }

    reuse = bool(opts.get("reuse_artifacts", False))
    art = _artifacts_dir(root)

    app_model = None
    if reuse:
        app_model = _load_json(art / "application-model.json")
    if app_model is None:
        try:
            from engines.app_model import build_application_model

            app_model = build_application_model(root)
        except Exception as exc:  # noqa: BLE001
            unknowns.append(
                {"area": "application_model", "reason": f"build failed: {exc}"}
            )
    state["application_model"] = app_model

    dataflow = None
    if reuse:
        dataflow = _load_json(art / "dataflow.json")
    if dataflow is None and not opts.get("skip_dataflow"):
        try:
            from engines.dataflow import analyze_dataflow

            dataflow = analyze_dataflow(root, application_model=app_model)
        except Exception as exc:  # noqa: BLE001
            unknowns.append({"area": "dataflow", "reason": f"analyze failed: {exc}"})
    state["dataflow"] = dataflow

    attack_graph = None
    if reuse:
        attack_graph = _load_json(art / "attack-paths.json")
    if attack_graph is None and not opts.get("skip_attack_graph"):
        try:
            from engines.attack_graph import run_attack_graph

            attack_graph = run_attack_graph(root)
        except Exception as exc:  # noqa: BLE001
            unknowns.append(
                {"area": "attack_graph", "reason": f"run failed: {exc}"}
            )
    state["attack_graph"] = attack_graph

    twin = None
    if reuse:
        twin = _load_json(art / "security-twin.json") or _load_json(art / "twin.json")
    if twin is None and not opts.get("skip_twin"):
        try:
            from engines.twin.build import build_security_twin

            twin = build_security_twin(
                root,
                attack_graph=attack_graph,
                application_model=app_model,
            )
        except Exception as exc:  # noqa: BLE001
            unknowns.append({"area": "security_twin", "reason": f"build failed: {exc}"})
    state["twin"] = twin

    if not opts.get("skip_predict"):
        try:
            from engines.predictive import run_predict

            state["predictive"] = run_predict(
                root,
                attack_graph=attack_graph,
                twin=twin,
                write_report=False,
                with_memory=False,
            )
        except Exception as exc:  # noqa: BLE001
            unknowns.append({"area": "predictive", "reason": f"run failed: {exc}"})

    return state
