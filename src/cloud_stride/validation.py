from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd

from .taxonomy import (
    ALLOWED_MITIGATION_CONTROLS,
    CLOUD_MODIFIER_NAMES,
    STRIDE_CATEGORIES,
    validate_ai_threat_type,
)


def validate_scenarios(scenarios: list[dict[str, Any]]) -> None:
    required_ids = [f"S{index:02d}" for index in range(1, 13)]
    scenario_ids = [scenario["scenario_id"] for scenario in scenarios]
    if sorted(scenario_ids) != required_ids:
        raise ValueError("Scenario set must match manuscript table with S01-S12.")
    for scenario in scenarios:
        if scenario.get("synthetic") is not True:
            raise ValueError("All scenarios must be synthetic.")


def validate_threat_catalog(catalog: list[dict[str, Any]]) -> None:
    for threat in catalog:
        if threat["stride_category"] not in STRIDE_CATEGORIES:
            raise ValueError(f"Invalid STRIDE category: {threat['stride_category']}")
        if not validate_ai_threat_type(threat["ai_threat_type"]):
            raise ValueError(f"Invalid AI threat type: {threat['ai_threat_type']}")
        for name, value in threat["cloud_modifiers"].items():
            if name not in CLOUD_MODIFIER_NAMES:
                raise ValueError(f"Invalid cloud modifier: {name}")
            if not isinstance(value, (int, float)) or value < 0 or value > 5:
                raise ValueError(f"Cloud modifier out of range: {name}={value}")


def validate_mitigation_controls(mitigation_catalog: pd.DataFrame) -> None:
    invalid = set(mitigation_catalog["control_key"]) - set(ALLOWED_MITIGATION_CONTROLS)
    if invalid:
        raise ValueError(f"Mitigation catalog contains non-Paper 1-selected controls: {sorted(invalid)}")


def validate_residual_risk(residual_risk_frame: pd.DataFrame) -> None:
    if (residual_risk_frame["residual_risk"] < 0).any():
        raise ValueError("Residual-risk calculations must be non-negative.")


def validate_reports_are_synthetic(report_paths: list[str | Path]) -> None:
    for path in report_paths:
        text = Path(path).read_text(encoding="utf-8")
        if "synthetic" not in text.lower():
            raise ValueError(f"Report missing synthetic label: {path}")


def validate_no_scope_creep(root: str | Path) -> None:
    banned_tokens = [
        "monte carlo",
        "pymc",
        "arviz",
        "beta-prior",
        "cvar",
        "retry storm",
        "mttr",
        "mtbf",
        "handoff failure",
    ]
    root_path = Path(root)
    search_roots = [
        root_path / "src",
        root_path / "experiments",
        root_path / "tests",
    ]
    for search_root in search_roots:
        if not search_root.exists():
            continue
        for path in search_root.rglob("*.py"):
            if path.name == "validation.py":
                continue
            text = path.read_text(encoding="utf-8").lower()
            for token in banned_tokens:
                if token in text:
                    raise ValueError(f"Out-of-scope token '{token}' found in {path}")
