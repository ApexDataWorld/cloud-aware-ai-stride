from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml


REQUIRED_SCENARIO_FIELDS = {
    "scenario_id",
    "scenario_name",
    "components",
    "assets",
    "trust_boundaries",
    "data_flows",
    "synthetic",
}


def _load_yaml(path: str | Path) -> dict[str, Any]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)


def validate_scenario_schema(scenario: dict[str, Any]) -> None:
    missing = REQUIRED_SCENARIO_FIELDS - set(scenario)
    if missing:
        raise ValueError(f"Scenario missing required fields: {sorted(missing)}")
    if scenario["synthetic"] is not True:
        raise ValueError("All scenarios must be labeled synthetic: true")


def load_scenarios(path: str | Path) -> list[dict[str, Any]]:
    payload = _load_yaml(path)
    scenarios = payload["scenarios"]
    for scenario in scenarios:
        validate_scenario_schema(scenario)
    scenario_ids = [scenario["scenario_id"] for scenario in scenarios]
    expected_ids = [f"S{index:02d}" for index in range(1, 13)]
    if len(scenarios) != 12:
        raise ValueError("Exactly twelve scenarios must be loaded.")
    if sorted(scenario_ids) != expected_ids:
        raise ValueError("Scenario ids S01 through S12 must be present.")
    return scenarios


def load_expected_threats(path: str | Path) -> dict[str, list[str]]:
    payload = _load_yaml(path)
    _, values = next(iter(payload.items()))
    return values
