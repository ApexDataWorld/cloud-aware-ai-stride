from __future__ import annotations

from pathlib import Path
from typing import Any

import pandas as pd
import yaml


def load_threat_catalog(path: str | Path) -> list[dict[str, Any]]:
    with Path(path).open("r", encoding="utf-8") as handle:
        return yaml.safe_load(handle)["threats"]


def flatten_threat_catalog(catalog: list[dict[str, Any]]) -> pd.DataFrame:
    rows = []
    for threat in catalog:
        row = {
            key: value
            for key, value in threat.items()
            if key not in {"cloud_modifiers", "example_controls", "evidence_required", "applicable_scenarios"}
        }
        row.update(threat["cloud_modifiers"])
        row["example_controls"] = ",".join(threat["example_controls"])
        row["evidence_required"] = ",".join(threat["evidence_required"])
        row["applicable_scenarios"] = ",".join(threat["applicable_scenarios"])
        rows.append(row)
    return pd.DataFrame(rows)


def _scenario_lookup(scenarios: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    return {scenario["scenario_id"]: scenario for scenario in scenarios}


def _map_single_method(
    scenarios: list[dict[str, Any]],
    catalog: list[dict[str, Any]],
    method: str,
) -> pd.DataFrame:
    scenario_by_id = _scenario_lookup(scenarios)
    rows: list[dict[str, Any]] = []
    for threat in catalog:
        for scenario_id in threat["applicable_scenarios"]:
            scenario = scenario_by_id[scenario_id]
            identified = threat["baseline_visible"] if method == "baseline_stride" else True
            if method == "cloud_aware_stride" and threat["ai_threat_type"] in scenario["expected_ai_threats"]:
                identified = True
            rows.append(
                {
                    "method": method,
                    "scenario_id": scenario_id,
                    "scenario_name": scenario["scenario_name"],
                    "threat_id": threat["threat_id"],
                    "threat_name": threat["threat_name"],
                    "stride_category": threat["stride_category"],
                    "ai_threat_type": threat["ai_threat_type"],
                    "affected_component": threat["affected_component"],
                    "affected_data_flow": threat["affected_data_flow"],
                    "trust_boundary": threat["trust_boundary"],
                    "baseline_likelihood": threat["baseline_likelihood"],
                    "baseline_impact": threat["baseline_impact"],
                    "identified": bool(identified),
                    "is_ai_specific": True,
                    "is_critical": bool(threat["critical"]),
                    "synthetic": True,
                }
                | threat["cloud_modifiers"]
            )
    return pd.DataFrame(rows)


def deduplicate_threats(mapping: pd.DataFrame) -> pd.DataFrame:
    return mapping.drop_duplicates(subset=["method", "scenario_id", "threat_id"]).reset_index(drop=True)


def build_baseline_mapping(scenarios: list[dict[str, Any]], catalog: list[dict[str, Any]]) -> pd.DataFrame:
    return deduplicate_threats(_map_single_method(scenarios, catalog, "baseline_stride"))


def build_cloud_aware_mapping(scenarios: list[dict[str, Any]], catalog: list[dict[str, Any]]) -> pd.DataFrame:
    return deduplicate_threats(_map_single_method(scenarios, catalog, "cloud_aware_stride"))


def export_threat_catalog(catalog: list[dict[str, Any]], output_path: str | Path) -> pd.DataFrame:
    frame = flatten_threat_catalog(catalog)
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    frame.to_csv(output_path, index=False)
    return frame


def export_scenario_threat_mapping(mapping: pd.DataFrame, output_path: str | Path) -> pd.DataFrame:
    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    mapping.to_csv(output_path, index=False)
    return mapping
