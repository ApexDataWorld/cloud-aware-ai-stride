from __future__ import annotations

from pathlib import Path

import pandas as pd
import yaml


def load_mitigation_catalog(path: str | Path) -> pd.DataFrame:
    with Path(path).open("r", encoding="utf-8") as handle:
        mitigations = yaml.safe_load(handle)["mitigations"]
    return pd.DataFrame(mitigations)


def build_mitigation_mapping(scored_mapping: pd.DataFrame, threat_catalog_frame: pd.DataFrame) -> pd.DataFrame:
    controls_by_threat = {
        row["threat_id"]: row["example_controls"].split(",") if row["example_controls"] else []
        for _, row in threat_catalog_frame.iterrows()
    }
    rows = []
    for _, row in scored_mapping.iterrows():
        if not row["identified"]:
            continue
        for control in controls_by_threat[row["threat_id"]]:
            rows.append(
                {
                    "method": row["method"],
                    "scenario_id": row["scenario_id"],
                    "threat_id": row["threat_id"],
                    "ai_threat_type": row["ai_threat_type"],
                    "control_key": control,
                    "synthetic_label": "synthetic",
                }
            )
    return pd.DataFrame(rows).drop_duplicates().reset_index(drop=True)


def compute_mitigation_coverage(mapping: pd.DataFrame) -> pd.DataFrame:
    grouped = (
        mapping.groupby(["method", "scenario_id", "threat_id"], as_index=False)["control_key"]
        .nunique()
        .rename(columns={"control_key": "mapped_controls"})
    )
    grouped["mitigation_coverage"] = grouped["mapped_controls"].clip(upper=3) / 3.0
    grouped["synthetic_label"] = "synthetic"
    return grouped
