from __future__ import annotations

import pandas as pd


def calculate_residual_risk(
    cloud_severity: float,
    mitigation_coverage: float,
    control_effectiveness: float,
) -> float:
    return float(max(0.0, cloud_severity * (1 - mitigation_coverage * control_effectiveness)))


def calculate_expected_loss(probability: float, impact: float) -> float:
    return float(probability * impact)


def calculate_residual_expected_loss(expected_loss: float, control_effectiveness: float) -> float:
    return float(expected_loss * (1 - control_effectiveness))


def build_residual_risk_ranking(
    scored_mapping: pd.DataFrame,
    mitigation_coverage: pd.DataFrame,
    control_effectiveness: pd.DataFrame,
) -> pd.DataFrame:
    effectiveness = control_effectiveness.rename(columns={"control_id": "control_effectiveness_id"})
    coverage = mitigation_coverage.copy()
    avg_effectiveness = float(effectiveness["estimated_effectiveness"].mean())
    merged = scored_mapping.merge(
        coverage[["method", "scenario_id", "threat_id", "mitigation_coverage"]],
        on=["method", "scenario_id", "threat_id"],
        how="left",
    )
    merged["mitigation_coverage"] = merged["mitigation_coverage"].fillna(0.0)
    merged["control_effectiveness"] = avg_effectiveness
    merged["residual_risk"] = merged.apply(
        lambda row: calculate_residual_risk(
            row["cloud_severity"], row["mitigation_coverage"], row["control_effectiveness"]
        ),
        axis=1,
    )
    merged["probability_proxy"] = merged["baseline_likelihood"] / 5.0
    merged["expected_loss"] = merged.apply(
        lambda row: calculate_expected_loss(row["probability_proxy"], row["baseline_impact"]),
        axis=1,
    )
    merged["residual_expected_loss"] = merged.apply(
        lambda row: calculate_residual_expected_loss(row["expected_loss"], row["control_effectiveness"]),
        axis=1,
    )
    ranking = merged[merged["identified"]].copy()
    ranking = ranking.sort_values(["method", "residual_risk"], ascending=[True, False]).reset_index(drop=True)
    ranking["synthetic_label"] = "synthetic"
    return ranking[
        [
            "method",
            "scenario_id",
            "threat_id",
            "threat_name",
            "ai_threat_type",
            "cloud_severity",
            "mitigation_coverage",
            "control_effectiveness",
            "residual_risk",
            "expected_loss",
            "residual_expected_loss",
            "synthetic_label",
        ]
    ]
