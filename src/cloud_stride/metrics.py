from __future__ import annotations

from pathlib import Path
from typing import Any

import numpy as np
import pandas as pd


def valid_threat_count(mapping: pd.DataFrame) -> int:
    return int(mapping["identified"].sum())


def unique_valid_threat_count(mapping: pd.DataFrame) -> int:
    return int(mapping.loc[mapping["identified"], "threat_id"].nunique())


def ai_specific_recall(mapping: pd.DataFrame, expected_ai_threats: dict[str, list[str]]) -> float:
    identified = set(mapping.loc[mapping["identified"], "ai_threat_type"])
    expected = {threat for threats in expected_ai_threats.values() for threat in threats}
    if not expected:
        return 0.0
    return float(len(identified & expected) / len(expected))


def critical_threat_recall(mapping: pd.DataFrame, expected_critical_threats: dict[str, list[str]]) -> float:
    identified = set(mapping.loc[mapping["identified"] & mapping["is_critical"], "ai_threat_type"])
    expected = {threat for threats in expected_critical_threats.values() for threat in threats}
    if not expected:
        return 0.0
    return float(len(identified & expected) / len(expected))


def duplicate_rate(mapping: pd.DataFrame) -> float:
    identified = mapping.loc[mapping["identified"]]
    if identified.empty:
        return 0.0
    duplicates = int(identified.duplicated(subset=["scenario_id", "threat_id"]).sum())
    return float(duplicates / len(identified))


def scenario_coverage(mapping: pd.DataFrame, scenarios: list[dict[str, Any]]) -> dict[str, Any]:
    covered = sorted(mapping.loc[mapping["identified"], "scenario_id"].unique().tolist())
    total = sorted([scenario["scenario_id"] for scenario in scenarios])
    return {
        "covered_count": len(covered),
        "total_count": len(total),
        "covered_scenarios": covered,
    }


def mitigation_coverage(coverage_frame: pd.DataFrame) -> float:
    if coverage_frame.empty:
        return 0.0
    return float(coverage_frame["mitigation_coverage"].mean())


def residual_risk_ranking(residual_risk_frame: pd.DataFrame) -> pd.DataFrame:
    return residual_risk_frame.sort_values("residual_risk", ascending=False).reset_index(drop=True)


def severity_summary(mapping: pd.DataFrame) -> dict[str, float]:
    identified = mapping.loc[mapping["identified"], "cloud_severity"]
    if identified.empty:
        return {"count": 0.0, "mean": 0.0, "median": 0.0, "min": 0.0, "max": 0.0}
    return {
        "count": float(identified.count()),
        "mean": float(identified.mean()),
        "median": float(identified.median()),
        "min": float(identified.min()),
        "max": float(identified.max()),
    }


def reproducibility_check(paths: list[str | Path]) -> bool:
    return all(Path(path).exists() for path in paths)


def spearman_severity_rank_correlation(baseline: pd.DataFrame, cloud_aware: pd.DataFrame) -> float:
    baseline_scores = baseline.loc[baseline["identified"], ["scenario_id", "threat_id", "cloud_severity"]]
    cloud_scores = cloud_aware.loc[cloud_aware["identified"], ["scenario_id", "threat_id", "cloud_severity"]]
    merged = baseline_scores.merge(cloud_scores, on=["scenario_id", "threat_id"], suffixes=("_baseline", "_cloud"))
    if len(merged) < 2:
        return 0.0
    baseline_rank = merged["cloud_severity_baseline"].rank(method="average")
    cloud_rank = merged["cloud_severity_cloud"].rank(method="average")
    return float(baseline_rank.corr(cloud_rank, method="pearson"))


def bootstrap_confidence_interval(values: list[float], iterations: int = 1000, alpha: float = 0.05) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "lower": 0.0, "upper": 0.0}
    rng = np.random.default_rng(42)
    array = np.asarray(values, dtype=float)
    stats = []
    for _ in range(iterations):
        sample = rng.choice(array, size=len(array), replace=True)
        stats.append(float(sample.mean()))
    return {
        "mean": float(array.mean()),
        "lower": float(np.quantile(stats, alpha / 2)),
        "upper": float(np.quantile(stats, 1 - alpha / 2)),
    }


def compute_metrics(
    baseline: pd.DataFrame,
    cloud_aware: pd.DataFrame,
    scenarios: list[dict[str, Any]],
    expected_ai: dict[str, list[str]],
    expected_critical: dict[str, list[str]],
    mitigation_coverage_frame: pd.DataFrame | None = None,
    residual_risk_frame: pd.DataFrame | None = None,
) -> dict[str, Any]:
    mitigation_value = mitigation_coverage(mitigation_coverage_frame) if mitigation_coverage_frame is not None else 0.0
    residual_rows = residual_risk_ranking(residual_risk_frame).head(10).to_dict("records") if residual_risk_frame is not None else []
    baseline_ai = ai_specific_recall(baseline, expected_ai)
    cloud_ai = ai_specific_recall(cloud_aware, expected_ai)
    baseline_critical = critical_threat_recall(baseline, expected_critical)
    cloud_critical = critical_threat_recall(cloud_aware, expected_critical)
    return {
        "synthetic_label": "synthetic",
        "baseline": {
            "valid_threat_count": valid_threat_count(baseline),
            "unique_valid_threat_count": unique_valid_threat_count(baseline),
            "ai_specific_recall": baseline_ai,
            "critical_threat_recall": baseline_critical,
            "duplicate_rate": duplicate_rate(baseline),
            "scenario_coverage": scenario_coverage(baseline, scenarios),
            "severity_summary": severity_summary(baseline),
        },
        "cloud_aware": {
            "valid_threat_count": valid_threat_count(cloud_aware),
            "unique_valid_threat_count": unique_valid_threat_count(cloud_aware),
            "ai_specific_recall": cloud_ai,
            "critical_threat_recall": cloud_critical,
            "duplicate_rate": duplicate_rate(cloud_aware),
            "scenario_coverage": scenario_coverage(cloud_aware, scenarios),
            "severity_summary": severity_summary(cloud_aware),
        },
        "severity_rank_correlation": spearman_severity_rank_correlation(baseline, cloud_aware),
        "mitigation_coverage": mitigation_value,
        "residual_risk_ranking": residual_rows,
        "bootstrap_ci_ai_specific_recall": {
            "baseline": bootstrap_confidence_interval([baseline_ai]),
            "cloud_aware": bootstrap_confidence_interval([cloud_ai]),
        },
        "bootstrap_ci_critical_threat_recall": {
            "baseline": bootstrap_confidence_interval([baseline_critical]),
            "cloud_aware": bootstrap_confidence_interval([cloud_critical]),
        },
    }
