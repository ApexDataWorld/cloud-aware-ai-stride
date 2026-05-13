from __future__ import annotations

from pathlib import Path

import pandas as pd
import yaml

from cloud_stride.metrics import compute_metrics
from cloud_stride.mitigation_mapping import (
    build_mitigation_mapping,
    compute_mitigation_coverage,
    load_mitigation_catalog,
)
from cloud_stride.reporting import generate_all_reports
from cloud_stride.residual_risk import build_residual_risk_ranking
from cloud_stride.scenario_loader import load_expected_threats, load_scenarios
from cloud_stride.scoring import score_mapping
from cloud_stride.threat_mapping import (
    build_baseline_mapping,
    build_cloud_aware_mapping,
    export_scenario_threat_mapping,
    export_threat_catalog,
    load_threat_catalog,
)
from cloud_stride.validation import (
    validate_mitigation_controls,
    validate_no_scope_creep,
    validate_residual_risk,
    validate_scenarios,
    validate_threat_catalog,
)


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def load_control_effectiveness(path: str | Path) -> pd.DataFrame:
    with Path(path).open("r", encoding="utf-8") as handle:
        return pd.DataFrame(yaml.safe_load(handle)["controls"])


def prepare_benchmark():
    root = repo_root()
    scenarios = load_scenarios(root / "data" / "scenarios" / "ai_pipeline_scenarios.yaml")
    expected_ai = load_expected_threats(root / "data" / "expected" / "expected_ai_threats.yaml")
    expected_critical = load_expected_threats(root / "data" / "expected" / "expected_critical_threats.yaml")
    threat_catalog = load_threat_catalog(root / "data" / "catalogs" / "cloud_aware_stride_catalog.yaml")
    mitigation_catalog = load_mitigation_catalog(root / "data" / "catalogs" / "mitigation_catalog.yaml")
    control_effectiveness = load_control_effectiveness(root / "data" / "catalogs" / "control_effectiveness_catalog.yaml")

    validate_scenarios(scenarios)
    validate_threat_catalog(threat_catalog)
    validate_mitigation_controls(mitigation_catalog)
    validate_no_scope_creep(root)

    baseline = score_mapping(build_baseline_mapping(scenarios, threat_catalog))
    cloud_aware = score_mapping(build_cloud_aware_mapping(scenarios, threat_catalog))
    threat_catalog_frame = export_threat_catalog(threat_catalog, root / "reports" / "tables" / "threat_catalog.csv")
    export_scenario_threat_mapping(
        pd.concat([baseline, cloud_aware], ignore_index=True),
        root / "reports" / "tables" / "scenario_threat_mapping.csv",
    )
    mitigation_mapping = build_mitigation_mapping(pd.concat([baseline, cloud_aware], ignore_index=True), threat_catalog_frame)
    mitigation_coverage = compute_mitigation_coverage(mitigation_mapping)
    residual_risk = build_residual_risk_ranking(
        pd.concat([baseline, cloud_aware], ignore_index=True),
        mitigation_coverage,
        control_effectiveness,
    )
    validate_residual_risk(residual_risk)
    metrics = compute_metrics(
        baseline,
        cloud_aware,
        scenarios,
        expected_ai,
        expected_critical,
        mitigation_coverage,
        residual_risk,
    )
    return {
        "root": root,
        "scenarios": scenarios,
        "baseline": baseline,
        "cloud_aware": cloud_aware,
        "threat_catalog_frame": threat_catalog_frame,
        "mitigation_mapping": mitigation_mapping,
        "mitigation_coverage": mitigation_coverage,
        "residual_risk": residual_risk,
        "metrics": metrics,
    }


def scenario_coverage_table(scenarios, baseline: pd.DataFrame, cloud_aware: pd.DataFrame) -> pd.DataFrame:
    rows = []
    for scenario in scenarios:
        scenario_id = scenario["scenario_id"]
        rows.append(
            {
                "scenario_id": scenario_id,
                "scenario_name": scenario["scenario_name"],
                "baseline_identified_threats": int(
                    baseline.loc[(baseline["scenario_id"] == scenario_id) & baseline["identified"]].shape[0]
                ),
                "cloud_aware_identified_threats": int(
                    cloud_aware.loc[(cloud_aware["scenario_id"] == scenario_id) & cloud_aware["identified"]].shape[0]
                ),
                "synthetic_label": "synthetic",
            }
        )
    return pd.DataFrame(rows)


def threat_coverage_table(metrics: dict, baseline: pd.DataFrame, cloud_aware: pd.DataFrame) -> pd.DataFrame:
    return pd.DataFrame(
        [
            {
                "method": "baseline_stride",
                "valid_threat_count": metrics["baseline"]["valid_threat_count"],
                "unique_valid_threat_count": metrics["baseline"]["unique_valid_threat_count"],
                "ai_specific_recall": metrics["baseline"]["ai_specific_recall"],
                "critical_threat_recall": metrics["baseline"]["critical_threat_recall"],
                "duplicate_rate": metrics["baseline"]["duplicate_rate"],
                "mean_cloud_severity": metrics["baseline"]["severity_summary"]["mean"],
                "synthetic_label": "synthetic",
            },
            {
                "method": "cloud_aware_stride",
                "valid_threat_count": metrics["cloud_aware"]["valid_threat_count"],
                "unique_valid_threat_count": metrics["cloud_aware"]["unique_valid_threat_count"],
                "ai_specific_recall": metrics["cloud_aware"]["ai_specific_recall"],
                "critical_threat_recall": metrics["cloud_aware"]["critical_threat_recall"],
                "duplicate_rate": metrics["cloud_aware"]["duplicate_rate"],
                "mean_cloud_severity": metrics["cloud_aware"]["severity_summary"]["mean"],
                "synthetic_label": "synthetic",
            },
        ]
    )


def run_all_reports(benchmark: dict) -> None:
    scenario_coverage = scenario_coverage_table(
        benchmark["scenarios"], benchmark["baseline"], benchmark["cloud_aware"]
    )
    threat_coverage = threat_coverage_table(
        benchmark["metrics"], benchmark["baseline"], benchmark["cloud_aware"]
    )
    generate_all_reports(
        benchmark["root"],
        benchmark["metrics"],
        threat_coverage,
        scenario_coverage,
        benchmark["mitigation_mapping"],
        benchmark["mitigation_coverage"],
        benchmark["residual_risk"],
    )
