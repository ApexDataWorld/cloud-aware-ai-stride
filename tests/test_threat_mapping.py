from pathlib import Path

from cloud_stride.scenario_loader import load_scenarios
from cloud_stride.threat_mapping import build_baseline_mapping, build_cloud_aware_mapping, load_threat_catalog


ROOT = Path(__file__).resolve().parent.parent


def test_mapping_generates_rows_for_both_methods():
    scenarios = load_scenarios(ROOT / "data" / "scenarios" / "ai_pipeline_scenarios.yaml")
    catalog = load_threat_catalog(ROOT / "data" / "catalogs" / "cloud_aware_stride_catalog.yaml")
    baseline = build_baseline_mapping(scenarios, catalog)
    cloud = build_cloud_aware_mapping(scenarios, catalog)
    assert not baseline.empty
    assert not cloud.empty
    assert cloud["identified"].sum() >= baseline["identified"].sum()
