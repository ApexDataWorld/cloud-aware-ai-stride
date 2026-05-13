from experiments.common import prepare_benchmark
from cloud_stride.metrics import compute_metrics
from cloud_stride.scenario_loader import load_expected_threats, load_scenarios


def test_metrics_are_computed():
    benchmark = prepare_benchmark()
    assert benchmark["metrics"]["cloud_aware"]["valid_threat_count"] >= benchmark["metrics"]["baseline"]["valid_threat_count"]


def test_reproducibility_metrics_present():
    benchmark = prepare_benchmark()
    assert "severity_rank_correlation" in benchmark["metrics"]
    assert "bootstrap_ci_ai_specific_recall" in benchmark["metrics"]
