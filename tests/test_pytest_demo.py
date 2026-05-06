from pathlib import Path

from cloud_stride.experiment import run_demo_experiment
from cloud_stride.metrics import severity_summary
from cloud_stride.schemas import load_assessment


ROOT = Path(__file__).resolve().parent.parent


def test_run_demo_experiment_writes_report(tmp_path: Path) -> None:
    output = tmp_path / "demo_report.md"
    summary = run_demo_experiment(
        ROOT / "results" / "baseline.yaml",
        ROOT / "results" / "cloud_aware.yaml",
        output,
    )
    assert output.exists()
    assert "Severity Score Summary" in summary["report_markdown"]
    assert "Critical threat recall" in summary["report_markdown"]
    assert "not applicable for this synthetic single-assessment benchmark" in summary["report_markdown"]


def test_severity_summary_contains_expected_fields() -> None:
    assessment = load_assessment(ROOT / "results" / "cloud_aware.yaml")
    summary = severity_summary(assessment)
    assert summary["count"] > 0
    assert summary["max"] >= summary["min"]
    assert "bootstrap_ci_mean" in summary
