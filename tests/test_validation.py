from pathlib import Path

from cloud_stride.validation import validate_no_scope_creep


ROOT = Path(__file__).resolve().parent.parent


def test_no_full_bayesian_or_monte_carlo_modules():
    validate_no_scope_creep(ROOT)


def test_no_multi_agent_reliability_modules():
    validate_no_scope_creep(ROOT)


def test_no_production_claims_in_reports():
    summary = (ROOT / "src" / "cloud_stride" / "reporting.py").read_text(encoding="utf-8").lower()
    assert "synthetic" in summary
    assert "production validation" not in summary
    assert "does not claim production breach results" in summary
