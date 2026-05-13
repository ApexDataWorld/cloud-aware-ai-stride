from experiments.common import prepare_benchmark
from cloud_stride.residual_risk import calculate_residual_risk


def test_residual_risk_formula_matches_paper():
    assert calculate_residual_risk(30, 0.5, 0.8) == 18.0


def test_residual_risk_formula_matches_section_vii():
    assert calculate_residual_risk(20, 0.25, 0.4) == 18.0


def test_residual_risk_is_non_negative():
    benchmark = prepare_benchmark()
    assert (benchmark["residual_risk"]["residual_risk"] >= 0).all()
