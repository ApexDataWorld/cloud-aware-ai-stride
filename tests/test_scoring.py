from cloud_stride.scoring import calculate_base_severity, calculate_cloud_severity


def test_scoring_formula_matches_paper():
    assert calculate_base_severity(4, 5) == 20
    assert calculate_cloud_severity(4, 5, 1, 2, 3, 1, 2, 1) == 30


def test_scoring_formula_matches_section_v():
    assert calculate_base_severity(3, 4) == 12
    assert calculate_cloud_severity(3, 4, 2, 2, 1, 1, 1, 1) == 20
