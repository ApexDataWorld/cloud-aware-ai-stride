from pathlib import Path

from experiments.common import prepare_benchmark
from cloud_stride.taxonomy import ALLOWED_MITIGATION_CONTROLS


ROOT = Path(__file__).resolve().parent.parent


def test_mitigation_mapping_completeness():
    benchmark = prepare_benchmark()
    assert not benchmark["mitigation_mapping"].empty


def test_all_mitigations_are_paper_1_selected_controls_only():
    benchmark = prepare_benchmark()
    assert set(benchmark["mitigation_mapping"]["control_key"]).issubset(set(ALLOWED_MITIGATION_CONTROLS))
