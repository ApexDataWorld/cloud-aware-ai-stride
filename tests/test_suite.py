import unittest
from pathlib import Path

from cloud_stride.metrics import (
    ai_specific_threat_recall,
    critical_threat_recall,
    duplicate_rate,
    evaluate_assessment_pair,
    severity_rank_correlation,
    unique_valid_threat_count,
    valid_threat_count,
)
from cloud_stride.scoring import calculate_cloud_adjusted_severity, calculate_severity
from cloud_stride.schemas import CloudFactors, ThreatAssessment, load_assessment, load_scenario, validate_directory
from cloud_stride.taxonomy import load_taxonomy_bundle


ROOT = Path(__file__).resolve().parent.parent


class ScoringTests(unittest.TestCase):
    def test_base_severity(self) -> None:
        self.assertEqual(calculate_severity(4, 5), 20)

    def test_cloud_adjusted_severity(self) -> None:
        threat = ThreatAssessment(
            threat_id="T1",
            scenario_id="s01",
            title="Example",
            category="Tampering",
            ai_threat_type="prompt_injection",
            component="retriever",
            asset_at_risk=["knowledge_base"],
            trust_boundary=["app_to_data"],
            ai_specific=True,
            identified=True,
            valid=True,
            canonical_key="s01-example",
            likelihood=4,
            impact=5,
            cloud_factors=CloudFactors(
                privilege_boundary=2,
                blast_radius=3,
                persistence=1,
                detectability=2,
                reversibility=1,
                compliance_sensitivity=1,
            ),
        )
        self.assertEqual(calculate_cloud_adjusted_severity(threat), 30)


class SchemaTests(unittest.TestCase):
    def test_load_scenario(self) -> None:
        scenario = load_scenario(ROOT / "scenarios" / "s01_customer_support_chatbot.yaml")
        self.assertEqual(scenario.pipeline_type, "rag")
        self.assertEqual(len(scenario.components), 4)
        self.assertIn("prompt_injection", scenario.expected_threat_categories)
        self.assertEqual(scenario.cloud_context.provider, "aws")

    def test_load_assessment(self) -> None:
        assessment = load_assessment(ROOT / "examples" / "threats_cloud_aware.yaml")
        self.assertEqual(assessment.assessor, "cloud_aware_stride")
        self.assertEqual(len(assessment.reference.ai_specific_threat_ids), 9)

    def test_validate_directory(self) -> None:
        valid, errors = validate_directory(ROOT / "scenarios")
        self.assertEqual(len(valid), 12)
        self.assertEqual(errors, [])


class TaxonomyTests(unittest.TestCase):
    def test_load_taxonomy_bundle(self) -> None:
        bundle = load_taxonomy_bundle(ROOT)
        self.assertIn("Spoofing", bundle.taxonomy["categories"])
        self.assertIn("prompt_injection", bundle.owasp_llm_mapping["mapping"])


class MetricsTests(unittest.TestCase):
    def test_metrics_summary_values(self) -> None:
        baseline = load_assessment(ROOT / "results" / "baseline.yaml")
        cloud_aware = load_assessment(ROOT / "results" / "cloud_aware.yaml")
        self.assertEqual(valid_threat_count(baseline), 9)
        self.assertEqual(valid_threat_count(cloud_aware), 17)
        self.assertEqual(unique_valid_threat_count(baseline), 8)
        self.assertEqual(unique_valid_threat_count(cloud_aware), 17)
        self.assertEqual(ai_specific_threat_recall(baseline), 0.0)
        self.assertEqual(ai_specific_threat_recall(cloud_aware), 1.0)
        self.assertLess(critical_threat_recall(baseline), critical_threat_recall(cloud_aware))
        self.assertAlmostEqual(duplicate_rate(baseline), 1 / 9, places=3)
        self.assertEqual(duplicate_rate(cloud_aware), 0.0)
        self.assertGreaterEqual(severity_rank_correlation(baseline, cloud_aware), 0.9)

    def test_evaluate_pair_contains_expected_keys(self) -> None:
        baseline = load_assessment(ROOT / "results" / "baseline.yaml")
        cloud_aware = load_assessment(ROOT / "results" / "cloud_aware.yaml")
        summary = evaluate_assessment_pair(baseline, cloud_aware)
        self.assertIn("baseline", summary)
        self.assertIn("comparison", summary)
        self.assertIn("agreement_score", summary)
        self.assertIn("critical_threat_recall", summary["baseline"])


if __name__ == "__main__":
    unittest.main()
