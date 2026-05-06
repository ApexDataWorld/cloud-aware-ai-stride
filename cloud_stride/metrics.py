from __future__ import annotations

from collections import Counter
from math import sqrt
from typing import Any

import numpy as np

from .schemas import AssessmentFile, ThreatAssessment
from .scoring import calculate_cloud_adjusted_severity


def _identified_valid_ids(assessment: AssessmentFile) -> set[str]:
    return {threat.threat_id for threat in assessment.threats if threat.identified and threat.valid}


def _identified_valid_ai_ids(assessment: AssessmentFile) -> set[str]:
    return {
        threat.threat_id
        for threat in assessment.threats
        if threat.identified and threat.valid and threat.ai_specific
    }


def valid_threat_count(assessment: AssessmentFile) -> int:
    return len(_identified_valid_ids(assessment))


def unique_valid_threat_count(assessment: AssessmentFile) -> int:
    canonical_keys = {
        threat.canonical_key for threat in assessment.threats if threat.identified and threat.valid
    }
    return len(canonical_keys)


def ai_specific_threat_recall(assessment: AssessmentFile) -> float:
    numerator = len(_identified_valid_ai_ids(assessment) & set(assessment.reference.ai_specific_threat_ids))
    denominator = len(assessment.reference.ai_specific_threat_ids)
    return numerator / denominator if denominator else 0.0


def critical_threat_ids(assessment: AssessmentFile) -> set[str]:
    return {
        threat.threat_id
        for threat in assessment.threats
        if threat.valid and threat.priority == "Critical"
    }


def identified_critical_threat_ids(assessment: AssessmentFile) -> set[str]:
    return {
        threat.threat_id
        for threat in assessment.threats
        if threat.identified and threat.valid and threat.priority == "Critical"
    }


def critical_threat_recall(assessment: AssessmentFile) -> float:
    reference_critical = critical_threat_ids(assessment)
    if not reference_critical:
        return 0.0
    return len(identified_critical_threat_ids(assessment) & reference_critical) / len(reference_critical)


def duplicate_rate(assessment: AssessmentFile) -> float:
    valid_threats = [threat.canonical_key for threat in assessment.threats if threat.identified and threat.valid]
    if not valid_threats:
        return 0.0
    counts = Counter(valid_threats)
    duplicates = sum(count - 1 for count in counts.values() if count > 1)
    return duplicates / len(valid_threats)


def severity_map(assessment: AssessmentFile) -> dict[str, int]:
    return {
        threat.threat_id: calculate_cloud_adjusted_severity(threat)
        for threat in assessment.threats
        if threat.identified and threat.valid
    }


def severity_scores(assessment: AssessmentFile) -> list[int]:
    return list(severity_map(assessment).values())


def agreement_score(first: AssessmentFile, second: AssessmentFile) -> float:
    universe = sorted(
        set(first.reference.valid_threat_ids)
        | set(second.reference.valid_threat_ids)
        | {threat.threat_id for threat in first.threats}
        | {threat.threat_id for threat in second.threats}
    )
    first_ids = _identified_valid_ids(first)
    second_ids = _identified_valid_ids(second)
    first_labels = [1 if threat_id in first_ids else 0 for threat_id in universe]
    second_labels = [1 if threat_id in second_ids else 0 for threat_id in universe]
    total = len(universe)
    if total == 0:
        return 0.0
    observed = sum(1 for left, right in zip(first_labels, second_labels) if left == right) / total
    left_positive = sum(first_labels) / total
    right_positive = sum(second_labels) / total
    expected = left_positive * right_positive + (1 - left_positive) * (1 - right_positive)
    if expected == 1.0:
        return 1.0
    return float((observed - expected) / (1 - expected))


def _rank(values: list[int]) -> list[float]:
    indexed = sorted(enumerate(values), key=lambda item: item[1])
    ranks = [0.0] * len(values)
    position = 0
    while position < len(indexed):
        end = position
        while end + 1 < len(indexed) and indexed[end + 1][1] == indexed[position][1]:
            end += 1
        average_rank = (position + end + 2) / 2
        for item_index in range(position, end + 1):
            ranks[indexed[item_index][0]] = average_rank
        position = end + 1
    return ranks


def _pearson(left: list[float], right: list[float]) -> float:
    if len(left) != len(right) or len(left) < 2:
        return 0.0
    left_mean = sum(left) / len(left)
    right_mean = sum(right) / len(right)
    numerator = sum((x - left_mean) * (y - right_mean) for x, y in zip(left, right))
    left_denominator = sqrt(sum((x - left_mean) ** 2 for x in left))
    right_denominator = sqrt(sum((y - right_mean) ** 2 for y in right))
    if left_denominator == 0 or right_denominator == 0:
        return 0.0
    return numerator / (left_denominator * right_denominator)


def severity_rank_correlation(first: AssessmentFile, second: AssessmentFile) -> float:
    first_scores = severity_map(first)
    second_scores = severity_map(second)
    shared = sorted(set(first_scores) & set(second_scores))
    if len(shared) < 2:
        return 0.0
    left = [first_scores[item] for item in shared]
    right = [second_scores[item] for item in shared]
    return float(_pearson(_rank(left), _rank(right)))


def bootstrap_confidence_interval(
    values: list[float], confidence: float = 0.95, n_bootstrap: int = 1000, seed: int = 42
) -> dict[str, float]:
    if not values:
        return {"mean": 0.0, "lower": 0.0, "upper": 0.0}
    rng = np.random.default_rng(seed)
    array = np.asarray(values, dtype=float)
    means = []
    for _ in range(n_bootstrap):
        sample = rng.choice(array, size=len(array), replace=True)
        means.append(float(np.mean(sample)))
    alpha = 1.0 - confidence
    lower = float(np.quantile(means, alpha / 2))
    upper = float(np.quantile(means, 1 - alpha / 2))
    return {"mean": float(np.mean(array)), "lower": lower, "upper": upper}


def severity_summary(assessment: AssessmentFile) -> dict[str, Any]:
    scores = severity_scores(assessment)
    if not scores:
        empty_ci = bootstrap_confidence_interval([])
        return {
            "count": 0,
            "mean": 0.0,
            "median": 0.0,
            "min": 0.0,
            "max": 0.0,
            "bootstrap_ci_mean": empty_ci,
        }
    scores_array = np.asarray(scores, dtype=float)
    return {
        "count": len(scores),
        "mean": float(np.mean(scores_array)),
        "median": float(np.median(scores_array)),
        "min": float(np.min(scores_array)),
        "max": float(np.max(scores_array)),
        "bootstrap_ci_mean": bootstrap_confidence_interval(scores),
    }


def scenario_coverage(assessment: AssessmentFile) -> dict[str, Any]:
    all_scenarios = sorted({threat.scenario_id for threat in assessment.threats})
    covered_scenarios = sorted(
        {threat.scenario_id for threat in assessment.threats if threat.identified and threat.valid}
    )
    return {
        "covered_count": len(covered_scenarios),
        "total_count": len(all_scenarios),
        "covered_scenarios": covered_scenarios,
    }


def _scenario_recalls(assessment: AssessmentFile) -> list[float]:
    grouped: dict[str, list[ThreatAssessment]] = {}
    for threat in assessment.threats:
        grouped.setdefault(threat.scenario_id, []).append(threat)

    reference_ai_ids = set(assessment.reference.ai_specific_threat_ids)
    scenario_scores: list[float] = []
    for threats in grouped.values():
        scenario_ai_ids = {threat.threat_id for threat in threats if threat.threat_id in reference_ai_ids}
        if not scenario_ai_ids:
            continue
        matched = {
            threat.threat_id
            for threat in threats
            if threat.identified and threat.valid and threat.ai_specific and threat.threat_id in scenario_ai_ids
        }
        scenario_scores.append(len(matched) / len(scenario_ai_ids))
    return scenario_scores


def _scenario_critical_recalls(assessment: AssessmentFile) -> list[float]:
    grouped: dict[str, list[ThreatAssessment]] = {}
    for threat in assessment.threats:
        grouped.setdefault(threat.scenario_id, []).append(threat)

    scenario_scores: list[float] = []
    for threats in grouped.values():
        critical_ids = {threat.threat_id for threat in threats if threat.valid and threat.priority == "Critical"}
        if not critical_ids:
            continue
        matched = {
            threat.threat_id
            for threat in threats
            if threat.identified and threat.valid and threat.priority == "Critical" and threat.threat_id in critical_ids
        }
        scenario_scores.append(len(matched) / len(critical_ids))
    return scenario_scores


def summarize_assessment(assessment: AssessmentFile) -> dict[str, Any]:
    recall_samples = _scenario_recalls(assessment)
    critical_recall_samples = _scenario_critical_recalls(assessment)
    duplicate_samples = []
    grouped: dict[str, list[str]] = {}
    for threat in assessment.threats:
        if threat.identified and threat.valid:
            grouped.setdefault(threat.scenario_id, []).append(threat.canonical_key)
    for keys in grouped.values():
        counts = Counter(keys)
        duplicates = sum(count - 1 for count in counts.values() if count > 1)
        duplicate_samples.append(duplicates / len(keys) if keys else 0.0)

    return {
        "assessor": assessment.assessor,
        "valid_threat_count": valid_threat_count(assessment),
        "unique_valid_threat_count": unique_valid_threat_count(assessment),
        "ai_specific_threat_recall": ai_specific_threat_recall(assessment),
        "critical_threat_count": len(identified_critical_threat_ids(assessment)),
        "critical_reference_count": len(critical_threat_ids(assessment)),
        "critical_threat_recall": critical_threat_recall(assessment),
        "duplicate_rate": duplicate_rate(assessment),
        "severity_summary": severity_summary(assessment),
        "scenario_coverage": scenario_coverage(assessment),
        "bootstrap_ci_ai_specific_recall": bootstrap_confidence_interval(recall_samples),
        "bootstrap_ci_critical_threat_recall": bootstrap_confidence_interval(critical_recall_samples),
        "bootstrap_ci_duplicate_rate": bootstrap_confidence_interval(duplicate_samples),
    }


def evaluate_assessment_pair(first: AssessmentFile, second: AssessmentFile) -> dict[str, Any]:
    first_summary = summarize_assessment(first)
    second_summary = summarize_assessment(second)
    return {
        "baseline": first_summary,
        "comparison": second_summary,
        "agreement_score": agreement_score(first, second),
        "severity_rank_correlation": severity_rank_correlation(first, second),
        "bootstrap_ci_valid_threat_delta": bootstrap_confidence_interval(
            [
                second_summary["valid_threat_count"] - first_summary["valid_threat_count"]
            ]
        ),
    }
