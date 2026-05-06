from __future__ import annotations

from .schemas import ThreatAssessment


def calculate_severity(likelihood: int, impact: int) -> int:
    return likelihood * impact


def calculate_cloud_adjusted_severity(threat: ThreatAssessment) -> int:
    base = calculate_severity(threat.likelihood, threat.impact)
    factors = threat.cloud_factors
    return (
        base
        + factors.privilege_boundary
        + factors.blast_radius
        + factors.persistence
        + factors.detectability
        + factors.reversibility
        + factors.compliance_sensitivity
    )


def score_threat(threat: ThreatAssessment) -> dict[str, object]:
    return {
        "threat_id": threat.threat_id,
        "title": threat.title,
        "category": threat.category,
        "ai_threat_type": threat.ai_threat_type,
        "base_severity": calculate_severity(threat.likelihood, threat.impact),
        "cloud_adjusted_severity": calculate_cloud_adjusted_severity(threat),
        "priority": threat.priority,
        "ai_specific": threat.ai_specific,
        "identified": threat.identified,
        "valid": threat.valid,
    }
