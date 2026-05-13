from __future__ import annotations

import pandas as pd


def calculate_base_severity(likelihood: float, impact: float) -> float:
    return float(likelihood * impact)


def calculate_cloud_severity(
    likelihood: float,
    impact: float,
    privilege_boundary: float,
    blast_radius: float,
    persistence: float,
    detectability_penalty: float,
    reversibility_penalty: float,
    compliance_sensitivity: float,
) -> float:
    # This is a heuristic prioritization score for Paper 2, not a compliance standard
    # or mathematically proven loss model.
    base = calculate_base_severity(likelihood, impact)
    return float(
        base
        + privilege_boundary
        + blast_radius
        + persistence
        + detectability_penalty
        + reversibility_penalty
        + compliance_sensitivity
    )


def score_mapping(mapping: pd.DataFrame) -> pd.DataFrame:
    scored = mapping.copy()
    scored["base_severity"] = scored.apply(
        lambda row: calculate_base_severity(row["baseline_likelihood"], row["baseline_impact"]),
        axis=1,
    )
    scored["cloud_severity"] = scored.apply(
        lambda row: calculate_cloud_severity(
            row["baseline_likelihood"],
            row["baseline_impact"],
            row["privilege_boundary"],
            row["blast_radius"],
            row["persistence"],
            row["detectability_penalty"],
            row["reversibility_penalty"],
            row["compliance_sensitivity"],
        ),
        axis=1,
    )
    return scored
