from __future__ import annotations

from typing import Any


def _format_ci(ci: dict[str, float]) -> str:
    return f"{ci['mean']:.3f} (95% CI {ci['lower']:.3f}-{ci['upper']:.3f})"


def render_markdown_report(summary: dict[str, Any]) -> str:
    baseline = summary["baseline"]
    comparison = summary["comparison"]
    baseline_severity = baseline["severity_summary"]
    comparison_severity = comparison["severity_summary"]
    lines = [
        "# Cloud-Aware STRIDE Evaluation Report",
        "",
        "> This report is generated from synthetic AI pipeline scenarios. It is intended to validate reproducibility, scoring behavior, and threat coverage. It is not a production breach study, enterprise field study, or independent human analyst study.",
        "",
        "## Summary",
        "",
        "| Metric | Baseline STRIDE | Cloud-Aware STRIDE |",
        "| --- | ---: | ---: |",
        f"| Valid threat count | {baseline['valid_threat_count']} | {comparison['valid_threat_count']} |",
        f"| Unique valid threat count | {baseline['unique_valid_threat_count']} | {comparison['unique_valid_threat_count']} |",
        f"| AI-specific threat recall | {baseline['ai_specific_threat_recall']:.3f} | {comparison['ai_specific_threat_recall']:.3f} |",
        f"| Critical threat count | {baseline['critical_threat_count']} | {comparison['critical_threat_count']} |",
        f"| Critical threat coverage | {baseline['critical_threat_count']}/{baseline['critical_reference_count']} | {comparison['critical_threat_count']}/{comparison['critical_reference_count']} |",
        f"| Critical threat recall | {baseline['critical_threat_recall']:.3f} | {comparison['critical_threat_recall']:.3f} |",
        f"| Duplicate rate | {baseline['duplicate_rate']:.3f} | {comparison['duplicate_rate']:.3f} |",
        f"| Scenario coverage | {baseline['scenario_coverage']['covered_count']}/{baseline['scenario_coverage']['total_count']} | {comparison['scenario_coverage']['covered_count']}/{comparison['scenario_coverage']['total_count']} |",
        "",
        "## Severity Score Summary",
        "",
        "| Metric | Baseline STRIDE | Cloud-Aware STRIDE |",
        "| --- | ---: | ---: |",
        f"| Count | {baseline_severity['count']} | {comparison_severity['count']} |",
        f"| Mean severity | {baseline_severity['mean']:.3f} | {comparison_severity['mean']:.3f} |",
        f"| Median severity | {baseline_severity['median']:.3f} | {comparison_severity['median']:.3f} |",
        f"| Min severity | {baseline_severity['min']:.3f} | {comparison_severity['min']:.3f} |",
        f"| Max severity | {baseline_severity['max']:.3f} | {comparison_severity['max']:.3f} |",
        "",
        "## Agreement",
        "",
        "- Cohen's kappa: not applicable for this synthetic single-assessment benchmark.",
        "- Inter-rater agreement will be evaluated in a future analyst study.",
        f"- Spearman severity rank correlation: {summary['severity_rank_correlation']:.3f}",
        "",
        "## Bootstrap Confidence Intervals",
        "",
        f"- Baseline AI-specific recall: {_format_ci(baseline['bootstrap_ci_ai_specific_recall'])}",
        f"- Cloud-aware AI-specific recall: {_format_ci(comparison['bootstrap_ci_ai_specific_recall'])}",
        f"- Baseline critical threat recall: {_format_ci(baseline['bootstrap_ci_critical_threat_recall'])}",
        f"- Cloud-aware critical threat recall: {_format_ci(comparison['bootstrap_ci_critical_threat_recall'])}",
        f"- Baseline duplicate rate: {_format_ci(baseline['bootstrap_ci_duplicate_rate'])}",
        f"- Cloud-aware duplicate rate: {_format_ci(comparison['bootstrap_ci_duplicate_rate'])}",
        f"- Baseline mean severity: {_format_ci(baseline_severity['bootstrap_ci_mean'])}",
        f"- Cloud-aware mean severity: {_format_ci(comparison_severity['bootstrap_ci_mean'])}",
        f"- Valid threat delta (cloud-aware minus baseline): {_format_ci(summary['bootstrap_ci_valid_threat_delta'])}",
        "",
        "## Interpretation",
        "",
        "The synthetic benchmark shows how cloud context and AI-specific taxonomy extensions can increase threat coverage while preserving an auditable, reproducible scoring workflow.",
        "",
        "## Experiment Notes",
        "",
        "- Method comparison: baseline STRIDE versus Cloud-Aware STRIDE",
        "- Scenario pack: synthetic enterprise AI pipeline benchmarks",
        f"- Synthetic scenarios represented in assessment files: {comparison['scenario_coverage']['total_count']}",
        "- Analyst deliverables: threats, STRIDE categories, affected components, severity, mitigations, and validation evidence",
    ]
    return "\n".join(lines)
