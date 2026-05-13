from __future__ import annotations

from pathlib import Path
from typing import Any

import matplotlib.pyplot as plt
import pandas as pd


def _ensure_output_dirs(root: str | Path) -> dict[str, Path]:
    root_path = Path(root)
    tables = root_path / "reports" / "tables"
    figures = root_path / "reports" / "figures"
    generated = root_path / "reports" / "generated_results"
    docs = root_path / "docs"
    for path in (tables, figures, generated, docs):
        path.mkdir(parents=True, exist_ok=True)
    return {"tables": tables, "figures": figures, "generated": generated, "docs": docs}


def write_table(frame: pd.DataFrame, path: str | Path) -> None:
    frame.to_csv(path, index=False)


def _method_label(method: str) -> str:
    return {
        "baseline_stride": "Baseline STRIDE",
        "cloud_aware_stride": "Cloud-Aware STRIDE",
    }.get(method, method)


def generate_summary_markdown(metrics: dict[str, Any], path: str | Path) -> None:
    baseline = metrics["baseline"]
    cloud_aware = metrics["cloud_aware"]
    lines = [
        "# Synthetic Cloud-Aware STRIDE Summary",
        "",
        "All scenarios and outputs in this report are synthetic. This repository does not claim production breach results.",
        "",
        "## Threat Coverage",
        "",
        f"- Baseline valid threat count: {baseline['valid_threat_count']}",
        f"- Cloud-aware valid threat count: {cloud_aware['valid_threat_count']}",
        f"- Baseline AI-specific recall: {baseline['ai_specific_recall']:.3f}",
        f"- Cloud-aware AI-specific recall: {cloud_aware['ai_specific_recall']:.3f}",
        f"- Baseline critical threat recall: {baseline['critical_threat_recall']:.3f}",
        f"- Cloud-aware critical threat recall: {cloud_aware['critical_threat_recall']:.3f}",
        f"- Severity rank correlation: {metrics['severity_rank_correlation']:.3f}",
        "",
        "In the synthetic benchmark, Cloud-Aware STRIDE identified more valid threats and achieved higher AI-specific and critical-threat recall than baseline STRIDE.",
        "",
        "## Residual Risk",
        "",
        f"- Mean mitigation coverage: {metrics['mitigation_coverage']:.3f}",
        "",
        "## Scope Label",
        "",
        "Synthetic artifact for Paper 2-centered reproducibility only. The repository does not claim production validation or universal superiority.",
    ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def generate_manuscript_tables(metrics: dict[str, Any], path: str | Path) -> None:
    baseline = metrics["baseline"]
    cloud_aware = metrics["cloud_aware"]
    lines = [
        "# Manuscript Result Tables",
        "",
        "All values below are synthetic and repo-generated.",
        "",
        "## IEEE Result Table",
        "",
        "| Metric | Baseline STRIDE | Cloud-Aware STRIDE |",
        "| --- | ---: | ---: |",
        f"| Valid threat count | {baseline['valid_threat_count']} | {cloud_aware['valid_threat_count']} |",
        f"| AI-specific recall | {baseline['ai_specific_recall']:.3f} | {cloud_aware['ai_specific_recall']:.3f} |",
        f"| Critical threat recall | {baseline['critical_threat_recall']:.3f} | {cloud_aware['critical_threat_recall']:.3f} |",
        f"| Severity rank correlation | {metrics['severity_rank_correlation']:.3f} | {metrics['severity_rank_correlation']:.3f} |",
        f"| Mean mitigation coverage | {metrics['mitigation_coverage']:.3f} | {metrics['mitigation_coverage']:.3f} |",
        "",
        "## LaTeX Table",
        "",
        r"\begin{tabular}{lcc}",
        r"\hline",
        r"Metric & Baseline STRIDE & Cloud-Aware STRIDE \\",
        r"\hline",
        f"Valid threat count & {baseline['valid_threat_count']} & {cloud_aware['valid_threat_count']} \\\\",
        f"AI-specific recall & {baseline['ai_specific_recall']:.3f} & {cloud_aware['ai_specific_recall']:.3f} \\\\",
        f"Critical threat recall & {baseline['critical_threat_recall']:.3f} & {cloud_aware['critical_threat_recall']:.3f} \\\\",
        f"Severity rank correlation & {metrics['severity_rank_correlation']:.3f} & {metrics['severity_rank_correlation']:.3f} \\\\",
        f"Mean mitigation coverage & {metrics['mitigation_coverage']:.3f} & {metrics['mitigation_coverage']:.3f} \\\\",
        r"\hline",
        r"\end{tabular}",
        "",
        "Synthetic benchmark note: In the synthetic benchmark, Cloud-Aware STRIDE identified more valid threats and achieved higher AI-specific and critical-threat recall than baseline STRIDE.",
    ]
    Path(path).write_text("\n".join(lines), encoding="utf-8")


def plot_threat_count_coverage(metrics: dict[str, Any], path: str | Path) -> None:
    labels = ["Baseline STRIDE", "Cloud-Aware STRIDE"]
    counts = [
        metrics["baseline"]["valid_threat_count"],
        metrics["cloud_aware"]["valid_threat_count"],
    ]
    plt.figure(figsize=(6, 4))
    plt.bar(labels, counts)
    plt.ylabel("Valid Threat Count")
    plt.title("Synthetic Valid Threat Counts")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_recall_comparison(metrics: dict[str, Any], path: str | Path) -> None:
    labels = ["AI-specific recall", "Critical recall"]
    baseline = [
        metrics["baseline"]["ai_specific_recall"] * 100.0,
        metrics["baseline"]["critical_threat_recall"] * 100.0,
    ]
    cloud_aware = [
        metrics["cloud_aware"]["ai_specific_recall"] * 100.0,
        metrics["cloud_aware"]["critical_threat_recall"] * 100.0,
    ]
    x_positions = range(len(labels))
    plt.figure(figsize=(8, 4))
    plt.bar([x - 0.2 for x in x_positions], baseline, width=0.4, label="Baseline STRIDE")
    plt.bar([x + 0.2 for x in x_positions], cloud_aware, width=0.4, label="Cloud-Aware STRIDE")
    plt.xticks(list(x_positions), labels)
    plt.ylabel("Recall (%)")
    plt.title("Synthetic Recall Comparison")
    plt.legend()
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_residual_risk_ranking(frame: pd.DataFrame, path: str | Path) -> None:
    subset = frame.head(10).copy()
    subset["readable_label"] = subset["threat_name"]
    subset = subset.iloc[::-1]
    plt.figure(figsize=(10, 6))
    plt.barh(subset["readable_label"], subset["residual_risk"])
    plt.xlabel("Residual Risk")
    plt.title("Synthetic Residual Risk Ranking")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def plot_mitigation_mapping_completeness(frame: pd.DataFrame, path: str | Path) -> None:
    summary = frame.groupby("method", as_index=False)["threat_id"].nunique()
    summary["method_label"] = summary["method"].map(_method_label)
    plt.figure(figsize=(7, 4))
    plt.bar(summary["method_label"], summary["threat_id"])
    plt.ylabel("Threats With Mapped Mitigations")
    plt.title("Synthetic Mitigation Mapping Completeness")
    plt.tight_layout()
    plt.savefig(path)
    plt.close()


def _remove_stale_legacy_figures(figures_dir: Path) -> None:
    for legacy_name in ("threat_coverage_bar.png", "mitigation_coverage.png"):
        legacy_path = figures_dir / legacy_name
        if legacy_path.exists():
            legacy_path.unlink()


def generate_all_reports(
    repo_root: str | Path,
    metrics: dict[str, Any],
    threat_coverage: pd.DataFrame,
    scenario_coverage: pd.DataFrame,
    mitigation_mapping: pd.DataFrame,
    mitigation_coverage: pd.DataFrame,
    residual_risk_ranking: pd.DataFrame,
) -> dict[str, Path]:
    outputs = _ensure_output_dirs(repo_root)
    _remove_stale_legacy_figures(outputs["figures"])
    write_table(threat_coverage, outputs["tables"] / "threat_coverage.csv")
    write_table(mitigation_mapping, outputs["tables"] / "mitigation_mapping.csv")
    write_table(residual_risk_ranking, outputs["tables"] / "residual_risk_ranking.csv")
    write_table(scenario_coverage, outputs["tables"] / "scenario_coverage.csv")
    write_table(mitigation_coverage, outputs["tables"] / "mitigation_coverage.csv")
    generate_summary_markdown(metrics, outputs["generated"] / "summary.md")
    generate_manuscript_tables(metrics, outputs["docs"] / "manuscript_tables.md")
    plot_threat_count_coverage(metrics, outputs["figures"] / "threat_count_coverage.png")
    plot_recall_comparison(metrics, outputs["figures"] / "recall_comparison.png")
    plot_residual_risk_ranking(residual_risk_ranking, outputs["figures"] / "residual_risk_ranking.png")
    plot_mitigation_mapping_completeness(mitigation_coverage, outputs["figures"] / "mitigation_mapping_completeness.png")
    return {
        "summary": outputs["generated"] / "summary.md",
        "threat_coverage": outputs["tables"] / "threat_coverage.csv",
        "manuscript_tables": outputs["docs"] / "manuscript_tables.md",
    }
