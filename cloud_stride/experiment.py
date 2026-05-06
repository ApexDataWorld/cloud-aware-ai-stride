from __future__ import annotations

from pathlib import Path
from typing import Any

from .metrics import evaluate_assessment_pair
from .report import render_markdown_report
from .schemas import load_assessment


def run_demo_experiment(
    baseline_file: str | Path,
    comparison_file: str | Path,
    output: str | Path | None = None,
) -> dict[str, Any]:
    summary = evaluate_assessment_pair(load_assessment(baseline_file), load_assessment(comparison_file))
    report = render_markdown_report(summary)
    if output is not None:
        Path(output).write_text(report, encoding="utf-8")
    summary["report_markdown"] = report
    return summary
