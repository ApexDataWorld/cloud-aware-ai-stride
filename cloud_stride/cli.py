from __future__ import annotations

import argparse
import json
from pathlib import Path

from .experiment import run_demo_experiment
from .metrics import evaluate_assessment_pair
from .report import render_markdown_report
from .schemas import load_assessment, validate_directory
from .scoring import score_threat
from .yamlio import dump_yaml


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="cloud_stride", description="Cloud-Aware STRIDE research scaffold CLI")
    subparsers = parser.add_subparsers(dest="command", required=True)

    validate_parser = subparsers.add_parser("validate", help="Validate scenario YAML files in a directory")
    validate_parser.add_argument("directory")

    score_parser = subparsers.add_parser("score", help="Score a threat assessment YAML file")
    score_parser.add_argument("assessment_file")

    evaluate_parser = subparsers.add_parser("evaluate", help="Compare baseline and cloud-aware results")
    evaluate_parser.add_argument("baseline_file")
    evaluate_parser.add_argument("comparison_file")
    evaluate_parser.add_argument("--output", default=None, help="Optional path to write a markdown report")

    demo_parser = subparsers.add_parser("demo", help="Run the bundled synthetic baseline-vs-cloud-aware demo")
    demo_parser.add_argument("--baseline-file", default="results/baseline.yaml")
    demo_parser.add_argument("--comparison-file", default="results/cloud_aware.yaml")
    demo_parser.add_argument("--output", default="reports/example_report.md")
    return parser


def _validate(directory: str) -> int:
    valid_paths, errors = validate_directory(directory)
    payload = {"validated": valid_paths, "errors": errors}
    print(json.dumps(payload, indent=2))
    return 1 if errors else 0


def _score(assessment_file: str) -> int:
    assessment = load_assessment(assessment_file)
    payload = {
        "study_id": assessment.study_id,
        "assessor": assessment.assessor,
        "scores": [score_threat(threat) for threat in assessment.threats],
    }
    print(dump_yaml(payload))
    return 0


def _evaluate(baseline_file: str, comparison_file: str, output: str | None) -> int:
    summary = evaluate_assessment_pair(load_assessment(baseline_file), load_assessment(comparison_file))
    report = render_markdown_report(summary)
    print(report)
    if output:
        Path(output).write_text(report, encoding="utf-8")
    return 0


def _demo(baseline_file: str, comparison_file: str, output: str) -> int:
    summary = run_demo_experiment(baseline_file, comparison_file, output)
    print(summary["report_markdown"])
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    if args.command == "validate":
        return _validate(args.directory)
    if args.command == "score":
        return _score(args.assessment_file)
    if args.command == "evaluate":
        return _evaluate(args.baseline_file, args.comparison_file, args.output)
    if args.command == "demo":
        return _demo(args.baseline_file, args.comparison_file, args.output)
    parser.error(f"Unsupported command: {args.command}")
    return 2
