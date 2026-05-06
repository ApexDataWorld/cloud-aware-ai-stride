# Cloud-Aware STRIDE Evaluation Report

> This report is generated from synthetic AI pipeline scenarios. It is intended to validate reproducibility, scoring behavior, and threat coverage. It is not a production breach study, enterprise field study, or independent human analyst study.

## Summary

| Metric | Baseline STRIDE | Cloud-Aware STRIDE |
| --- | ---: | ---: |
| Valid threat count | 9 | 17 |
| Unique valid threat count | 8 | 17 |
| AI-specific threat recall | 0.000 | 1.000 |
| Critical threat count | 4 | 11 |
| Critical threat coverage | 4/11 | 11/11 |
| Critical threat recall | 0.364 | 1.000 |
| Duplicate rate | 0.111 | 0.000 |
| Scenario coverage | 8/12 | 12/12 |

## Severity Score Summary

| Metric | Baseline STRIDE | Cloud-Aware STRIDE |
| --- | ---: | ---: |
| Count | 9 | 17 |
| Mean severity | 26.667 | 28.529 |
| Median severity | 25.000 | 29.000 |
| Min severity | 18.000 | 18.000 |
| Max severity | 38.000 | 38.000 |

## Agreement

- Cohen's kappa: not applicable for this synthetic single-assessment benchmark.
- Inter-rater agreement will be evaluated in a future analyst study.
- Spearman severity rank correlation: 1.000

## Bootstrap Confidence Intervals

- Baseline AI-specific recall: 0.000 (95% CI 0.000-0.000)
- Cloud-aware AI-specific recall: 1.000 (95% CI 1.000-1.000)
- Baseline critical threat recall: 0.333 (95% CI 0.056-0.611)
- Cloud-aware critical threat recall: 1.000 (95% CI 1.000-1.000)
- Baseline duplicate rate: 0.062 (95% CI 0.000-0.188)
- Cloud-aware duplicate rate: 0.000 (95% CI 0.000-0.000)
- Baseline mean severity: 26.667 (95% CI 22.886-30.778)
- Cloud-aware mean severity: 28.529 (95% CI 25.588-31.412)
- Valid threat delta (cloud-aware minus baseline): 8.000 (95% CI 8.000-8.000)

## Interpretation

The synthetic benchmark shows how cloud context and AI-specific taxonomy extensions can increase threat coverage while preserving an auditable, reproducible scoring workflow.

## Experiment Notes

- Method comparison: baseline STRIDE versus Cloud-Aware STRIDE
- Scenario pack: synthetic enterprise AI pipeline benchmarks
- Synthetic scenarios represented in assessment files: 12
- Analyst deliverables: threats, STRIDE categories, affected components, severity, mitigations, and validation evidence