# Cloud-Aware STRIDE for AI Pipelines

This repository supports the Paper 2-centered IEEE manuscript:

Cloud-Aware STRIDE for AI Pipelines: Threat Modeling, Control-Plane Mitigations, and Residual-Risk Prioritization for LLM, RAG, MCP, and MLOps Systems.

This repository implements Cloud-Aware STRIDE as the primary contribution. It uses selected MCP control-plane mitigation patterns from Paper 1 and lightweight residual-risk prioritization concepts from Paper 12.

All scenarios and default outputs are synthetic. This repository does not claim production breach results.

## Scope Boundary

In scope:
- Cloud-Aware STRIDE threat modeling
- AI pipeline component decomposition
- LLM/RAG/MCP/MLOps/cloud IAM threat taxonomy
- cloud severity modifiers
- mitigation mapping using selected Paper 1 controls
- lightweight residual-risk prioritization using selected Paper 12 concepts
- synthetic scenario validation

Out of scope:
- full MCP control-plane implementation
- full Bayesian Monte Carlo risk quantification
- multi-agent reliability experiments
- RAG benchmarking
- healthcare claims calibration
- fairness drift monitoring
- SLO forecasting
- production breach analysis

## Related Work and Portfolio Positioning

This repository supports the Paper 2-centered IEEE manuscript.

- Paper 2, this manuscript: Cloud-Aware STRIDE threat modeling for LLM, RAG, MCP, MLOps, and cloud-connected AI systems.
- Paper 1, supporting mitigation layer only: selected MCP control-plane mitigation patterns including MCP gateway enforcement, OAuth/OIDC identity binding, ABAC, OPA/Rego, audit logging, OpenTelemetry traceability, and fail-closed behavior.
- Paper 12, supporting prioritization layer only: lightweight residual-risk prioritization using baseline severity, mitigation coverage, control effectiveness, and residual-risk ranking.

This repository implements Paper 2 as the primary contribution. It does not implement the full Paper 1 MCP control-plane architecture and does not implement the full Paper 12 Bayesian Monte Carlo risk quantification model.

## Repository Layout

```text
cloud-aware-stride-ai-pipelines/
  data/
  src/cloud_stride/
  experiments/
  reports/
  tests/
  docs/
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Reproducibility

Run the experiment pipeline from the repository root:

```bash
python -m experiments.run_threat_modeling
python -m experiments.run_mitigation_analysis
python -m experiments.run_residual_risk_analysis
python -m experiments.run_all_experiments
```

Run the test suite:

```bash
pytest tests/
```

Generated outputs include:
- `reports/tables/threat_coverage.csv`
- `reports/tables/mitigation_mapping.csv`
- `reports/tables/residual_risk_ranking.csv`
- `reports/tables/scenario_coverage.csv`
- `reports/generated_results/summary.md`
- `reports/figures/threat_coverage_bar.png`
- `reports/figures/residual_risk_ranking.png`
- `reports/figures/mitigation_coverage.png`

All generated outputs are labeled synthetic.

## Citation

If you use this repository, please cite:

Gupta, S. (2026). Cloud-Aware STRIDE for AI Pipelines: Threat Modeling, Control-Plane Mitigations, and Residual-Risk Prioritization for LLM, RAG, MCP, and MLOps Systems. IEEE Access, forthcoming.
