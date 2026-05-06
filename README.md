# cloud-aware-ai-stride

This repository supports the paper "Cloud-Aware STRIDE for AI Pipelines: Threat Modeling LLM, RAG, MCP, and MLOps Systems." It provides a reproducible research scaffold for applying STRIDE to modern AI pipelines, including LLM applications, RAG systems, MCP tool layers, MLOps pipelines, and cloud IAM boundaries. The repository includes synthetic scenarios, a Cloud-Aware STRIDE taxonomy, severity scoring functions, evaluation metrics, analyst-oriented methodology artifacts, and report generation utilities. It does not provide offensive exploit tooling or claim production breach results.

## Paper Title

Cloud-Aware STRIDE for AI Pipelines: Threat Modeling LLM, RAG, MCP, and MLOps Systems

## Repository Purpose

The goal of this repository is to provide a clean, testable, publication-supporting artifact for:

- decomposing AI systems into STRIDE-relevant components
- extending classical STRIDE with AI- and cloud-aware threats
- scoring severity with cloud context adjustments
- comparing baseline and cloud-aware assessments
- reproducing synthetic benchmark outputs from YAML inputs
- documenting analyst workflow and validation evidence for repeatable studies

This is a research scaffold, not a production scanner or offensive security tool.

## Repository Layout

```text
cloud-aware-ai-stride/
  cloud_stride/              # package code for validation, scoring, metrics, reporting, and CLI
  taxonomy/                  # Cloud-Aware STRIDE taxonomy and framework mappings
  scenarios/                 # twelve synthetic AI pipeline scenarios
  examples/                  # example assessor threat files for scoring
  results/                   # baseline vs cloud-aware synthetic comparison inputs
  reports/                   # generated markdown outputs
  docs/                      # threat modeling guide and analyst instructions
  paper/                     # manuscript support files, references, figures, and tables
  tests/                     # pytest coverage
```

## Installation

```bash
python -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
pip install -e .
```

## Quickstart

Validate the full synthetic scenario pack:

```bash
python -m cloud_stride validate scenarios/
```

Score a single example threat file:

```bash
python -m cloud_stride score examples/threats.yaml
```

Compare baseline vs cloud-aware results and write a markdown report:

```bash
python -m cloud_stride evaluate results/baseline.yaml results/cloud_aware.yaml --output reports/example_report.md
```

Run the bundled reproducible demo experiment:

```bash
python -m cloud_stride demo --output reports/example_report.md
```

Run the test suite:

```bash
pytest
```

## Methodology

The scaffold operationalizes four paper claims:

1. Classical STRIDE alone can miss AI-specific threats such as prompt injection, memorization leakage, unsafe tool use, and poisoned model lifecycle artifacts.
2. Cloud-Aware STRIDE can capture a broader mix of LLM, RAG, MCP, MLOps, and multi-tenant cloud threats.
3. Cloud context changes severity ranking through privilege boundary, blast radius, persistence, detectability, and compliance sensitivity.
4. Threat-modeling outputs can be compared reproducibly using structured YAML, scoring utilities, agreement metrics, and generated markdown reports.

### Seven-Step Cloud-Aware STRIDE Method

1. Define system objective and business context.
2. Create the AI pipeline component diagram.
3. Identify assets, actors, data flows, and trust boundaries.
4. Apply STRIDE to each component and data flow.
5. Add AI-specific threat prompts.
6. Apply cloud severity modifiers.
7. Produce a mitigation backlog and validation metrics.

See [`docs/threat_modeling_guide.md`](/Users/saurabhgupta/projects/github/cloud-aware-ai-stride/docs/threat_modeling_guide.md) and [`docs/analyst_instructions.md`](/Users/saurabhgupta/projects/github/cloud-aware-ai-stride/docs/analyst_instructions.md) for the paper-aligned workflow.

### Severity Scoring

Base severity:

```text
likelihood * impact
```

Cloud-adjusted severity:

```text
base severity
+ privilege_boundary
+ blast_radius
+ persistence
+ detectability
+ reversibility
+ compliance_sensitivity
```

### Supported STRIDE Categories

- Spoofing
- Tampering
- Repudiation
- Information Disclosure
- Denial of Service
- Elevation of Privilege

### Synthetic Scenarios

The repository now includes a twelve-scenario synthetic benchmark aligned to the manuscript’s public-study design and numbering:

- customer support chatbot
- healthcare claims assistant
- financial document summarizer
- code generation assistant
- MCP-based enterprise agent
- HR policy assistant
- MLOps deployment pipeline
- multi-tenant analytics assistant
- security operations copilot
- cloud cost optimization agent
- data science notebook assistant
- sales proposal generator

## Example Commands

Use the packaged CLI:

```bash
cloud-stride validate scenarios/
cloud-stride score examples/threats_cloud_aware.yaml
cloud-stride evaluate results/baseline.yaml results/cloud_aware.yaml
```

## Reproducing Results

1. Install the package and development dependencies.
2. Validate the twelve scenario YAML files in `scenarios/`.
3. Score one or both example assessment files in `examples/`.
4. Run `python -m cloud_stride demo --output reports/example_report.md`.
5. Confirm the output matches [`reports/example_report.md`](/Users/saurabhgupta/projects/github/cloud-aware-ai-stride/reports/example_report.md).
6. Run `pytest` to verify schema, scoring, taxonomy, and metrics behavior.

## Evaluation Metrics

The metrics module includes:

- valid threat count
- unique valid threat count
- AI-specific threat recall
- duplicate rate
- Cohen's kappa agreement score
- Spearman severity rank correlation
- bootstrap confidence intervals

## Safety Scope

The repository intentionally excludes:

- real exploit code
- cloud credential usage
- offensive attack automation
- production scanning
- real sensitive datasets

All included scenarios, results, and report outputs are synthetic.

## Limitations

- The dataset is synthetic and intentionally small.
- Threat validity labels are encoded in benchmark YAML rather than derived from field studies.
- Agreement and recall results should be read as reproducibility examples, not empirical proof of operational superiority.
- Cloud-adjusted severity is a simple additive research heuristic suitable for experimentation, not a compliance scoring standard.
- The repo includes 12 synthetic scenarios and a synthetic matched result bundle, but those bundled results are still illustrative rather than empirical study outcomes.
