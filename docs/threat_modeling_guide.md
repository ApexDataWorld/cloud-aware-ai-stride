# Cloud-Aware STRIDE Threat Modeling Guide

This guide mirrors the method described in Paper 2 and turns the framework into a repeatable engineering workflow.

## Goal

Use Cloud-Aware STRIDE to identify, classify, score, and validate threats in LLM, RAG, MCP, MLOps, and cloud-connected AI systems.

## Seven-Step Method

1. Define system objective and business context.
2. Create an AI pipeline component diagram.
3. Identify assets, actors, data flows, and trust boundaries.
4. Apply STRIDE to each component and data flow.
5. Add AI-specific threat prompts.
6. Apply cloud severity modifiers.
7. Produce a mitigation backlog and validation metrics.

## Reference Decomposition

The repository models AI pipelines across these layers:

- user interface
- API gateway, authentication, and rate limiting
- AI orchestrator or agent runtime
- prompt store
- RAG retrieval pipeline
- embedding model
- vector database
- LLM or model gateway
- MCP client or tool router
- MCP server or tool registry
- enterprise APIs, databases, SaaS, and cloud services
- IAM and workload identity
- secrets management
- logging and tracing
- CI/CD and model registry
- human approval and audit workflow

## Threat Record Expectations

Each threat record should capture:

- scenario id
- component
- STRIDE category
- AI threat type
- assets at risk
- trust boundaries involved
- likelihood and impact
- cloud severity modifiers
- mitigation ideas
- validation evidence

## Cloud Severity Modifiers

- `privilege_boundary`: how sharply the threat crosses privilege boundaries
- `blast_radius`: how much of the system or tenant population can be affected
- `persistence`: whether the threat lingers across sessions or artifacts
- `detectability`: how likely the organization is to notice the problem
- `reversibility`: how difficult the effect is to undo
- `compliance_sensitivity`: legal, contractual, or regulatory exposure

## Study Use

For a paper-aligned analyst study, compare:

- baseline STRIDE over the same scenario and trust boundaries
- Cloud-Aware STRIDE with AI-specific prompts and cloud modifiers

Primary metrics:

- valid threat count
- unique valid threat count
- AI-specific threat recall
- duplicate rate
- Cohen's kappa
- Spearman severity rank correlation
- bootstrap confidence intervals
