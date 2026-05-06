# Analyst Instructions

These instructions support a repeatable baseline-vs-cloud-aware evaluation study using the repository’s synthetic scenarios.

## Task

For each assigned scenario, produce:

- a list of threats
- the STRIDE category for each threat
- the affected component
- a short threat description
- a severity score
- proposed mitigations
- evidence needed to validate mitigations

## Baseline Round

- Use classical STRIDE on the scenario’s components and trust boundaries.
- Do not use the Cloud-Aware STRIDE taxonomy prompts during the baseline pass.
- Record only threats you can justify from the provided scenario artifact.

## Cloud-Aware Round

- Revisit the same scenario using the Cloud-Aware STRIDE taxonomy.
- Explicitly consider AI-native assets such as prompts, retrieved context, embeddings, tool descriptions, model artifacts, and inference traces.
- Apply cloud severity modifiers for privilege boundary crossing, blast radius, persistence, detectability, reversibility, and compliance sensitivity.

## Quality Guidance

- Prefer specific threats over generic statements.
- Normalize duplicate findings to a single canonical threat when possible.
- Tie mitigations to the affected component or boundary.
- List concrete validation evidence such as policy tests, trace reviews, access checks, or prompt red-team exercises.

## Safety Boundary

- Use only the synthetic scenarios in this repository.
- Do not introduce real credentials, production architecture details, or exploit instructions.
- Keep descriptions defensive and evaluation-focused.
