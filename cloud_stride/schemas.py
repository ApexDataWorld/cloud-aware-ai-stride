from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError, field_validator, model_validator

from .yamlio import load_yaml

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)


class DataAsset(BaseModel):
    name: str
    sensitivity: Literal["low", "moderate", "high", "regulated"]
    residency: Literal["single-region", "multi-region", "cross-border"]


class Component(BaseModel):
    name: str
    kind: str
    trust_zone: str
    cloud_dependency: str
    notes: str = ""


class TrustBoundary(BaseModel):
    source: str
    target: str
    rationale: str


class CloudContext(BaseModel):
    provider: Literal["aws", "azure", "gcp", "hybrid", "multi-cloud", "cloud-agnostic"]
    identity_model: str
    sensitive_data: bool
    regulated_data: Literal["none", "possible", "present"]
    multi_tenant: bool
    network_exposure: Literal["internal", "internet-facing", "partner-connected", "hybrid"]


class ScenarioModel(BaseModel):
    scenario_id: str
    title: str
    summary: str
    pipeline_type: Literal["llm", "rag", "mcp", "mlops", "analytics"]
    cloud: Literal["aws", "azure", "gcp", "hybrid", "multi-cloud"]
    components: list[Component]
    assets: list[DataAsset]
    trust_boundaries: list[TrustBoundary]
    cloud_context: CloudContext
    expected_threat_categories: list[str]
    assumptions: list[str]
    security_objectives: list[str]


class CloudFactors(BaseModel):
    privilege_boundary: int = Field(ge=0, le=5)
    blast_radius: int = Field(ge=0, le=5)
    persistence: int = Field(ge=0, le=5)
    detectability: int = Field(ge=0, le=5)
    reversibility: int = Field(ge=0, le=5)
    compliance_sensitivity: int = Field(ge=0, le=5)


class ThreatAssessment(BaseModel):
    threat_id: str
    scenario_id: str
    title: str
    category: Literal[*STRIDE_CATEGORIES]
    ai_threat_type: str
    component: str
    asset_at_risk: list[str]
    trust_boundary: list[str]
    ai_specific: bool
    identified: bool = True
    valid: bool = True
    canonical_key: str
    likelihood: int = Field(ge=1, le=5)
    impact: int = Field(ge=1, le=5)
    priority: Literal["Low", "Moderate", "High", "Critical"] = "Moderate"
    cloud_factors: CloudFactors
    notes: str = ""
    mitigations: list[str] = Field(default_factory=list)
    evidence: list[str] = Field(default_factory=list)


class ReferenceCatalog(BaseModel):
    valid_threat_ids: list[str]
    ai_specific_threat_ids: list[str]

    @model_validator(mode="after")
    def ai_subset_of_valid(self) -> "ReferenceCatalog":
        valid = set(self.valid_threat_ids)
        ai_specific = set(self.ai_specific_threat_ids)
        missing = ai_specific - valid
        if missing:
            raise ValueError(f"AI-specific reference ids must also be valid threat ids: {sorted(missing)}")
        return self


class AssessmentFile(BaseModel):
    study_id: str
    assessor: str
    reference: ReferenceCatalog
    threats: list[ThreatAssessment]

    @field_validator("threats")
    @classmethod
    def unique_threat_ids(cls, threats: list[ThreatAssessment]) -> list[ThreatAssessment]:
        ids = [item.threat_id for item in threats]
        if len(ids) != len(set(ids)):
            raise ValueError("Threat ids must be unique within an assessment file.")
        return threats

def load_scenario(path: str | Path) -> ScenarioModel:
    return ScenarioModel.model_validate(load_yaml(path))


def load_assessment(path: str | Path) -> AssessmentFile:
    return AssessmentFile.model_validate(load_yaml(path))


def validate_directory(directory: str | Path) -> tuple[list[str], list[str]]:
    directory = Path(directory)
    valid_paths: list[str] = []
    errors: list[str] = []

    for path in sorted(directory.glob("*.y*ml")):
        try:
            load_scenario(path)
        except (ValidationError, ValueError) as exc:
            errors.append(f"{path.name}: {exc}")
        else:
            valid_paths.append(path.name)

    return valid_paths, errors
