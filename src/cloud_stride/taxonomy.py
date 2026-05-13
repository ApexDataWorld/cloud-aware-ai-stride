from __future__ import annotations

STRIDE_CATEGORIES = (
    "Spoofing",
    "Tampering",
    "Repudiation",
    "Information Disclosure",
    "Denial of Service",
    "Elevation of Privilege",
)

AI_THREAT_TYPES = (
    "forged_mcp_server_identity",
    "impersonated_workload_identity",
    "indirect_prompt_injection",
    "retrieval_poisoning",
    "model_artifact_replacement",
    "missing_tool_call_audit_trail",
    "sensitive_context_leakage",
    "embedding_metadata_leakage",
    "model_resource_exhaustion",
    "retrieval_amplification",
    "excessive_agency",
    "confused_deputy_through_mcp_tool",
)

CLOUD_MODIFIER_NAMES = (
    "privilege_boundary",
    "blast_radius",
    "persistence",
    "detectability_penalty",
    "reversibility_penalty",
    "compliance_sensitivity",
)

ALLOWED_MITIGATION_CONTROLS = (
    "mcp_gateway_policy_enforcement_point",
    "oauth_oidc_identity_binding",
    "workload_identity_federation",
    "abac_authorization",
    "opa_rego_policy_evaluation",
    "tool_metadata_risk_tiering",
    "structured_audit_logging",
    "opentelemetry_traceability",
    "approval_gate",
    "rate_limit",
    "response_filtering",
    "fail_closed_high_risk_tools",
)


def validate_stride_category(category: str) -> bool:
    return category in STRIDE_CATEGORIES


def validate_ai_threat_type(threat_type: str) -> bool:
    return threat_type in AI_THREAT_TYPES


def validate_cloud_modifier_name(name: str) -> bool:
    return name in CLOUD_MODIFIER_NAMES


def validate_mitigation_control(control: str) -> bool:
    return control in ALLOWED_MITIGATION_CONTROLS
