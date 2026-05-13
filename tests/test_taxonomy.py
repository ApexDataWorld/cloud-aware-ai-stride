from cloud_stride.taxonomy import AI_THREAT_TYPES, STRIDE_CATEGORIES, validate_ai_threat_type, validate_stride_category


def test_valid_stride_categories():
    assert all(validate_stride_category(category) for category in STRIDE_CATEGORIES)


def test_threats_match_manuscript_taxonomy():
    required = {
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
    }
    assert required == set(AI_THREAT_TYPES)
    assert all(validate_ai_threat_type(threat) for threat in required)
