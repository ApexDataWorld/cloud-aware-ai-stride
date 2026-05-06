from __future__ import annotations

from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .yamlio import load_yaml


class TaxonomyBundle(BaseModel):
    taxonomy: dict[str, Any]
    owasp_llm_mapping: dict[str, Any]
    nist_ai_rmf_mapping: dict[str, Any]
    mitre_atlas_mapping: dict[str, Any]

def load_taxonomy_bundle(root: str | Path | None = None) -> TaxonomyBundle:
    repo_root = Path(root) if root is not None else Path(__file__).resolve().parent.parent
    taxonomy_dir = repo_root / "taxonomy"
    return TaxonomyBundle(
        taxonomy=load_yaml(taxonomy_dir / "cloud_aware_stride_taxonomy.yaml"),
        owasp_llm_mapping=load_yaml(taxonomy_dir / "owasp_llm_mapping.yaml"),
        nist_ai_rmf_mapping=load_yaml(taxonomy_dir / "nist_ai_rmf_mapping.yaml"),
        mitre_atlas_mapping=load_yaml(taxonomy_dir / "mitre_atlas_mapping.yaml"),
    )
