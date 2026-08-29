from pathlib import Path

import yaml

from cargomesh.standards import normalize_dcsa_references

PROJECT_ROOT = Path(__file__).resolve().parents[2]
VENDOR_ROOT = PROJECT_ROOT / "third_party" / "dcsa"
TNT_SPEC = VENDOR_ROOT / "tnt" / "v2" / "tnt_v2.3.0.yaml"


def test_supported_tnt_direct_references_normalize_to_existing_local_files() -> None:
    document = yaml.safe_load(TNT_SPEC.read_text(encoding="utf-8"))

    normalized = normalize_dcsa_references(
        document,
        document_path=TNT_SPEC,
        vendor_root=VENDOR_ROOT,
    )
    rendered = yaml.safe_dump(normalized)

    assert "api.swaggerhub.com/domains/dcsaorg" not in rendered
    assert "../../domain/event/event_domain_v2.0.0.yaml#/components/parameters" in rendered
    assert "../../domain/dcsa/dcsa_domain_v2.0.0.yaml#/components/parameters" in rendered
