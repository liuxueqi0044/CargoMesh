from pathlib import Path

from cargomesh.standards import compare_contracts, guard_tnt_query_model

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def test_compatibility_report_identifies_breaking_and_safe_changes() -> None:
    baseline = {
        "components": {
            "schemas": {
                "Event": {
                    "type": "object",
                    "required": ["eventType"],
                    "properties": {
                        "eventType": {"type": "string", "enum": ["SHIPMENT", "TRANSPORT"]}
                    },
                }
            }
        }
    }
    candidate = {
        "components": {
            "schemas": {
                "Event": {
                    "type": "object",
                    "required": ["eventType", "eventID"],
                    "properties": {
                        "eventType": {"type": "string", "enum": ["SHIPMENT", "EQUIPMENT"]},
                        "eventID": {"type": "string"},
                    },
                }
            }
        }
    }

    report = compare_contracts(baseline, candidate)

    assert report.breaking
    assert {change.kind.value for change in report.changes} >= {
        "ADDED",
        "ENUM_VALUE_ADDED",
        "ENUM_VALUE_REMOVED",
        "REQUIRED_ADDED",
    }


def test_pinned_tnt_query_and_model_surface_stay_in_lockstep() -> None:
    spec = PROJECT_ROOT / "third_party" / "dcsa" / "tnt" / "v2" / "tnt_v2.3.0.yaml"

    report = guard_tnt_query_model(spec)

    assert report.ok, report
