from __future__ import annotations

import pytest
from pydantic import ValidationError

from cargomesh.adapters.contracts import BrowserRecipe


def valid_recipe() -> dict[str, object]:
    return {
        "operation": "fetch",
        "capability": "shipment.track.read",
        "portal_signatures": [
            {
                "key": "heading",
                "locator": {"kind": "role", "role": "heading", "name": "Track shipment"},
                "expectation": {"mode": "equals", "value": "Track shipment"},
            }
        ],
        "actions": [
            {"kind": "navigate", "path": "/track"},
            {
                "kind": "fill",
                "locator": {"kind": "label", "value": "Booking reference"},
                "value": {
                    "source": "input",
                    "pointer": "/transaction/subject/carrier_booking_reference",
                },
            },
            {
                "kind": "extract_text",
                "locator": {"kind": "test_id", "value": "tracking-status"},
                "output_key": "tracking.status",
            },
        ],
    }


def test_recipe_accepts_only_bounded_semantic_actions() -> None:
    recipe = BrowserRecipe.model_validate(valid_recipe())
    assert recipe.operation == "fetch"
    assert recipe.actions[0].kind == "navigate"


@pytest.mark.parametrize(
    "action",
    [
        {"kind": "navigate", "path": "https://evil.example/"},
        {"kind": "navigate", "path": "/../admin"},
        {"kind": "evaluate", "script": "document.body.innerHTML"},
        {"kind": "click", "locator": {"kind": "css", "value": "#submit"}},
    ],
)
def test_recipe_rejects_absolute_traversal_and_unrestricted_actions(
    action: dict[str, object],
) -> None:
    payload = valid_recipe()
    payload["actions"] = [action, *list(payload["actions"])[1:]]
    with pytest.raises(ValidationError):
        BrowserRecipe.model_validate(payload)


def test_recipe_requires_navigation_first_unique_outputs_and_signature() -> None:
    payload = valid_recipe()
    payload["actions"] = list(payload["actions"])[1:]
    with pytest.raises(ValidationError, match="first browser action"):
        BrowserRecipe.model_validate(payload)

    payload = valid_recipe()
    payload["actions"] = [*list(payload["actions"]), list(payload["actions"])[-1]]
    with pytest.raises(ValidationError, match="output keys"):
        BrowserRecipe.model_validate(payload)

    payload = valid_recipe()
    payload["portal_signatures"] = []
    with pytest.raises(ValidationError, match="portal signature"):
        BrowserRecipe.model_validate(payload)
