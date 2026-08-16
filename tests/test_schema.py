"""Tests for the structured-output contract."""

from __future__ import annotations

import pytest

from flakectl.schema import ANALYSIS_SCHEMA, SchemaError, validate_analysis_payload
from flakectl.taxonomy import default_taxonomy

CATEGORIES = default_taxonomy().names

VALID = {
    "category": "infrastructure",
    "confidence": 0.93,
    "evidence": ["L7: toomanyrequests: Rate exceeded"],
    "explanation": "  Registry rate limiting.  ",
    "suggested_mitigation": "  Retry with backoff.  ",
    "is_likely_regression": False,
}


def test_a_valid_payload_is_normalised() -> None:
    result = validate_analysis_payload(VALID, CATEGORIES)
    assert result["explanation"] == "Registry rate limiting."
    assert result["suggested_mitigation"] == "Retry with backoff."
    assert result["confidence"] == pytest.approx(0.93)


def test_integer_confidence_is_coerced() -> None:
    assert validate_analysis_payload({**VALID, "confidence": 1}, CATEGORIES)["confidence"] == 1.0


@pytest.mark.parametrize("field", ANALYSIS_SCHEMA["required"])
def test_every_required_field_is_enforced(field: str) -> None:
    payload = {key: value for key, value in VALID.items() if key != field}
    with pytest.raises(SchemaError, match="missing required field"):
        validate_analysis_payload(payload, CATEGORIES)


@pytest.mark.parametrize(
    ("payload", "message"),
    [
        ({"category": 7}, "'category' must be a string"),
        ({"category": "resource"}, "not in the taxonomy"),
        ({"confidence": "high"}, "must be a number"),
        ({"confidence": 1.4}, "between 0 and 1"),
        ({"confidence": -0.1}, "between 0 and 1"),
        ({"evidence": "one line"}, "must be a list of strings"),
        ({"evidence": [1, 2]}, "must be a list of strings"),
        ({"explanation": None}, "must be a string"),
        ({"suggested_mitigation": []}, "must be a string"),
        ({"is_likely_regression": "yes"}, "must be a boolean"),
    ],
)
def test_bad_field_values_are_rejected(payload: dict, message: str) -> None:
    with pytest.raises(SchemaError, match=message):
        validate_analysis_payload({**VALID, **payload}, CATEGORIES)


def test_a_non_object_payload_is_rejected() -> None:
    with pytest.raises(SchemaError, match="expected a JSON object"):
        validate_analysis_payload("probably a flake", CATEGORIES)


def test_schema_is_strict_enough_for_structured_outputs() -> None:
    """Structured outputs require additionalProperties:false and required."""
    assert ANALYSIS_SCHEMA["additionalProperties"] is False
    assert set(ANALYSIS_SCHEMA["required"]) == set(ANALYSIS_SCHEMA["properties"])
