"""The structured-output contract every categorizer must satisfy.

Structured output, schema-validated. Invalid output triggers a bounded retry
and then falls through to ``unknown`` — there are no free-text-only
responses anywhere in the pipeline.

``is_likely_regression`` is deliberately separate from ``category``. A real
regression must never be silently absorbed into "flake", so it is reported
as its own field and gated on its own, and the eval harness measures the
false-regression rate against it.
"""

from __future__ import annotations

from typing import Any

#: Version stamped onto every analysis, so a report says which contract and
#: prompt produced it.
PROMPT_VERSION = "v1"

#: JSON schema handed to the model and enforced on the way back.
ANALYSIS_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "category": {
            "type": "string",
            "description": (
                "One of the taxonomy category names. Use 'unknown' rather than "
                "guessing when the evidence does not support a specific category."
            ),
        },
        "confidence": {
            "type": "number",
            "description": "0.0-1.0. Below the confidence gate the answer becomes 'unknown'.",
        },
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
            "description": (
                "Verbatim log lines that support the categorization, prefixed with their "
                "line number where known. Never paraphrase."
            ),
        },
        "explanation": {
            "type": "string",
            "description": "Plain English, one short paragraph, aimed at a maintainer.",
        },
        "suggested_mitigation": {
            "type": "string",
            "description": "What a maintainer should actually do about it.",
        },
        "is_likely_regression": {
            "type": "boolean",
            "description": (
                "True only if the evidence points at a genuine behaviour change in "
                "Podman itself. Reported separately from category so a regression is "
                "never absorbed into a flake bucket."
            ),
        },
    },
    "required": [
        "category",
        "confidence",
        "evidence",
        "explanation",
        "suggested_mitigation",
        "is_likely_regression",
    ],
    "additionalProperties": False,
}


class SchemaError(ValueError):
    """Raised when a categorizer returns output that violates the schema."""


def validate_analysis_payload(payload: Any, valid_categories: tuple[str, ...]) -> dict[str, Any]:
    """Validate and normalise a categorizer's structured output.

    Args:
        payload: The parsed JSON object returned by a provider.
        valid_categories: Category names from the loaded taxonomy.

    Returns:
        The payload with types coerced and fields normalised.

    Raises:
        SchemaError: If a required field is missing, mistyped, or names a
            category that is not in the taxonomy.
    """
    if not isinstance(payload, dict):
        raise SchemaError(f"expected a JSON object, got {type(payload).__name__}")

    missing = [field for field in ANALYSIS_SCHEMA["required"] if field not in payload]
    if missing:
        raise SchemaError(f"missing required field(s): {', '.join(missing)}")

    category = payload["category"]
    if not isinstance(category, str):
        raise SchemaError("'category' must be a string")
    if category not in valid_categories:
        raise SchemaError(
            f"category {category!r} is not in the taxonomy "
            f"({', '.join(valid_categories)})"
        )

    try:
        confidence = float(payload["confidence"])
    except (TypeError, ValueError) as exc:
        raise SchemaError("'confidence' must be a number") from exc
    if not 0.0 <= confidence <= 1.0:
        raise SchemaError(f"'confidence' must be between 0 and 1, got {confidence}")

    evidence = payload["evidence"]
    if not isinstance(evidence, list) or not all(isinstance(item, str) for item in evidence):
        raise SchemaError("'evidence' must be a list of strings")

    for field in ("explanation", "suggested_mitigation"):
        if not isinstance(payload[field], str):
            raise SchemaError(f"{field!r} must be a string")

    if not isinstance(payload["is_likely_regression"], bool):
        raise SchemaError("'is_likely_regression' must be a boolean")

    return {
        "category": category,
        "confidence": confidence,
        "evidence": evidence,
        "explanation": payload["explanation"].strip(),
        "suggested_mitigation": payload["suggested_mitigation"].strip(),
        "is_likely_regression": payload["is_likely_regression"],
    }
