"""Tests for the Gemini adapter. Mocked transport: no network, no key."""

from __future__ import annotations

import json
from typing import Any

import pytest

from flakectl.detector import DetectionResult
from flakectl.models import Failure, Verdict
from flakectl.providers import PROVIDER_NAMES, build_provider
from flakectl.providers.base import AnalysisRequest, ProviderError
from flakectl.providers.gemini_provider import (
    KEY_VARIABLES,
    GeminiProvider,
    to_gemini_schema,
)
from flakectl.schema import validate_analysis_payload
from flakectl.taxonomy import default_taxonomy
from flakectl.tools import ToolBudget, ToolLayer

TAXONOMY = default_taxonomy()

ANSWER = {
    "category": "race_timing",
    "confidence": 0.95,
    "evidence": ["[FAILED] Timed out after 3.000s."],
    "explanation": "The healthcheck had not converged.",
    "suggested_mitigation": "Use Eventually instead of a fixed sleep.",
    "is_likely_regression": False,
}


def request(tools: ToolLayer | None = None) -> AnalysisRequest:
    return AnalysisRequest(
        failure=Failure(
            test_name="Podman healthcheck run [It] podman healthcheck run that succeeds",
            output_block="[FAILED] Timed out after 3.000s.",
            spec_file="test/e2e/healthcheck_run_test.go",
        ),
        fingerprint="6a1cfc950ff997af",
        signature="[FAILED] Timed out after <dur>.",
        detection=DetectionResult(verdict=Verdict.CONFIRMED_FLAKE, reason="passed on attempt 2"),
        taxonomy=TAXONOMY,
        tools=tools,
    )


def text_reply(payload: Any, finish: str = "STOP") -> dict[str, Any]:
    body = payload if isinstance(payload, str) else json.dumps(payload)
    return {
        "modelVersion": "gemini-3.6-flash",
        "candidates": [{"finishReason": finish, "content": {"parts": [{"text": body}]}}],
    }


def call_reply(name: str, args: dict[str, Any]) -> dict[str, Any]:
    return {
        "modelVersion": "gemini-3.6-flash",
        "candidates": [
            {"content": {"parts": [{"functionCall": {"name": name, "args": args}}]}}
        ],
    }


class Recorder:
    """Replays scripted responses and records every request body."""

    def __init__(self, *replies: dict[str, Any]) -> None:
        self.replies = list(replies)
        self.bodies: list[dict[str, Any]] = []
        self.headers: list[dict[str, str]] = []
        self.urls: list[str] = []

    def __call__(self, url: str, headers: dict[str, str], body: dict[str, Any]):
        self.urls.append(url)
        self.headers.append(headers)
        self.bodies.append(body)
        return self.replies[min(len(self.bodies) - 1, len(self.replies) - 1)]


# -- registration ---------------------------------------------------------


def test_gemini_is_a_registered_provider() -> None:
    assert "gemini" in PROVIDER_NAMES
    assert build_provider("gemini", api_key="x").name == "gemini"


# -- schema conversion ----------------------------------------------------


def test_unsupported_schema_keywords_are_stripped() -> None:
    """Gemini takes an OpenAPI subset and 400s on additionalProperties."""
    converted = to_gemini_schema(
        {
            "type": "object",
            "additionalProperties": False,
            "properties": {
                "nested": {"type": "object", "additionalProperties": False},
                "list": {"type": "array", "items": {"additionalProperties": False}},
            },
        }
    )
    assert "additionalProperties" not in json.dumps(converted)
    assert converted["properties"]["nested"]["type"] == "object"


def test_schema_conversion_keeps_everything_else() -> None:
    converted = to_gemini_schema(
        {"type": "string", "enum": ["a", "b"], "description": "keep me"}
    )
    assert converted == {"type": "string", "enum": ["a", "b"], "description": "keep me"}


# -- single-shot mode -----------------------------------------------------


def test_single_shot_uses_a_response_schema_and_no_tools() -> None:
    recorder = Recorder(text_reply(ANSWER))
    result = GeminiProvider(api_key="k", transport=recorder, use_tools=False).analyze(request())

    assert validate_analysis_payload(result.payload, TAXONOMY.names)["category"] == "race_timing"
    assert result.model == "gemini-3.6-flash"

    body = recorder.bodies[0]
    assert "tools" not in body
    schema = body["generationConfig"]["responseSchema"]
    assert schema["properties"]["category"]["enum"] == list(TAXONOMY.names)
    assert "additionalProperties" not in json.dumps(schema)


def test_the_key_is_sent_as_a_header_and_the_model_in_the_url() -> None:
    recorder = Recorder(text_reply(ANSWER))
    GeminiProvider(api_key="secret-key", transport=recorder).analyze(request())

    assert recorder.headers[0]["x-goog-api-key"] == "secret-key"
    assert recorder.urls[0].endswith("/gemini-3.6-flash:generateContent")


def test_a_markdown_fenced_answer_is_still_parsed() -> None:
    recorder = Recorder(text_reply(f"```json\n{json.dumps(ANSWER)}\n```"))
    result = GeminiProvider(api_key="k", transport=recorder).analyze(request())
    assert validate_analysis_payload(result.payload, TAXONOMY.names)["category"] == "race_timing"


def test_non_json_output_is_returned_raw_for_the_orchestrator_to_retry() -> None:
    recorder = Recorder(text_reply("probably a flake"))
    assert GeminiProvider(api_key="k", transport=recorder).analyze(request()).payload == (
        "probably a flake"
    )


# -- function-calling loop ------------------------------------------------


def test_the_tool_loop_runs_and_charges_the_budget(tmp_path) -> None:
    source = tmp_path / "test" / "e2e"
    source.mkdir(parents=True)
    (source / "healthcheck_run_test.go").write_text(
        "\n".join(f"line {i}" for i in range(1, 80)), encoding="utf-8"
    )
    tools = ToolLayer(budget=ToolBudget(), source_root=tmp_path)
    recorder = Recorder(
        call_reply("get_test_source", {"spec_file": "healthcheck_run_test.go", "line": 40}),
        text_reply(ANSWER),
    )

    result = GeminiProvider(api_key="k", transport=recorder).analyze(request(tools))

    assert result.tool_calls == 1
    assert tools.budget.calls_used == 1
    # The model turn is echoed back, then the function response.
    assert recorder.bodies[1]["contents"][1]["role"] == "model"
    response_part = recorder.bodies[1]["contents"][2]["parts"][0]["functionResponse"]
    assert response_part["name"] == "get_test_source"
    assert "line 40" in response_part["response"]["result"]


def test_tool_declarations_are_converted_for_gemini() -> None:
    recorder = Recorder(text_reply(ANSWER))
    GeminiProvider(api_key="k", transport=recorder).analyze(request(ToolLayer()))

    declarations = recorder.bodies[0]["tools"][0]["function_declarations"]
    assert {d["name"] for d in declarations} == {
        "get_log_slice",
        "get_test_source",
        "search_history",
        "search_issues",
        "recent_changes",
    }
    assert all("parameters" in d and d["description"] for d in declarations)


def test_a_spent_budget_is_reported_back_as_a_function_error() -> None:
    tools = ToolLayer(budget=ToolBudget(max_calls=0))
    recorder = Recorder(call_reply("search_issues", {"query": "pasta"}), text_reply(ANSWER))

    GeminiProvider(api_key="k", transport=recorder).analyze(request(tools))

    payload = recorder.bodies[1]["contents"][2]["parts"][0]["functionResponse"]["response"]
    assert "budget exceeded" in payload["error"]
    assert "Answer now" in recorder.bodies[1]["contents"][3]["parts"][0]["text"]


def test_an_unknown_tool_is_reported_as_a_function_error() -> None:
    recorder = Recorder(call_reply("rm_rf", {}), text_reply(ANSWER))
    GeminiProvider(api_key="k", transport=recorder).analyze(request(ToolLayer()))

    payload = recorder.bodies[1]["contents"][2]["parts"][0]["functionResponse"]["response"]
    assert "unknown tool" in payload["error"]


def test_the_loop_gives_up_after_max_turns() -> None:
    recorder = Recorder(call_reply("search_issues", {"query": "x"}))
    with pytest.raises(ProviderError, match="no final answer"):
        GeminiProvider(api_key="k", transport=recorder, max_turns=2).analyze(
            request(ToolLayer(budget=ToolBudget(max_calls=10)))
        )


# -- error handling -------------------------------------------------------


def test_an_api_error_object_is_surfaced() -> None:
    recorder = Recorder({"error": {"code": 429, "message": "quota exceeded"}})
    with pytest.raises(ProviderError, match="quota exceeded"):
        GeminiProvider(api_key="k", transport=recorder).analyze(request())


def test_a_safety_finish_reason_is_treated_as_a_refusal() -> None:
    recorder = Recorder(text_reply(ANSWER, finish="SAFETY"))
    with pytest.raises(ProviderError, match="declined"):
        GeminiProvider(api_key="k", transport=recorder).analyze(request())


def test_a_blocked_prompt_is_surfaced() -> None:
    recorder = Recorder({"promptFeedback": {"blockReason": "OTHER"}, "candidates": []})
    with pytest.raises(ProviderError, match="blockReason=OTHER"):
        GeminiProvider(api_key="k", transport=recorder).analyze(request())


# -- credentials ----------------------------------------------------------


def test_a_missing_key_names_the_offline_alternative(monkeypatch) -> None:
    for name in KEY_VARIABLES:
        monkeypatch.delenv(name, raising=False)
    with pytest.raises(ProviderError, match="offline provider"):
        _ = GeminiProvider().api_key


def test_the_key_is_read_from_the_environment(monkeypatch) -> None:
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.setenv("GOOGLE_API_KEY", "from-env")
    assert GeminiProvider().api_key == "from-env"
    assert GeminiProvider.credentials_available() is True
