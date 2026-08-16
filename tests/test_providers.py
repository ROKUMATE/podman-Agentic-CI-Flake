"""Tests for the provider adapters behind the shared interface.

None of these need an API key, a network, or a running Ollama server.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from flakectl.detector import DetectionResult
from flakectl.models import Failure, Verdict
from flakectl.providers import PROVIDER_NAMES, ProviderError, build_provider
from flakectl.providers.anthropic_provider import AnthropicProvider
from flakectl.providers.base import AnalysisRequest, Provider
from flakectl.providers.ollama_provider import OllamaProvider
from flakectl.providers.rules_provider import RulesProvider
from flakectl.schema import validate_analysis_payload
from flakectl.taxonomy import default_taxonomy
from flakectl.tools import ToolBudget, ToolLayer

TAXONOMY = default_taxonomy()

ANSWER = {
    "category": "race_timing",
    "confidence": 0.81,
    "evidence": ["L12: Timed out after 3.000s."],
    "explanation": "The spec polls with a fixed sleep.",
    "suggested_mitigation": "Use Eventually instead of time.Sleep.",
    "is_likely_regression": False,
}


def request(
    block: str = "[FAILED] Error: dial tcp 10.88.0.1:5000: i/o timeout",
    verdict: Verdict = Verdict.UNKNOWN,
    reason: str = "only 1 failing attempt with usable data",
    caused_by_change: bool | None = None,
    tools: ToolLayer | None = None,
) -> AnalysisRequest:
    return AnalysisRequest(
        failure=Failure(
            test_name="Podman run networking [It] --net=host",
            output_block=block,
            spec_file="test/e2e/run_networking_test.go",
            spec_line=431,
            job="int podman fedora-41 root",
        ),
        fingerprint="abc123def4567890",
        signature="Error: dial tcp <ip>:<port>: i/o timeout",
        detection=DetectionResult(
            verdict=verdict, reason=reason, caused_by_change=caused_by_change
        ),
        taxonomy=TAXONOMY,
        tools=tools,
    )


# -- shared contract ------------------------------------------------------


def test_every_named_provider_can_be_built() -> None:
    for name in PROVIDER_NAMES:
        assert isinstance(build_provider(name), Provider)


def test_unknown_provider_name_is_rejected() -> None:
    with pytest.raises(ProviderError, match="unknown provider"):
        build_provider("gpt")


def test_prompt_context_carries_the_whole_failure_record() -> None:
    context = request().as_prompt_context()
    assert "Podman run networking" in context
    assert "run_networking_test.go:431" in context
    assert "abc123def4567890" in context
    assert "i/o timeout" in context


def test_prompt_context_flags_a_truncated_window() -> None:
    item = request()
    truncated = AnalysisRequest(
        failure=Failure(test_name="t", output_block="boom", truncated=True),
        fingerprint=item.fingerprint,
        signature=item.signature,
        detection=item.detection,
        taxonomy=TAXONOMY,
    )
    assert "truncated by the ingestion byte cap" in truncated.as_prompt_context()


# -- rules provider (the offline default) ---------------------------------


def test_rules_provider_classifies_a_known_signature() -> None:
    result = RulesProvider().analyze(request())
    payload = validate_analysis_payload(result.payload, TAXONOMY.names)

    assert payload["category"] == "network_timeout"
    assert payload["confidence"] > 0.8
    assert payload["evidence"]
    assert "net-dial-timeout" in payload["explanation"]
    assert result.model is None  # no model was involved


def test_rules_provider_escalates_a_reproducible_failure_with_no_rule() -> None:
    result = RulesProvider().analyze(
        request(
            block="[FAILED] Expected 3 items, found 2",
            verdict=Verdict.REAL_FAILURE,
            reason="failed on all 2 attempts at the same commit abc123",
        )
    )
    payload = validate_analysis_payload(result.payload, TAXONOMY.names)

    assert payload["category"] == "real_regression"
    assert payload["is_likely_regression"] is True
    assert payload["confidence"] == pytest.approx(0.7)


def test_rules_provider_lowers_confidence_for_a_pre_existing_failure() -> None:
    """Also failing on main means the change under test is not the cause."""
    result = RulesProvider().analyze(
        request(
            block="[FAILED] Expected 3 items, found 2",
            verdict=Verdict.REAL_FAILURE,
            reason="failed on all 2 attempts; also fails on main",
            caused_by_change=False,
        )
    )
    payload = validate_analysis_payload(result.payload, TAXONOMY.names)

    assert payload["confidence"] == pytest.approx(0.5)
    assert "pre-existing" in payload["explanation"]


def test_rules_provider_abstains_on_an_unclassified_confirmed_flake() -> None:
    result = RulesProvider().analyze(
        request(
            block="[FAILED] Expected 3 items, found 2",
            verdict=Verdict.CONFIRMED_FLAKE,
            reason="failed on attempt 1 and passed on attempt 2",
        )
    )
    payload = validate_analysis_payload(result.payload, TAXONOMY.names)

    assert payload["category"] == "unknown"
    assert payload["is_likely_regression"] is False
    assert "agent is worth invoking" in payload["explanation"]


def test_rules_provider_abstains_with_no_rule_and_no_history() -> None:
    result = RulesProvider().analyze(request(block="[FAILED] Expected 3 items, found 2"))
    payload = validate_analysis_payload(result.payload, TAXONOMY.names)

    assert payload["category"] == "unknown"
    assert payload["confidence"] == 0.0


def test_rules_provider_output_always_validates() -> None:
    """Whatever the input, the offline path emits schema-valid output."""
    for verdict in Verdict:
        for block in ("toomanyrequests: Rate exceeded", "something entirely unrecognised"):
            result = RulesProvider().analyze(request(block=block, verdict=verdict))
            validate_analysis_payload(result.payload, TAXONOMY.names)


# -- anthropic provider (stubbed client, no network) ----------------------


class StubBlock:
    def __init__(self, **kwargs: Any) -> None:
        self.__dict__.update(kwargs)


class StubResponse:
    def __init__(self, content: list[Any], stop_reason: str = "end_turn") -> None:
        self.content = content
        self.stop_reason = stop_reason
        self.model = "claude-opus-5"
        self.stop_details = None


class StubMessages:
    """Replays scripted responses and records the requests it received."""

    def __init__(self, responses: list[StubResponse]) -> None:
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    def create(self, **kwargs: Any) -> StubResponse:
        self.requests.append(kwargs)
        return self.responses[min(len(self.requests) - 1, len(self.responses) - 1)]


class StubClient:
    def __init__(self, responses: list[StubResponse]) -> None:
        self.messages = StubMessages(responses)


def text_response(payload: dict[str, Any]) -> StubResponse:
    return StubResponse([StubBlock(type="text", text=json.dumps(payload))])


def tool_response(name: str, arguments: dict[str, Any]) -> StubResponse:
    return StubResponse(
        [StubBlock(type="tool_use", id="toolu_1", name=name, input=arguments)],
        stop_reason="tool_use",
    )


def test_anthropic_provider_returns_the_models_structured_answer() -> None:
    client = StubClient([text_response(ANSWER)])
    result = AnthropicProvider(client=client).analyze(request())

    assert validate_analysis_payload(result.payload, TAXONOMY.names)["category"] == "race_timing"
    assert result.model == "claude-opus-5"
    assert result.tool_calls == 0


def test_anthropic_provider_sends_the_taxonomy_and_schema() -> None:
    client = StubClient([text_response(ANSWER)])
    AnthropicProvider(client=client).analyze(request())

    sent = client.messages.requests[0]
    assert "race_timing" in sent["system"]
    assert "Prefer `unknown` over a guess" in sent["system"]
    schema = sent["output_config"]["format"]["schema"]
    assert schema["properties"]["category"]["enum"] == list(TAXONOMY.names)
    assert {tool["name"] for tool in sent["tools"]} == {
        definition["name"] for definition in ToolLayer.definitions()
    }
    # Sampling parameters are not accepted on this model family.
    assert "temperature" not in sent and "top_p" not in sent


def test_anthropic_provider_runs_the_tool_loop(tmp_path) -> None:
    source = tmp_path / "test" / "e2e"
    source.mkdir(parents=True)
    (source / "run_networking_test.go").write_text(
        "\n".join(f"line {i}" for i in range(1, 60)), encoding="utf-8"
    )
    tools = ToolLayer(budget=ToolBudget(), source_root=tmp_path)
    client = StubClient(
        [
            tool_response("get_test_source", {"spec_file": "run_networking_test.go", "line": 30}),
            text_response(ANSWER),
        ]
    )

    result = AnthropicProvider(client=client).analyze(request(tools=tools))

    assert result.tool_calls == 1
    assert tools.budget.calls_used == 1
    followup = client.messages.requests[1]["messages"][-1]["content"][0]
    assert followup["type"] == "tool_result"
    assert followup["is_error"] is False
    assert "line 30" in followup["content"]


def test_anthropic_provider_reports_an_exhausted_budget_to_the_model() -> None:
    tools = ToolLayer(budget=ToolBudget(max_calls=0))
    client = StubClient(
        [tool_response("search_issues", {"query": "pasta"}), text_response(ANSWER)]
    )

    AnthropicProvider(client=client).analyze(request(tools=tools))

    messages = client.messages.requests[1]["messages"]
    assert messages[-2]["content"][0]["is_error"] is True
    assert "budget exceeded" in messages[-2]["content"][0]["content"]
    assert "Answer now" in messages[-1]["content"]


def test_anthropic_provider_reports_an_unknown_tool_as_a_tool_error() -> None:
    client = StubClient([tool_response("rm_rf", {}), text_response(ANSWER)])
    AnthropicProvider(client=client).analyze(request(tools=ToolLayer()))

    result_block = client.messages.requests[1]["messages"][-1]["content"][0]
    assert result_block["is_error"] is True
    assert "unknown tool" in result_block["content"]


def test_anthropic_provider_raises_on_a_refusal() -> None:
    client = StubClient([StubResponse([], stop_reason="refusal")])
    with pytest.raises(ProviderError, match="declined"):
        AnthropicProvider(client=client).analyze(request())


def test_anthropic_provider_gives_up_after_max_turns() -> None:
    client = StubClient([tool_response("search_issues", {"query": "x"})])
    with pytest.raises(ProviderError, match="no final answer"):
        AnthropicProvider(client=client, max_turns=2).analyze(
            request(tools=ToolLayer(budget=ToolBudget(max_calls=10)))
        )


def test_anthropic_provider_returns_raw_text_when_the_answer_is_not_json() -> None:
    """The orchestrator's schema retry handles this; the provider must not crash."""
    client = StubClient([StubResponse([StubBlock(type="text", text="I think it's flaky")])])
    result = AnthropicProvider(client=client).analyze(request())
    assert result.payload == "I think it's flaky"


def test_anthropic_provider_without_the_sdk_reports_clearly(monkeypatch) -> None:
    import builtins

    real_import = builtins.__import__

    def fail_on_anthropic(name, *args, **kwargs):
        if name == "anthropic":
            raise ImportError("No module named 'anthropic'")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", fail_on_anthropic)
    with pytest.raises(ProviderError, match="offline provider"):
        _ = AnthropicProvider().client


# -- ollama provider (mocked transport, no server) ------------------------


def test_ollama_provider_parses_a_local_models_answer() -> None:
    captured: dict[str, Any] = {}

    def transport(url: str, body: dict[str, Any]) -> dict[str, Any]:
        captured["url"] = url
        captured["body"] = body
        return {"model": "llama3.1", "message": {"content": json.dumps(ANSWER)}}

    result = OllamaProvider(transport=transport).analyze(request())

    assert validate_analysis_payload(result.payload, TAXONOMY.names)["category"] == "race_timing"
    assert result.model == "llama3.1"
    assert captured["url"].endswith("/api/chat")
    assert captured["body"]["stream"] is False
    assert captured["body"]["format"]["properties"]["category"]["enum"] == list(TAXONOMY.names)
    assert "race_timing" in captured["body"]["messages"][0]["content"]


def test_ollama_provider_returns_raw_text_when_the_answer_is_not_json() -> None:
    def transport(url: str, body: dict[str, Any]) -> dict[str, Any]:
        return {"message": {"content": "probably a flake"}}

    assert OllamaProvider(transport=transport).analyze(request()).payload == "probably a flake"


def test_ollama_provider_rejects_an_unexpected_response_shape() -> None:
    def transport(url: str, body: dict[str, Any]) -> dict[str, Any]:
        return {"error": "model not found"}

    with pytest.raises(ProviderError, match="unexpected response shape"):
        OllamaProvider(transport=transport).analyze(request())
