"""Tests for the orchestrator's guardrails: cache, schema, regression guard, gate."""

from __future__ import annotations

import pytest

from flakectl.agent import Categorizer
from flakectl.detector import DetectionResult
from flakectl.fingerprint import fingerprint_failure
from flakectl.models import Failure, Verdict
from flakectl.providers.base import AnalysisRequest, ProviderError, ProviderResult
from flakectl.store import Store
from flakectl.tools import BudgetExceeded

GOOD_PAYLOAD = {
    "category": "network_timeout",
    "confidence": 0.9,
    "evidence": ["L4: dial tcp 10.88.0.14:39251: i/o timeout"],
    "explanation": "The socket never came up.",
    "suggested_mitigation": "Wait on readiness rather than elapsed time.",
    "is_likely_regression": False,
}


class FakeProvider:
    """Returns a scripted sequence of payloads, one per call."""

    name = "fake"

    def __init__(self, *payloads, raises: Exception | None = None) -> None:
        self.payloads = list(payloads)
        self.raises = raises
        self.calls = 0
        self.last_request: AnalysisRequest | None = None

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        self.calls += 1
        self.last_request = request
        if self.raises is not None:
            raise self.raises
        payload = self.payloads[min(self.calls - 1, len(self.payloads) - 1)]
        return ProviderResult(payload=payload, model="fake-model-1", tool_calls=2)


def failure(block: str = "[FAILED] Error: dial tcp: i/o timeout") -> Failure:
    return Failure(
        test_name="Podman run networking [It] --net=host",
        output_block=block,
        spec_file="test/e2e/run_networking_test.go",
        job="int podman fedora-41 root",
    )


def detection(verdict: Verdict = Verdict.UNKNOWN, **kwargs) -> DetectionResult:
    return DetectionResult(verdict=verdict, reason=kwargs.pop("reason", "no history"), **kwargs)


def categorize(categorizer: Categorizer, item: Failure, det: DetectionResult):
    fingerprint, signature = fingerprint_failure(item)
    return categorizer.categorize(item, fingerprint, signature, det)


def test_a_valid_answer_is_returned_with_provenance() -> None:
    provider = FakeProvider(GOOD_PAYLOAD)
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert analysis.category == "network_timeout"
    assert analysis.confidence == pytest.approx(0.9)
    assert analysis.provider == "fake"
    assert analysis.model == "fake-model-1"
    assert analysis.prompt_version == "v1"
    assert analysis.tool_calls == 2
    assert analysis.needs_human is False


def test_a_known_fingerprint_never_reaches_the_provider() -> None:
    """This is what makes model cost O(distinct flakes), not O(failures)."""
    provider = FakeProvider(GOOD_PAYLOAD)
    with Store() as store:
        categorizer = Categorizer(provider, store=store)
        first = failure()
        fingerprint, signature = fingerprint_failure(first)
        store.record_failure(first, fingerprint, signature)

        one = categorizer.categorize(first, fingerprint, signature, detection())
        two = categorizer.categorize(first, fingerprint, signature, detection())

    assert provider.calls == 1
    assert one.cached is False
    assert two.cached is True
    assert two.category == one.category


def test_cache_can_be_bypassed_for_reanalysis() -> None:
    provider = FakeProvider(GOOD_PAYLOAD)
    with Store() as store:
        categorizer = Categorizer(provider, store=store)
        item = failure()
        fingerprint, signature = fingerprint_failure(item)
        categorizer.categorize(item, fingerprint, signature, detection())
        categorizer.categorize(item, fingerprint, signature, detection(), use_cache=False)

    assert provider.calls == 2


def test_invalid_output_is_retried_once_then_abstains() -> None:
    provider = FakeProvider({"category": "network_timeout"}, {"category": "network_timeout"})
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert provider.calls == 2
    assert analysis.category == "unknown"
    assert analysis.needs_human is True
    assert "schema validation" in analysis.explanation


def test_a_retry_that_succeeds_is_used() -> None:
    provider = FakeProvider("not json at all", GOOD_PAYLOAD)
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert provider.calls == 2
    assert analysis.category == "network_timeout"


def test_a_category_outside_the_taxonomy_is_rejected() -> None:
    provider = FakeProvider({**GOOD_PAYLOAD, "category": "resource"})
    analysis = categorize(Categorizer(provider), failure(), detection())
    assert analysis.category == "unknown"


def test_low_confidence_becomes_an_abstention() -> None:
    provider = FakeProvider({**GOOD_PAYLOAD, "confidence": 0.4})
    analysis = categorize(Categorizer(provider, min_confidence=0.6), failure(), detection())

    assert analysis.category == "unknown"
    assert analysis.needs_human is True
    assert "below the 0.60 gate" in analysis.explanation


def test_confidence_exactly_at_the_gate_is_accepted() -> None:
    provider = FakeProvider({**GOOD_PAYLOAD, "confidence": 0.6})
    analysis = categorize(Categorizer(provider, min_confidence=0.6), failure(), detection())
    assert analysis.category == "network_timeout"


def test_a_regression_verdict_always_needs_a_human() -> None:
    provider = FakeProvider(
        {**GOOD_PAYLOAD, "category": "real_regression", "is_likely_regression": True}
    )
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert analysis.category == "real_regression"
    assert analysis.needs_human is True


def test_a_regression_claim_is_downgraded_when_a_rerun_passed() -> None:
    """Measured non-determinism beats an inferred regression."""
    provider = FakeProvider(
        {**GOOD_PAYLOAD, "category": "real_regression", "is_likely_regression": True}
    )
    confirmed = detection(
        Verdict.CONFIRMED_FLAKE, reason="failed on attempt 1 and passed on attempt 2"
    )
    analysis = categorize(Categorizer(provider), failure(), confirmed)

    assert analysis.category == "unknown"
    assert analysis.is_likely_regression is False
    assert analysis.needs_human is True
    assert "contradicts it" in analysis.explanation


def test_a_flake_category_survives_a_confirmed_flake_verdict() -> None:
    provider = FakeProvider(GOOD_PAYLOAD)
    confirmed = detection(Verdict.CONFIRMED_FLAKE, reason="passed on attempt 2")
    analysis = categorize(Categorizer(provider), failure(), confirmed)

    assert analysis.category == "network_timeout"
    assert analysis.needs_human is False


def test_a_provider_failure_becomes_an_abstention_not_a_crash() -> None:
    provider = FakeProvider(raises=ProviderError("no API key"))
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert analysis.category == "unknown"
    assert analysis.needs_human is True
    assert "could not answer" in analysis.explanation


def test_an_exhausted_budget_becomes_an_abstention_not_a_crash() -> None:
    provider = FakeProvider(raises=BudgetExceeded("context byte budget exhausted"))
    analysis = categorize(Categorizer(provider), failure(), detection())

    assert analysis.category == "unknown"
    assert "budget was exhausted" in analysis.explanation


def test_the_request_carries_the_rerun_evidence_to_the_provider() -> None:
    provider = FakeProvider(GOOD_PAYLOAD)
    confirmed = detection(Verdict.CONFIRMED_FLAKE, reason="passed on attempt 2 at abc123")
    categorize(Categorizer(provider), failure(), confirmed)

    context = provider.last_request.as_prompt_context()
    assert "verdict: confirmed_flake" in context
    assert "passed on attempt 2 at abc123" in context
    assert "run_networking_test.go" in context
