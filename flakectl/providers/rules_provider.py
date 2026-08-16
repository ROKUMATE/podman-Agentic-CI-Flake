"""Offline provider: the deterministic ruleset plus the re-run verdict.

This is the default. It runs with no API key, no network and no model, and
it is what the ``--offline`` demo exercises end to end. It also sets the
floor the agent has to beat: the eval harness scores every provider against
the same labelled corpus, so "is the model actually worth it?" is a number
rather than an opinion.

Where the rules do not match, this provider abstains rather than guessing —
except when the re-run detector has already proved the failure reproduces
deterministically, which is itself evidence of a regression.
"""

from __future__ import annotations

from flakectl.models import Verdict
from flakectl.providers.base import AnalysisRequest, ProviderResult
from flakectl.rules import RuleEngine, default_rules

#: Confidence assigned when the re-run detector, not a rule, drives the call.
REPRODUCIBLE_FAILURE_CONFIDENCE = 0.7
#: Lowered when the same failure also occurs on main at the same base commit,
#: which means the change under test did not introduce it.
PRE_EXISTING_FAILURE_CONFIDENCE = 0.5
#: A confirmed flake with no matching rule: we know *that* it flakes, not why.
UNCLASSIFIED_FLAKE_CONFIDENCE = 0.4


class RulesProvider:
    """Categorize from maintainer-owned rules and deterministic signals."""

    name = "rules"

    def __init__(self, engine: RuleEngine | None = None) -> None:
        self.engine = engine or default_rules()

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        """Match the ruleset, falling back to the re-run verdict."""
        match = self.engine.match(request.failure.output_block)
        if match is not None:
            return ProviderResult(
                payload={
                    "category": match.rule.category,
                    "confidence": match.rule.confidence,
                    "evidence": list(match.evidence),
                    "explanation": (
                        f"Matched deterministic rule '{match.rule.id}', which classifies this "
                        f"signature as {match.rule.category}. {request.detection.reason.capitalize()}."
                    ),
                    "suggested_mitigation": match.rule.mitigation,
                    "is_likely_regression": request.taxonomy.get(match.rule.category).escalate,
                },
                model=None,
            )
        return ProviderResult(payload=self._from_detection(request), model=None)

    def _from_detection(self, request: AnalysisRequest) -> dict:
        """No rule matched — see whether the re-run evidence decides it."""
        detection = request.detection
        signature_line = [f"signature: {request.signature}"] if request.signature else []

        if detection.verdict is Verdict.REAL_FAILURE:
            pre_existing = detection.caused_by_change is False
            return {
                "category": "real_regression",
                "confidence": (
                    PRE_EXISTING_FAILURE_CONFIDENCE
                    if pre_existing
                    else REPRODUCIBLE_FAILURE_CONFIDENCE
                ),
                "evidence": signature_line + [f"re-run evidence: {detection.reason}"],
                "explanation": (
                    "No signature rule matched, and the failure reproduced on every attempt "
                    "at the same commit, which is the shape of a deterministic failure rather "
                    "than a flake."
                    + (
                        " It also fails on main at the same base commit, so it is pre-existing "
                        "rather than introduced by the change under test."
                        if pre_existing
                        else ""
                    )
                ),
                "suggested_mitigation": (
                    "Escalate to the area owner. Do not file as a flake and do not retry."
                ),
                "is_likely_regression": True,
            }

        if detection.verdict is Verdict.CONFIRMED_FLAKE:
            return {
                "category": "unknown",
                "confidence": UNCLASSIFIED_FLAKE_CONFIDENCE,
                "evidence": signature_line + [f"re-run evidence: {detection.reason}"],
                "explanation": (
                    "The re-run history proves this failure is non-deterministic, but no "
                    "signature rule matched, so which kind of flake it is remains unknown. "
                    "This is the case an agent is worth invoking on."
                ),
                "suggested_mitigation": (
                    "Route to the weekly digest for human triage, or re-run with a model-backed "
                    "provider. Add a rule once the class is understood."
                ),
                "is_likely_regression": False,
            }

        return {
            "category": "unknown",
            "confidence": 0.0,
            "evidence": signature_line,
            "explanation": (
                "No signature rule matched and there is no re-run history to decide flake "
                "versus real failure. Declining to guess."
            ),
            "suggested_mitigation": (
                "Re-run the job to obtain a second attempt, or analyse with a model-backed "
                "provider."
            ),
            "is_likely_regression": False,
        }
