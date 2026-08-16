"""Pillar 3 — the categorization orchestrator.

The provider produces an answer; this module decides whether that answer is
allowed to stand. Four gates, in order:

1. **Cache.** A fingerprint that has been analysed before reuses its stored
   analysis and never reaches a model. This is what makes model cost
   O(distinct failure modes) rather than O(failures), and it is also what
   makes the output stable — the same flake gets the same explanation in
   week three that it got in week one.
2. **Schema.** Invalid structured output triggers one bounded retry, then
   falls through to ``unknown``. Never a free-text answer.
3. **Regression guard.** A regression claim contradicted by a passing
   re-run at the same commit is downgraded, because the re-run is
   deterministic evidence and the categorization is not.
4. **Confidence gate.** Below the threshold the answer becomes ``unknown``
   and is flagged for a human. Abstention is a first-class outcome.
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from flakectl.detector import DetectionResult
from flakectl.models import Analysis, Failure, Verdict
from flakectl.providers.base import AnalysisRequest, Provider, ProviderError
from flakectl.schema import PROMPT_VERSION, SchemaError, validate_analysis_payload
from flakectl.store import Store
from flakectl.taxonomy import Taxonomy, default_taxonomy
from flakectl.tools import BudgetExceeded, ToolLayer

#: Below this, an answer is replaced by an abstention.
DEFAULT_MIN_CONFIDENCE = 0.6

#: One retry on invalid output, then abstain.
MAX_SCHEMA_RETRIES = 1


@dataclass(slots=True)
class Categorizer:
    """Runs a provider under the pipeline's guardrails.

    Args:
        provider: The backend that produces categorizations.
        taxonomy: Categories to validate against. Defaults to the shipped one.
        store: Analysis cache. Without it, every failure reaches the provider.
        min_confidence: The abstention threshold.
    """

    provider: Provider
    taxonomy: Taxonomy | None = None
    store: Store | None = None
    min_confidence: float = DEFAULT_MIN_CONFIDENCE

    def __post_init__(self) -> None:
        if self.taxonomy is None:
            self.taxonomy = default_taxonomy()

    def categorize(
        self,
        failure: Failure,
        fingerprint: str,
        signature: str,
        detection: DetectionResult,
        tools: ToolLayer | None = None,
        *,
        use_cache: bool = True,
    ) -> Analysis:
        """Categorize one failure, or abstain.

        Args:
            failure: The failure to categorize.
            fingerprint: Its fingerprint, used as the cache key.
            signature: Its normalised error signature.
            detection: The re-run verdict, computed without a model.
            tools: Tool layer for providers that support tool calling.
            use_cache: Set false to force re-analysis of a known fingerprint.

        Returns:
            An :class:`~flakectl.models.Analysis`. Never raises for a bad
            answer — an unusable one becomes an abstention.
        """
        assert self.taxonomy is not None  # set in __post_init__

        if use_cache and self.store is not None:
            cached = self.store.get_analysis(fingerprint)
            if cached is not None:
                return cached

        request = AnalysisRequest(
            failure=failure,
            fingerprint=fingerprint,
            signature=signature,
            detection=detection,
            taxonomy=self.taxonomy,
            tools=tools,
        )
        analysis = self._ask(request)
        analysis = self._guard_regression(analysis, detection)
        analysis = self._apply_confidence_gate(analysis)

        if self.store is not None:
            self.store.put_analysis(fingerprint, analysis)
        return analysis

    # -- internals -------------------------------------------------------

    def _ask(self, request: AnalysisRequest) -> Analysis:
        """Call the provider, retrying once on invalid structured output."""
        assert self.taxonomy is not None
        last_error = ""
        for attempt in range(MAX_SCHEMA_RETRIES + 1):
            try:
                result = self.provider.analyze(request)
            except BudgetExceeded as exc:
                return self._abstain(
                    f"the analysis budget was exhausted before an answer was reached ({exc})"
                )
            except ProviderError as exc:
                return self._abstain(f"the {self.provider.name} provider could not answer ({exc})")

            try:
                payload = validate_analysis_payload(result.payload, self.taxonomy.names)
            except SchemaError as exc:
                last_error = str(exc)
                continue

            return Analysis(
                category=payload["category"],
                confidence=payload["confidence"],
                evidence=payload["evidence"],
                explanation=payload["explanation"],
                suggested_mitigation=payload["suggested_mitigation"],
                is_likely_regression=payload["is_likely_regression"],
                provider=self.provider.name,
                model=result.model,
                prompt_version=PROMPT_VERSION,
                rule_id=_rule_id_of(payload["evidence"], result),
                tool_calls=result.tool_calls,
            )

        return self._abstain(
            f"the categorizer returned output that failed schema validation "
            f"after {MAX_SCHEMA_RETRIES + 1} attempts ({last_error})"
        )

    def _guard_regression(self, analysis: Analysis, detection: DetectionResult) -> Analysis:
        """Never let a regression claim outrank a passing re-run.

        A test that failed and then passed at the same commit is
        non-deterministic by definition. That is measured evidence; the
        categorization is an inference. When they disagree, the evidence
        wins and the failure goes to a human.
        """
        if detection.verdict is not Verdict.CONFIRMED_FLAKE:
            return analysis
        if not analysis.is_likely_regression and analysis.category != "real_regression":
            return analysis
        return replace(
            analysis,
            category="unknown",
            is_likely_regression=False,
            confidence=min(analysis.confidence, self.min_confidence - 0.01),
            explanation=(
                f"{analysis.explanation} "
                "[flakectl: downgraded — the categorizer called this a regression, but the "
                f"re-run history contradicts it ({detection.reason}). Sent for human review "
                "rather than filed either way.]"
            ),
            needs_human=True,
        )

    def _apply_confidence_gate(self, analysis: Analysis) -> Analysis:
        """Turn a low-confidence answer into an abstention."""
        assert self.taxonomy is not None
        if analysis.confidence >= self.min_confidence:
            return replace(analysis, needs_human=self.taxonomy.get(analysis.category).escalate)
        return replace(
            analysis,
            category=self.taxonomy.abstain_category.name,
            needs_human=True,
            explanation=(
                f"{analysis.explanation} "
                f"[flakectl: confidence {analysis.confidence:.2f} is below the "
                f"{self.min_confidence:.2f} gate, so the answer is recorded as unknown and "
                "routed to a human.]"
            ),
        )

    def _abstain(self, reason: str) -> Analysis:
        """Build an abstention when no usable answer was produced."""
        assert self.taxonomy is not None
        return Analysis(
            category=self.taxonomy.abstain_category.name,
            confidence=0.0,
            evidence=[],
            explanation=f"No categorization was produced: {reason}.",
            suggested_mitigation=self.taxonomy.abstain_category.typical_mitigation,
            is_likely_regression=False,
            provider=self.provider.name,
            prompt_version=PROMPT_VERSION,
            needs_human=True,
        )


def _rule_id_of(evidence: list[str], result: object) -> str | None:
    """Recover a rule id when the offline provider produced the answer.

    Reports cite the rule so a maintainer can go and read it.
    """
    payload = getattr(result, "payload", None)
    if isinstance(payload, dict):
        explanation = payload.get("explanation", "")
        marker = "deterministic rule '"
        if marker in explanation:
            return explanation.split(marker, 1)[1].split("'", 1)[0]
    return None
