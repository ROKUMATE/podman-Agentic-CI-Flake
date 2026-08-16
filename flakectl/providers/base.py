"""The model-provider adapter boundary.

Every categorizer — the offline ruleset, a hosted Claude model, a local
model behind Ollama — implements this one interface. That boundary is the
point: swapping inference backends is a provider swap, not a rewrite, and
the orchestrator, the schema, the tool layer and the eval harness are all
shared.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

from flakectl.detector import DetectionResult
from flakectl.models import Failure
from flakectl.taxonomy import Taxonomy
from flakectl.tools import ToolLayer


class ProviderError(RuntimeError):
    """Raised when a provider cannot produce an answer at all.

    Distinct from a schema violation: this means the backend is missing,
    unreachable, or misconfigured, not that it answered badly.
    """


@dataclass(frozen=True, slots=True)
class AnalysisRequest:
    """Everything a categorizer is given about one failure."""

    failure: Failure
    fingerprint: str
    signature: str
    detection: DetectionResult
    taxonomy: Taxonomy
    tools: ToolLayer | None = None

    def as_prompt_context(self) -> str:
        """Render the failure record as text for a model prompt."""
        failure = self.failure
        lines = [
            "## Failing test",
            f"name: {failure.test_name}",
            f"suite: {failure.suite or 'unknown'}",
            f"spec: {failure.spec_file or 'unknown'}:{failure.spec_line or '?'}",
            f"job: {failure.job or 'unknown'}",
            f"os: {failure.os or 'unknown'}",
            f"exit code: {failure.exit_code if failure.exit_code is not None else 'unknown'}",
            "",
            "## Fingerprint",
            f"fingerprint: {self.fingerprint}",
            f"normalised signature: {self.signature}",
            "",
            "## Re-run evidence (deterministic, computed without a model)",
            f"verdict: {self.detection.verdict}",
            f"reason: {self.detection.reason}",
            "",
            "## Failure window (already sliced and byte-capped at ingestion)",
            failure.output_block,
        ]
        if failure.truncated:
            lines.append("\n[note: this window was truncated by the ingestion byte cap]")
        return "\n".join(lines)


@dataclass(frozen=True, slots=True)
class ProviderResult:
    """A provider's raw answer, before schema validation."""

    payload: Any
    model: str | None = None
    tool_calls: int = 0


@runtime_checkable
class Provider(Protocol):
    """A categorizer backend."""

    name: str

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        """Produce a structured categorization for one failure.

        Raises:
            ProviderError: If the backend is unavailable or misconfigured.
        """
        ...
