"""Shared data types.

These are the records that flow through the pipeline:
ingest -> fingerprint -> detect -> categorize -> report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Verdict(StrEnum):
    """Output of the re-run detector: is this failure non-deterministic?

    This is the flake/real-failure call, and it is made *without* a model
    wherever re-run history is available.
    """

    CONFIRMED_FLAKE = "confirmed_flake"
    REAL_FAILURE = "real_failure"
    UNKNOWN = "unknown"


@dataclass(frozen=True, slots=True)
class Failure:
    """One failing test, sliced down to its failure window.

    ``job`` and ``os`` are ingestion metadata rather than log content: in
    production they come from the GitHub Actions API (``/runs/{id}/jobs``),
    and in this proof-of-concept they come from the history file or a CLI
    flag. The parser leaves them unset.
    """

    test_name: str
    output_block: str
    status: str = "failed"
    suite: str | None = None
    spec_file: str | None = None
    spec_line: int | None = None
    exit_code: int | None = None
    job: str | None = None
    os: str | None = None
    source_format: str = "generic"
    truncated: bool = False

    @property
    def identity(self) -> str:
        """Stable test identity, used as one half of the fingerprint input."""
        if self.spec_file:
            return f"{self.spec_file}::{self.test_name}"
        return self.test_name


@dataclass(frozen=True, slots=True)
class Analysis:
    """A categorization of one failure, from rules or from the agent.

    Field names follow the proposal's structured-output schema. In
    particular ``is_likely_regression`` is a distinct output from
    ``category``: a real regression must never be silently absorbed into
    "flake", so it is reported separately and gated separately.
    """

    category: str
    confidence: float
    evidence: list[str]
    explanation: str
    suggested_mitigation: str
    is_likely_regression: bool
    provider: str
    model: str | None = None
    prompt_version: str | None = None
    rule_id: str | None = None
    needs_human: bool = False
    tool_calls: int = 0
    cached: bool = False


@dataclass(frozen=True, slots=True)
class Occurrence:
    """How often one fingerprint has been seen, and where.

    ``is_new`` is called out separately because a brand-new signature
    usually means something changed recently, which makes it the most
    actionable line on a weekly report.
    """

    fingerprint: str
    signature: str
    test_identity: str
    count: int
    first_seen: str
    last_seen: str
    jobs: tuple[str, ...] = ()
    oses: tuple[str, ...] = ()
    is_new: bool = False


@dataclass(slots=True)
class TriagedFailure:
    """A failure after the full pipeline has run over it."""

    failure: Failure
    fingerprint: str
    signature: str
    verdict: Verdict
    analysis: Analysis
    occurrences: int = 1
    first_seen: str | None = None
    last_seen: str | None = None
    is_new_signature: bool = True
    notes: list[str] = field(default_factory=list)
