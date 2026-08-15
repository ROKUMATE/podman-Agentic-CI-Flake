"""The pipeline: ingest -> fingerprint -> detect -> categorize -> report.

One function wires the four pillars together in the order the proposal
describes, so the CLI and the eval harness drive the same code path rather
than two similar ones.

The ordering matters and is not arbitrary. Fingerprinting happens *before*
categorization so a known signature can short-circuit to its cached
analysis; re-run detection happens before categorization so the categorizer
is handed deterministic evidence rather than asked to infer it.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path

from flakectl.agent import DEFAULT_MIN_CONFIDENCE, Categorizer
from flakectl.detector import RerunHistory, Run, detect
from flakectl.fingerprint import fingerprint_failure
from flakectl.junit import parse_junit_file
from flakectl.models import Failure, TriagedFailure
from flakectl.parser import DEFAULT_BYTE_CAP, parse_log_file
from flakectl.providers import build_provider
from flakectl.schema import PROMPT_VERSION
from flakectl.store import MEMORY, Store
from flakectl.taxonomy import Taxonomy, default_taxonomy
from flakectl.tools import ToolBudget, ToolLayer


@dataclass(slots=True)
class Report:
    """Everything one ``analyze`` run produced.

    Carries its own provenance — provider, model, prompt version — because
    every artifact this tool emits has to say what generated it.
    """

    generated_at: str
    provider: str
    model: str | None
    prompt_version: str
    triaged: list[TriagedFailure] = field(default_factory=list)
    sources: list[str] = field(default_factory=list)
    distinct_fingerprints: int = 0
    cached_analyses: int = 0

    @property
    def total_failures(self) -> int:
        return len(self.triaged)

    @property
    def needs_human(self) -> list[TriagedFailure]:
        """Failures the tool declined to decide, or escalated."""
        return [item for item in self.triaged if item.analysis.needs_human]

    @property
    def likely_regressions(self) -> list[TriagedFailure]:
        return [item for item in self.triaged if item.analysis.is_likely_regression]

    @property
    def dedup_ratio(self) -> float:
        """Failures per distinct fingerprint.

        The factor by which fingerprinting reduces model spend.
        """
        if not self.distinct_fingerprints:
            return 0.0
        return self.total_failures / self.distinct_fingerprints


@dataclass(slots=True)
class PipelineConfig:
    """Knobs for one analysis run."""

    provider_name: str = "rules"
    model: str | None = None
    min_confidence: float = DEFAULT_MIN_CONFIDENCE
    byte_cap: int = DEFAULT_BYTE_CAP
    db_path: str = MEMORY
    source_root: Path | None = None
    budget: ToolBudget = field(default_factory=ToolBudget)
    taxonomy: Taxonomy | None = None


def ingest(
    log_paths: list[str] | None = None,
    junit_paths: list[str] | None = None,
    *,
    byte_cap: int = DEFAULT_BYTE_CAP,
    history: RerunHistory | None = None,
) -> list[tuple[Failure, Run | None, str]]:
    """Pillar 1 — read logs and artifacts into structured failure records.

    Args:
        log_paths: Raw CI logs (fallback ingestion path).
        junit_paths: JUnit/Ginkgo XML reports (preferred path).
        byte_cap: Hard cap on each failure's output block.
        history: Supplies each log's job/OS metadata, as the Actions API
            would in production.

    Returns:
        ``(failure, run, source_path)`` triples, in the order read.
    """
    records: list[tuple[Failure, Run | None, str]] = []

    for path in junit_paths or []:
        for failure in parse_junit_file(path, byte_cap=byte_cap):
            run = history.run_for_log(Path(path).name) if history else None
            records.append((failure, run, path))

    for path in log_paths or []:
        run = history.run_for_log(Path(path).name) if history else None
        job = run.job if run else None
        operating_system = run.os if run else None
        for failure in parse_log_file(path, byte_cap=byte_cap, job=job, os=operating_system):
            records.append((failure, run, path))

    return records


def analyze(
    log_paths: list[str] | None = None,
    junit_paths: list[str] | None = None,
    *,
    history: RerunHistory | None = None,
    config: PipelineConfig | None = None,
    store: Store | None = None,
) -> Report:
    """Run the full pipeline over a set of logs and artifacts.

    Args:
        log_paths: Raw CI logs.
        junit_paths: JUnit XML reports.
        history: Re-run history for the deterministic flake call.
        config: Provider, thresholds and budgets.
        store: An open store. One is opened from ``config.db_path`` if omitted.

    Returns:
        A :class:`Report` covering every failure found.
    """
    config = config or PipelineConfig()
    taxonomy = config.taxonomy or default_taxonomy()
    owns_store = store is None
    store = store or Store(config.db_path)

    provider_kwargs = {"model": config.model} if config.model else {}
    provider = build_provider(config.provider_name, **provider_kwargs)
    categorizer = Categorizer(
        provider=provider,
        taxonomy=taxonomy,
        store=store,
        min_confidence=config.min_confidence,
    )

    report = Report(
        generated_at=datetime.now(UTC).isoformat(timespec="seconds"),
        provider=provider.name,
        model=config.model,
        prompt_version=PROMPT_VERSION,
    )

    try:
        records = ingest(
            log_paths, junit_paths, byte_cap=config.byte_cap, history=history
        )
        report.sources = sorted({source for _, _, source in records})

        for failure, run, source in records:
            fingerprint, signature = fingerprint_failure(failure)
            occurrence = store.record_failure(failure, fingerprint, signature)
            detection = detect(failure, history, run)

            tools = ToolLayer(
                budget=ToolBudget(
                    max_calls=config.budget.max_calls,
                    max_total_bytes=config.budget.max_total_bytes,
                    max_lines_per_call=config.budget.max_lines_per_call,
                ),
                logs=_retained_log(source),
                source_root=config.source_root,
                store=store,
            )

            analysis = categorizer.categorize(
                failure, fingerprint, signature, detection, tools
            )
            if analysis.cached:
                report.cached_analyses += 1

            report.triaged.append(
                TriagedFailure(
                    failure=failure,
                    fingerprint=fingerprint,
                    signature=signature,
                    verdict=detection.verdict,
                    analysis=analysis,
                    occurrences=occurrence.count,
                    first_seen=occurrence.first_seen,
                    last_seen=occurrence.last_seen,
                    is_new_signature=occurrence.is_new,
                    notes=[detection.reason],
                )
            )

        report.distinct_fingerprints = len({item.fingerprint for item in report.triaged})
        return report
    finally:
        if owns_store:
            store.close()


def _retained_log(source: str) -> dict[str, str]:
    """Keep the full log available to ``get_log_slice`` for this analysis.

    Ingestion caps the *record*; the agent can still ask for more of the
    retained log, within its byte budget. In production this is a fetch
    against the Actions API rather than a local read.
    """
    try:
        text = Path(source).read_text(encoding="utf-8", errors="replace")
    except OSError:
        return {}
    return {Path(source).name: text, source: text}
