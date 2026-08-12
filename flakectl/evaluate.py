"""Score a categorizer against a hand-labelled corpus.

Without this, every claim about accuracy is vibes. The harness runs the
same :class:`~flakectl.agent.Categorizer` the CLI uses, over labelled
snippets, and reports:

- per-category precision, recall and F1;
- overall accuracy;
- **missed-regression rate** — labelled a regression, categorized as a
  flake. This is the number that decides whether auto-filing is ever
  allowed to be switched on, because absorbing a real regression into
  "flake" is the failure that costs maintainer trust fastest;
- **false-regression rate** — the mirror image: labelled a flake, reported
  as a regression. Cheaper to be wrong about, but it is the noise that gets
  a tool muted;
- abstention rate, and mean latency per analysis.

Because every provider implements the same interface, the same corpus
scores a local model and a hosted one, and the comparison is a number
rather than an argument.
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path

from flakectl.agent import DEFAULT_MIN_CONFIDENCE, Categorizer
from flakectl.detector import DetectionResult
from flakectl.fingerprint import fingerprint_failure
from flakectl.models import Failure, Verdict
from flakectl.providers import build_provider
from flakectl.taxonomy import Taxonomy, default_taxonomy


class LabelError(ValueError):
    """Raised when a label file cannot be read."""


@dataclass(frozen=True, slots=True)
class LabelledFailure:
    """One hand-labelled example."""

    id: str
    label: str
    log: str
    test_name: str = "unknown"
    spec_file: str | None = None
    verdict: Verdict = Verdict.UNKNOWN
    reason: str = ""

    def as_failure(self) -> Failure:
        return Failure(
            test_name=self.test_name, output_block=self.log, spec_file=self.spec_file
        )

    def as_detection(self) -> DetectionResult:
        return DetectionResult(
            verdict=self.verdict,
            reason=self.reason or "from labelled corpus",
            caused_by_change=None if "also fails on main" not in self.reason else False,
        )


@dataclass(frozen=True, slots=True)
class Prediction:
    """What the categorizer said about one labelled example."""

    example: LabelledFailure
    predicted: str
    confidence: float
    is_likely_regression: bool
    latency_ms: float

    @property
    def correct(self) -> bool:
        return self.predicted == self.example.label


@dataclass(slots=True)
class CategoryScore:
    """Precision, recall and F1 for one category."""

    name: str
    support: int = 0
    true_positives: int = 0
    false_positives: int = 0
    false_negatives: int = 0

    @property
    def precision(self) -> float:
        denominator = self.true_positives + self.false_positives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def recall(self) -> float:
        denominator = self.true_positives + self.false_negatives
        return self.true_positives / denominator if denominator else 0.0

    @property
    def f1(self) -> float:
        if not (self.precision + self.recall):
            return 0.0
        return 2 * self.precision * self.recall / (self.precision + self.recall)


@dataclass(slots=True)
class EvalResult:
    """The full scorecard for one provider over one corpus."""

    provider: str
    model: str | None
    min_confidence: float
    predictions: list[Prediction] = field(default_factory=list)
    scores: dict[str, CategoryScore] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.predictions)

    @property
    def accuracy(self) -> float:
        if not self.total:
            return 0.0
        return sum(1 for p in self.predictions if p.correct) / self.total

    @property
    def abstentions(self) -> list[Prediction]:
        return [p for p in self.predictions if p.predicted == "unknown"]

    @property
    def abstention_rate(self) -> float:
        return len(self.abstentions) / self.total if self.total else 0.0

    @property
    def decided(self) -> list[Prediction]:
        """Predictions where the tool committed to an answer."""
        return [p for p in self.predictions if p.predicted != "unknown"]

    @property
    def accuracy_when_decided(self) -> float:
        """Accuracy over the answers the tool actually stood behind.

        Reported next to raw accuracy because abstaining is a design goal,
        not a miss — a tool that answers 70% of failures correctly and
        declines the rest is the intended behaviour.
        """
        decided = self.decided
        if not decided:
            return 0.0
        return sum(1 for p in decided if p.correct) / len(decided)

    @property
    def missed_regressions(self) -> list[Prediction]:
        """Labelled a regression, reported as a flake. The dangerous error."""
        return [
            p
            for p in self.predictions
            if p.example.label == "real_regression"
            and p.predicted not in {"real_regression", "unknown"}
        ]

    @property
    def missed_regression_rate(self) -> float:
        supported = sum(1 for p in self.predictions if p.example.label == "real_regression")
        return len(self.missed_regressions) / supported if supported else 0.0

    @property
    def false_regressions(self) -> list[Prediction]:
        """Labelled a flake, reported as a regression. The noisy error."""
        return [
            p
            for p in self.predictions
            if p.example.label != "real_regression"
            and (p.predicted == "real_regression" or p.is_likely_regression)
        ]

    @property
    def false_regression_rate(self) -> float:
        supported = sum(1 for p in self.predictions if p.example.label != "real_regression")
        return len(self.false_regressions) / supported if supported else 0.0

    @property
    def mean_latency_ms(self) -> float:
        if not self.predictions:
            return 0.0
        return sum(p.latency_ms for p in self.predictions) / self.total


def load_labels(path: str | Path) -> list[LabelledFailure]:
    """Read a JSONL corpus of hand-labelled failures.

    Raises:
        LabelError: If a line is malformed or missing a required field.
    """
    examples: list[LabelledFailure] = []
    with open(path, encoding="utf-8") as handle:
        for number, line in enumerate(handle, start=1):
            line = line.strip()
            if not line or line.startswith("//"):
                continue
            try:
                entry = json.loads(line)
            except json.JSONDecodeError as exc:
                raise LabelError(f"{path}:{number}: not valid JSON ({exc})") from exc
            for required in ("id", "label", "log"):
                if required not in entry:
                    raise LabelError(f"{path}:{number}: missing {required!r}")
            examples.append(
                LabelledFailure(
                    id=entry["id"],
                    label=entry["label"],
                    log=entry["log"],
                    test_name=entry.get("test_name", "unknown"),
                    spec_file=entry.get("spec_file"),
                    verdict=Verdict(entry["verdict"]) if entry.get("verdict") else Verdict.UNKNOWN,
                    reason=entry.get("reason", ""),
                )
            )
    if not examples:
        raise LabelError(f"{path}: no labelled examples found")
    return examples


def evaluate(
    examples: list[LabelledFailure],
    *,
    provider_name: str = "rules",
    model: str | None = None,
    min_confidence: float = DEFAULT_MIN_CONFIDENCE,
    taxonomy: Taxonomy | None = None,
) -> EvalResult:
    """Score a provider against a labelled corpus.

    The store is deliberately omitted: caching would make the second
    sighting of a signature free, which is the right behaviour in
    production and the wrong one when measuring the categorizer.
    """
    taxonomy = taxonomy or default_taxonomy()
    unknown_labels = {e.label for e in examples} - set(taxonomy.names)
    if unknown_labels:
        raise LabelError(
            f"corpus uses labels outside the taxonomy: {', '.join(sorted(unknown_labels))}"
        )

    provider_kwargs = {"model": model} if model else {}
    categorizer = Categorizer(
        provider=build_provider(provider_name, **provider_kwargs),
        taxonomy=taxonomy,
        store=None,
        min_confidence=min_confidence,
    )

    result = EvalResult(
        provider=provider_name,
        model=model,
        min_confidence=min_confidence,
        scores={name: CategoryScore(name=name) for name in taxonomy.names},
    )

    for example in examples:
        failure = example.as_failure()
        fingerprint, signature = fingerprint_failure(failure)

        started = time.perf_counter()
        analysis = categorizer.categorize(
            failure, fingerprint, signature, example.as_detection()
        )
        latency_ms = (time.perf_counter() - started) * 1000

        result.predictions.append(
            Prediction(
                example=example,
                predicted=analysis.category,
                confidence=analysis.confidence,
                is_likely_regression=analysis.is_likely_regression,
                latency_ms=latency_ms,
            )
        )

    for prediction in result.predictions:
        actual = prediction.example.label
        predicted = prediction.predicted
        result.scores[actual].support += 1
        if predicted == actual:
            result.scores[actual].true_positives += 1
        else:
            result.scores[actual].false_negatives += 1
            result.scores[predicted].false_positives += 1

    return result


def format_report(result: EvalResult) -> str:
    """Render the scorecard as a plain-text table."""
    lines = [
        f"Corpus: {result.total} hand-labelled failures",
        f"Provider: {result.provider}"
        + (f" (model {result.model})" if result.model else "")
        + f", confidence gate {result.min_confidence:.2f}",
        "",
        f"{'CATEGORY':<20} {'SUPPORT':>7} {'PREC':>6} {'RECALL':>7} {'F1':>6}",
        "-" * 50,
    ]

    # 'unknown' is excluded: an abstention is a designed outcome, not a
    # prediction of a category, so scoring precision on it is meaningless.
    # It is accounted for as a recall miss on the true label, and reported
    # on its own as the abstention rate below.
    scored = {name: score for name, score in result.scores.items() if name != "unknown"}
    for name, score in scored.items():
        if not score.support and not score.false_positives:
            continue
        lines.append(
            f"{name:<20} {score.support:>7} {score.precision:>6.2f} "
            f"{score.recall:>7.2f} {score.f1:>6.2f}"
        )

    macro = [s for s in scored.values() if s.support]
    macro_f1 = sum(s.f1 for s in macro) / len(macro) if macro else 0.0
    lines += [
        "-" * 50,
        f"{'macro avg':<20} {result.total:>7} {'':>6} {'':>7} {macro_f1:>6.2f}",
        "",
        "Overall",
        f"  accuracy                    {result.accuracy:>6.1%}",
        f"  accuracy when it answered   {result.accuracy_when_decided:>6.1%}  "
        f"({len(result.decided)} of {result.total})",
        f"  abstention rate             {result.abstention_rate:>6.1%}  "
        f"({len(result.abstentions)} routed to a human)",
        f"  mean latency                {result.mean_latency_ms:>6.2f} ms",
        "",
        "Regression safety (the gate on ever enabling auto-filing)",
        f"  missed-regression rate      {result.missed_regression_rate:>6.1%}  "
        f"(regression reported as a flake — must be 0)",
        f"  false-regression rate       {result.false_regression_rate:>6.1%}  "
        f"(flake reported as a regression — noise)",
    ]

    if result.missed_regressions:
        lines += ["", "  Missed regressions:"]
        lines += [
            f"    {p.example.id}: labelled real_regression, predicted {p.predicted}"
            for p in result.missed_regressions
        ]
    if result.false_regressions:
        lines += ["", "  False regressions:"]
        lines += [
            f"    {p.example.id}: labelled {p.example.label}, predicted {p.predicted}"
            for p in result.false_regressions
        ]
    if result.abstentions:
        lines += ["", "  Abstained (routed to a human, not counted as a wrong answer):"]
        lines += [
            f"    {p.example.id}: labelled {p.example.label}" for p in result.abstentions
        ]

    return "\n".join(lines)
