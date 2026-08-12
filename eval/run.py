#!/usr/bin/env python3
"""Score the categorizer against the hand-labelled corpus.

    python eval/run.py                          # offline ruleset (the default)
    python eval/run.py --provider anthropic     # hosted model, needs a key
    python eval/run.py --provider ollama        # local model, needs ollama serve

The same corpus scores every provider, so "is the model worth it?" is a
number rather than an opinion.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from flakectl.agent import DEFAULT_MIN_CONFIDENCE  # noqa: E402
from flakectl.evaluate import (  # noqa: E402
    LabelError,
    evaluate,
    format_report,
    load_labels,
)
from flakectl.providers import PROVIDER_NAMES, ProviderError  # noqa: E402

DEFAULT_LABELS = Path(__file__).resolve().parent / "labels.jsonl"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--labels", default=str(DEFAULT_LABELS), help="JSONL corpus to score.")
    parser.add_argument(
        "--provider", default="rules", choices=PROVIDER_NAMES, help="Categorizer backend."
    )
    parser.add_argument("--model", default=None, help="Model id, for model-backed providers.")
    parser.add_argument(
        "--min-confidence",
        type=float,
        default=DEFAULT_MIN_CONFIDENCE,
        help="Below this, an answer becomes an abstention.",
    )
    args = parser.parse_args()

    try:
        examples = load_labels(args.labels)
        result = evaluate(
            examples,
            provider_name=args.provider,
            model=args.model,
            min_confidence=args.min_confidence,
        )
    except (LabelError, ProviderError, OSError) as exc:
        print(f"eval failed: {exc}", file=sys.stderr)
        return 2

    print(format_report(result))

    # The gate from the proposal's risk table: a regression absorbed into a
    # flake category is the failure that costs maintainer trust, so it fails
    # the run rather than being a line in a table nobody reads.
    if result.missed_regressions:
        print(
            f"\nFAIL: {len(result.missed_regressions)} regression(s) were categorized as flakes.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
