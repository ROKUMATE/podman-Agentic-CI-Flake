#!/usr/bin/env bash
#
# End-to-end demo. Runs entirely offline: no API key, no network, no server.
#
#   ./demo.sh
#
# Walks the pipeline in the order the design describes:
#   ingest -> fingerprint -> detect -> categorize -> report
# and finishes by scoring the categorizer against the labelled corpus.

set -euo pipefail

FLAKECTL="${FLAKECTL:-.venv/bin/flakectl}"
if [ ! -x "$FLAKECTL" ]; then
    FLAKECTL="$(command -v flakectl || true)"
fi
if [ -z "$FLAKECTL" ]; then
    echo "flakectl not found. Run 'make install' first." >&2
    exit 1
fi

WORKDIR="$(mktemp -d)"
trap 'rm -rf "$WORKDIR"' EXIT

step() {
    printf '\n\033[1m==> %s\033[0m\n\n' "$1"
}

step "1/6  Ingest: slice a 40-line CI log into a bounded failure record"
echo "Pillar 1 keeps only the failure window and caps it in bytes at the"
echo "ingestion layer, so a huge log becomes a small record."
echo
"$FLAKECTL" ingest samples/int_fedora41_race_timing.log

step "2/6  Analyze: the whole pipeline over the sample corpus, offline"
echo "Six raw logs plus one JUnit artifact. The re-run history supplies the"
echo "deterministic flake/real-failure call; a maintainer-owned ruleset"
echo "supplies the category. No model is invoked."
echo
"$FLAKECTL" analyze samples/*.log \
    --junit samples/junit_int_remote.xml \
    --history samples/history.json \
    --source-root samples/src \
    --issues samples/issues.json \
    --changes samples/recent_changes.json \
    --db "$WORKDIR/flakectl.db" \
    --out "$WORKDIR/report.json"

step "3/6  Two failures that both reproduce — only one is a regression"
echo "Both failed on every attempt at the same commit. The baseline"
echo "comparison against main is what tells them apart:"
echo
python3 - "$WORKDIR/report.json" <<'PY'
import json, sys
report = json.load(open(sys.argv[1]))
for failure in report["failures"]:
    if failure["verdict"] != "real_failure" or failure["source_format"] == "junit":
        continue
    analysis = failure["analysis"]
    print(f"  {failure['test_name']}")
    print(f"    category           : {analysis['category']}")
    print(f"    is_likely_regression: {analysis['is_likely_regression']}")
    print(f"    escalated to human : {analysis['needs_human']}")
    print(f"    re-run evidence    : {failure['notes'][0]}")
    print()
PY

step "4/6  Run it again: known fingerprints never reach a model"
echo "Same logs, same store. Every signature is already known, so every"
echo "analysis is reused rather than re-derived. This is what makes model"
echo "cost O(distinct failure modes) instead of O(failures)."
echo
"$FLAKECTL" analyze samples/*.log \
    --history samples/history.json \
    --db "$WORKDIR/flakectl.db" \
    --out "$WORKDIR/report2.json" | grep -E 'dedup|need a human'

step "5/6  Report: the weekly digest, in dry-run form"
"$FLAKECTL" report --input "$WORKDIR/report.json" --out "$WORKDIR/weekly-report.md"
echo
sed -n '1,20p' "$WORKDIR/weekly-report.md"
echo "  ... (full digest at $WORKDIR/weekly-report.md, including the issue"
echo "      bodies and PR comment it *would* file — it never writes to GitHub)"

step "6/6  Eval: score the categorizer against the hand-labelled corpus"
echo "The number that matters is the missed-regression rate: a real"
echo "regression reported as a flake. It has to be zero."
echo
"$FLAKECTL" eval

printf '\n\033[1m==> Done.\033[0m Everything above ran offline, with no API key.\n'
printf '    For the agentic path:  flakectl analyze samples/*.log --online --provider anthropic\n\n'
