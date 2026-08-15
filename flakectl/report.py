"""Pillar 4 — get findings in front of maintainers without becoming noise.

Three renderings of the same report: a terminal table for the person who
just ran the command, a JSON document for machines and for the ``report``
subcommand, and a weekly markdown digest for the humans who will read it on
a Monday.

Everything here is **dry-run**. This proof-of-concept never writes to
GitHub: the issue filer renders the issue body it *would* file, complete
with the fingerprint marker that would let a recurrence update the existing
issue instead of opening a second one. Turning that into a real write is
deliberately a separate, later decision, gated on the eval numbers.
"""

from __future__ import annotations

import json
from dataclasses import asdict
from typing import Any

from flakectl.models import Analysis, Failure, TriagedFailure, Verdict
from flakectl.pipeline import Report


class ReportFormatError(ValueError):
    """Raised when a report file cannot be read."""


#: Per-run ceiling on issues, so a bad day cannot spam the tracker.
DEFAULT_MAX_ISSUES = 5

#: Marker embedded in a filed issue so recurrences find it again.
FINGERPRINT_MARKER = "<!-- flakectl-fingerprint: {fingerprint} -->"

_STATUS_ICON = {
    "confirmed_flake": "flake",
    "real_failure": "real",
    "unknown": "?",
}


def _truncate(text: str, width: int) -> str:
    return text if len(text) <= width else text[: width - 1] + "…"


def render_table(report: Report, *, width: int = 44) -> str:
    """Render the per-failure table shown after ``flakectl analyze``."""
    if not report.triaged:
        return "No failures found."

    header = (
        f"{'TEST':<{width}}  {'VERDICT':<9}  {'CATEGORY':<18}  {'CONF':>5}  "
        f"{'FINGERPRINT':<16}  {'SEEN':>4}  NEW"
    )
    lines = [header, "-" * len(header)]
    for item in report.triaged:
        lines.append(
            f"{_truncate(item.failure.test_name, width):<{width}}  "
            f"{_STATUS_ICON.get(item.verdict, item.verdict):<9}  "
            f"{item.analysis.category:<18}  "
            f"{item.analysis.confidence:>5.2f}  "
            f"{item.fingerprint:<16}  "
            f"{item.occurrences:>4}  "
            f"{'yes' if item.is_new_signature else 'no'}"
        )

    lines.append("")
    lines.append(
        f"{report.total_failures} failure(s) · {report.distinct_fingerprints} distinct "
        f"signature(s) · {report.dedup_ratio:.1f}x dedup · "
        f"{report.cached_analyses} reused cached analysis/analyses"
    )
    lines.append(
        f"{len(report.needs_human)} need a human · "
        f"{len(report.likely_regressions)} flagged as likely regression"
    )
    lines.append(
        f"provider={report.provider} model={report.model or 'n/a'} "
        f"prompt={report.prompt_version} (agent-generated, dry-run)"
    )
    return "\n".join(lines)


def to_dict(report: Report) -> dict[str, Any]:
    """Serialise a report to a JSON-safe dictionary."""
    return {
        "schema": "flakectl/report/v1",
        "generated_at": report.generated_at,
        "generated_by": {
            "tool": "flakectl",
            "provider": report.provider,
            "model": report.model,
            "prompt_version": report.prompt_version,
            "agent_generated": True,
            "dry_run": True,
        },
        "sources": report.sources,
        "summary": {
            "failures": report.total_failures,
            "distinct_fingerprints": report.distinct_fingerprints,
            "dedup_ratio": round(report.dedup_ratio, 2),
            "cached_analyses": report.cached_analyses,
            "needs_human": len(report.needs_human),
            "likely_regressions": len(report.likely_regressions),
        },
        "failures": [
            {
                "test_name": item.failure.test_name,
                "suite": item.failure.suite,
                "spec_file": item.failure.spec_file,
                "spec_line": item.failure.spec_line,
                "job": item.failure.job,
                "os": item.failure.os,
                "source_format": item.failure.source_format,
                "truncated": item.failure.truncated,
                "fingerprint": item.fingerprint,
                "signature": item.signature,
                "verdict": str(item.verdict),
                "occurrences": item.occurrences,
                "first_seen": item.first_seen,
                "last_seen": item.last_seen,
                "is_new_signature": item.is_new_signature,
                "notes": item.notes,
                "analysis": asdict(item.analysis),
            }
            for item in report.triaged
        ],
    }


def to_json(report: Report, *, indent: int = 2) -> str:
    """Serialise a report to a JSON string."""
    return json.dumps(to_dict(report), indent=indent)


def from_dict(data: dict[str, Any]) -> Report:
    """Rebuild a report from its JSON form.

    Lets ``flakectl report`` render a digest from a report produced by an
    earlier ``flakectl analyze`` run, rather than re-analysing.

    Raises:
        ReportFormatError: If the document is not a flakectl report.
    """
    if data.get("schema") != "flakectl/report/v1":
        raise ReportFormatError(
            f"unsupported report schema {data.get('schema')!r}; expected 'flakectl/report/v1'"
        )
    provenance = data.get("generated_by", {})
    report = Report(
        generated_at=data.get("generated_at", ""),
        provider=provenance.get("provider", "unknown"),
        model=provenance.get("model"),
        prompt_version=provenance.get("prompt_version", ""),
        sources=list(data.get("sources", [])),
    )
    for entry in data.get("failures", []):
        analysis = entry["analysis"]
        report.triaged.append(
            TriagedFailure(
                failure=Failure(
                    test_name=entry["test_name"],
                    output_block="",
                    suite=entry.get("suite"),
                    spec_file=entry.get("spec_file"),
                    spec_line=entry.get("spec_line"),
                    job=entry.get("job"),
                    os=entry.get("os"),
                    source_format=entry.get("source_format", "generic"),
                    truncated=bool(entry.get("truncated", False)),
                ),
                fingerprint=entry["fingerprint"],
                signature=entry.get("signature", ""),
                verdict=Verdict(entry["verdict"]),
                analysis=Analysis(**analysis),
                occurrences=entry.get("occurrences", 1),
                first_seen=entry.get("first_seen"),
                last_seen=entry.get("last_seen"),
                is_new_signature=bool(entry.get("is_new_signature", False)),
                notes=list(entry.get("notes", [])),
            )
        )
    summary = data.get("summary", {})
    report.distinct_fingerprints = summary.get(
        "distinct_fingerprints", len({item.fingerprint for item in report.triaged})
    )
    report.cached_analyses = summary.get("cached_analyses", 0)
    return report


def issue_body(item: TriagedFailure, report: Report) -> str:
    """Render the issue that *would* be filed for one fingerprint.

    The fingerprint marker is what makes filing idempotent: a recurrence
    finds this issue and updates it rather than opening a second one.
    """
    analysis = item.analysis
    evidence = "\n".join(f"    {line}" for line in analysis.evidence) or "    (none cited)"
    return "\n".join(
        [
            FINGERPRINT_MARKER.format(fingerprint=item.fingerprint),
            f"### Flake: {item.failure.test_name}",
            "",
            f"- **Category**: `{analysis.category}` (confidence {analysis.confidence:.2f})",
            f"- **Fingerprint**: `{item.fingerprint}`",
            f"- **Seen**: {item.occurrences}x, first {item.first_seen}, last {item.last_seen}",
            f"- **Spec**: `{item.failure.spec_file or 'unknown'}:{item.failure.spec_line or '?'}`",
            f"- **Jobs**: {item.failure.job or 'unknown'}",
            f"- **Re-run evidence**: {'; '.join(item.notes) or 'none'}",
            f"- **Likely regression**: {'yes' if analysis.is_likely_regression else 'no'}",
            "",
            "**Analysis**",
            "",
            analysis.explanation,
            "",
            "**Evidence**",
            "",
            "```",
            evidence,
            "```",
            "",
            "**Suggested mitigation**",
            "",
            analysis.suggested_mitigation,
            "",
            "---",
            f"_Agent-generated by flakectl (provider `{analysis.provider}`, model "
            f"`{analysis.model or 'n/a'}`, prompt `{analysis.prompt_version}`"
            + (f", rule `{analysis.rule_id}`" if analysis.rule_id else "")
            + ")._",
        ]
    )


def pr_comment(item: TriagedFailure) -> str:
    """Render the PR comment that *would* be posted.

    Narrowly scoped and deliberately modest: one comment per PR, edited in
    place, and only for a known high-confidence fingerprint.
    """
    return (
        FINGERPRINT_MARKER.format(fingerprint=item.fingerprint)
        + f"\nThis failure in `{item.failure.test_name}` matches known flake "
        f"`{item.fingerprint}` (`{item.analysis.category}`, seen {item.occurrences}x). "
        "It is likely not caused by your change.\n\n"
        f"_{item.analysis.suggested_mitigation}_\n\n"
        "_Agent-generated by flakectl · dry-run · reply if this looks wrong._"
    )


def render_markdown(
    report: Report,
    *,
    max_issues: int = DEFAULT_MAX_ISSUES,
    top: int = 10,
) -> str:
    """Render the weekly flake digest.

    Newly-appeared signatures get their own section: a brand-new flake
    usually means something changed recently, which makes it the most
    actionable line on the page.
    """
    lines = [
        "# Weekly flake report",
        "",
        f"Generated {report.generated_at} by flakectl "
        f"(provider `{report.provider}`, model `{report.model or 'n/a'}`, "
        f"prompt `{report.prompt_version}`). **Dry run — nothing was filed.**",
        "",
        "## Summary",
        "",
        f"- {report.total_failures} failure(s) across {len(report.sources)} source(s)",
        f"- {report.distinct_fingerprints} distinct signature(s) "
        f"({report.dedup_ratio:.1f}x dedup — the factor by which model spend is reduced)",
        f"- {report.cached_analyses} analysis/analyses reused from cache, not re-derived",
        f"- {len(report.needs_human)} routed to a human (abstained or escalated)",
        f"- {len(report.likely_regressions)} flagged as a likely regression",
        "",
    ]

    ranked = sorted(report.triaged, key=lambda item: (-item.occurrences, item.fingerprint))
    lines += ["## Top flakes by frequency", ""]
    lines += _frequency_table(ranked[:top])

    new_signatures = [item for item in report.triaged if item.is_new_signature]
    lines += ["", "## Newly-appeared signatures", ""]
    if new_signatures:
        lines.append(
            "A signature seen for the first time usually means something changed recently."
        )
        lines.append("")
        lines += _frequency_table(new_signatures)
    else:
        lines.append("_None this run._")

    regressions = report.likely_regressions
    lines += ["", "## Flagged as likely regressions — do not treat as flakes", ""]
    if regressions:
        for item in regressions:
            lines.append(
                f"- **{item.failure.test_name}** — `{item.analysis.category}` "
                f"(confidence {item.analysis.confidence:.2f}, `{item.fingerprint}`). "
                f"{item.analysis.explanation}"
            )
    else:
        lines.append("_None this run._")

    needs_human = report.needs_human
    lines += ["", "## Digest for human triage", ""]
    if needs_human:
        lines.append(
            "The tool declined to decide these. No issue is filed and no PR is commented on."
        )
        lines.append("")
        for item in needs_human:
            lines.append(
                f"- **{item.failure.test_name}** (`{item.fingerprint}`) — "
                f"{item.analysis.explanation}"
            )
    else:
        lines.append("_Nothing needed a human this run._")

    lines += ["", "## Would-be issue filings (dry run)", ""]
    filable = [
        item
        for item in report.triaged
        if not item.analysis.needs_human and item.analysis.category != "unknown"
    ]
    if not filable:
        lines.append("_Nothing met the bar for filing._")
    else:
        capped = filable[:max_issues]
        lines.append(
            f"{len(filable)} candidate(s); the per-run cap of {max_issues} would allow "
            f"{len(capped)}."
        )
        for item in capped:
            lines += ["", "<details>", f"<summary>{item.failure.test_name}</summary>", ""]
            lines.append(issue_body(item, report))
            lines += ["", "</details>"]

    known_flakes = [
        item
        for item in filable
        if not item.is_new_signature and not item.analysis.is_likely_regression
    ]
    lines += ["", "## Would-be PR comment (dry run)", ""]
    if known_flakes:
        lines += ["```markdown", pr_comment(known_flakes[0]), "```"]
    else:
        lines.append("_No known high-confidence flake to comment about._")

    lines += [
        "",
        "---",
        "",
        "_Every artifact above is agent-generated and shown in dry-run form. "
        "flakectl does not write to GitHub._",
        "",
    ]
    return "\n".join(lines)


def _frequency_table(items: list[TriagedFailure]) -> list[str]:
    if not items:
        return ["_None._"]
    rows = [
        "| Fingerprint | Test | Category | Conf | Verdict | Seen | Jobs |",
        "| --- | --- | --- | ---: | --- | ---: | --- |",
    ]
    for item in items:
        rows.append(
            f"| `{item.fingerprint}` "
            f"| {item.failure.test_name} "
            f"| `{item.analysis.category}` "
            f"| {item.analysis.confidence:.2f} "
            f"| {item.verdict} "
            f"| {item.occurrences} "
            f"| {item.failure.job or 'unknown'} |"
        )
    return rows
