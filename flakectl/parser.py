"""Pillar 1 — turn a raw CI log into structured failure records.

The job here is *slicing*, not understanding. A Podman e2e job can emit tens
of megabytes of Ginkgo output; almost all of it is passing specs. We keep
only the failure window — the ``[FAILED]`` block, the ``Summarizing N
Failures`` section, and a bounded amount of surrounding context — and we
enforce a hard byte cap at this layer rather than trusting a later stage to
stay inside its budget.

Structured artifacts (JUnit XML) are the preferred ingestion path; see
:mod:`flakectl.junit`. This module is the fallback for raw logs.
"""

from __future__ import annotations

import re
from dataclasses import replace

from flakectl.models import Failure

#: Default cap on a single failure's output block. A 40MB log becomes a
#: handful of records of roughly this size.
DEFAULT_BYTE_CAP = 4096

#: Lines of surrounding context kept around a failure in generic logs.
DEFAULT_CONTEXT_LINES = 12

_ANSI = re.compile(r"\x1b\[[0-9;]*[a-zA-Z]")
#: GitHub Actions prefixes every log line with an RFC3339 timestamp.
_ACTIONS_TIMESTAMP = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z\s?")
_ACTIONS_COMMAND = re.compile(r"^##\[(?:group|endgroup|section|command|debug)\].*$")

_SEPARATOR = re.compile(r"^-{3,}$")
_GINKGO_SUITE = re.compile(r"^Running Suite:\s*(.+?)\s*(?:-\s*/.*)?$", re.MULTILINE)
_GINKGO_FAILED_HEADER = re.compile(r"^\s*(?:[•*]\s*)?\[FAILED\]", re.MULTILINE)
_GINKGO_LOCATION = re.compile(r"^\s*(/[^\s:]+\.go):(\d+)\s*$")
_GINKGO_IN_AT = re.compile(r"In\s+\[\w+\]\s+at:\s*(\S+?\.go):(\d+)")
_SUMMARIZING = re.compile(r"^Summarizing\s+(\d+)\s+Failure", re.MULTILINE)
_SUMMARY_ENTRY = re.compile(r"^\s*\[(?:FAIL|PANIC!?|TIMEDOUT)\]\s*(.+?)\s*$")

_EXIT_CODE = re.compile(
    r"(?:Process completed with exit code|exit status|exited with code)\s+(\d+)"
)

_GO_TEST_FAIL = re.compile(r"^\s*--- FAIL:\s+(\S+)")
_TAP_NOT_OK = re.compile(r"^not ok\s+\d+\s+(.+?)\s*$")
_GENERIC_FAIL = re.compile(r"^\s*(?:FAIL|FAILED|ERROR):\s*(.+?)\s*$")


def _clean(text: str) -> str:
    """Strip transport noise: CRLF, ANSI colour, Actions timestamps/commands."""
    lines = []
    for raw in text.replace("\r\n", "\n").replace("\r", "\n").split("\n"):
        line = _ANSI.sub("", raw)
        line = _ACTIONS_TIMESTAMP.sub("", line)
        if _ACTIONS_COMMAND.match(line):
            continue
        lines.append(line.rstrip())
    return "\n".join(lines)


def _cap(text: str, byte_cap: int) -> tuple[str, bool]:
    """Cap ``text`` to ``byte_cap`` bytes, eliding the middle.

    The head carries the assertion and the tail carries the source location,
    so the middle is what we can afford to lose.
    """
    encoded = text.encode("utf-8", errors="replace")
    if len(encoded) <= byte_cap:
        return text, False
    marker = b"\n... [flakectl: elided by ingestion byte cap] ...\n"
    budget = max(byte_cap - len(marker), 0)
    head = encoded[: int(budget * 0.6)]
    tail = encoded[len(encoded) - (budget - len(head)) :] if budget > len(head) else b""
    return (head + marker + tail).decode("utf-8", errors="replace"), True


def _split_blocks(text: str) -> list[str]:
    """Split Ginkgo output on its ``------`` spec separators."""
    blocks: list[str] = []
    current: list[str] = []
    for line in text.split("\n"):
        if _SEPARATOR.match(line.strip()):
            blocks.append("\n".join(current))
            current = []
        else:
            current.append(line)
    blocks.append("\n".join(current))
    return blocks


def _looks_like_ginkgo(text: str) -> bool:
    return bool(_SUMMARIZING.search(text) or _GINKGO_FAILED_HEADER.search(text))


def _parse_location(block: str) -> tuple[str | None, int | None]:
    """Find the failing source location in a Ginkgo failure block.

    ``In [It] at: file.go:431`` points at the failing assertion and is
    preferred over the spec's declaration site.
    """
    at = _GINKGO_IN_AT.search(block)
    if at:
        return at.group(1), int(at.group(2))
    for line in block.split("\n"):
        loc = _GINKGO_LOCATION.match(line)
        if loc:
            return loc.group(1), int(loc.group(2))
    return None, None


def _parse_test_name(block: str) -> str | None:
    """The spec description sits on the first prose line of the block."""
    seen_header = False
    for line in block.split("\n"):
        stripped = line.strip()
        if not stripped:
            continue
        if not seen_header:
            if _GINKGO_FAILED_HEADER.match(line):
                seen_header = True
            continue
        if _GINKGO_LOCATION.match(line) or stripped.startswith("["):
            continue
        return stripped
    return None


def _parse_summary_names(text: str) -> list[str]:
    """Names listed under ``Summarizing N Failures:``.

    This section is authoritative about *which* specs failed, so it is the
    fallback when a detailed block cannot be matched.
    """
    match = _SUMMARIZING.search(text)
    if not match:
        return []
    names: list[str] = []
    for line in text[match.end() :].split("\n"):
        if line.strip().startswith("Ran ") or line.startswith("FAIL!"):
            break
        entry = _SUMMARY_ENTRY.match(line)
        if entry:
            names.append(entry.group(1))
    return names


def _parse_ginkgo(text: str, byte_cap: int) -> list[Failure]:
    suite_match = _GINKGO_SUITE.search(text)
    suite = suite_match.group(1).strip() if suite_match else None
    exit_match = _EXIT_CODE.search(text)
    exit_code = int(exit_match.group(1)) if exit_match else None

    summary_names = _parse_summary_names(text)
    summarizing = _SUMMARIZING.search(text)
    detail_region = text[: summarizing.start()] if summarizing else text

    failures: list[Failure] = []
    matched_names: set[str] = set()
    for block in _split_blocks(detail_region):
        if not _GINKGO_FAILED_HEADER.search(block):
            continue
        name = _parse_test_name(block)
        if not name:
            continue
        spec_file, spec_line = _parse_location(block)
        body, truncated = _cap(block.strip(), byte_cap)
        matched_names.add(name)
        failures.append(
            Failure(
                test_name=name,
                output_block=body,
                suite=suite,
                spec_file=spec_file,
                spec_line=spec_line,
                exit_code=exit_code,
                source_format="ginkgo",
                truncated=truncated,
            )
        )

    # Specs named in the summary but with no detailed block still count.
    for name in summary_names:
        if name in matched_names:
            continue
        body, truncated = _cap(f"[FAIL] {name}", byte_cap)
        failures.append(
            Failure(
                test_name=name,
                output_block=body,
                suite=suite,
                exit_code=exit_code,
                source_format="ginkgo",
                truncated=truncated,
            )
        )
    return failures


def _parse_generic(text: str, byte_cap: int, context_lines: int) -> list[Failure]:
    """Fallback for Go test, TAP/bats, and plain ``FAIL:`` output."""
    lines = text.split("\n")
    exit_match = _EXIT_CODE.search(text)
    exit_code = int(exit_match.group(1)) if exit_match else None

    failures: list[Failure] = []
    for index, line in enumerate(lines):
        name: str | None = None
        for pattern in (_GO_TEST_FAIL, _TAP_NOT_OK, _GENERIC_FAIL):
            match = pattern.match(line)
            if match:
                name = match.group(1).strip()
                break
        if not name:
            continue
        start = max(index - 2, 0)
        end = min(index + context_lines + 1, len(lines))
        body, truncated = _cap("\n".join(lines[start:end]).strip(), byte_cap)
        failures.append(
            Failure(
                test_name=name,
                output_block=body,
                exit_code=exit_code,
                source_format="generic",
                truncated=truncated,
            )
        )
    return failures


def parse_log(
    text: str,
    *,
    byte_cap: int = DEFAULT_BYTE_CAP,
    context_lines: int = DEFAULT_CONTEXT_LINES,
    job: str | None = None,
    os: str | None = None,
) -> list[Failure]:
    """Parse a CI log into structured failure records.

    Args:
        text: Raw log content.
        byte_cap: Hard cap on each failure's output block, in bytes.
        context_lines: Lines of trailing context for generic-format logs.
        job: Optional ingestion metadata (from the Actions API in production).
        os: Optional ingestion metadata.

    Returns:
        One :class:`~flakectl.models.Failure` per failing test, in log order.
    """
    cleaned = _clean(text)
    if _looks_like_ginkgo(cleaned):
        failures = _parse_ginkgo(cleaned, byte_cap)
    else:
        failures = _parse_generic(cleaned, byte_cap, context_lines)

    if job is None and os is None:
        return failures
    return [replace(item, job=job, os=os) for item in failures]


def parse_log_file(path: str, **kwargs: object) -> list[Failure]:
    """Read a log file from disk and parse it. See :func:`parse_log`."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_log(handle.read(), **kwargs)  # type: ignore[arg-type]
