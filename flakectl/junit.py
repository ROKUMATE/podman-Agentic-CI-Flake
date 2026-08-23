"""Pillar 1 — the *preferred* ingestion path: JUnit/Ginkgo XML artifacts.

Where a job publishes a JUnit report, the test name, spec file, line number
and failure message are already delimited for us. Raw log scraping
(:mod:`flakectl.parser`) is the fallback, not the default.

Ginkgo v2's ``--junit-report`` output is the shape targeted here, but the
parser is deliberately tolerant: plain JUnit from ``go test`` or bats works
too.
"""

from __future__ import annotations

from xml.etree import ElementTree

from flakectl.models import Failure
from flakectl.parser import DEFAULT_BYTE_CAP, cap_block, find_source_location


class JUnitParseError(ValueError):
    """Raised when the XML cannot be read as a JUnit report."""


def _properties(suite: ElementTree.Element) -> dict[str, str]:
    """Collect ``<properties><property name= value=>`` into a dict."""
    props: dict[str, str] = {}
    for prop in suite.iterfind("./properties/property"):
        name = prop.get("name")
        if name:
            props[name] = prop.get("value", "")
    return props


def _failure_body(node: ElementTree.Element) -> str:
    """Join a failure element's ``message`` attribute and its text body.

    Ginkgo puts the assertion in ``message`` and the full output, including
    the ``In [It] at:`` location, in the element text. Both matter.
    """
    parts = [node.get("message", "").strip(), (node.text or "").strip()]
    return "\n".join(part for part in parts if part)


def _int_or_none(value: str | None) -> int | None:
    try:
        return int(value) if value is not None else None
    except ValueError:
        return None


def parse_junit(
    text: str,
    *,
    byte_cap: int = DEFAULT_BYTE_CAP,
    job: str | None = None,
    os: str | None = None,
) -> list[Failure]:
    """Parse a JUnit XML report into structured failure records.

    ``<skipped>`` and passing cases are ignored; ``<failure>`` and
    ``<error>`` both produce records.

    Args:
        text: XML document content.
        byte_cap: Hard cap on each failure's output block, in bytes.
        job: Optional ingestion metadata, overriding any suite property.
        os: Optional ingestion metadata, overriding any suite property.

    Raises:
        JUnitParseError: If the document is not well-formed XML.
    """
    try:
        root = ElementTree.fromstring(text)
    except ElementTree.ParseError as exc:
        raise JUnitParseError(f"not well-formed JUnit XML: {exc}") from exc

    # A report may be a single <testsuite> or a <testsuites> wrapper.
    suites = list(root.iter("testsuite")) if root.tag != "testsuite" else [root]
    if not suites and root.tag not in {"testsuite", "testsuites"}:
        raise JUnitParseError(f"expected <testsuite>/<testsuites>, got <{root.tag}>")

    failures: list[Failure] = []
    for suite in suites:
        props = _properties(suite)
        suite_name = suite.get("name")
        suite_job = job or props.get("job") or props.get("JobName")
        suite_os = os or props.get("os") or props.get("OS") or suite.get("hostname")

        for case in suite.iterfind("testcase"):
            for node in list(case.iterfind("failure")) + list(case.iterfind("error")):
                body = _failure_body(node)
                spec_file = case.get("file")
                spec_line = _int_or_none(case.get("line"))
                if spec_file is None:
                    spec_file, spec_line = find_source_location(body)

                capped, truncated = cap_block(body, byte_cap)
                failures.append(
                    Failure(
                        test_name=case.get("name", "<unnamed testcase>"),
                        output_block=capped,
                        status="failed" if node.tag == "failure" else "errored",
                        suite=suite_name,
                        spec_file=spec_file,
                        spec_line=spec_line,
                        job=suite_job,
                        os=suite_os,
                        source_format="junit",
                        truncated=truncated,
                    )
                )
    return failures


def parse_junit_file(path: str, **kwargs: object) -> list[Failure]:
    """Read a JUnit XML file from disk and parse it. See :func:`parse_junit`."""
    with open(path, encoding="utf-8", errors="replace") as handle:
        return parse_junit(handle.read(), **kwargs)  # type: ignore[arg-type]
