"""Pillar 3 — the tools the agent may call, and the budget it may spend.

The agent does not get the whole log. It gets the sliced failure and a set
of tools it can use to go and find more, and every limit on that is enforced
*here* rather than asked of the model: maximum tool calls per analysis,
maximum total bytes pulled into context, maximum lines per call.

A model that ignores an instruction to be frugal is a bug report. A model
that cannot exceed a budget because the tool layer will not let it is a
design.

The backing sources are pluggable. In production they are the Actions API,
a git checkout and the issues API; here they are in-memory text, a local
source tree and JSON fixtures, which keeps the demo offline and the tests
deterministic.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from flakectl.store import Store

#: Defaults sized for one analysis of one failure.
DEFAULT_MAX_CALLS = 8
DEFAULT_MAX_TOTAL_BYTES = 16384
DEFAULT_MAX_LINES_PER_CALL = 200


class ToolError(ValueError):
    """Raised when a tool is called that does not exist, or with bad arguments."""


class BudgetExceeded(RuntimeError):
    """Raised when a tool call would exceed the analysis budget.

    The orchestrator treats this as a signal to stop and answer with what it
    has — or to abstain — rather than as a crash.
    """


@dataclass(slots=True)
class ToolBudget:
    """Hard caps for a single analysis.

    Args:
        max_calls: Total tool invocations allowed.
        max_total_bytes: Total bytes of tool output allowed into context.
        max_lines_per_call: Lines any one call may return; requests above
            this are clamped rather than refused.
    """

    max_calls: int = DEFAULT_MAX_CALLS
    max_total_bytes: int = DEFAULT_MAX_TOTAL_BYTES
    max_lines_per_call: int = DEFAULT_MAX_LINES_PER_CALL
    calls_used: int = 0
    bytes_used: int = 0

    @property
    def bytes_remaining(self) -> int:
        return max(self.max_total_bytes - self.bytes_used, 0)

    @property
    def calls_remaining(self) -> int:
        return max(self.max_calls - self.calls_used, 0)

    def clamp_lines(self, requested: int) -> int:
        """Clamp a line request down to the per-call cap."""
        return max(1, min(int(requested), self.max_lines_per_call))

    def charge_call(self) -> None:
        """Account for one tool invocation.

        Raises:
            BudgetExceeded: If no calls remain.
        """
        if self.calls_remaining <= 0:
            raise BudgetExceeded(
                f"tool call budget exhausted after {self.calls_used} calls"
            )
        self.calls_used += 1

    def charge_bytes(self, payload: str) -> str:
        """Account for a tool result, truncating it to what remains.

        Raises:
            BudgetExceeded: If the byte budget is already spent.
        """
        if self.bytes_remaining <= 0:
            raise BudgetExceeded(
                f"context byte budget exhausted after {self.bytes_used} bytes"
            )
        encoded = payload.encode("utf-8", errors="replace")
        if len(encoded) <= self.bytes_remaining:
            self.bytes_used += len(encoded)
            return payload
        truncated = encoded[: self.bytes_remaining].decode("utf-8", errors="ignore")
        self.bytes_used = self.max_total_bytes
        return truncated + "\n[flakectl: truncated by the analysis byte budget]"


@dataclass(slots=True)
class ToolLayer:
    """The tools an agent may call, bound to their backing sources.

    Args:
        budget: The caps for this analysis.
        logs: Full log text keyed by job id, for :meth:`get_log_slice`.
        source_root: Directory the test sources are read from.
        store: Fingerprint store backing :meth:`search_history`.
        issues: Known flake issues, standing in for the issues API.
        changes: Recent commits per path, standing in for git history.
    """

    budget: ToolBudget = field(default_factory=ToolBudget)
    logs: dict[str, str] = field(default_factory=dict)
    source_root: Path | None = None
    store: Store | None = None
    issues: list[dict[str, Any]] = field(default_factory=list)
    changes: dict[str, list[dict[str, Any]]] = field(default_factory=dict)

    # -- individual tools ------------------------------------------------

    def get_log_slice(self, job_id: str, offset: int = 0, lines: int = 50) -> str:
        """Pull more log context on demand.

        The ingested record is deliberately small; this is how the agent
        asks for the part it did not get, within the byte budget.
        """
        text = self.logs.get(job_id)
        if text is None:
            return f"no log retained for job {job_id!r}"
        all_lines = text.split("\n")
        start = max(int(offset), 0)
        count = self.budget.clamp_lines(lines)
        window = all_lines[start : start + count]
        if not window:
            return f"offset {start} is past the end of the log ({len(all_lines)} lines)"
        header = f"[lines {start + 1}-{start + len(window)} of {len(all_lines)}]"
        return header + "\n" + "\n".join(window)

    def get_test_source(self, spec_file: str, line: int = 0, context: int = 30) -> str:
        """Read the failing spec at the commit that failed.

        This is what lets the agent tell "the test waits with a fixed sleep"
        apart from "the product has a genuine race" — the distinction is in
        the source, not in the log.
        """
        if self.source_root is None:
            return "no source checkout available"
        candidate = self._resolve_source(spec_file)
        if candidate is None:
            return f"source not available for {spec_file!r}"

        source_lines = candidate.read_text(encoding="utf-8", errors="replace").split("\n")
        if line <= 0:
            window = source_lines[: self.budget.clamp_lines(context)]
            start = 1
        else:
            half = max(int(context) // 2, 1)
            start = max(int(line) - half, 1)
            end = min(start + self.budget.clamp_lines(context), len(source_lines) + 1)
            window = source_lines[start - 1 : end - 1]
        numbered = "\n".join(f"{start + i:>5}  {t}" for i, t in enumerate(window))
        return f"{candidate.name} lines {start}-{start + len(window) - 1}:\n{numbered}"

    def search_history(self, fingerprint: str) -> str:
        """Has this exact failure been seen before, how often, and where?"""
        if self.store is None:
            return "no history store available"
        occurrence = self.store.occurrence(fingerprint)
        if occurrence is None:
            return f"fingerprint {fingerprint} has not been seen before (new signature)"
        return json.dumps(
            {
                "fingerprint": occurrence.fingerprint,
                "occurrences": occurrence.count,
                "first_seen": occurrence.first_seen,
                "last_seen": occurrence.last_seen,
                "jobs": list(occurrence.jobs),
                "oses": list(occurrence.oses),
            },
            indent=2,
        )

    def search_issues(self, query: str) -> str:
        """Is there already an open flake issue for this?"""
        if not self.issues:
            return "no issue index available"
        terms = [term for term in query.lower().split() if len(term) > 3]
        hits = [
            issue
            for issue in self.issues
            if any(term in json.dumps(issue).lower() for term in terms)
        ]
        if not hits:
            return f"no open issues matching {query!r}"
        return json.dumps(hits[:5], indent=2)

    def recent_changes(self, path: str) -> str:
        """Did a recent commit touch the code under test?

        A strong signal that a failure is a regression rather than a flake.
        """
        if not self.changes:
            return "no change history available"
        matches: list[dict[str, Any]] = []
        for tracked_path, commits in self.changes.items():
            if tracked_path in path or path in tracked_path:
                matches.extend(commits)
        if not matches:
            return f"no commits in the recent window touching {path!r}"
        return json.dumps(matches[:5], indent=2)

    # -- dispatch --------------------------------------------------------

    def call(self, name: str, arguments: dict[str, Any] | None = None) -> str:
        """Invoke a tool by name, charging the budget.

        Args:
            name: Tool name, as advertised by :meth:`definitions`.
            arguments: Keyword arguments for the tool.

        Raises:
            ToolError: If the tool does not exist or the arguments are wrong.
            BudgetExceeded: If a cap has been reached.
        """
        handlers = {
            "get_log_slice": self.get_log_slice,
            "get_test_source": self.get_test_source,
            "search_history": self.search_history,
            "search_issues": self.search_issues,
            "recent_changes": self.recent_changes,
        }
        handler = handlers.get(name)
        if handler is None:
            raise ToolError(f"unknown tool {name!r}; available: {', '.join(sorted(handlers))}")

        self.budget.charge_call()
        try:
            result = handler(**(arguments or {}))
        except TypeError as exc:
            raise ToolError(f"bad arguments for {name!r}: {exc}") from exc
        return self.budget.charge_bytes(result)

    @staticmethod
    def definitions() -> list[dict[str, Any]]:
        """JSON-schema tool definitions, for a tool-calling model API."""
        return [
            {
                "name": "get_log_slice",
                "description": (
                    "Pull additional lines from the full CI log for a job. Use when the "
                    "sliced failure window is not enough to tell what happened."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "job_id": {"type": "string", "description": "Job identifier."},
                        "offset": {"type": "integer", "description": "First line, 0-based."},
                        "lines": {"type": "integer", "description": "How many lines to read."},
                    },
                    "required": ["job_id"],
                },
            },
            {
                "name": "get_test_source",
                "description": (
                    "Read the failing test's source at the commit that failed. Use this to "
                    "tell a sleep-based wait apart from a genuine product race."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "spec_file": {"type": "string", "description": "Path to the spec file."},
                        "line": {"type": "integer", "description": "Line to centre on."},
                        "context": {"type": "integer", "description": "Lines of context."},
                    },
                    "required": ["spec_file"],
                },
            },
            {
                "name": "search_history",
                "description": (
                    "Look up how often this fingerprint has been seen, since when, and on "
                    "which jobs and operating systems."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "fingerprint": {"type": "string", "description": "Failure fingerprint."}
                    },
                    "required": ["fingerprint"],
                },
            },
            {
                "name": "search_issues",
                "description": "Check whether an open issue already tracks this flake.",
                "input_schema": {
                    "type": "object",
                    "properties": {"query": {"type": "string", "description": "Search terms."}},
                    "required": ["query"],
                },
            },
            {
                "name": "recent_changes",
                "description": (
                    "List recent commits touching a path. Recent changes to the code under "
                    "test are evidence for a regression rather than a flake."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string", "description": "Source path to check."}
                    },
                    "required": ["path"],
                },
            },
        ]

    def _resolve_source(self, spec_file: str) -> Path | None:
        """Find a spec file under the source root, by full path then basename."""
        root = self.source_root
        if root is None:
            return None
        direct = root / spec_file.lstrip("/")
        if direct.is_file():
            return direct
        name = Path(spec_file).name
        return next((match for match in root.rglob(name) if match.is_file()), None)
