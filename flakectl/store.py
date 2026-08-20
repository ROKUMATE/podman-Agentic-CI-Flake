"""Pillar 2 — the fingerprint and analysis store.

SQLite, from the standard library: file-based, zero-ops, and inspectable by
any maintainer with ``sqlite3``. Postgres later is a driver swap; Postgres
now is deployment friction.

The store is what makes "only unseen fingerprints reach the model" true.
:meth:`Store.get_analysis` is consulted before every categorization, and a
hit means no model call at all.
"""

from __future__ import annotations

import json
import sqlite3
from dataclasses import replace
from datetime import UTC, datetime
from types import TracebackType

from flakectl.models import Analysis, Failure, Occurrence

#: Use an in-memory database when no path is given.
MEMORY = ":memory:"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS fingerprints (
    fingerprint   TEXT PRIMARY KEY,
    signature     TEXT NOT NULL,
    test_identity TEXT NOT NULL,
    count         INTEGER NOT NULL DEFAULT 0,
    first_seen    TEXT NOT NULL,
    last_seen     TEXT NOT NULL,
    jobs          TEXT NOT NULL DEFAULT '[]',
    oses          TEXT NOT NULL DEFAULT '[]'
);

CREATE TABLE IF NOT EXISTS failures (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    fingerprint   TEXT NOT NULL REFERENCES fingerprints(fingerprint),
    test_name     TEXT NOT NULL,
    suite         TEXT,
    spec_file     TEXT,
    spec_line     INTEGER,
    job           TEXT,
    os            TEXT,
    source_format TEXT,
    output_block  TEXT NOT NULL,
    seen_at       TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS failures_by_fingerprint ON failures(fingerprint);

CREATE TABLE IF NOT EXISTS analyses (
    fingerprint          TEXT PRIMARY KEY REFERENCES fingerprints(fingerprint),
    category             TEXT NOT NULL,
    confidence           REAL NOT NULL,
    evidence             TEXT NOT NULL,
    explanation          TEXT NOT NULL,
    suggested_mitigation TEXT NOT NULL,
    is_likely_regression INTEGER NOT NULL,
    provider             TEXT NOT NULL,
    model                TEXT,
    prompt_version       TEXT,
    rule_id              TEXT,
    needs_human          INTEGER NOT NULL DEFAULT 0,
    tool_calls           INTEGER NOT NULL DEFAULT 0,
    created_at           TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _merge(existing: str, value: str | None) -> str:
    """Add ``value`` to a JSON list column, keeping it sorted and unique."""
    items = set(json.loads(existing or "[]"))
    if value:
        items.add(value)
    return json.dumps(sorted(items))


class Store:
    """Persistent fingerprint, failure and analysis records.

    Usable as a context manager::

        with Store("flakectl.db") as store:
            occurrence = store.record_failure(failure, fingerprint, signature)
    """

    def __init__(self, path: str = MEMORY) -> None:
        self.path = path
        self._conn = sqlite3.connect(path)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def __enter__(self) -> Store:
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.close()

    def close(self) -> None:
        """Commit and close the underlying connection."""
        self._conn.commit()
        self._conn.close()

    # -- writes ---------------------------------------------------------

    def record_failure(
        self,
        failure: Failure,
        fingerprint: str,
        signature: str,
        *,
        now: str | None = None,
    ) -> Occurrence:
        """Record one sighting of a failure and update its fingerprint.

        Args:
            failure: The failure being recorded.
            fingerprint: Its fingerprint.
            signature: Its normalised error signature.
            now: Timestamp override, for deterministic tests.

        Returns:
            The updated :class:`~flakectl.models.Occurrence`, with
            ``is_new`` set when this fingerprint had never been seen before.
        """
        timestamp = now or _now()
        row = self._conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        is_new = row is None

        if is_new:
            self._conn.execute(
                "INSERT INTO fingerprints "
                "(fingerprint, signature, test_identity, count, first_seen, last_seen, jobs, oses)"
                " VALUES (?, ?, ?, 1, ?, ?, ?, ?)",
                (
                    fingerprint,
                    signature,
                    failure.identity,
                    timestamp,
                    timestamp,
                    _merge("[]", failure.job),
                    _merge("[]", failure.os),
                ),
            )
        else:
            self._conn.execute(
                "UPDATE fingerprints SET count = count + 1, last_seen = ?, jobs = ?, oses = ? "
                "WHERE fingerprint = ?",
                (
                    timestamp,
                    _merge(row["jobs"], failure.job),
                    _merge(row["oses"], failure.os),
                    fingerprint,
                ),
            )

        self._conn.execute(
            "INSERT INTO failures "
            "(fingerprint, test_name, suite, spec_file, spec_line, job, os, source_format,"
            " output_block, seen_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fingerprint,
                failure.test_name,
                failure.suite,
                failure.spec_file,
                failure.spec_line,
                failure.job,
                failure.os,
                failure.source_format,
                failure.output_block,
                timestamp,
            ),
        )
        self._conn.commit()

        occurrence = self.occurrence(fingerprint)
        if occurrence is None:  # pragma: no cover - just written above
            raise RuntimeError(f"fingerprint {fingerprint} vanished after insert")
        return replace(occurrence, is_new=is_new)

    def put_analysis(self, fingerprint: str, analysis: Analysis, *, now: str | None = None) -> None:
        """Cache an analysis against a fingerprint.

        Replaces any previous analysis for that fingerprint, so re-running
        with a better prompt or a different provider updates the cache.
        """
        self._conn.execute(
            "INSERT OR REPLACE INTO analyses "
            "(fingerprint, category, confidence, evidence, explanation, suggested_mitigation,"
            " is_likely_regression, provider, model, prompt_version, rule_id, needs_human,"
            " tool_calls, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (
                fingerprint,
                analysis.category,
                analysis.confidence,
                json.dumps(analysis.evidence),
                analysis.explanation,
                analysis.suggested_mitigation,
                int(analysis.is_likely_regression),
                analysis.provider,
                analysis.model,
                analysis.prompt_version,
                analysis.rule_id,
                int(analysis.needs_human),
                analysis.tool_calls,
                now or _now(),
            ),
        )
        self._conn.commit()

    # -- reads ----------------------------------------------------------

    def get_analysis(self, fingerprint: str) -> Analysis | None:
        """Look up a cached analysis.

        A hit here is the whole point of Pillar 2: a known fingerprint never
        reaches a model. The returned analysis is marked ``cached``.
        """
        row = self._conn.execute(
            "SELECT * FROM analyses WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        if row is None:
            return None
        return Analysis(
            category=row["category"],
            confidence=row["confidence"],
            evidence=json.loads(row["evidence"]),
            explanation=row["explanation"],
            suggested_mitigation=row["suggested_mitigation"],
            is_likely_regression=bool(row["is_likely_regression"]),
            provider=row["provider"],
            model=row["model"],
            prompt_version=row["prompt_version"],
            rule_id=row["rule_id"],
            needs_human=bool(row["needs_human"]),
            tool_calls=row["tool_calls"],
            cached=True,
        )

    def occurrence(self, fingerprint: str) -> Occurrence | None:
        """Current counters for one fingerprint."""
        row = self._conn.execute(
            "SELECT * FROM fingerprints WHERE fingerprint = ?", (fingerprint,)
        ).fetchone()
        return _to_occurrence(row) if row else None

    def top_flakes(self, limit: int = 10) -> list[Occurrence]:
        """Fingerprints by frequency, most frequent first."""
        rows = self._conn.execute(
            "SELECT * FROM fingerprints ORDER BY count DESC, last_seen DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [_to_occurrence(row) for row in rows]

    def new_since(self, timestamp: str) -> list[Occurrence]:
        """Fingerprints first seen at or after ``timestamp``.

        A brand-new signature is the most actionable thing on the weekly
        report, so it gets its own section.
        """
        rows = self._conn.execute(
            "SELECT * FROM fingerprints WHERE first_seen >= ? ORDER BY first_seen DESC",
            (timestamp,),
        ).fetchall()
        return [_to_occurrence(row) for row in rows]

    def failure_count(self) -> int:
        """Total sightings recorded, across all fingerprints."""
        return int(self._conn.execute("SELECT COUNT(*) FROM failures").fetchone()[0])

    def fingerprint_count(self) -> int:
        """Number of distinct fingerprints.

        The ratio of this to :meth:`failure_count` is the dedup factor, and
        therefore the factor by which model spend is reduced.
        """
        return int(self._conn.execute("SELECT COUNT(*) FROM fingerprints").fetchone()[0])


def _to_occurrence(row: sqlite3.Row) -> Occurrence:
    return Occurrence(
        fingerprint=row["fingerprint"],
        signature=row["signature"],
        test_identity=row["test_identity"],
        count=row["count"],
        first_seen=row["first_seen"],
        last_seen=row["last_seen"],
        jobs=tuple(json.loads(row["jobs"])),
        oses=tuple(json.loads(row["oses"])),
    )
