"""Pillar 2 — the deterministic pre-filter.

A maintainer-editable ruleset that classifies the well-understood failure
classes without a model. Rules are cheap, reviewable and versionable; the
agent only ever sees what these cannot resolve.

Matching is first-wins in file order, so specificity is expressed by
ordering rather than by scoring. Every match carries the matched log lines
as evidence, so a maintainer can see *why* a rule fired without re-reading
the log.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

from flakectl.taxonomy import Taxonomy, default_taxonomy

#: The ruleset shipped with flakectl.
DEFAULT_RULES_PATH = Path(__file__).parent / "data" / "rules.yaml"

#: Cap on how many evidence lines one match reports.
MAX_EVIDENCE_LINES = 4


class RulesError(ValueError):
    """Raised when the ruleset is malformed."""


@dataclass(frozen=True, slots=True)
class Rule:
    """One deterministic signature rule."""

    id: str
    category: str
    confidence: float
    any_of: tuple[re.Pattern[str], ...] = ()
    all_of: tuple[re.Pattern[str], ...] = ()
    none_of: tuple[re.Pattern[str], ...] = ()
    mitigation: str = ""


@dataclass(frozen=True, slots=True)
class RuleMatch:
    """A rule that fired, and the lines that made it fire."""

    rule: Rule
    evidence: tuple[str, ...]


def _compile(patterns: object, rule_id: str, field: str, case_sensitive: bool) -> tuple:
    if patterns is None:
        return ()
    if not isinstance(patterns, list):
        raise RulesError(f"rule {rule_id!r}: {field} must be a list of regexes")
    flags = 0 if case_sensitive else re.IGNORECASE
    compiled = []
    for pattern in patterns:
        try:
            compiled.append(re.compile(str(pattern), flags))
        except re.error as exc:
            raise RulesError(f"rule {rule_id!r}: bad regex in {field}: {pattern!r} ({exc})") from exc
    return tuple(compiled)


def _parse(data: object, source: str, taxonomy: Taxonomy) -> tuple[Rule, ...]:
    if not isinstance(data, dict):
        raise RulesError(f"{source}: expected a mapping at the top level")
    raw_rules = data.get("rules")
    if not isinstance(raw_rules, list):
        raise RulesError(f"{source}: 'rules' must be a list")

    rules: list[Rule] = []
    seen: set[str] = set()
    for entry in raw_rules:
        if not isinstance(entry, dict) or "id" not in entry:
            raise RulesError(f"{source}: every rule needs an 'id'")
        rule_id = str(entry["id"])
        if rule_id in seen:
            raise RulesError(f"{source}: duplicate rule id {rule_id!r}")
        seen.add(rule_id)

        category = str(entry.get("category", ""))
        if category not in taxonomy:
            raise RulesError(
                f"rule {rule_id!r}: category {category!r} is not in the taxonomy "
                f"({', '.join(taxonomy.names)})"
            )

        confidence = float(entry.get("confidence", 0.0))
        if not 0.0 <= confidence <= 1.0:
            raise RulesError(f"rule {rule_id!r}: confidence must be between 0 and 1")

        case_sensitive = bool(entry.get("case_sensitive", False))
        any_of = _compile(entry.get("any_of"), rule_id, "any_of", case_sensitive)
        all_of = _compile(entry.get("all_of"), rule_id, "all_of", case_sensitive)
        none_of = _compile(entry.get("none_of"), rule_id, "none_of", case_sensitive)
        if not any_of and not all_of:
            raise RulesError(f"rule {rule_id!r}: needs at least one of any_of/all_of")

        rules.append(
            Rule(
                id=rule_id,
                category=category,
                confidence=confidence,
                any_of=any_of,
                all_of=all_of,
                none_of=none_of,
                mitigation=" ".join(str(entry.get("mitigation", "")).split()),
            )
        )
    return tuple(rules)


class RuleEngine:
    """Applies an ordered ruleset to a failure's output block."""

    def __init__(self, rules: tuple[Rule, ...]) -> None:
        self.rules = rules

    def __len__(self) -> int:
        return len(self.rules)

    def __iter__(self):
        return iter(self.rules)

    def get(self, rule_id: str) -> Rule | None:
        """Look up a rule by id, for report traceability."""
        return next((rule for rule in self.rules if rule.id == rule_id), None)

    def match(self, text: str) -> RuleMatch | None:
        """Find the first rule that fires against ``text``.

        Args:
            text: A failure's output block.

        Returns:
            The winning :class:`RuleMatch`, or ``None`` if nothing matched —
            in which case the failure is a candidate for the agent.
        """
        lines = text.split("\n")
        for rule in self.rules:
            if any(pattern.search(text) for pattern in rule.none_of):
                continue
            if rule.all_of and not all(pattern.search(text) for pattern in rule.all_of):
                continue
            if rule.any_of and not any(pattern.search(text) for pattern in rule.any_of):
                continue
            return RuleMatch(rule=rule, evidence=_evidence(lines, rule))
        return None


def _evidence(lines: list[str], rule: Rule) -> tuple[str, ...]:
    """Collect the log lines that made a rule fire, with line numbers."""
    patterns = rule.any_of + rule.all_of
    found: list[str] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        if any(pattern.search(line) for pattern in patterns):
            found.append(f"L{number}: {line.strip()}")
            if len(found) == MAX_EVIDENCE_LINES:
                break
    return tuple(found)


def load_rules(
    path: str | Path | None = None,
    taxonomy: Taxonomy | None = None,
) -> RuleEngine:
    """Load a ruleset from YAML and validate it against the taxonomy.

    Args:
        path: Rules file. Defaults to the one shipped with flakectl.
        taxonomy: Taxonomy to validate categories against.

    Raises:
        RulesError: If the file is malformed or names an unknown category.
    """
    resolved = Path(path) if path is not None else DEFAULT_RULES_PATH
    with open(resolved, encoding="utf-8") as handle:
        data = yaml.safe_load(handle)
    return RuleEngine(_parse(data, str(resolved), taxonomy or default_taxonomy()))


@lru_cache(maxsize=1)
def default_rules() -> RuleEngine:
    """The shipped ruleset, parsed once and cached."""
    return load_rules()
