"""The flake taxonomy, loaded from maintainer-owned YAML.

The categories are deliberately *not* hardcoded here. A maintainer who wants
to add a category, sharpen a description, or add an example signature edits
``data/taxonomy.yaml`` and opens a review — no Python change, no release.
The categorizer is handed these descriptions at analysis time, so the file
is the actual specification of what the tool means by each label.
"""

from __future__ import annotations

from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

import yaml

#: The taxonomy shipped with flakectl.
DEFAULT_TAXONOMY_PATH = Path(__file__).parent / "data" / "taxonomy.yaml"


class TaxonomyError(ValueError):
    """Raised when the taxonomy file is malformed."""


class UnknownCategory(KeyError):
    """Raised when a category name is not in the taxonomy."""


@dataclass(frozen=True, slots=True)
class Category:
    """One category in the taxonomy."""

    name: str
    summary: str
    description: str
    example_signatures: tuple[str, ...] = ()
    typical_mitigation: str = ""
    escalate: bool = False
    abstain: bool = False


@dataclass(frozen=True, slots=True)
class Taxonomy:
    """The full set of categories a failure may be assigned."""

    version: int
    categories: tuple[Category, ...]

    def __contains__(self, name: object) -> bool:
        return any(category.name == name for category in self.categories)

    def __iter__(self):
        return iter(self.categories)

    def __len__(self) -> int:
        return len(self.categories)

    @property
    def names(self) -> tuple[str, ...]:
        """Every category name, in file order."""
        return tuple(category.name for category in self.categories)

    @property
    def abstain_category(self) -> Category:
        """The category used when the tool declines to answer."""
        for category in self.categories:
            if category.abstain:
                return category
        raise TaxonomyError("taxonomy defines no abstain category")

    @property
    def escalate_categories(self) -> tuple[Category, ...]:
        """Categories that must never be treated as flakes."""
        return tuple(category for category in self.categories if category.escalate)

    @property
    def flake_categories(self) -> tuple[Category, ...]:
        """Categories that describe a genuine flake.

        Everything that is neither an escalation nor an abstention.
        """
        return tuple(
            category
            for category in self.categories
            if not category.escalate and not category.abstain
        )

    def get(self, name: str) -> Category:
        """Look up a category by name.

        Raises:
            UnknownCategory: If no such category is defined.
        """
        for category in self.categories:
            if category.name == name:
                return category
        raise UnknownCategory(
            f"{name!r} is not in the taxonomy; known categories: {', '.join(self.names)}"
        )

    def is_flake(self, name: str) -> bool:
        """Is this category one of the flake categories?"""
        category = self.get(name)
        return not category.escalate and not category.abstain

    def prompt_block(self) -> str:
        """Render the taxonomy as text for a model prompt.

        Keeping this next to the loader means the prompt and the YAML can
        never drift apart.
        """
        lines: list[str] = []
        for category in self.categories:
            lines.append(f"- {category.name}: {category.summary}")
            lines.append(f"  {' '.join(category.description.split())}")
            if category.example_signatures:
                lines.append("  Example signatures:")
                lines.extend(f"    * {signature}" for signature in category.example_signatures)
        return "\n".join(lines)


def _parse(data: object, source: str) -> Taxonomy:
    if not isinstance(data, dict):
        raise TaxonomyError(f"{source}: expected a mapping at the top level")
    raw_categories = data.get("categories")
    if not isinstance(raw_categories, list) or not raw_categories:
        raise TaxonomyError(f"{source}: 'categories' must be a non-empty list")

    categories: list[Category] = []
    seen: set[str] = set()
    for entry in raw_categories:
        if not isinstance(entry, dict) or "name" not in entry:
            raise TaxonomyError(f"{source}: every category needs a 'name'")
        name = str(entry["name"])
        if name in seen:
            raise TaxonomyError(f"{source}: duplicate category {name!r}")
        seen.add(name)
        categories.append(
            Category(
                name=name,
                summary=str(entry.get("summary", "")),
                description=" ".join(str(entry.get("description", "")).split()),
                example_signatures=tuple(entry.get("example_signatures") or ()),
                typical_mitigation=" ".join(str(entry.get("typical_mitigation", "")).split()),
                escalate=bool(entry.get("escalate", False)),
                abstain=bool(entry.get("abstain", False)),
            )
        )

    taxonomy = Taxonomy(version=int(data.get("version", 1)), categories=tuple(categories))
    # Fail loudly at load time rather than at abstention time.
    taxonomy.abstain_category
    return taxonomy


def load_taxonomy(path: str | Path | None = None) -> Taxonomy:
    """Load a taxonomy from YAML.

    Args:
        path: Taxonomy file. Defaults to the one shipped with flakectl.

    Raises:
        TaxonomyError: If the file is malformed or defines no abstain category.
    """
    resolved = Path(path) if path is not None else DEFAULT_TAXONOMY_PATH
    with open(resolved, encoding="utf-8") as handle:
        return _parse(yaml.safe_load(handle), str(resolved))


@lru_cache(maxsize=1)
def default_taxonomy() -> Taxonomy:
    """The shipped taxonomy, parsed once and cached."""
    return load_taxonomy()
