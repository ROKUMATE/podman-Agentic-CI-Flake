"""Model-provider adapters.

``rules`` is the default and runs entirely offline. ``anthropic`` and
``ollama`` are opt-in and are only imported when selected, so neither the
SDK nor a running server is needed for the default path.
"""

from __future__ import annotations

from flakectl.providers.base import (
    AnalysisRequest,
    Provider,
    ProviderError,
    ProviderResult,
)
from flakectl.providers.rules_provider import RulesProvider

#: Provider names accepted by the CLI, in the order they are offered.
PROVIDER_NAMES = ("rules", "anthropic", "ollama")


def build_provider(name: str, **kwargs: object) -> Provider:
    """Construct a provider by name.

    Args:
        name: One of :data:`PROVIDER_NAMES`.
        **kwargs: Passed to the provider's constructor (e.g. ``model``).

    Raises:
        ProviderError: If the name is not a known provider.
    """
    if name == "rules":
        return RulesProvider()
    if name == "anthropic":
        from flakectl.providers.anthropic_provider import AnthropicProvider

        return AnthropicProvider(**kwargs)  # type: ignore[arg-type]
    if name == "ollama":
        from flakectl.providers.ollama_provider import OllamaProvider

        return OllamaProvider(**kwargs)  # type: ignore[arg-type]
    raise ProviderError(f"unknown provider {name!r}; available: {', '.join(PROVIDER_NAMES)}")


__all__ = [
    "PROVIDER_NAMES",
    "AnalysisRequest",
    "Provider",
    "ProviderError",
    "ProviderResult",
    "RulesProvider",
    "build_provider",
]
