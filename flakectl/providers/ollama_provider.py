"""Local provider: a model served by Ollama on the same machine.

Local-first inference is the target the proposal argues for: CI logs are
Red Hat infrastructure data, and a triage tool that ships them to a hosted
API is a harder sell than one that does not. This adapter exists to prove
the boundary in :mod:`flakectl.providers.base` is real — the orchestrator,
schema, taxonomy and eval harness are identical whichever backend runs.

It is single-shot rather than tool-calling: smaller local models handle a
constrained JSON answer far more reliably than a multi-turn tool loop, and
the honest thing is to ship the version that works. Tool support here is a
next step, not a claim.

Uses ``urllib`` from the standard library, so nothing extra is installed and
the transport can be swapped for a fake in tests.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from flakectl.providers.anthropic_provider import SYSTEM_PROMPT, _schema_for
from flakectl.providers.base import AnalysisRequest, ProviderError, ProviderResult

DEFAULT_ENDPOINT = "http://localhost:11434/api/chat"
DEFAULT_MODEL = "llama3.1"
DEFAULT_TIMEOUT_SECONDS = 120

#: A callable taking (url, json body) and returning the decoded response.
Transport = Callable[[str, dict[str, Any]], dict[str, Any]]


def _http_transport(url: str, body: dict[str, Any], timeout: int) -> dict[str, Any]:
    """POST JSON to a local Ollama server."""
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json"}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        raise ProviderError(
            f"could not reach Ollama at {url} ({exc.reason}). Start it with `ollama serve`, "
            "or use the default offline provider, which needs no server."
        ) from exc


class OllamaProvider:
    """Categorize with a locally served model."""

    name = "ollama"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        endpoint: str = DEFAULT_ENDPOINT,
        transport: Transport | None = None,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
    ) -> None:
        self.model = model
        self.endpoint = endpoint
        self.timeout = timeout
        self._transport = transport

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        """Ask the local model for a schema-constrained answer."""
        body = {
            "model": self.model,
            "stream": False,
            # Ollama constrains generation to a JSON schema passed as `format`.
            "format": _schema_for(request.taxonomy.names),
            "messages": [
                {
                    "role": "system",
                    "content": SYSTEM_PROMPT + "\n\n## Taxonomy\n" + request.taxonomy.prompt_block(),
                },
                {"role": "user", "content": request.as_prompt_context()},
            ],
        }

        transport = self._transport
        response = (
            transport(self.endpoint, body)
            if transport is not None
            else _http_transport(self.endpoint, body, self.timeout)
        )

        content = response.get("message", {}).get("content")
        if not isinstance(content, str):
            raise ProviderError(f"unexpected response shape from Ollama: {response!r}")

        try:
            payload: Any = json.loads(content)
        except json.JSONDecodeError:
            payload = content
        return ProviderResult(payload=payload, model=response.get("model", self.model))
