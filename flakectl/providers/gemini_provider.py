"""Hosted provider: Google Gemini, with function calling.

The third hosted backend behind the same interface, and the clearest
evidence that the adapter boundary in :mod:`flakectl.providers.base` is
real rather than aspirational: the orchestrator, the tool layer, the
budget, the schema, the taxonomy and the eval harness are all unchanged.
Only this file knows what a Gemini request looks like.

Uses ``urllib`` from the standard library, so no extra dependency and the
transport can be swapped for a fake in tests. The API key is read from the
environment when the request is made; it is never stored, logged, or
written to a report.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from collections.abc import Callable
from typing import Any

from flakectl.providers.anthropic_provider import SYSTEM_PROMPT, _schema_for
from flakectl.providers.base import AnalysisRequest, ProviderError, ProviderResult
from flakectl.tools import BudgetExceeded, ToolError, ToolLayer

DEFAULT_ENDPOINT = "https://generativelanguage.googleapis.com/v1beta/models"
DEFAULT_MODEL = "gemini-3.6-flash"
DEFAULT_MAX_TURNS = 8
DEFAULT_TIMEOUT_SECONDS = 120

#: Environment variables checked for a key, in order.
KEY_VARIABLES = ("GEMINI_API_KEY", "GOOGLE_API_KEY")

#: A callable taking (url, headers, json body) and returning the decoded response.
Transport = Callable[[str, dict[str, str], dict[str, Any]], dict[str, Any]]


def _http_transport(
    url: str, headers: dict[str, str], body: dict[str, Any], timeout: int
) -> dict[str, Any]:
    """POST JSON to the Gemini REST API."""
    payload = json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        url, data=payload, headers={"Content-Type": "application/json", **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            return json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")[:400]
        raise ProviderError(f"Gemini returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise ProviderError(f"could not reach the Gemini API ({exc.reason})") from exc


#: JSON Schema keywords Gemini's OpenAPI-subset validator rejects outright.
_UNSUPPORTED_SCHEMA_KEYS = ("additionalProperties", "$schema", "definitions", "$defs")


def to_gemini_schema(schema: Any) -> Any:
    """Strip JSON Schema keywords Gemini's schema validator does not accept.

    Gemini takes an OpenAPI 3 subset rather than full JSON Schema, so a
    schema that is valid for the Anthropic path returns a 400 here. The
    shared schema stays canonical; this converts on the way out.
    """
    if isinstance(schema, list):
        return [to_gemini_schema(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    return {
        key: to_gemini_schema(value)
        for key, value in schema.items()
        if key not in _UNSUPPORTED_SCHEMA_KEYS
    }


def _function_declarations() -> list[dict[str, Any]]:
    """Convert the shared tool definitions into Gemini's schema shape."""
    return [
        {
            "name": definition["name"],
            "description": definition["description"],
            "parameters": to_gemini_schema(definition["input_schema"]),
        }
        for definition in ToolLayer.definitions()
    ]


def _strip_fences(text: str) -> str:
    """Remove a ```json fence if the model wrapped its answer in one."""
    stripped = text.strip()
    if not stripped.startswith("```"):
        return stripped
    body = stripped.split("\n", 1)[1] if "\n" in stripped else ""
    return body.rsplit("```", 1)[0].strip()


class GeminiProvider:
    """Categorize with a hosted Gemini model over the flakectl tool layer."""

    name = "gemini"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        api_key: str | None = None,
        endpoint: str = DEFAULT_ENDPOINT,
        transport: Transport | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        timeout: int = DEFAULT_TIMEOUT_SECONDS,
        use_tools: bool = True,
    ) -> None:
        self.model = model
        self.endpoint = endpoint
        self.max_turns = max_turns
        self.timeout = timeout
        self.use_tools = use_tools
        self._api_key = api_key
        self._transport = transport

    @staticmethod
    def credentials_available() -> bool:
        """Is a Gemini key present in the environment?"""
        return any(os.environ.get(name) for name in KEY_VARIABLES)

    @property
    def api_key(self) -> str:
        """The key, read from the environment on demand.

        Raises:
            ProviderError: If no key is set. The offline provider needs none.
        """
        if self._api_key:
            return self._api_key
        for name in KEY_VARIABLES:
            value = os.environ.get(name)
            if value:
                return value
        raise ProviderError(
            f"no Gemini API key found. Set {' or '.join(KEY_VARIABLES)}, or use the "
            "default offline provider, which needs no credentials."
        )

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        """Run the function-calling loop and return the model's answer."""
        tools = request.tools or ToolLayer()
        system = SYSTEM_PROMPT + "\n\n## Taxonomy\n" + request.taxonomy.prompt_block()
        contents: list[dict[str, Any]] = [
            {"role": "user", "parts": [{"text": request.as_prompt_context()}]}
        ]
        tool_calls = 0

        for _ in range(self.max_turns):
            response = self._send(system, contents, request)
            candidate = self._first_candidate(response)
            parts = candidate.get("content", {}).get("parts", []) or []

            calls = [part["functionCall"] for part in parts if "functionCall" in part]
            if not calls:
                text = "".join(part.get("text", "") for part in parts)
                return ProviderResult(
                    payload=self._parse(text),
                    model=response.get("modelVersion", self.model),
                    tool_calls=tool_calls,
                )

            contents.append({"role": "model", "parts": parts})
            results, budget_spent = self._run_tools(tools, calls)
            tool_calls += len(calls)
            contents.append({"role": "user", "parts": results})
            if budget_spent:
                contents.append(
                    {
                        "role": "user",
                        "parts": [
                            {
                                "text": (
                                    "Your tool budget is spent. Answer now with the evidence "
                                    "you already have, or answer 'unknown' if it is not enough."
                                )
                            }
                        ],
                    }
                )

        raise ProviderError(f"no final answer after {self.max_turns} turns")

    # -- internals -------------------------------------------------------

    def _send(
        self, system: str, contents: list[dict[str, Any]], request: AnalysisRequest
    ) -> dict[str, Any]:
        body: dict[str, Any] = {
            "system_instruction": {"parts": [{"text": system}]},
            "contents": contents,
        }
        if self.use_tools:
            # Gemini rejects a response schema combined with function
            # declarations, so when tools are on we constrain the answer by
            # prompt and let the orchestrator's schema gate and bounded
            # retry do the enforcing instead.
            body["tools"] = [{"function_declarations": _function_declarations()}]
        else:
            body["generationConfig"] = {
                "responseMimeType": "application/json",
                "responseSchema": to_gemini_schema(_schema_for(request.taxonomy.names)),
            }

        url = f"{self.endpoint}/{self.model}:generateContent"
        headers = {"x-goog-api-key": self.api_key}

        if self._transport is not None:
            return self._transport(url, headers, body)
        return _http_transport(url, headers, body, self.timeout)

    @staticmethod
    def _first_candidate(response: dict[str, Any]) -> dict[str, Any]:
        """Pull the first candidate out, turning refusals into provider errors."""
        if "error" in response:
            message = response["error"].get("message", response["error"])
            raise ProviderError(f"Gemini error: {message}")

        candidates = response.get("candidates") or []
        if not candidates:
            blocked = response.get("promptFeedback", {}).get("blockReason")
            raise ProviderError(
                f"Gemini returned no candidates (blockReason={blocked})"
                if blocked
                else f"Gemini returned no candidates: {response!r}"
            )

        candidate = candidates[0]
        reason = candidate.get("finishReason")
        if reason in {"SAFETY", "RECITATION", "BLOCKLIST", "PROHIBITED_CONTENT"}:
            raise ProviderError(f"the model declined to analyse this failure ({reason})")
        return candidate

    def _run_tools(
        self, tools: ToolLayer, calls: list[dict[str, Any]]
    ) -> tuple[list[dict[str, Any]], bool]:
        """Execute the requested functions, converting caps into tool errors."""
        results: list[dict[str, Any]] = []
        budget_spent = False
        for call in calls:
            name = call.get("name", "")
            try:
                output = tools.call(name, dict(call.get("args") or {}))
                payload = {"result": output}
            except BudgetExceeded as exc:
                payload = {"error": f"budget exceeded: {exc}"}
                budget_spent = True
            except ToolError as exc:
                payload = {"error": str(exc)}
            results.append({"functionResponse": {"name": name, "response": payload}})
        return results, budget_spent

    @staticmethod
    def _parse(text: str) -> Any:
        """Parse the final message as JSON, tolerating a markdown fence."""
        try:
            return json.loads(_strip_fences(text))
        except json.JSONDecodeError:
            return text
