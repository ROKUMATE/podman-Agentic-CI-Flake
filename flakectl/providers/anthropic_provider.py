"""Hosted provider: Claude, with a real tool-calling loop.

This is the agentic path from the proposal. The model starts with the
sliced failure and can call back for more — additional log context, the
failing spec's source at the commit that failed, the fingerprint's history,
recent commits touching the code under test, existing flake issues — and
every one of those calls is metered by :class:`~flakectl.tools.ToolBudget`
rather than by asking the model to be frugal.

The SDK is imported lazily so the offline path never needs it installed,
and the API key is read from the environment only when this provider is
explicitly selected. It is never persisted or logged.
"""

from __future__ import annotations

import json
import os
from copy import deepcopy
from typing import Any

from flakectl.providers.base import AnalysisRequest, ProviderError, ProviderResult
from flakectl.schema import ANALYSIS_SCHEMA, PROMPT_VERSION
from flakectl.tools import BudgetExceeded, ToolError, ToolLayer

#: Latest Claude model at the time of writing.
DEFAULT_MODEL = "claude-opus-5"

#: Ceiling on agent turns, independent of the tool budget.
DEFAULT_MAX_TURNS = 8

DEFAULT_MAX_TOKENS = 16000

SYSTEM_PROMPT = f"""\
You are triaging a failing test from Podman's CI (GitHub Actions; Ginkgo and \
bats suites across several distros, rootful and rootless). Your job is to \
decide which category of failure this is, and to back that decision with \
evidence from the log.

Rules you must follow:

1. Answer with the given JSON schema. Nothing else.
2. Cite verbatim log lines in `evidence`. Never paraphrase, never invent a line.
3. Prefer `unknown` over a guess. A tool that abstains on the failures it \
cannot read is more useful than one that is confidently wrong; abstention is \
an expected outcome, not a failure.
4. `is_likely_regression` is a separate judgement from `category`. Set it true \
only when the evidence points at a real behaviour change in Podman itself. A \
real regression must never be quietly absorbed into a flake category.
5. Use the tools when the sliced window is not enough. Reading the failing \
spec's source is how you tell a test that waits with a fixed sleep apart from a \
genuine product race. Your tool budget is finite and enforced outside your \
control; if a call is refused, answer with what you already have.
6. The re-run evidence in the failure record is deterministic ground truth. \
If it says the test passed on a re-run at the same commit, the failure is \
non-deterministic — do not call it a regression.

Prompt version: {PROMPT_VERSION}
"""


def _schema_for(valid_categories: tuple[str, ...]) -> dict[str, Any]:
    """Constrain the schema's category field to the loaded taxonomy."""
    schema = deepcopy(ANALYSIS_SCHEMA)
    schema["properties"]["category"]["enum"] = list(valid_categories)
    return schema


def _text_of(response: Any) -> str:
    """Concatenate the text blocks of a response."""
    return "".join(block.text for block in response.content if block.type == "text")


class AnthropicProvider:
    """Categorize with a hosted Claude model over the flakectl tool layer."""

    name = "anthropic"

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        *,
        client: Any | None = None,
        max_turns: int = DEFAULT_MAX_TURNS,
        max_tokens: int = DEFAULT_MAX_TOKENS,
    ) -> None:
        self.model = model
        self.max_turns = max_turns
        self.max_tokens = max_tokens
        self._client = client

    @property
    def client(self) -> Any:
        """The Anthropic client, constructed on first use.

        Raises:
            ProviderError: If the SDK is not installed or no credentials are
                available. The offline provider needs neither.
        """
        if self._client is not None:
            return self._client
        try:
            import anthropic
        except ImportError as exc:  # pragma: no cover - depends on install extras
            raise ProviderError(
                "the 'anthropic' package is not installed. Install it with "
                "`pip install -e \".[llm]\"`, or use the default offline provider."
            ) from exc
        try:
            self._client = anthropic.Anthropic()
        except Exception as exc:  # pragma: no cover - depends on environment
            raise ProviderError(
                f"could not construct an Anthropic client ({exc}). Set ANTHROPIC_API_KEY, "
                "or use the default offline provider, which needs no credentials."
            ) from exc
        return self._client

    @staticmethod
    def credentials_available() -> bool:
        """Is an API key present in the environment?

        Used to give a clear message before starting work, rather than
        failing partway through a batch.
        """
        return bool(os.environ.get("ANTHROPIC_API_KEY"))

    def analyze(self, request: AnalysisRequest) -> ProviderResult:
        """Run the tool-calling loop and return the model's structured answer."""
        tools = request.tools or ToolLayer()
        messages: list[dict[str, Any]] = [
            {"role": "user", "content": request.as_prompt_context()}
        ]
        schema = _schema_for(request.taxonomy.names)
        tool_calls = 0

        for _ in range(self.max_turns):
            response = self.client.messages.create(
                model=self.model,
                max_tokens=self.max_tokens,
                system=SYSTEM_PROMPT + "\n\n## Taxonomy\n" + request.taxonomy.prompt_block(),
                messages=messages,
                tools=ToolLayer.definitions(),
                output_config={"format": {"type": "json_schema", "schema": schema}},
            )

            # A declined request returns 200 with empty or partial content.
            if response.stop_reason == "refusal":
                raise ProviderError(
                    "the model declined to analyse this failure "
                    f"({getattr(response, 'stop_details', None)})"
                )

            tool_uses = [block for block in response.content if block.type == "tool_use"]
            if not tool_uses:
                return ProviderResult(
                    payload=self._parse(_text_of(response)),
                    model=getattr(response, "model", self.model),
                    tool_calls=tool_calls,
                )

            messages.append({"role": "assistant", "content": response.content})
            results, budget_spent = self._run_tools(tools, tool_uses)
            tool_calls += len(tool_uses)
            messages.append({"role": "user", "content": results})
            if budget_spent:
                messages.append(
                    {
                        "role": "user",
                        "content": (
                            "Your tool budget is spent. Answer now with the evidence you "
                            "already have, or answer 'unknown' if it is not enough."
                        ),
                    }
                )

        raise ProviderError(f"no final answer after {self.max_turns} turns")

    def _run_tools(
        self, tools: ToolLayer, tool_uses: list[Any]
    ) -> tuple[list[dict[str, Any]], bool]:
        """Execute the requested tools, converting caps into tool errors.

        A spent budget is reported back to the model as a tool error rather
        than raised, so the turn can still end in a valid answer.
        """
        results: list[dict[str, Any]] = []
        budget_spent = False
        for use in tool_uses:
            try:
                content = tools.call(use.name, dict(use.input))
                is_error = False
            except BudgetExceeded as exc:
                content = f"budget exceeded: {exc}"
                is_error = True
                budget_spent = True
            except ToolError as exc:
                content = str(exc)
                is_error = True
            results.append(
                {
                    "type": "tool_result",
                    "tool_use_id": use.id,
                    "content": content,
                    "is_error": is_error,
                }
            )
        return results, budget_spent

    @staticmethod
    def _parse(text: str) -> Any:
        """Parse the model's final message as JSON.

        The schema constrains the response, but a malformed answer is
        handled by the orchestrator's retry rather than crashing the run.
        """
        try:
            return json.loads(text)
        except json.JSONDecodeError:
            return text
