"""Thin wrapper around the Anthropic SDK: structured extraction, web-search discovery, refusal handling and cost.

Every call's usage is added to `Llm.cost`, priced by the model that actually served the response.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Generic, Literal, TypeVar, cast

from pydantic import BaseModel, ValidationError

from porygon_mitigator.config import Settings
from porygon_mitigator.models.cve import GenerationCost

T = TypeVar("T", bound=BaseModel)

# $ per million tokens: (input, output, cache read). Cache writes cost 1.25x input; batch requests cost half.
PRICES: dict[str, tuple[float, float, float]] = {
    "claude-opus-5-5": (4.00, 20.00, 0.20),
    "claude-sonnet-5-5": (2.00, 10.00, 0.20),
    "claude-haiku-5-5": (0.10, 0.50, 0.01),
    "claude-fable-5-1": (10.00, 50.00, 0.25),
    "claude-opus-5": (5.00, 25.00, 0.50),
    "claude-sonnet-5": (2.00, 10.00, 0.20),
    "claude-opus-4-8": (5.00, 25.00, 0.50),
}
WEB_SEARCH_USD = 0.01
FALLBACK_BETA = "server-side-fallback-2026-07-01"

Outcome = Literal["ok", "refusal", "truncated", "error"]


def _price(model: str) -> tuple[float, float, float]:
    for name, price in PRICES.items():
        if model.startswith(name):
            return price
    return PRICES["claude-opus-5-5"]


def usage_cost(model: str, usage: Any, *, batch: bool = False) -> float:
    price_in, price_out, price_read = _price(model)
    input_tokens = getattr(usage, "input_tokens", 0) or 0
    output_tokens = getattr(usage, "output_tokens", 0) or 0
    cache_write = getattr(usage, "cache_creation_input_tokens", 0) or 0
    cache_read = getattr(usage, "cache_read_input_tokens", 0) or 0
    dollars = (input_tokens * price_in + output_tokens * price_out + cache_write * price_in * 1.25
               + cache_read * price_read) / 1_000_000
    if batch:
        dollars *= 0.5
    server = getattr(usage, "server_tool_use", None)
    searches = (getattr(server, "web_search_requests", 0) or 0) if server else 0
    return dollars + searches * WEB_SEARCH_USD


def add_usage(total: GenerationCost, model: str, usage: Any, *, batch: bool = False) -> None:
    total.input_tokens += getattr(usage, "input_tokens", 0) or 0
    total.output_tokens += getattr(usage, "output_tokens", 0) or 0
    total.cache_read_input_tokens += getattr(usage, "cache_read_input_tokens", 0) or 0
    total.cache_creation_input_tokens += getattr(usage, "cache_creation_input_tokens", 0) or 0
    server = getattr(usage, "server_tool_use", None)
    total.web_searches += (getattr(server, "web_search_requests", 0) or 0) if server else 0
    total.cost_usd = round(total.cost_usd + usage_cost(model, usage, batch=batch), 6)


@dataclass
class ParseResult(Generic[T]):
    outcome: Outcome
    parsed: T | None
    model: str
    note: str = ""


@dataclass
class SearchHit:
    url: str
    title: str = ""
    page_age: str | None = None


@dataclass
class Llm:
    """Claude access for one research run. Not thread-safe; one per run."""

    settings: Settings
    cost: GenerationCost = field(default_factory=GenerationCost)
    _client: Any = None

    def client(self) -> Any:
        if self._client is None:
            import anthropic

            self._client = anthropic.AsyncAnthropic(max_retries=4, timeout=300.0)
        return self._client

    async def parse(
        self,
        *,
        system: str,
        user: str,
        output_format: type[T],
        effort: str | None = None,
        max_tokens: int = 16000,
        model: str | None = None,
    ) -> ParseResult[T]:
        import anthropic

        chosen = model or self.settings.model
        try:
            response = await self.client().beta.messages.parse(
                model=chosen,
                max_tokens=max_tokens,
                system=[{"type": "text", "text": system, "cache_control": {"type": "ephemeral"}}],
                messages=[{"role": "user", "content": user}],
                output_format=output_format,
                output_config={"effort": effort or self.settings.effort},
                betas=[FALLBACK_BETA],
                fallbacks="default",
            )
        except anthropic.BadRequestError as error:
            return ParseResult("error", None, chosen, f"bad request: {error.message}")
        except anthropic.APIError as error:
            return ParseResult("error", None, chosen, f"API error: {type(error).__name__}")
        except ValidationError:
            # The SDK validates the JSON before we see stop_reason, so output cut at max_tokens raises here.
            return ParseResult("truncated", None, chosen, "structured output didn't parse (likely cut at max_tokens)")
        served = str(getattr(response, "model", chosen) or chosen)
        add_usage(self.cost, served, response.usage)
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            return ParseResult("refusal", None, served, f"model declined ({category or 'no category'})")
        if response.stop_reason == "max_tokens":
            return ParseResult("truncated", None, served, "output hit max_tokens")
        parsed = cast(T | None, response.parsed_output)
        if parsed is None:
            return ParseResult("error", None, served, "no structured output")
        return ParseResult("ok", parsed, served)

    async def search(
        self, *, system: str, prompt: str, domains: list[str], max_uses: int = 3, model: str | None = None
    ) -> tuple[list[SearchHit], str]:
        """Run Claude web search restricted to `domains`; return result URLs (in order) and a status note."""
        import anthropic

        chosen = model or self.settings.model
        tool: dict[str, Any] = {
            "type": "web_search_20260209",
            "name": "web_search",
            "max_uses": max_uses,
            "allowed_callers": ["direct"],
        }
        if domains:
            tool["allowed_domains"] = domains
        messages: list[dict[str, Any]] = [{"role": "user", "content": prompt}]
        hits: list[SearchHit] = []
        seen: set[str] = set()
        text_urls: list[str] = []
        note = "ok"
        for _ in range(4):  # initial call + up to 3 pause_turn continuations
            try:
                response = await self.client().messages.create(
                    model=chosen,
                    max_tokens=4096,
                    system=system,
                    messages=cast(Any, messages),
                    tools=cast(Any, [tool]),
                    output_config={"effort": "low"},
                )
            except anthropic.BadRequestError as error:
                return hits, f"web search unavailable: {error.message}"
            except anthropic.APIError as error:
                return hits, f"web search failed: {type(error).__name__}"
            add_usage(self.cost, str(getattr(response, "model", chosen) or chosen), response.usage)
            for block in response.content:
                if block.type == "web_search_tool_result":
                    content = block.content
                    if isinstance(content, list):
                        for item in content:
                            url = getattr(item, "url", "")
                            if url and url not in seen:
                                seen.add(url)
                                hits.append(SearchHit(url=url, title=getattr(item, "title", "") or "",
                                                      page_age=getattr(item, "page_age", None)))
                    else:
                        note = f"search error: {getattr(content, 'error_code', 'unknown')}"
                elif block.type == "text":
                    text_urls.extend(re.findall(r"https://[^\s<>()\"'\]]+", block.text))
            if response.stop_reason != "pause_turn":
                break
            messages = [*messages, {"role": "assistant", "content": response.content}]
        # Claude's own ranking (the URLs it listed) first, then the remaining search results.
        ordered: list[SearchHit] = []
        by_url = {hit.url: hit for hit in hits}
        for url in text_urls:
            url = url.rstrip(".,;")
            if url not in {hit.url for hit in ordered}:
                ordered.append(by_url.get(url, SearchHit(url=url)))
        ordered.extend(hit for hit in hits if hit.url not in {item.url for item in ordered})
        return ordered, note
