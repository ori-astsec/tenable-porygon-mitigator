"""The eval's Claude calls on Amazon Bedrock instead of the Claude API (`--bedrock`), for teams whose Claude access
goes through AWS. Credentials and region come from the usual AWS settings (AWS_PROFILE, AWS_REGION).

Only the eval uses this: the product always calls the Claude API with ANTHROPIC_API_KEY. Bedrock has no Message
Batches API, so Bedrock passes run online at full price, and no server-side fallbacks, so the judge goes without them.
The eval's inputs are public advisories, so requests use global cross-region inference profiles.
"""

from __future__ import annotations

import re
from types import SimpleNamespace
from typing import Any

from porygon_mitigator.config import Settings
from porygon_mitigator.extract.llm import Llm

INFERENCE_PROFILE_PREFIX = "global.anthropic."


def bedrock_model(model: str) -> str:
    """'claude-opus-5-5' -> 'global.anthropic.claude-opus-5-5'. A Bedrock ID is kept as given."""
    return model if "anthropic." in model else INFERENCE_PROFILE_PREFIX + model


def api_model(model: str) -> str:
    """The Claude API name of a model ('global.anthropic.claude-opus-5-5' -> 'claude-opus-5-5'), so pricing and the
    served-model check read the same on both."""
    return re.sub(r"-v\d+:\d+$", "", model.split("anthropic.", 1)[-1])


def messages_client(bedrock: bool) -> Any:
    """The async client the runner sends extraction requests through."""
    import anthropic

    return anthropic.AsyncAnthropicBedrock(max_retries=4) if bedrock else anthropic.AsyncAnthropic(max_retries=4)


class _BedrockParse:
    """Stands in for `client.beta.messages` inside Llm.parse, so the judge runs that code unchanged on Bedrock."""

    def __init__(self) -> None:
        import anthropic

        self.client: Any = anthropic.AsyncAnthropicBedrock(max_retries=4, timeout=300.0)

    async def parse(self, **params: Any) -> Any:
        params.pop("fallbacks", None)  # Bedrock has no server-side fallbacks;
        params.pop("betas", None)  # the only beta Llm.parse sends is theirs
        params["model"] = bedrock_model(params["model"])
        response = await self.client.beta.messages.parse(**params)
        response.model = api_model(str(response.model))
        return response


class _BedrockClient:
    def __init__(self) -> None:
        self.beta = SimpleNamespace(messages=_BedrockParse())

    async def close(self) -> None:
        await self.beta.messages.client.close()


def judge_llm(settings: Settings, bedrock: bool) -> Llm:
    return Llm(settings, _client=_BedrockClient()) if bedrock else Llm(settings)


async def close_llm(llm: Llm) -> None:
    """Close the client an Llm opened, so it isn't torn down after its event loop has closed."""
    if llm._client is not None:
        await llm._client.close()
