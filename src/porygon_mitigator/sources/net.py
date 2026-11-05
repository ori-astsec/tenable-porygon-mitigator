"""The only HTTP client in the package.

- https only, and only hosts in `sources.registry` (every redirect hop is re-checked before it's requested);
- bodies streamed with a hard size cap; known binary downloads are never fetched;
- 429/5xx retried with jittered backoff (Retry-After honoured), at most a few times;
- bounded concurrency and a polite User-Agent.
"""

from __future__ import annotations

import asyncio
import hashlib
import random
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx

from porygon_mitigator.config import USER_AGENT
from porygon_mitigator.sources.registry import is_allowed

MAX_BYTES = 10 * 1024 * 1024
MAX_REDIRECTS = 5
RETRIES = 3
_BINARY_SUFFIXES = (
    ".exe", ".msi", ".msu", ".cab", ".zip", ".7z", ".rar", ".iso", ".img", ".dmg", ".pkg", ".rpm", ".deb",
    ".bin", ".jar", ".war", ".apk", ".vhd", ".vhdx", ".tgz", ".bz2", ".xz",
)  # fmt: skip


class FetchError(Exception):
    """A fetch that failed for a reason worth recording (not allowed, too large, HTTP error...)."""

    def __init__(self, reason: str, status: int | None = None) -> None:
        super().__init__(reason)
        self.reason = reason
        self.status = status


@dataclass
class FetchResult:
    url: str
    final_url: str
    status: int
    content_type: str
    body: bytes
    sha256: str = field(init=False)

    def __post_init__(self) -> None:
        self.sha256 = hashlib.sha256(self.body).hexdigest()

    @property
    def text(self) -> str:
        encoding = "utf-8"
        if "charset=" in self.content_type:
            encoding = self.content_type.split("charset=", 1)[1].split(";")[0].strip() or "utf-8"
        try:
            return self.body.decode(encoding, errors="replace")
        except LookupError:
            return self.body.decode("utf-8", errors="replace")


def _retry_after(response: httpx.Response, attempt: int) -> float:
    header = response.headers.get("Retry-After", "")
    if header.isdigit():
        return min(float(header), 60.0)
    return min(2.0 ** attempt + random.uniform(0, 1), 30.0)  # noqa: S311 - jitter, not crypto


class Http:
    """Async HTTP access restricted to the registry. Use as `async with Http() as http:`."""

    def __init__(self, *, concurrency: int = 6, timeout: float = 30.0, max_bytes: int = MAX_BYTES) -> None:
        self._client = httpx.AsyncClient(
            timeout=httpx.Timeout(timeout, connect=15.0),
            follow_redirects=False,
            headers={"User-Agent": USER_AGENT, "Accept-Language": "en"},
        )
        self._semaphore = asyncio.Semaphore(concurrency)
        self._max_bytes = max_bytes

    async def __aenter__(self) -> Http:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _send(self, method: str, url: str, **kwargs: Any) -> FetchResult:
        current = url
        for _hop in range(MAX_REDIRECTS + 1):
            if not is_allowed(current):
                raise FetchError(f"host not in the egress registry: {urlsplit(current).hostname}")
            if urlsplit(current).path.lower().endswith(_BINARY_SUFFIXES):
                raise FetchError("binary download skipped")
            response = await self._request(method, current, **kwargs)
            if response is None:
                raise FetchError("too large")
            status, headers, body = response
            if status in (301, 302, 303, 307, 308) and "location" in headers:
                # The redirect target carries its own query string; never re-send the original params.
                current = urljoin(str(httpx.URL(current, params=kwargs.pop("params", None))), headers["location"])
                if status == 303:
                    method = "GET"
                continue
            if status >= 400:
                raise FetchError(f"HTTP {status}", status)
            return FetchResult(url, current, status, headers.get("content-type", ""), body)
        raise FetchError("too many redirects")

    async def _request(self, method: str, url: str, **kwargs: Any) -> tuple[int, dict[str, str], bytes] | None:
        for attempt in range(RETRIES + 1):
            async with self._semaphore:
                try:
                    async with self._client.stream(method, url, **kwargs) as response:
                        declared = response.headers.get("content-length", "")
                        if declared.isdigit() and int(declared) > self._max_bytes:
                            return None
                        if response.status_code in (429, 500, 502, 503, 504) and attempt < RETRIES:
                            delay = _retry_after(response, attempt)
                        else:
                            chunks, total = [], 0
                            async for chunk in response.aiter_bytes():
                                total += len(chunk)
                                if total > self._max_bytes:
                                    return None
                                chunks.append(chunk)
                            headers = {k.lower(): v for k, v in response.headers.items()}
                            return response.status_code, headers, b"".join(chunks)
                except (httpx.TransportError, httpx.TimeoutException) as error:
                    if attempt >= RETRIES:
                        raise FetchError(f"network error: {type(error).__name__}") from error
                    delay = min(2.0 ** attempt + random.uniform(0, 1), 30.0)  # noqa: S311
            await asyncio.sleep(delay)
        raise FetchError("retries exhausted")

    async def get(self, url: str, *, params: dict[str, str] | None = None,
                  headers: dict[str, str] | None = None) -> FetchResult:
        kwargs: dict[str, Any] = {}
        if params:
            kwargs["params"] = params
        if headers:
            kwargs["headers"] = headers
        return await self._send("GET", url, **kwargs)

    async def get_json(self, url: str, *, params: dict[str, str] | None = None,
                       headers: dict[str, str] | None = None) -> Any:
        result = await self.get(url, params=params, headers={"Accept": "application/json", **(headers or {})})
        return _json(result)

    async def post_json(self, url: str, body: Any, *, headers: dict[str, str] | None = None) -> Any:
        result = await self._send("POST", url, json=body,
                                  headers={"Accept": "application/json", **(headers or {})})
        return _json(result)


def _json(result: FetchResult) -> Any:
    import json

    try:
        return json.loads(result.body)
    except ValueError as error:
        raise FetchError("response is not JSON") from error
