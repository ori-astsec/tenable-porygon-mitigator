"""A PAN-OS XML API client that can only read.

The host is the user's own firewall or Panorama, so it isn't in the egress registry: it is reached only when the user
names it. Every call goes through `_call`, which refuses anything that could change the device: op commands must be
`<show>`, config calls must be `get` or `show`, and logs are read only. Set `target` to a firewall's serial number to
proxy each call through Panorama to that firewall.
"""

from __future__ import annotations

import asyncio
import os
import xml.etree.ElementTree as ET

import httpx

API_KEY_ENV = "PANOS_API_KEY"
CA_BUNDLE_ENV = "PANOS_CA_BUNDLE"
READ_TYPES = ("op", "config", "log")
CONFIG_READ_ACTIONS = ("get", "show")
LOG_POLL_SECONDS = 1.0
LOG_POLL_ATTEMPTS = 60
MAX_LOGS = 5000  # the API's own cap per query


class PanosError(RuntimeError):
    """The device answered with an error, or a call would not have been read-only."""


def _parse(body: bytes) -> ET.Element:
    if b"<!DOCTYPE" in body[:4096] or b"<!ENTITY" in body:
        raise PanosError("refusing an XML response with a DTD")
    try:
        root = ET.fromstring(body)  # noqa: S314 - DTDs refused above
    except ET.ParseError as error:
        raise PanosError(f"response isn't XML: {error}") from error
    if root.get("status") != "success":
        message = " ".join(text.strip() for text in root.itertext() if text.strip())
        raise PanosError(f"device returned {root.get('status') or 'no status'}: {message[:300]}")
    return root


class PanosClient:
    """Use as `async with PanosClient(host) as client:`. The API key comes from PANOS_API_KEY unless given."""

    def __init__(self, host: str, *, api_key: str | None = None, target: str | None = None,
                 verify: bool | str = True, transport: httpx.AsyncBaseTransport | None = None,
                 timeout: float = 120.0) -> None:
        key = api_key or os.environ.get(API_KEY_ENV)
        if not key:
            raise PanosError(f"{API_KEY_ENV} is not set")
        if verify is True and os.environ.get(CA_BUNDLE_ENV):
            verify = os.environ[CA_BUNDLE_ENV]
        self.host = host
        self.target = target
        self._url = httpx.URL(scheme="https", host=host, path="/api/")
        self._client = httpx.AsyncClient(headers={"X-PAN-KEY": key}, verify=verify, transport=transport,
                                         timeout=timeout, follow_redirects=False)

    async def __aenter__(self) -> PanosClient:
        return self

    async def __aexit__(self, *exc: object) -> None:
        await self._client.aclose()

    async def _call(self, params: dict[str, str]) -> ET.Element:
        kind = params.get("type", "")
        if kind not in READ_TYPES:
            raise PanosError(f"refusing API type {kind!r}: only {', '.join(READ_TYPES)} are read-only")
        if kind == "op" and not params.get("cmd", "").lstrip().startswith("<show>"):
            raise PanosError("refusing an op command that isn't <show>")
        if kind == "config" and params.get("action") not in CONFIG_READ_ACTIONS:
            raise PanosError(f"refusing config action {params.get('action')!r}")
        if kind == "log" and params.get("action", "get") != "get":
            raise PanosError("refusing a log action other than reading")
        if self.target:
            params = {**params, "target": self.target}
        try:
            response = await self._client.get(self._url, params=params)
        except httpx.HTTPError as error:
            raise PanosError(f"can't reach {self.host}: {type(error).__name__}") from error
        if response.status_code >= 400:
            raise PanosError(f"HTTP {response.status_code} from {self.host}")
        return _parse(response.content)

    async def op(self, cmd: str) -> ET.Element:
        return await self._call({"type": "op", "cmd": cmd})

    async def config(self, xpath: str, *, running: bool = True) -> ET.Element | None:
        """The config at `xpath`: running (`show`) or candidate (`get`). None when nothing is there."""
        root = await self._call({"type": "config", "action": "show" if running else "get", "xpath": xpath})
        result = root.find("result")
        if result is None or len(result) == 0:
            return None
        return result[0] if len(result) == 1 else result

    async def logs(self, log_type: str, query: str, nlogs: int = MAX_LOGS) -> list[ET.Element]:
        """Run a log query (an async job on the device) and return its entries."""
        started = await self._call({"type": "log", "log-type": log_type, "query": query,
                                    "nlogs": str(min(nlogs, MAX_LOGS))})
        job = started.findtext("result/job")
        if not job:
            raise PanosError("log query returned no job id")
        for _attempt in range(LOG_POLL_ATTEMPTS):
            result = await self._call({"type": "log", "action": "get", "job-id": job.strip()})
            if result.findtext("result/job/status") == "FIN":
                return list(result.iterfind("result/log/logs/entry"))
            await asyncio.sleep(LOG_POLL_SECONDS)
        raise PanosError(f"log job {job} didn't finish")


def members(element: ET.Element | None, tag: str) -> list[str]:
    """`<tag><member>a</member>...</tag>` as a list."""
    if element is None:
        return []
    node = element.find(tag)
    return [] if node is None else [(item.text or "").strip() for item in node.iterfind("member")]


def first_child_tag(element: ET.Element | None, tag: str) -> str:
    """`<action><drop/></action>` -> `drop`."""
    node = element.find(tag) if element is not None else None
    return node[0].tag if node is not None and len(node) else ""


def text(element: ET.Element | None, path: str, default: str = "") -> str:
    if element is None:
        return default
    return (element.findtext(path) or default).strip()
