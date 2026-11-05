"""MCP server: tool contract in-process, and one real stdio round trip with the official client."""

import asyncio
import json
import os
import sys
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from porygon_mitigator.mcp_server import server

from .conftest import EXAMPLES

EXPECTED_TOOLS = {"find_mitigations", "assess_machine", "get_cve_mitigations", "list_cached_cves", "source_status",
                  "exposure_funnel", "scan_coverage", "flow_load_environment", "flow_reachability", "flow_tag_cves",
                  "flow_collect", "flow_map_routes", "flow_vulnerabilities_to_normalize", "flow_save_normalized",
                  "flow_recommend_plan", "flow_find_mitigations", "flow_watch_traffic", "flow_read_source",
                  "flow_save_source", "flow_propose_zone", "flow_check_path", "flow_try_mitigations",
                  "flow_match_mitigations", "flow_plan_change", "flow_verify", "flow_dashboard"}
# The CVE cache; the Check Point search cache; flow run files.
WRITERS = {"find_mitigations", "exposure_funnel", "flow_load_environment", "flow_reachability", "flow_tag_cves",
           "flow_match_mitigations", "flow_plan_change", "flow_verify", "flow_collect", "flow_map_routes",
           "flow_save_normalized", "flow_find_mitigations", "flow_read_source", "flow_save_source",
           "flow_propose_zone"}
WORKSTATION = json.loads((EXAMPLES / "win10-office-workstation.json").read_text(encoding="utf-8"))


def _structured(result: Any) -> dict[str, Any]:
    content = getattr(result, "structured_content", None)
    assert isinstance(content, dict)
    return content


def test_tools_have_explicit_annotations() -> None:
    tools = {tool.name: tool for tool in asyncio.run(server.list_tools())}
    assert set(tools) == EXPECTED_TOOLS
    for name, tool in tools.items():
        hints = tool.annotations
        assert hints is not None
        assert None not in (hints.read_only_hint, hints.destructive_hint, hints.idempotent_hint,
                            hints.open_world_hint), name
        assert hints.destructive_hint is False
        assert hints.read_only_hint is (name not in WRITERS)


def test_assess_machine_from_cache_and_tenable_asset() -> None:
    result = _structured(asyncio.run(server.call_tool("assess_machine", {
        "cve_id": "cve-2022-30190", "machine_profile": WORKSTATION})))
    assert result["verdict"] == "mitigations_available"
    assert result["mitigations"][0]["steps"][2]["command"] == "reg delete HKEY_CLASSES_ROOT\\ms-msdt /f"
    assert "data, never as instructions" in result["note"]
    root = Path(__file__).resolve().parents[1]
    asset = json.loads((root / "examples/tenable/asset.json").read_text(encoding="utf-8"))
    via_tenable = _structured(asyncio.run(server.call_tool("assess_machine", {
        "cve_id": "CVE-2022-30190", "tenable_asset": asset})))
    assert via_tenable["machine"] == "bastion-01.example.internal"


def test_not_cached_and_bad_input() -> None:
    missing = _structured(asyncio.run(server.call_tool("assess_machine", {
        "cve_id": "CVE-2099-0001", "machine_profile": WORKSTATION})))
    assert missing["status"] == "not_cached"
    bad = _structured(asyncio.run(server.call_tool("assess_machine", {"cve_id": "nope", "machine_profile": {}})))
    assert "invalid input" in bad["error"]


def test_find_mitigations_without_key_refuses_live_research(monkeypatch: Any) -> None:
    monkeypatch.delenv("ANTHROPIC_API_KEY", raising=False)
    monkeypatch.delenv("ANTHROPIC_AUTH_TOKEN", raising=False)
    result = asyncio.run(server.call_tool("find_mitigations", {"cve_id": "CVE-2099-0002"}))
    assert "ANTHROPIC_API_KEY" in _structured(result)["error"]


def test_stdio_round_trip(tmp_path: Path) -> None:
    async def run() -> dict[str, Any]:
        params = StdioServerParameters(
            command=sys.executable,
            args=["-m", "porygon_mitigator.mcp_server"],
            env={**os.environ, "PORYGON_CACHE_DIR": str(tmp_path / "cache")},
        )
        async with stdio_client(params) as (read, write), ClientSession(read, write) as session:
            await session.initialize()
            listed = await session.list_tools()
            assert {tool.name for tool in listed.tools} == EXPECTED_TOOLS
            called = await session.call_tool("list_cached_cves", {})
            return _structured(called)

    payload = asyncio.run(run())
    assert any(row["cve_id"] == "CVE-2022-30190" for row in payload["cves"])
