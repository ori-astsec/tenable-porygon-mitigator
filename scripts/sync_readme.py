"""Regenerate the README tables that must match the code: outbound endpoints and MCP tools.

    uv run python scripts/sync_readme.py          # rewrite README.md in place
    uv run python scripts/sync_readme.py --check  # exit 1 if README.md is out of date (used by tests)
"""

from __future__ import annotations

import asyncio
import re
import sys
from pathlib import Path

from porygon_mitigator.mcp_server import server
from porygon_mitigator.sources.registry import HOSTS

README = Path(__file__).resolve().parents[1] / "README.md"


def egress_table() -> str:
    rows = ["| Host | Used for | Category |", "|---|---|---|"]
    rows += [f"| `{host.domain}` | {host.purpose} | {host.category} |" for host in HOSTS]
    return "\n".join(rows)


def tools_table() -> str:
    tools = asyncio.run(server.list_tools())
    rows = ["| Tool | Read-only | Network | What it does |", "|---|---|---|---|"]
    for tool in tools:
        hints = tool.annotations
        read_only = "yes" if hints and hints.read_only_hint else "no (writes local files)"
        network = "yes" if hints and hints.open_world_hint else "no"
        description = " ".join((tool.description or "").split())
        first = description.split(". ")[0].rstrip(".") + "."
        rows.append(f"| `{tool.name}` | {read_only} | {network} | {first} |")
    return "\n".join(rows)


def render(text: str) -> str:
    for name, table in (("egress", egress_table()), ("tools", tools_table())):
        pattern = re.compile(rf"(<!-- {name}:start -->\n)(?:.*?\n)?(<!-- {name}:end -->)", re.S)
        if not pattern.search(text):
            raise SystemExit(f"README.md has no <!-- {name}:start/end --> markers")
        text = pattern.sub(lambda match, table=table: match.group(1) + table + "\n" + match.group(2), text)
    return text


def main(argv: list[str]) -> int:
    current = README.read_text(encoding="utf-8")
    updated = render(current)
    if "--check" in argv:
        if updated != current:
            print("README.md tables are out of date: run `uv run python scripts/sync_readme.py`")
            return 1
        return 0
    README.write_text(updated, encoding="utf-8")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
