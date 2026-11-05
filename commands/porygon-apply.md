---
description: Approve a Porygon plan and apply it to the simulated environment and the local mock firewall
argument-hint: <plan hash> [--tenable-execute] [--rescan-scan-id ID]
disable-model-invocation: true
allowed-tools: Bash(uv run --directory ${CLAUDE_PLUGIN_ROOT} porygon flow apply:*)
---

You approved this plan by typing this command.

!`uv run --directory ${CLAUDE_PLUGIN_ROOT} porygon flow apply $ARGUMENTS 2>&1`

Report the result above plainly. If it applied, say it changed the simulated environment, plus the mock firewall on this
machine if the output says calls were sent, and no real device, then call `flow_verify`, then `flow_dashboard`. If a Tenable follow-up is listed, say whether it was a dry run or executed, and what Tenable can't
do. If it failed, show the error and don't retry.
