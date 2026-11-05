---
description: Allow Porygon to read source files from a folder, so its agent can convert them
argument-hint: <folder>
disable-model-invocation: true
allowed-tools: Bash(uv run --directory ${CLAUDE_PLUGIN_ROOT} porygon flow allow-source:*)
---

You allowed this folder by typing this command.

!`uv run --directory ${CLAUDE_PLUGIN_ROOT} porygon flow allow-source $ARGUMENTS 2>&1`

Report the result above plainly. If it worked, go on reading the source the person named.
