"""A benchmark for the agent's part of the flow's first two steps, Map (`flow_load_environment`) and Scan
(`flow_reachability`). The deterministic engine has its own checks in `tests/`; this measures what a
model decides: which files it loads, what it does when a load is refused, and whether what it tells the person matches
what the tools returned. `README.md` explains how to run it and use it to improve the prompts.
"""
