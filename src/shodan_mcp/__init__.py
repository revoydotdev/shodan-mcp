"""shodan-mcp — MCP control surface for a Shodan account.

Real subprocess-free wrapper around the `shodan` Python client (no stubs). Read tools
are free/cheap; credit-spending and account-mutating tools (search ingest, scan, alerts)
are confirm-gated — calling them with `confirm=False` (the default) returns a `Preview`
of what would happen instead of executing.
"""

__version__ = "0.1.0"
