"""Entrypoint: `python -m shodan_mcp` (stdio MCP server)."""

from __future__ import annotations

from shodan_mcp.server import build_server


def main() -> None:
    build_server().run()


if __name__ == "__main__":
    main()
