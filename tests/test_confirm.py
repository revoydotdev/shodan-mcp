"""Tests for the shodan confirm-gate (credit-spending protection)."""

from __future__ import annotations

import asyncio

from shodan_mcp.confirm import Preview, confirm_required
from shodan_mcp.server import mcp


def test_confirm_false_returns_preview_not_execute() -> None:
    calls: list[dict] = []

    @confirm_required("scan")
    def scan(ips: str = "", confirm: bool = False) -> dict:
        calls.append({"ips": ips})
        return {"ok": True}

    preview = scan(ips="1.2.3.4")
    assert isinstance(preview, Preview)
    assert preview.preview is True
    assert preview.target == "1.2.3.4"
    assert calls == []


def test_confirm_true_executes() -> None:
    calls: list[dict] = []

    @confirm_required("scan")
    def scan(ips: str = "", confirm: bool = False) -> dict:
        calls.append({"ips": ips})
        return {"ok": True, "scan_id": "x"}

    result = scan(ips="1.2.3.4", confirm=True)
    assert result == {"ok": True, "scan_id": "x"}
    assert calls == [{"ips": "1.2.3.4"}]


def test_target_resolution_skips_empty() -> None:
    @confirm_required("act")
    def op(query: str = "", domain: str = "") -> dict:
        return {"ok": True}

    preview = op(query="", domain="example.com")
    assert isinstance(preview, Preview)
    assert preview.target == "example.com"


def test_describe_overrides_would_do() -> None:
    def describe(args: dict) -> str:
        return f"scan {args['ips']} with these ports"

    @confirm_required("scan", describe=describe)
    def op(ips: str = "", confirm: bool = False) -> dict:
        return {"ok": True}

    preview = op(ips="10.0.0.1")
    assert isinstance(preview, Preview)
    assert preview.would_do == "scan 10.0.0.1 with these ports"


def test_confirm_gated_tools_are_tagged_for_read_only_mode() -> None:
    """Read-only mode must be able to identify every confirm-gated action."""
    tools = {tool.name: tool for tool in asyncio.run(mcp._list_tools())}
    for name in ("search_ingest", "scan", "alert_create", "alert_remove"):
        assert "mutating" in (tools[name].tags or set())
