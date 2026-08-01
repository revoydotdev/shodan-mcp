"""FastMCP server for driving a Shodan account.

Tool safety mirrors lutris-mcp/apk-lab-mcp:
- Read tools (account/host/count/search/dns/ports/scans/alerts-list) are free-to-call
  (some spend a query credit per page — noted in their descriptions).
- Credit-spending / account-mutating tools (`search_ingest`, `scan`, `alert_create`,
  `alert_remove`) are ``@confirm_required`` — a first call returns a `Preview`.
- The `tool` wrapper tags mutators `mutating`; `SHODAN_MCP_READ_ONLY=1` removes every
  mutator from the schema entirely (recon-only mode — no credit spend, no scans).
"""

from __future__ import annotations

import json
import logging
import math
import os
import re
import sys
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from fastmcp import FastMCP

from shodan_mcp import __version__
from shodan_mcp.client import ShodanConfigError, get_client
from shodan_mcp.confirm import confirm_required

log = logging.getLogger("shodan_mcp")

INSTRUCTIONS = """\
Drive a Shodan account end-to-end. Start with `account_info` to see plan + remaining
query/scan credits before spending any. Reads: host_info, count (free), search (1 query
credit/page), dns_domain, ports/protocols/search_tokens, scans_list, scan_status,
alerts_list. To pull a full result set, use `search_ingest` — it pages through the
Shodan search cursor (100/page, 1 credit/page) up to `max_pages` and writes JSONL to
disk. Credit-spending/mutating tools (search_ingest, scan, alert_create, alert_remove)
return a Preview unless confirm=True. `count` is free — use it to size a query before
ingesting."""

mcp: FastMCP = FastMCP(name="shodan-mcp", instructions=INSTRUCTIONS)


def tool(*args: Any, **kwargs: Any) -> Callable[[Any], Any]:
    """Register a tool, tagging confirm-gated mutators `mutating` (for read-only mode)."""

    def deco(fn: Any) -> Any:
        if getattr(fn, "__shodan_mutates__", False):
            tags: set[str] = set(kwargs.get("tags") or ())
            tags.add("mutating")
            kwargs["tags"] = tags
        return mcp.tool(*args, **kwargs)(fn)

    return deco


def _read_only() -> bool:
    return os.environ.get("SHODAN_MCP_READ_ONLY", "").strip().lower() in {"1", "true", "yes", "on"}


def _err(msg: str, code: str = "SHODAN_ERROR") -> dict[str, Any]:
    return {"ok": False, "error_code": code, "error_detail": msg}


def _facets(facets: str | None) -> list[str] | None:
    return [f.strip() for f in facets.split(",") if f.strip()] if facets else None


def _fields(fields: str | None) -> list[str] | None:
    return [f.strip() for f in fields.split(",") if f.strip()] if fields else None


def _guard(fn: Callable[[], dict[str, Any]]) -> dict[str, Any]:
    try:
        return fn()
    except ShodanConfigError as e:
        return _err(str(e), "CONFIG")
    except Exception as e:  # shodan.APIError et al.
        return _err(str(e), type(e).__name__)


# ---------------------------------------------------------------- read tools

@tool(description="Account overview: plan, query-credit and scan-credit balances, enabled add-ons. FREE — call this first before spending credits.")
def account_info() -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().info()})


@tool(description="Full Shodan host record for an IP: open ports, banners, services, vulns, location. `history` returns all past banners; `minify` trims. Costs ~1 query credit per IP.")
def host_info(ip: str, history: bool = False, minify: bool = True) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().host(ip, history=history, minify=minify)})


@tool(description="Count how many results a search query matches, with optional facets (comma-separated, e.g. 'country,org'). FREE — use it to size a query before search_ingest.")
def count(query: str, facets: str | None = None) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().count(query, facets=_facets(facets))})


@tool(description="One page (100 results) of a Shodan search. `page` 1-based; `facets` + `fields` comma-separated. Costs 1 query credit per page. For a full pull use search_ingest.")
def search(query: str, page: int = 1, facets: str | None = None,
           minify: bool = True, fields: str | None = None) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().search(
        query, page=page, facets=_facets(facets), minify=minify, fields=_fields(fields))})


@tool(description="DNS + subdomain + hostname records Shodan holds for a domain (e.g. example.com). `history` includes historical DNS; `page` 1-based.")
def dns_domain(domain: str, history: bool = False, page: int = 1) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().dns.domain_info(domain, history=history, page=page)})


@tool(description="List the ports Shodan actively crawls. FREE.")
def ports() -> dict[str, Any]:
    return _guard(lambda: {"ok": True, "ports": get_client().ports()})


@tool(description="List the protocols Shodan's on-demand scanning supports (for scan()). FREE.")
def protocols() -> dict[str, Any]:
    return _guard(lambda: {"ok": True, "protocols": get_client().protocols()})


@tool(description="Break a search query into its filters/tokens as Shodan parses it — validate a query before spending credits. FREE.")
def search_tokens(query: str) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().search_tokens(query)})


@tool(description="List your on-demand scans (most recent first), 100 per page.")
def scans_list(page: int = 1) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().scans(page=page)})


@tool(description="Status of one on-demand scan by its scan id (from scan()/scans_list).")
def scan_status(scan_id: str) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().scan_status(scan_id)})


@tool(description="List your network alerts / monitors.")
def alerts_list() -> dict[str, Any]:
    return _guard(lambda: {"ok": True, "alerts": get_client().alerts()})


# ---------------------------------------------- ingest (credit-spending) + mutators

@tool(description=(
    "Pull a FULL search result set by paging through the Shodan cursor (100/page) and "
    "ingest it to a JSONL file on disk. Pages up to `max_pages` (each page = 1 query "
    "credit), so it is credit-gated: returns a Preview unless confirm=True. `out_dir` "
    "defaults to ~/shodan-ingest. Reports total available, pages pulled, whether the "
    "pull was truncated by max_pages, and an estimated credit spend. Call count() first "
    "to size the query."))
@confirm_required("search_ingest",
    describe=lambda a: f"page through up to {a.get('max_pages')} pages of {a.get('query')!r} (~{a.get('max_pages')} query credits) and write JSONL to {a.get('out_dir') or '~/shodan-ingest'}")
def search_ingest(query: str, out_dir: str | None = None, max_pages: int = 10,
                  minify: bool = True, fields: str | None = None,
                  confirm: bool = False) -> dict[str, Any]:
    def run() -> dict[str, Any]:
        api = get_client()
        base = Path(out_dir).expanduser() if out_dir else Path.home() / "shodan-ingest"
        base.mkdir(parents=True, exist_ok=True)
        ts = time.strftime("%Y%m%d-%H%M%S")
        safe = re.sub(r"[^A-Za-z0-9._-]+", "_", query)[:60] or "query"
        out_file = base / f"shodan_{safe}_{ts}.jsonl"
        flds = _fields(fields)
        written = pages_pulled = 0
        total: int | None = None
        page = 1
        with out_file.open("w", encoding="utf-8") as fh:
            while page <= max_pages:
                res = api.search(query, page=page, minify=minify, fields=flds)
                if total is None:
                    total = int(res.get("total", 0) or 0)
                matches = res.get("matches", []) or []
                if not matches:
                    break
                for m in matches:
                    fh.write(json.dumps(m) + "\n")
                    written += 1
                pages_pulled += 1
                if written >= (total or 0):
                    break
                page += 1
        pages_available = math.ceil((total or 0) / 100)
        return {
            "ok": True, "query": query, "total_available": total,
            "pages_available": pages_available, "pages_pulled": pages_pulled,
            "max_pages": max_pages, "results_written": written,
            "out_file": str(out_file),
            "truncated": pages_pulled < pages_available,
            "credits_spent_estimate": pages_pulled,
        }

    return _guard(run)


@tool(description=(
    "Launch an on-demand Shodan scan of one or more IPs/netblocks (comma-separated or a "
    "CIDR). Consumes SCAN credits and touches real hosts — returns a Preview unless "
    "confirm=True. `force` re-scans even if recently seen."))
@confirm_required("scan", describe=lambda a: f"launch an on-demand scan of {a.get('ips')!r} (spends scan credits)")
def scan(ips: str, force: bool = False, confirm: bool = False) -> dict[str, Any]:
    targets = [s.strip() for s in ips.split(",") if s.strip()]
    return _guard(lambda: {"ok": True, **get_client().scan(targets, force=force)})


@tool(description="Create a network alert/monitor for an IP or netblock. Changes account state — Preview unless confirm=True. `expires` seconds (0 = never).")
@confirm_required("alert_create", describe=lambda a: f"create alert {a.get('name')!r} monitoring {a.get('ip')!r}")
def alert_create(name: str, ip: str, expires: int = 0, confirm: bool = False) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, **get_client().create_alert(name, ip, expires=expires)})


@tool(description="Delete a network alert/monitor by its alert id. Changes account state — Preview unless confirm=True.")
@confirm_required("alert_remove", describe=lambda a: f"delete alert {a.get('alert_id')!r}")
def alert_remove(alert_id: str, confirm: bool = False) -> dict[str, Any]:
    return _guard(lambda: {"ok": True, "deleted": get_client().delete_alert(alert_id) or alert_id})


def _setup_logging() -> None:
    h = logging.StreamHandler(sys.stderr)
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
    logging.basicConfig(level=logging.INFO, handlers=[h])


def build_server() -> FastMCP:
    _setup_logging()
    if _read_only():
        import asyncio

        muts = [t.name for t in asyncio.run(mcp._list_tools()) if "mutating" in (t.tags or set())]
        for name in muts:
            mcp.local_provider.remove_tool(name)
        log.info("read-only mode: removed %d credit-spending/mutating tools", len(muts))
    log.info("shodan-mcp %s ready", __version__)
    return mcp
