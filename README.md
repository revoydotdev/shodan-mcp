# shodan-mcp

A governed Model Context Protocol server for Shodan. It gives an agent useful
network-intelligence reads, bounded collection, and explicit approval boundaries for
operations that spend credits or change account state.

The server wraps the official `shodan` Python client and exposes typed results rather
than shell output. Search ingestion is paginated, budget-aware, and written as JSONL so
large investigations can be resumed and audited.

## Safety model

- Read-only mode removes every credit-spending or mutating tool from discovery.
- `count` provides a free preflight before a search consumes query credits.
- Scans and alert changes return an exact preview before a confirmed execution.
- An optional egress assertion fails closed if traffic leaves through the wrong address.
- Credentials stay in the Shodan CLI store or environment; they are never accepted as
  MCP tool arguments.

## Install

```bash
uv venv .venv --python 3.13
uv pip install -e . --python .venv/bin/python
```

Register with an MCP client:

```bash
claude mcp add shodan -s user -- uv run --project /path/to/shodan-mcp shodan-mcp
```

## API key & egress

- Key: `$SHODAN_API_KEY`, else `~/.shodan/api_key` (the shodan CLI's location).
- **Egress guard (opt-in, fail-closed):** set
  `SHODAN_MCP_EXPECTED_EXIT=<ip-or-substring>` and the server refuses to start
  unless its observed public egress matches.
- **Recon-only mode:** `SHODAN_MCP_READ_ONLY=1` removes every credit-spending / mutating
  tool from the schema (`search_ingest`, `scan`, `alert_create`, `alert_remove`).

## Tools

**Read (free unless noted):** `account_info` (plan + credits — call first), `host_info`
(~1 credit/IP), `count` (free), `search` (1 credit/page), `dns_domain`, `ports`,
`protocols`, `search_tokens` (free), `scans_list`, `scan_status`, `alerts_list`.

**Credit-spending / mutating (confirm-gated — first call returns a `Preview`, call again
with `confirm=True`):**
- `search_ingest(query, out_dir?, max_pages=10, …)` — the full-result pull: pages the
  cursor up to `max_pages` (1 query credit/page) into a JSONL file; reports total
  available, pages pulled, truncation, and estimated credit spend.
- `scan(ips, force?)` — on-demand scan (scan credits).
- `alert_create(name, ip, expires?)` / `alert_remove(alert_id)` — network monitors.

Always `count()` a query first to size it before `search_ingest`.

## Verification

```bash
uv sync --all-extras
uv run ruff check .
uv run pytest
```

The test suite is hermetic: it exercises confirmation and tool-surface behavior without
calling Shodan. Live use requires your own account, key, credits, and authorization to
inspect the target systems.

## License

MIT. See [LICENSE](LICENSE).
