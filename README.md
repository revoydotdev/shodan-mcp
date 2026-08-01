# shodan-mcp

MCP control surface that drives a **Shodan account end-to-end** — account/credits, host
lookups, search, DNS, on-demand scans, and alerts — with a **credit-aware paginated
ingest** that pages through the Shodan search cursor (100 results/page) and writes JSONL
to disk. Thin wrapper over the official `shodan` Python client; no stubs.

## Install

```bash
uv venv .venv --python 3.13
uv pip install -e . --python .venv/bin/python
```

Register (Claude Code, user scope):

```bash
claude mcp add shodan -s user -- /home/revelri/Dev/revelri/shodan-mcp/.venv/bin/python -m shodan_mcp
```

## API key & egress

- Key: `$SHODAN_API_KEY`, else `~/.shodan/api_key` (the shodan CLI's location).
- **VPN-egress guard (opt-in, fail-closed):** set `SHODAN_MCP_EXPECTED_EXIT=<ip-or-substring>`
  and the server refuses to run unless the current public egress IP matches — so it can't
  accidentally query from your residential IP. For full namespace isolation, launch inside
  the `wdvpn` netns, e.g. wrap the command in `sudo ip netns exec wdvpn su - revelri -c '…'`.
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
