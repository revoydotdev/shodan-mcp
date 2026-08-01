"""Shodan client factory: API key resolution + optional VPN-egress guard.

Key: ``$SHODAN_API_KEY`` else ``~/.shodan/api_key`` (the shodan CLI's location).

Egress opsec (retains shodan-recon's "route through the VPN" posture) is opt-in and
fail-closed: set ``SHODAN_MCP_EXPECTED_EXIT=<ip-or-substring>`` and the factory refuses
to build a client unless the current public egress IP matches — so an accidental
residential-IP run is blocked. For full namespace isolation, launch the server inside
the ``wdvpn`` netns (see README). With the var unset, egress is whatever the process
inherits (works out of the box).
"""

from __future__ import annotations

import os
import urllib.request
from pathlib import Path

import shodan


class ShodanConfigError(RuntimeError):
    pass


def _read_key() -> str:
    key = os.environ.get("SHODAN_API_KEY")
    if key:
        return key.strip()
    p = Path.home() / ".shodan" / "api_key"
    if p.exists():
        return p.read_text(encoding="utf-8").strip()
    raise ShodanConfigError(
        "no Shodan API key — set SHODAN_API_KEY or create ~/.shodan/api_key"
    )


def _egress_ip() -> str | None:
    for url in ("https://api.ipify.org", "https://ifconfig.me/ip"):
        try:
            with urllib.request.urlopen(url, timeout=6) as r:  # noqa: S310
                return r.read().decode().strip()
        except Exception:
            continue
    return None


def _check_egress() -> None:
    expected = os.environ.get("SHODAN_MCP_EXPECTED_EXIT", "").strip()
    if not expected:
        return
    ip = _egress_ip()
    if ip is None:
        raise ShodanConfigError(
            "SHODAN_MCP_EXPECTED_EXIT is set but egress IP is unresolvable — refusing (fail-closed)"
        )
    if expected not in ip:
        raise ShodanConfigError(
            f"egress IP {ip} does not match SHODAN_MCP_EXPECTED_EXIT={expected!r} — refusing (VPN guard)"
        )


_client: shodan.Shodan | None = None


def get_client() -> shodan.Shodan:
    """Return a cached Shodan client, enforcing the egress guard first."""
    global _client
    _check_egress()
    if _client is None:
        _client = shodan.Shodan(_read_key())
    return _client
