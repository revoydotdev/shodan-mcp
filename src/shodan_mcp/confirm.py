"""Confirm-gate for credit-spending / account-mutating tools.

Thin adapter over ``mcp_safety_core`` (the shared portfolio lib) so this repo
has no local implementation to maintain while preserving shodan's domain target
params and the historical ``confirm_required`` / ``Preview`` public API.
"""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from mcp_safety_core.confirm import Preview
from mcp_safety_core.confirm import confirm_required as _core_confirm

SHODAN_TARGET_PARAMS = ("query", "ips", "ip", "name", "alert_id", "domain", "out_dir")


def confirm_required(
    action: str,
    describe: Callable[[dict[str, Any]], str | None] | None = None,
) -> Callable:
    """Gate a Shodan credit-spending / mutating tool behind ``confirm=True``."""
    return _core_confirm(action, describe=describe, target_params=SHODAN_TARGET_PARAMS)


__all__ = ["Preview", "confirm_required"]
