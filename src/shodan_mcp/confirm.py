"""Confirm-gate for credit-spending / account-mutating tools.

When ``confirm`` is False (default), the wrapped tool returns a structured ``Preview``
instead of executing — so an agent must take an explicit second step before anything
spends Shodan credits or changes account state (a scan, an alert, a paginated ingest).
Mirrors the proven lutris-mcp/apk-lab-mcp pattern.
"""

from __future__ import annotations

import inspect
from collections.abc import Callable
from functools import wraps
from typing import Any, TypeVar, get_type_hints

from pydantic import BaseModel

F = TypeVar("F", bound=Callable[..., Any])

# First non-empty wins for the preview's target summary.
_TARGET_PARAMS = ("query", "ips", "ip", "name", "alert_id", "domain", "out_dir")


class Preview(BaseModel):
    preview: bool = True
    action: str
    target: str
    would_do: str
    note: str = "Pass confirm=True to execute."


def _resolve_target(bound: inspect.BoundArguments) -> str:
    for key in _TARGET_PARAMS:
        if key in bound.arguments:
            value = bound.arguments[key]
            if value in (None, ""):
                continue
            return str(value)[:160]
    return "<unknown>"


def confirm_required(
    action: str,
    describe: Callable[[dict[str, Any]], str | None] | None = None,
) -> Callable[[F], F]:
    """Gate a credit-spending / mutating tool behind ``confirm=True``."""

    def decorator(fn: F) -> F:
        sig = inspect.signature(fn)

        @wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            try:
                bound = sig.bind_partial(*args, **kwargs)
            except TypeError:
                return fn(*args, **kwargs)
            bound.apply_defaults()
            if not bool(bound.arguments.get("confirm", False)):
                target = _resolve_target(bound)
                would_do = f"{action} on {target}"
                if describe is not None:
                    try:
                        summary = describe(dict(bound.arguments))
                    except Exception:
                        summary = None
                    if summary:
                        would_do = summary
                return Preview(action=action, target=target, would_do=would_do)
            return fn(*args, **kwargs)

        # Widen the advertised return schema so the Preview branch validates (FastMCP
        # derives structured output from the annotation). Verified pattern.
        try:
            orig_ret = get_type_hints(fn).get("return", inspect.Signature.empty)
        except Exception:
            orig_ret = inspect.Signature.empty
        widened = Preview if orig_ret is inspect.Signature.empty else orig_ret | Preview
        wrapper.__signature__ = sig.replace(return_annotation=widened)  # type: ignore[attr-defined]
        wrapper.__annotations__ = {**getattr(fn, "__annotations__", {}), "return": widened}

        wrapper.__shodan_mutates__ = True  # type: ignore[attr-defined]
        wrapper.__shodan_action__ = action  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator
