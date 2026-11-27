"""Unified result envelope and error codes for the agent-facing entry point.

Every unified command prints exactly one JSON object with this shape:

    {schema_version, ok, channel, action, backend, items, meta, error}

`schema_version` only changes on incompatible shape changes. Agents branch
on `ok` and `error.code`; they should never need to parse upstream output.
"""

from __future__ import annotations

import datetime as _dt
import socket
import subprocess
import urllib.error
from typing import Any, Optional

from agent_reach.utils.text import (
    sanitize_untrusted_value,
    scrub_url_credentials,
    strip_control_chars,
)

SCHEMA_VERSION = 1

NEED_SETUP = "NEED_SETUP"
NEED_LOGIN = "NEED_LOGIN"
UPSTREAM_BROKEN = "UPSTREAM_BROKEN"
TIMEOUT = "TIMEOUT"
RATE_LIMITED = "RATE_LIMITED"
PLATFORM_BLOCKED = "PLATFORM_BLOCKED"
NOT_FOUND = "NOT_FOUND"
BAD_INPUT = "BAD_INPUT"

#: Codes where trying another backend cannot help.
FINAL_CODES = frozenset({NOT_FOUND, BAD_INPUT, PLATFORM_BLOCKED, RATE_LIMITED, NEED_LOGIN, "BUSY"})

DEFAULT_HINTS = {
    "BUSY": "The shared browser stayed full while this command waited in line, or a login window is open. Retry later; do not switch profiles.",
    PLATFORM_BLOCKED: "Stop automation. Keep this profile; the user must resolve the platform verification in the official page. Do not switch backends or retry.",
    NEED_SETUP: "This backend is not installed. Ask the user to run `agent-reach doctor` for setup steps.",
    NEED_LOGIN: "The attempted saved/local session did not grant access. Offer site-scoped local reuse or let the user log in themselves; never ask for a password.",
    UPSTREAM_BROKEN: "This channel is temporarily not working; `message` is what was reported. Tell the user in plain words which platform has a problem, without naming tools; suggest `agent-reach update` only if the message points to an outdated tool; do not retry in a loop.",
    TIMEOUT: "The operation timed out. Inspect channel status and the failed stage; do not reopen login windows or repeat requests in a loop.",
    RATE_LIMITED: "The platform reported a rate limit. Reach pauses this channel; respect retry_after_seconds and do not switch backends.",
    NOT_FOUND: "The requested content does not exist. Check the link or id.",
    BAD_INPUT: "Invalid arguments. Run `agent-reach channels` to see valid usage.",
}

_MAX_MESSAGE_CHARS = 500


class ReachError(Exception):
    """A failure with a unified code; upstream messages and hints are passed through unchanged."""

    def __init__(self, code: str, message: str, hint: Optional[str] = None):
        super().__init__(message)
        self.code = code
        self.message = message
        self.hint = hint


def _clean(text: object) -> str:
    return strip_control_chars(scrub_url_credentials(str(text))).strip()[:_MAX_MESSAGE_CHARS]


def classify(exc: BaseException) -> ReachError:
    """Map any exception raised by a backend to a ReachError."""
    if isinstance(exc, ReachError):
        return exc
    if isinstance(exc, urllib.error.HTTPError):
        if exc.code == 404:
            return ReachError(NOT_FOUND, f"HTTP 404: {_clean(exc.reason)}")
        if exc.code == 429:
            return ReachError(RATE_LIMITED, "HTTP 429")
        return ReachError(UPSTREAM_BROKEN, f"HTTP {exc.code}: {_clean(exc.reason)}")
    if isinstance(exc, (subprocess.TimeoutExpired, socket.timeout, TimeoutError)):
        return ReachError(TIMEOUT, "upstream did not answer in time")
    if isinstance(exc, urllib.error.URLError):
        if isinstance(exc.reason, (socket.timeout, TimeoutError)):
            return ReachError(TIMEOUT, "upstream did not answer in time")
        return ReachError(UPSTREAM_BROKEN, f"network error: {_clean(exc.reason)}")
    if isinstance(exc, FileNotFoundError):
        return ReachError(NEED_SETUP, f"missing executable: {_clean(exc.filename or exc)}")
    return ReachError(UPSTREAM_BROKEN, f"{type(exc).__name__}: {_clean(exc)}")


def make_item(
    *,
    title: Optional[str] = None,
    url: Optional[str] = None,
    author: Optional[str] = None,
    published_at: Optional[str] = None,
    text: Optional[str] = None,
    raw: Any = None,
) -> dict:
    """One normalized item. Missing fields are null; `raw` keeps upstream data."""
    def _clean_opt(val: Optional[str]) -> Optional[str]:
        if not val:
            return None
        cleaned = strip_control_chars(val)
        return cleaned or None

    return {
        "title": _clean_opt(title),
        "url": _clean_opt(url),
        "author": _clean_opt(author),
        "published_at": _clean_opt(published_at),
        "text": _clean_opt(text),
        "raw": sanitize_untrusted_value(raw),
    }


def unix_to_iso(value: Any) -> Optional[str]:
    """Convert a unix timestamp to ISO 8601 UTC, or None."""
    try:
        seconds = int(value)
    except (TypeError, ValueError):
        return None
    if seconds <= 0:
        return None
    return _dt.datetime.fromtimestamp(seconds, _dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def envelope(
    *,
    channel: Optional[str],
    action: Optional[str],
    backend: Optional[str] = None,
    items: Optional[list] = None,
    elapsed_ms: int = 0,
    attempts: Optional[list] = None,
    error: Optional[ReachError] = None,
) -> dict:
    """Build the unified output object."""
    sanitized_items = sanitize_untrusted_value(list(items or [])) if error is None else []
    return {
        "schema_version": SCHEMA_VERSION,
        "ok": error is None,
        "channel": channel,
        "action": action,
        "backend": backend if error is None else None,
        "items": sanitized_items,
        "meta": {
            "elapsed_ms": elapsed_ms,
            "attempts": list(attempts or []),
            "untrusted_content": True,
        },
        "error": None
        if error is None
        else {
            "code": error.code,
            "message": _clean(error.message),
            "hint": error.hint or DEFAULT_HINTS.get(error.code, ""),
        },
    }
