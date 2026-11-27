"""Text helpers."""

from __future__ import annotations

import re

_URL_CREDENTIALS_RE = re.compile(
    r"([A-Za-z][A-Za-z0-9+.\-]{0,19}://)[^/\s@]+@"
)
_BARE_USERINFO_RE = re.compile(
    r"(?<![A-Za-z0-9._%+\-])[^:/\s@]+:[^/\s@]+@(?=[A-Za-z0-9.\-\[])"
)
_URL_QUERY_SECRET_RE = re.compile(
    r"([?&#](?:"
    r"access[_-]?token|auth[_-]?token|token|bearer|"
    r"api[_-]?key|key|password|passwd|secret|"
    r"signature|sig|session(?:id)?|cookie|credential"
    r")=)[^&#\s]*",
    re.IGNORECASE,
)


def scrub_url_credentials(text: object) -> str:
    """Redact URL userinfo and sensitive query/fragment values from text."""
    scrubbed = _URL_CREDENTIALS_RE.sub(r"\1***@", str(text))
    scrubbed = _BARE_USERINFO_RE.sub("***@", scrubbed)
    return _URL_QUERY_SECRET_RE.sub(r"\1***", scrubbed)


_CONTROL_CHARS_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def strip_control_chars(text: object) -> str:
    """Remove ASCII control characters (preserving tab, LF, CR) from untrusted text."""
    return _CONTROL_CHARS_RE.sub("", str(text))


def sanitize_untrusted_value(value: object):
    """Recursively strip ASCII control characters from untrusted JSON-like structures."""
    if isinstance(value, str):
        return strip_control_chars(value)
    if isinstance(value, list):
        return [sanitize_untrusted_value(v) for v in value]
    if isinstance(value, tuple):
        return [sanitize_untrusted_value(v) for v in value]
    if isinstance(value, dict):
        return {strip_control_chars(k) if isinstance(k, str) else k: sanitize_untrusted_value(v) for k, v in value.items()}
    return value
