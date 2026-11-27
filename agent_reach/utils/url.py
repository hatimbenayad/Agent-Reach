"""Security helpers for untrusted URLs."""

from __future__ import annotations

import ipaddress
import socket
import urllib.request
from urllib.parse import urlsplit

_ORIGINAL_URLOPEN = urllib.request.urlopen

_BLOCKED_PUBLIC_FETCH_HOSTS = {
    "home.arpa",
    "instance-data",
    "internal",
    "ip6-localhost",
    "ip6-loopback",
    "lan",
    "local",
    "localdomain",
    "localhost",
    "metadata.google.internal",
}
_BLOCKED_PUBLIC_FETCH_SUFFIXES = (
    ".home.arpa",
    ".internal",
    ".lan",
    ".local",
    ".localdomain",
    ".localhost",
)


def _literal_ip_address(
    host: str,
) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Parse canonical and legacy IPv4 literal spellings without DNS."""
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        pass

    try:
        packed = socket.inet_aton(host)
    except OSError:
        return None
    return ipaddress.IPv4Address(packed)


def _is_global_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if isinstance(ip, ipaddress.IPv6Address) and ip.ipv4_mapped is not None:
        ip = ip.ipv4_mapped
    return ip.is_global and not any(
        (
            ip.is_private,
            ip.is_loopback,
            ip.is_link_local,
            ip.is_reserved,
            ip.is_multicast,
            ip.is_unspecified,
        )
    )


def normalize_public_http_url(url: str) -> str:
    """Normalize a URL or reject targets that are not clearly public HTTP(S)."""
    candidate = str(url or "").strip()
    if (
        not candidate
        or "\\" in candidate
        or any(
            character.isspace() or ord(character) < 0x20 or ord(character) == 0x7F
            for character in candidate
        )
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")
    if "://" not in candidate:
        before_slash = candidate.split("/", 1)[0]
        if ":" in before_slash:
            host_part, port_part = before_slash.rsplit(":", 1)
            if not host_part or not port_part.isdigit():
                raise ValueError("only public HTTP(S) URLs are allowed")
        candidate = f"https://{candidate}"

    raw_authority = candidate.split("://", 1)[1].split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if "\\" in raw_authority or "%" in raw_authority:
        raise ValueError("only public HTTP(S) URLs are allowed")

    try:
        parsed = urlsplit(candidate)
        raw_host = (parsed.hostname or "").strip().rstrip(".")
        # Accessing the port rejects malformed or out-of-range authorities.
        _ = parsed.port
    except (TypeError, ValueError):
        raise ValueError("only public HTTP(S) URLs are allowed") from None

    if not raw_host:
        raise ValueError("only public HTTP(S) URLs are allowed")
    try:
        host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
    except UnicodeError:
        raise ValueError("only public HTTP(S) URLs are allowed") from None

    literal_address = _literal_ip_address(host)
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not host
        or parsed.username is not None
        or parsed.password is not None
        or "%" in host
        or host in _BLOCKED_PUBLIC_FETCH_HOSTS
        or host.endswith(_BLOCKED_PUBLIC_FETCH_SUFFIXES)
        or ("." not in host and literal_address is None)
        or (literal_address is not None and not _is_global_ip(literal_address))
    ):
        raise ValueError("only public HTTP(S) URLs are allowed")

    return parsed.geturl()


def assert_public_http_url(url: str, *, resolve_dns: bool = True) -> str:
    """Validate URL syntax, literal IPs, and DNS resolution against private/internal targets."""
    normalized = normalize_public_http_url(url)
    parsed = urlsplit(normalized)
    raw_host = (parsed.hostname or "").strip().rstrip(".")
    host = raw_host.encode("idna").decode("ascii").lower().rstrip(".")
    if _literal_ip_address(host) is not None or not resolve_dns:
        return normalized

    port = parsed.port or (443 if parsed.scheme.lower() == "https" else 80)
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        raise ValueError("SSRF blocked: DNS resolution failed for target host") from None

    addresses: list[str] = []
    for info in infos:
        sockaddr = info[4]
        if sockaddr and isinstance(sockaddr[0], str):
            addresses.append(sockaddr[0].split("%", 1)[0])
    if not addresses:
        raise ValueError("SSRF blocked: target host resolved to no addresses")

    for addr in addresses:
        ip = _literal_ip_address(addr)
        if ip is None or not _is_global_ip(ip):
            raise ValueError("SSRF blocked: target host resolves to non-public IP")

    return normalized


class _SafeRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Re-validate every HTTP redirect target against SSRF rules."""

    def __init__(self, *, max_redirects: int = 5):
        self._max_redirects = max_redirects
        self._seen = 0

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self._seen += 1
        if self._seen > self._max_redirects:
            raise ValueError("too many redirects")
        assert_public_http_url(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def safe_urlopen(
    req_or_url: str | urllib.request.Request,
    *,
    timeout: float,
    max_redirects: int = 5,
):
    """Open a public HTTP(S) request after SSRF validation and redirect re-validation."""
    target_url = req_or_url.full_url if isinstance(req_or_url, urllib.request.Request) else str(req_or_url)
    assert_public_http_url(target_url)
    if urllib.request.urlopen is not _ORIGINAL_URLOPEN:
        resp = urllib.request.urlopen(req_or_url, timeout=timeout)  # nosec B310 - URL validated above
        final_url = resp.geturl() if hasattr(resp, "geturl") else None
        if isinstance(final_url, str) and final_url:
            assert_public_http_url(final_url)
        return resp
    opener = urllib.request.build_opener(_SafeRedirectHandler(max_redirects=max_redirects))
    return opener.open(req_or_url, timeout=timeout)


def domain_matches(host: str, *domains: str) -> bool:
    """Match a hostname/cookie domain exactly or as a real subdomain."""
    normalized_host = str(host or "").lower().lstrip(".").rstrip(".")
    if not normalized_host:
        return False
    for domain in domains:
        allowed = domain.lower().lstrip(".").rstrip(".")
        if normalized_host == allowed or normalized_host.endswith("." + allowed):
            return True
    return False


def host_matches(url: str, *domains: str) -> bool:
    """Return whether *url* has an exact allowed host or a real subdomain.

    Only HTTP(S) URLs without userinfo are accepted. Using ``hostname`` rather
    than substring matching prevents lookalikes such as ``x.com.evil.test`` and
    userinfo disguises such as ``x.com@evil.test``.
    """
    try:
        parsed = urlsplit(url)
        host = (parsed.hostname or "").lower().rstrip(".")
        # ``hostname`` is permissive: malformed or out-of-range ports only
        # raise when ``port`` is accessed. Force that validation here so
        # hostile authorities fail closed.
        _ = parsed.port
    except (TypeError, ValueError):
        return False

    if parsed.scheme.lower() not in {"http", "https"}:
        return False
    if not host or parsed.username is not None or parsed.password is not None:
        return False

    return domain_matches(host, *domains)
