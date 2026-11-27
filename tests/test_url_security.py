"""Credential-bearing channels must reject lookalike or disguised hosts."""

import pytest

from agent_reach.channels.bilibili import BilibiliChannel
from agent_reach.channels.facebook import FacebookChannel
from agent_reach.channels.github import GitHubChannel
from agent_reach.channels.instagram import InstagramChannel
from agent_reach.channels.linkedin import LinkedInChannel
from agent_reach.channels.reddit import RedditChannel
from agent_reach.channels.twitter import TwitterChannel
from agent_reach.channels.v2ex import V2EXChannel
from agent_reach.channels.xiaohongshu import XiaoHongShuChannel
from agent_reach.channels.xiaoyuzhou import XiaoyuzhouChannel
from agent_reach.channels.xueqiu import XueqiuChannel
from agent_reach.channels.youtube import YouTubeChannel
from agent_reach.utils.url import host_matches


@pytest.mark.parametrize(
    ("channel", "valid_url"),
    [
        (TwitterChannel(), "https://mobile.twitter.com/user/status/1"),
        (TwitterChannel(), "https://X.COM./user/status/1"),
        (XiaoHongShuChannel(), "https://www.xiaohongshu.com/explore/1"),
        (XiaoHongShuChannel(), "https://xhslink.com/a/1"),
        (BilibiliChannel(), "https://www.bilibili.com/video/BV1"),
        (BilibiliChannel(), "https://b23.tv/abc"),
        (XueqiuChannel(), "https://stock.xueqiu.com/v5/stock/quote"),
    ],
)
def test_credential_channels_accept_exact_hosts_and_subdomains(channel, valid_url):
    assert channel.can_handle(valid_url)


@pytest.mark.parametrize(
    ("channel", "malicious_url"),
    [
        (TwitterChannel(), "https://x.com.evil.test/user/status/1"),
        (TwitterChannel(), "https://notx.com/user/status/1"),
        (TwitterChannel(), "https://x.com@evil.test/user/status/1"),
        (TwitterChannel(), "https://user:pass@x.com/user/status/1"),
        (TwitterChannel(), "ftp://x.com/user/status/1"),
        (XiaoHongShuChannel(), "https://xiaohongshu.com.evil.test/explore/1"),
        (XiaoHongShuChannel(), "https://xiaohongshu.com@evil.test/explore/1"),
        (BilibiliChannel(), "https://bilibili.com.evil.test/video/BV1"),
        (BilibiliChannel(), "https://b23.tv@evil.test/abc"),
        (XueqiuChannel(), "https://xueqiu.com.evil.test/S/SH600519"),
        (XueqiuChannel(), "https://xueqiu.com@evil.test/S/SH600519"),
    ],
)
def test_credential_channels_reject_lookalikes_and_userinfo(channel, malicious_url):
    assert not channel.can_handle(malicious_url)


@pytest.mark.parametrize(
    ("channel", "subdomain_url", "port_url"),
    [
        (
            GitHubChannel(),
            "https://api.github.com/repos/openai/openai-python",
            "https://github.com:443/openai/openai-python",
        ),
        (
            YouTubeChannel(),
            "https://m.youtube.com/watch?v=abc",
            "https://youtu.be:443/abc",
        ),
        (
            RedditChannel(),
            "https://old.reddit.com/r/python",
            "https://reddit.com:443/r/python",
        ),
        (
            LinkedInChannel(),
            "https://www.linkedin.com/in/example",
            "https://linkedin.com:443/in/example",
        ),
        (
            V2EXChannel(),
            "https://www.v2ex.com/t/1",
            "https://v2ex.com:443/t/1",
        ),
        (
            XiaoyuzhouChannel(),
            "https://www.xiaoyuzhoufm.com/episode/1",
            "https://xiaoyuzhoufm.com:443/episode/1",
        ),
        (
            FacebookChannel(),
            "https://m.facebook.com/groups/1",
            "https://facebook.com:443/groups/1",
        ),
        (
            InstagramChannel(),
            "https://www.instagram.com/example",
            "https://instagram.com:443/example",
        ),
    ],
)
def test_fixed_domain_channels_accept_subdomains_and_explicit_ports(
    channel, subdomain_url, port_url
):
    assert channel.can_handle(subdomain_url)
    assert channel.can_handle(port_url)


@pytest.mark.parametrize(
    ("channel", "official_domain"),
    [
        (GitHubChannel(), "github.com"),
        (YouTubeChannel(), "youtube.com"),
        (RedditChannel(), "reddit.com"),
        (LinkedInChannel(), "linkedin.com"),
        (V2EXChannel(), "v2ex.com"),
        (XiaoyuzhouChannel(), "xiaoyuzhoufm.com"),
        (FacebookChannel(), "facebook.com"),
        (InstagramChannel(), "instagram.com"),
    ],
)
def test_fixed_domain_channels_reject_suffix_lookalikes_and_userinfo(
    channel, official_domain
):
    assert not channel.can_handle(f"https://{official_domain}.evil.test/path")
    assert not channel.can_handle(f"https://{official_domain}@evil.test/path")
    assert not channel.can_handle(f"https://user:pass@{official_domain}/path")


@pytest.mark.parametrize(
    "malicious_url",
    [
        "https://x.com:not-a-port/path",
        "https://x.com:65536/path",
        "https://x.com:-1/path",
        "https://x.com:999999999999/path",
    ],
)
def test_host_matches_rejects_invalid_ports(malicious_url):
    assert not host_matches(malicious_url, "x.com")


@pytest.mark.parametrize(
    "resolved_ip",
    ["127.0.0.1", "10.0.0.5", "169.254.169.254", "::1", "::ffff:127.0.0.1"],
)
def test_assert_public_http_url_blocks_private_dns_resolutions(monkeypatch, resolved_ip):
    import socket

    from agent_reach.utils.url import assert_public_http_url

    family = socket.AF_INET6 if ":" in resolved_ip else socket.AF_INET
    monkeypatch.setattr(
        socket,
        "getaddrinfo",
        lambda host, port, *a, **k: [(family, socket.SOCK_STREAM, 6, "", (resolved_ip, 443))],
    )
    with pytest.raises(ValueError, match="non-public IP"):
        assert_public_http_url("https://rebind.example/audio.mp3")


def test_assert_public_http_url_fails_closed_on_dns_error(monkeypatch):
    import socket

    from agent_reach.utils.url import assert_public_http_url

    def fail_dns(*_a, **_k):
        raise socket.gaierror("name resolution failed")

    monkeypatch.setattr(socket, "getaddrinfo", fail_dns)
    with pytest.raises(ValueError, match="DNS resolution failed"):
        assert_public_http_url("https://missing.example/audio.mp3")


def test_safe_urlopen_blocks_redirect_to_private_host(monkeypatch):
    import urllib.request

    from agent_reach.utils.url import _SafeRedirectHandler, safe_urlopen

    handler = _SafeRedirectHandler()
    req = urllib.request.Request("https://b23.tv/abc", method="HEAD")
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        handler.redirect_request(req, None, 302, "Found", {}, "http://127.0.0.1:9222/json")
    with pytest.raises(ValueError, match="HTTP\\(S\\)"):
        handler.redirect_request(req, None, 302, "Found", {}, "file:///etc/passwd")

    class BadRedirectResp:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def geturl(self):
            return "http://169.254.169.254/latest/meta-data"

    monkeypatch.setattr(urllib.request, "urlopen", lambda *a, **k: BadRedirectResp())
    with pytest.raises(ValueError, match="only public HTTP"):
        safe_urlopen(req, timeout=1)
