# -*- coding: utf-8 -*-
"""Twitter/X — OpenCLI in the Agent Reach browser (experimental)."""

import re

from agent_reach.backends.opencli import opencli_call, opencli_items
from agent_reach.runtime.result import BAD_INPUT, UPSTREAM_BROKEN, ReachError
from agent_reach.utils.url import host_matches

from .base import Action, Channel, Param, require_non_flag

_TWITTER_HANDLE_RE = re.compile(r"^[A-Za-z0-9_]{1,30}$")
_TWEET_ID_RE = re.compile(r"^[0-9]{1,30}$")

_TWITTER_LOGIN_HINT = (
    "Ask the user to log in to x.com in the Agent Reach dedicated browser. Never log in on their behalf."
)


def _x(args, timeout: float) -> list:
    items = opencli_items(opencli_call("twitter", list(args), timeout=timeout, login_hint=_TWITTER_LOGIN_HINT))
    if not items:
        raise ReachError(UPSTREAM_BROKEN, "OpenCLI finished but returned no items")
    return items


class TwitterChannel(Channel):
    name = "twitter"
    description = "Twitter/X 推文"

    # twitter-cli is not used here: even with explicit credentials it re-reads
    # browser cookies whenever verification fails.
    level = "experimental"
    login_url = "https://x.com/i/flow/login"
    tools = ("opencli",)
    prereqs = ("node", "chrome")

    def setup_problems(self):
        from agent_reach.runtime.browser_binding import setup_problems

        return setup_problems(self.name)

    actions = (
        Action(
            "search",
            "Search tweets",
            (
                Param("query", "what to search for"),
                Param("limit", "max results", required=False, type=int, default=5),
            ),
            (("opencli", "_opencli_search"),),
            live_test={"query": "openai", "limit": 2},
            public_web=("x.com/", "twitter.com/"),
        ),
        Action(
            "profile",
            "A user's profile",
            (Param("username", "handle without @"),),
            (("opencli", "_opencli_profile"),),
            live_test={"username": "OpenAI"},
        ),
        Action(
            "tweets",
            "A user's recent tweets",
            (
                Param("username", "handle without @"),
                Param("limit", "max tweets", required=False, type=int, default=5),
            ),
            (("opencli", "_opencli_tweets"),),
        ),
        Action(
            "thread",
            "A tweet with its replies",
            (Param("target", "tweet id or link"),),
            (("opencli", "_opencli_thread"),),
        ),
    )

    def can_handle(self, url: str) -> bool:
        return host_matches(url, "x.com", "twitter.com")

    # ── unified entry backends ──

    def _opencli_search(self, *, query: str, limit: int, timeout: float) -> list:
        return _x(["search", require_non_flag(query, "query"), "--limit", str(limit)], timeout)[:limit]

    @staticmethod
    def _clean_username(username: str) -> str:
        handle = str(username or "").strip().lstrip("@")
        if not _TWITTER_HANDLE_RE.fullmatch(handle):
            raise ReachError(BAD_INPUT, "username must be a valid X/Twitter handle")
        return handle

    def _opencli_profile(self, *, username: str, timeout: float) -> list:
        return _x(["profile", self._clean_username(username)], timeout)[:1]

    def _opencli_tweets(self, *, username: str, limit: int, timeout: float) -> list:
        return _x(["tweets", self._clean_username(username), "--limit", str(limit)], timeout)[:limit]

    def _opencli_thread(self, *, target: str, timeout: float) -> list:
        raw = str(target or "").strip()
        if host_matches(raw, "x.com", "twitter.com"):
            tweet_id = raw.rstrip("/").split("/")[-1].split("?")[0].split("#")[0]
        else:
            tweet_id = raw
        if not _TWEET_ID_RE.fullmatch(tweet_id):
            raise ReachError(BAD_INPUT, "target must be a numeric tweet id or x.com/twitter.com status link")
        return _x(["thread", tweet_id], timeout)
