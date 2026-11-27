# -*- coding: utf-8 -*-
"""Facebook search and profiles through OpenCLI in the shared Agent Reach browser."""

import re

from agent_reach.runtime.result import BAD_INPUT, ReachError

from ._opencli_site import OpenCLISiteChannel
from .base import Action, Param, require_non_flag

_FACEBOOK_USER_RE = re.compile(r"^[A-Za-z0-9._-]{1,80}$")


class FacebookChannel(OpenCLISiteChannel):
    name = "facebook"
    description = "Facebook 帖子、主页和群组"
    site = "facebook"
    domains = ("facebook.com", "fb.com", "fb.watch")
    usage = "opencli facebook search/profile/feed/groups -f yaml"
    login_hint = "facebook.com"

    level = "experimental"
    login_url = "https://www.facebook.com/login"
    actions = (
        Action(
            "search",
            "Search Facebook",
            (
                Param("query", "what to search for"),
                Param("limit", "max results", required=False, type=int, default=5),
            ),
            (("opencli", "_opencli_search"),),
            live_test={"query": "openai", "limit": 2},
            public_web=("facebook.com/",),
        ),
        Action(
            "profile",
            "A user's or page's profile",
            (Param("username", "username or page name"),),
            (("opencli", "_opencli_profile"),),
            live_test={"username": "zuck"},
        ),
    )

    def _opencli_search(self, *, query: str, limit: int, timeout: float) -> list:
        return self._opencli(["search", require_non_flag(query, "query"), "--limit", str(limit)], timeout)[:limit]

    def _opencli_profile(self, *, username: str, timeout: float) -> list:
        user = require_non_flag(username, "username")
        if not _FACEBOOK_USER_RE.fullmatch(user) or user in {".", ".."}:
            raise ReachError(BAD_INPUT, "username must be a valid Facebook username or page name")
        return self._opencli(["profile", user], timeout, empty_is_error=False)[:1]
