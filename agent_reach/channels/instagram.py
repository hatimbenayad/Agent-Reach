# -*- coding: utf-8 -*-
"""Instagram users, profiles and posts through OpenCLI in the shared Agent Reach browser."""

import re

from agent_reach.runtime.result import BAD_INPUT, ReachError

from ._opencli_site import OpenCLISiteChannel
from .base import Action, Param, require_non_flag

_INSTAGRAM_USER_RE = re.compile(r"^[A-Za-z0-9._]{1,40}$")


class InstagramChannel(OpenCLISiteChannel):
    name = "instagram"
    description = "Instagram 用户、主页和指定用户帖子"
    site = "instagram"
    domains = ("instagram.com", "instagr.am")
    usage = "opencli instagram search/profile/user/explore -f yaml"
    login_hint = "instagram.com"
    login_cookie = "sessionid"

    level = "experimental"
    login_url = "https://www.instagram.com/accounts/login/"
    actions = (
        Action(
            "search",
            "Search users (not posts)",
            (
                Param("query", "what to search for"),
                Param("limit", "max results", required=False, type=int, default=5),
            ),
            (("opencli", "_opencli_search"),),
            live_test={"query": "nasa", "limit": 2},
        ),
        Action(
            "profile",
            "A user's profile",
            (Param("username", "Instagram username"),),
            (("opencli", "_opencli_profile"),),
            live_test={"username": "nasa"},
        ),
        Action(
            "posts",
            "A user's recent posts",
            (
                Param("username", "Instagram username"),
                Param("limit", "max posts", required=False, type=int, default=6),
            ),
            (("opencli", "_opencli_posts"),),
            live_test={"username": "nasa", "limit": 2},
        ),
    )

    def _opencli_search(self, *, query: str, limit: int, timeout: float) -> list:
        return self._opencli(["search", require_non_flag(query, "query"), "--limit", str(limit)], timeout)[:limit]

    @staticmethod
    def _clean_username(username: str) -> str:
        user = str(username or "").strip().lstrip("@")
        if not _INSTAGRAM_USER_RE.fullmatch(user) or user in {".", ".."}:
            raise ReachError(BAD_INPUT, "username must be a valid Instagram handle")
        return user

    def _opencli_profile(self, *, username: str, timeout: float) -> list:
        return self._opencli(["profile", self._clean_username(username)], timeout, empty_is_error=False)[:1]

    def _opencli_posts(self, *, username: str, limit: int, timeout: float) -> list:
        return self._opencli(["user", self._clean_username(username), "--limit", str(limit)], timeout)[:limit]
