"""Shared fakes and fixtures. Nothing here touches the network."""

from __future__ import annotations

import contextlib
import sys
import types
from collections.abc import Mapping, Sequence
from typing import Any
from urllib.parse import parse_qs, urlparse

#: A key that is easy to grep for in "did it leak" assertions.
KEY = "SECRETKEY0123456789ABCDEF"


class FakeTransport:
    """Records request URLs and replays canned (status, headers, payload) tuples."""

    def __init__(self, responses: Sequence[Any]):
        self.responses = list(responses)
        self.calls: list[str] = []

    def __call__(self, url: str, headers: Mapping[str, str], timeout: float):
        self.calls.append(url)
        if not self.responses:
            return 500, {}, {"error": "no canned response left"}
        item = self.responses.pop(0)
        if isinstance(item, Exception):
            raise item
        return item

    @property
    def last_params(self) -> dict[str, str]:
        query = parse_qs(urlparse(self.calls[-1]).query)
        return {k: v[0] for k, v in query.items()}


def match_item(index: int = 0, **overrides: Any) -> dict[str, Any]:
    item = {
        "ip_str": f"203.0.113.{index % 250 + 1}",
        "port": 443 + index,
        "transport": "tcp",
        "product": "nginx",
        "version": "1.24.0",
        "org": "Example Org",
        "isp": "Example ISP",
        "asn": "AS64500",
        "os": "Linux",
        "hostnames": ["a.example.com", "b.example.com"],
        "domains": ["example.com"],
        "cpe": ["cpe:/a:igor_sysoev:nginx:1.24.0"],
        "tags": ["cloud"],
        "location": {
            "city": "Edmonton",
            "region_code": "AB",
            "country_name": "Canada",
            "country_code": "CA",
        },
        "timestamp": "2026-11-01T00:00:00.000000",
        "data": "<html><head><title>hi</title></head><body>HTTP/1.1 200 OK</body></html>",
        "vulns": {"CVE-2021-44228": {"cvss": 10.0}},
    }
    item.update(overrides)
    return item


def payload(matches: int = 1, total: int | None = None, **extra: Any) -> dict[str, Any]:
    data = {
        "total": matches if total is None else total,
        "matches": [match_item(i) for i in range(matches)],
    }
    data.update(extra)
    return data


class FakeClient:
    """Stands in for ShodanClient so the CLI and GUI tests need no HTTP."""

    def __init__(
        self, pages: dict[int, dict[str, Any]] | None = None, error: Exception | None = None
    ):
        self.pages = pages or {1: payload(3, total=3)}
        self.error = error
        self.calls: list[dict[str, Any]] = []

    def search(self, query: str, *, page: int = 1, facets: Any = None, minify: bool = True):
        self.calls.append({"query": query, "page": page, "facets": facets})
        if self.error is not None:
            raise self.error
        return self.pages.get(page, {"total": 0, "matches": []})

    def host(self, ip: str, *, history: bool = False):
        self.calls.append({"host": ip, "history": history})
        if self.error is not None:
            raise self.error
        return {
            "ip_str": ip,
            "ports": [80, 443],
            "org": "Example Org",
            "data": [match_item(0), match_item(1)],
        }

    def api_info(self):
        return {"plan": "dev", "query_credits": 99, "scan_credits": 1, "unlocked": True}

    def redact(self, text: str) -> str:
        return text


def _keyring_module(stored: dict[str, str]) -> types.ModuleType:
    module = types.ModuleType("keyring")

    def get_password(service, user):
        return stored.get(user)

    def set_password(service, user, value):
        stored[user] = value

    def delete_password(service, user):
        stored.pop(user, None)

    module.get_password = get_password
    module.set_password = set_password
    module.delete_password = delete_password
    return module


@contextlib.contextmanager
def keyring_stub(stored: dict[str, str] | None = None, fail: bool = False):
    """Install a fake `keyring` module for the duration of a test."""
    stored = {} if stored is None else stored
    module = _keyring_module(stored)
    if fail:

        def boom(*_args, **_kwargs):
            raise RuntimeError("no keyring in tests")

        module.get_password = boom
        module.set_password = boom
        module.delete_password = boom
    sys.modules["keyring"] = module
    try:
        yield stored
    finally:
        sys.modules.pop("keyring", None)
