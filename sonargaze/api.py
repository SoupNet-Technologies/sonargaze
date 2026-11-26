"""Shodan REST client. urllib only, one host, key scrubbed from every message."""

from __future__ import annotations

import json
import time
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Callable, Iterator, Mapping
from typing import Any

from . import __version__

API_BASE = "https://api.shodan.io"
USER_AGENT = f"sonargaze/{__version__}"
_REDACTED = "***"

#: transport(url, headers, timeout) -> (status, headers, payload)
Transport = Callable[[str, Mapping[str, str], float], "tuple[int, Mapping[str, str], Any]"]


class SonargazeError(Exception):
    """Base class for every error sonargaze raises."""


class AuthError(SonargazeError):
    """The API key was rejected by Shodan."""


class RateLimited(SonargazeError):
    """Shodan throttled us and the retries ran out."""

    def __init__(self, message: str, retry_after: float | None = None):
        super().__init__(message)
        self.retry_after = retry_after


class APIError(SonargazeError):
    """Shodan answered, but not with success."""

    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class NetworkError(SonargazeError):
    """We could not reach Shodan at all."""


def _urllib_transport(url: str, headers: Mapping[str, str], timeout: float):
    request = urllib.request.Request(url, headers=dict(headers))
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            body = response.read().decode("utf-8", "replace")
            status = response.status
            resp_headers = dict(response.headers)
    except urllib.error.HTTPError as exc:  # 4xx/5xx still carry a body we want
        body = exc.read().decode("utf-8", "replace")
        status = exc.code
        resp_headers = dict(exc.headers or {})
    try:
        payload: Any = json.loads(body) if body.strip() else {}
    except json.JSONDecodeError:
        payload = {"error": body.strip()[:400] or f"HTTP {status}"}
    return status, resp_headers, payload


class ShodanClient:
    """A small, predictable client for the parts of Shodan sonargaze needs.

    Parameters
    ----------
    api_key:
        Shodan API key. It is never included in error text.
    retries:
        Extra attempts for 429/5xx/network failures.
    min_interval:
        Minimum seconds between requests, to stay polite with rate limits.
    transport:
        Injection point for tests. Defaults to urllib.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = API_BASE,
        timeout: float = 20.0,
        retries: int = 3,
        backoff: float = 0.8,
        min_interval: float = 0.0,
        transport: Transport | None = None,
        sleep: Callable[[float], None] = time.sleep,
        clock: Callable[[], float] = time.monotonic,
    ):
        if not api_key or not api_key.strip():
            raise AuthError("No Shodan API key configured.")
        self._api_key = api_key.strip()
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.retries = max(0, int(retries))
        self.backoff = backoff
        self.min_interval = max(0.0, min_interval)
        self._transport: Transport = transport or _urllib_transport
        self._sleep = sleep
        self._clock = clock
        self._last_call: float | None = None
        self.requests_made = 0

    # helpers

    def redact(self, text: str) -> str:
        """Remove the API key from arbitrary text."""
        return text.replace(self._api_key, _REDACTED) if self._api_key else text

    def _pace(self):
        if self.min_interval and self._last_call is not None:
            elapsed = self._clock() - self._last_call
            remaining = self.min_interval - elapsed
            if remaining > 0:
                self._sleep(remaining)
        self._last_call = self._clock()

    def _url(self, path: str, params: Mapping[str, Any]) -> str:
        query = {k: v for k, v in params.items() if v is not None}
        query["key"] = self._api_key
        return f"{self.base_url}{path}?{urllib.parse.urlencode(query, doseq=True)}"

    @staticmethod
    def _message(status: int, payload: Any) -> str:
        if isinstance(payload, Mapping):
            for field in ("error", "message"):
                value = payload.get(field)
                if isinstance(value, str) and value.strip():
                    return value.strip()
        return f"HTTP {status}"

    # request

    def _get(self, path: str, params: Mapping[str, Any] | None = None) -> Any:
        url = self._url(path, params or {})
        attempt = 0

        # 401 and 4xx are final, 429 and 5xx get another go
        while True:
            self._pace()
            self.requests_made += 1
            try:
                status, headers, payload = self._transport(
                    url, {"User-Agent": USER_AGENT, "Accept": "application/json"}, self.timeout
                )
            except (urllib.error.URLError, TimeoutError, OSError) as exc:
                if attempt >= self.retries:
                    raise NetworkError(self.redact(f"could not reach Shodan: {exc}")) from None
                self._sleep(self.backoff * (2**attempt))
                attempt += 1
                continue

            if status == 200:
                return payload

            message = self.redact(self._message(status, payload))

            if status == 401:
                raise AuthError(f"Shodan rejected the API key: {message}")
            if status == 429:
                retry_after = _retry_after(headers)
                if attempt >= self.retries:
                    raise RateLimited(f"Shodan rate-limited the request: {message}", retry_after)
                self._sleep(retry_after if retry_after is not None else self.backoff * (2**attempt))
                attempt += 1
                continue
            if status >= 500:
                if attempt >= self.retries:
                    raise APIError(f"Shodan is having a bad day ({status}): {message}", status)
                self._sleep(self.backoff * (2**attempt))
                attempt += 1
                continue
            raise APIError(message, status)

    # endpoints

    def api_info(self) -> dict[str, Any]:
        """Account plan and remaining query/scan credits."""
        return _as_dict(self._get("/api-info"))

    def search(
        self,
        query: str,
        *,
        page: int = 1,
        facets: Mapping[str, Any] | None = None,
        minify: bool = True,
    ) -> dict[str, Any]:
        """One page of results (Shodan returns 100 per page)."""
        query = _require_query(query)
        if page < 1:
            raise ValueError("page must be 1 or greater")
        params: dict[str, Any] = {"query": query, "page": page, "minify": str(minify).lower()}
        if facets:
            params["facets"] = ",".join(_facet_strings(facets))
        return _as_dict(self._get("/shodan/host/search", params))

    def iterate_search(
        self,
        query: str,
        *,
        pages: int = 1,
        facets: Mapping[str, Any] | None = None,
        minify: bool = True,
    ) -> Iterator[dict[str, Any]]:
        """Yield one result payload per page, stopping early on an empty page."""
        if pages < 1:
            raise ValueError("pages must be 1 or greater")
        query = _require_query(query)
        for page in range(1, pages + 1):
            payload = self.search(query, page=page, facets=facets, minify=minify)
            yield payload
            if not payload.get("matches"):
                return

    def count(self, query: str, *, facets: Mapping[str, Any] | None = None) -> dict[str, Any]:
        """Total count (and optional facets) for a query without spending results."""
        query = _require_query(query)
        params: dict[str, Any] = {"query": query}
        if facets:
            params["facets"] = ",".join(_facet_strings(facets))
        return _as_dict(self._get("/shodan/host/count", params))

    def host(self, ip: str, *, history: bool = False) -> dict[str, Any]:
        """Everything Shodan knows about one address."""
        if not ip or not ip.strip():
            raise ValueError("an IP or netblock is required")
        params = {"history": "true"} if history else None
        path = "/shodan/host/" + urllib.parse.quote(ip.strip(), safe="")
        return _as_dict(self._get(path, params))

    def ports(self) -> list[Any]:
        """Ports Shodan tracks (used for GUI completion lists)."""
        return _as_list(self._get("/shodan/ports"))

    def protocols(self) -> list[Any]:
        return _as_list(self._get("/shodan/protocols"))

    def filters(self) -> list[Any]:
        """Search filters Shodan understands, as ``{"name", "description"}`` dicts."""
        return _as_list(self._get("/shodan/host/search/filters"))

    def facet_options(self) -> list[Any]:
        """Facets Shodan can summarise results by."""
        return _as_list(self._get("/shodan/host/search/facets"))


def _retry_after(headers: Mapping[str, str]) -> float | None:
    for key, value in headers.items():
        if key.lower() == "retry-after":
            try:
                return max(0.0, float(value))
            except (TypeError, ValueError):
                return None
    return None


def _facet_strings(facets: Mapping[str, Any]) -> list[str]:
    out: list[str] = []
    for name, limit in facets.items():
        out.append(name if limit is None else f"{name}:{int(limit)}")
    return out


def _require_query(query: str) -> str:
    if not query or not query.strip():
        raise ValueError("search query cannot be empty")
    return query.strip()


def _as_dict(payload: Any) -> dict[str, Any]:
    if isinstance(payload, dict):
        return payload
    raise APIError("Shodan returned an unexpected payload (not an object)")


def _as_list(payload: Any) -> list[Any]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict) and isinstance(payload.get("matches"), list):
        return payload["matches"]
    raise APIError("Shodan returned an unexpected payload (not a list)")
