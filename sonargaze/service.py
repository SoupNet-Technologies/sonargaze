"""The search flow shared by the CLI and the GUI.

One place that knows how pages, counts, and partial failures combine, so the two
front-ends cannot drift apart.
"""

from __future__ import annotations

import contextlib
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

from .api import ShodanClient
from .models import Match, matches_from_payload


@dataclass(slots=True)
class SearchResult:
    query: str
    matches: list[Match] = field(default_factory=list)
    total: int = 0
    pages_fetched: int = 0
    facets: dict[str, Any] = field(default_factory=dict)
    pages_available: int = 0
    last_page_count: int = 0

    @property
    def has_more(self) -> bool:
        """True when Shodan likely has another page to fetch."""
        return self.pages_fetched < self.pages_available and self.last_page_count > 0

    def meta(self) -> dict[str, Any]:
        from .export import provenance

        return provenance(self.query, total=self.total, pages=self.pages_fetched)


def page_limit(total: int) -> int:
    """Shodan serves at most 100 results per page, and caps depth per plan."""
    return max(1, (total + 99) // 100)


def absorb(result: SearchResult, payload: Mapping[str, Any], page: int) -> SearchResult:
    """Fold one page payload into a running result."""
    matches = matches_from_payload(payload)
    result.matches.extend(matches)
    result.last_page_count = len(matches)
    result.pages_fetched = max(result.pages_fetched, page)
    with contextlib.suppress(TypeError, ValueError):
        result.total = int(payload.get("total") or result.total or 0)
    facet_data = payload.get("facets")
    if isinstance(facet_data, Mapping):
        result.facets = {str(name): list(values) for name, values in facet_data.items()}
    result.pages_available = page_limit(result.total) if result.total else result.pages_fetched
    return result


def search(
    client: ShodanClient,
    query: str,
    *,
    pages: int = 1,
    facets: Mapping[str, Any] | None = None,
    minify: bool = True,
    on_page: Callable[[SearchResult, int], None] | None = None,
) -> SearchResult:
    """Run a paginated search, optionally reporting each page as it lands."""
    if pages < 1:
        raise ValueError("pages must be 1 or greater")
    result = SearchResult(query=query)
    for page in range(1, pages + 1):
        payload = client.search(query, page=page, facets=facets, minify=minify)
        absorb(result, payload, page)
        if on_page is not None:
            on_page(result, page)
        if result.last_page_count < 100:
            break
    return result
