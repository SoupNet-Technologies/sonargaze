"""Building Shodan query strings without hand-typing filter syntax.

Shodan's query language is plain ``filter:value`` tokens joined by spaces. Typing
it is fine for people who do it daily; this module exists so the GUI can expose
friendly fields and the CLI can validate values before spending a query credit.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from typing import Any

#: friendly name -> Shodan filter name
FILTERS: dict[str, str] = {
    "net": "net",
    "country": "country",
    "city": "city",
    "region": "state",
    "port": "port",
    "product": "product",
    "version": "version",
    "org": "org",
    "hostname": "hostname",
    "domain": "domain",
    "os": "os",
    "tag": "tag",
    "before": "before",
    "after": "after",
    "ssl": "ssl",
    "has_vuln": "has_vuln",
    "http_title": "http.title",
    "http_status": "http.status",
    "asn": "asn",
    "isp": "isp",
}

#: filters whose value is a bare number and must be validated
_NUMERIC = {"port", "asn", "http_status"}

MAX_PORT = 65535


class QueryError(ValueError):
    """A query or one of its filter values is not usable."""


def quote_value(value: Any) -> str:
    """Quote a filter value only when Shodan's lexer needs it."""
    text = str(value).strip()
    if not text:
        raise QueryError("filter value cannot be empty")
    if any(ch in text for ch in ('"', "'", "\\")):
        raise QueryError(f"filter values cannot contain quotes or backslashes: {text!r}")
    if any(ch.isspace() for ch in text) or any(ch in text for ch in (":", ",", "/")):
        return f'"{text}"'
    return text


def clause(name: str, value: Any) -> str:
    """One ``filter:value`` token, with validation for known filters."""
    key = name.strip().lower()
    if key not in FILTERS:
        raise QueryError(f"unknown filter {name!r}; known filters: {', '.join(sorted(FILTERS))}")
    if isinstance(value, bool):
        return f"{FILTERS[key]}:true" if value else f"{FILTERS[key]}:false"
    if key in _NUMERIC:
        try:
            number = int(str(value).strip())
        except (TypeError, ValueError):
            raise QueryError(f"{key} must be a whole number, got {value!r}") from None
        if key == "port" and not 1 <= number <= MAX_PORT:
            raise QueryError(f"port must be between 1 and {MAX_PORT}, got {number}")
        return f"{FILTERS[key]}:{number}"
    return f"{FILTERS[key]}:{quote_value(value)}"


def compose(clauses: Iterable[str]) -> str:
    """Join non-empty clauses into a query string."""
    parts = [part.strip() for part in clauses if part and part.strip()]
    return " ".join(parts)


@dataclass(slots=True)
class QueryBuilder:
    """Collect a base query plus friendly filters, then render once."""

    base: str = ""
    filters: dict[str, Any] = field(default_factory=dict)

    def with_filter(self, name: str, value: Any) -> QueryBuilder:
        if value is None or value == "":
            return self
        self.filters[name.lower()] = value
        return self

    def with_filters(self, **filters: Any) -> QueryBuilder:
        for name, value in filters.items():
            self.with_filter(name, value)
        return self

    def build(self) -> str:
        built = compose([self.base, *[clause(k, v) for k, v in self.filters.items()]])
        if not built:
            raise QueryError("a search needs at least one term or filter")
        return built


def build_query(base: str = "", *, extra: str = "", **filters: Any) -> str:
    """Convenience wrapper: ``build_query("apache", country="CA", port=443)``."""
    builder = QueryBuilder(base=base)
    for name, value in filters.items():
        builder.with_filter(name, value)
    query = composer_join(builder.build() if (base.strip() or filters) else "", extra)
    if not query:
        raise QueryError("a search needs at least one term or filter")
    return query


def composer_join(first: str, extra: str) -> str:
    return compose([first, extra])


def summarize_params(query: str) -> Mapping[str, Any]:
    """Best-effort split of a query into filter tokens (used for display only)."""
    tokens: dict[str, str] = {}
    for token in query.split():
        name, sep, value = token.partition(":")
        if sep and value:
            tokens[name] = value.strip('"')
    return tokens


def free_text(query: str) -> list[str]:
    """Tokens that are not ``filter:value`` pairs."""
    return [token for token in query.split() if ":" not in token]
