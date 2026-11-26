"""Result models: one flat, printable shape for a Shodan match.

Shodan payloads are wide, nested, and inconsistent between hosts. Everything the
UI and the exporters touch goes through here so there is exactly one place that
knows how a match is laid out.
"""

from __future__ import annotations

import html
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Any

_SKIP_TAGS = {"script", "style", "head", "title", "noscript"}
_BLOCK_TAGS = {"p", "div", "li", "tr", "br", "h1", "h2", "h3", "table", "section"}


class _TextExtractor(HTMLParser):
    """Strip markup without pulling in a parser dependency."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self._parts: list[str] = []
        self._skip_depth = 0

    def handle_starttag(self, tag: str, attrs):
        if tag in _SKIP_TAGS:
            self._skip_depth += 1
        elif tag == "br":
            self._parts.append("\n")

    def handle_endtag(self, tag: str):
        if tag in _SKIP_TAGS:
            if self._skip_depth:
                self._skip_depth -= 1
        elif tag in _BLOCK_TAGS:
            self._parts.append("\n")

    def handle_data(self, data: str):
        if not self._skip_depth:
            self._parts.append(data)

    def text(self) -> str:
        return "".join(self._parts)


def strip_html(value: str) -> str:
    """Turn a banner into readable text, keeping the line structure."""
    if not value:
        return ""
    parser = _TextExtractor()
    try:
        parser.feed(value)
        parser.close()
        text = parser.text()
    except Exception:  # malformed markup: fall back to entity decoding only
        text = html.unescape(value)
    # squeeze runs of blank lines down to one, banners are full of them
    lines = [line.rstrip() for line in text.replace("\r\n", "\n").split("\n")]
    collapsed: list[str] = []
    blank = False
    for line in lines:
        if line.strip():
            collapsed.append(line)
            blank = False
        elif not blank:
            collapsed.append("")
            blank = True
    return "\n".join(collapsed).strip()


def _str_list(value: Any) -> list[str]:
    if not value:
        return []
    if isinstance(value, str):
        return [part for part in (p.strip() for p in value.split(",")) if part]
    if isinstance(value, Sequence | set):
        return [str(item) for item in value if str(item).strip()]
    return [str(value)]


def _int_or_none(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def format_location(location: Mapping[str, Any] | None) -> str:
    """``city, region, country`` with the empty parts dropped."""
    if not location:
        return ""
    parts: list[str] = []
    for key in ("city", "region_code", "country_name"):
        value = location.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    return ", ".join(parts)


@dataclass(slots=True)
class Match:
    """One host/port as Shodan reported it."""

    ip: str = ""
    port: int | None = None
    transport: str = ""
    product: str = ""
    version: str = ""
    org: str = ""
    isp: str = ""
    asn: str = ""
    os: str = ""
    hostnames: list[str] = field(default_factory=list)
    domains: list[str] = field(default_factory=list)
    cpes: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    city: str = ""
    region: str = ""
    country: str = ""
    country_code: str = ""
    latitude: float | None = None
    longitude: float | None = None
    timestamp: str = ""
    banner: str = ""
    vulns: list[str] = field(default_factory=list)
    raw: dict[str, Any] = field(default_factory=dict, repr=False)

    # construction

    @classmethod
    def from_payload(cls, payload: Mapping[str, Any]) -> Match:
        location = payload.get("location") or {}
        if not isinstance(location, Mapping):
            location = {}
        port = _int_or_none(payload.get("port"))
        return cls(
            ip=str(payload.get("ip_str") or payload.get("ip") or ""),
            port=port,
            transport=str(payload.get("transport") or ("tcp" if port else "")),
            product=str(payload.get("product") or ""),
            version=str(payload.get("version") or ""),
            org=str(payload.get("org") or ""),
            isp=str(payload.get("isp") or ""),
            asn=str(payload.get("asn") or ""),
            os=str(payload.get("os") or payload.get("opts", {}).get("os") or "")
            if isinstance(payload.get("opts"), Mapping)
            else str(payload.get("os") or ""),
            hostnames=_str_list(payload.get("hostnames")),
            domains=_str_list(payload.get("domains")),
            cpes=_str_list(payload.get("cpe") or payload.get("cpe23")),
            tags=_str_list(payload.get("tags")),
            city=str(location.get("city") or ""),
            region=str(location.get("region_code") or ""),
            country=str(location.get("country_name") or ""),
            country_code=str(location.get("country_code") or ""),
            latitude=location.get("latitude")
            if isinstance(location.get("latitude"), float)
            else None,
            longitude=location.get("longitude")
            if isinstance(location.get("longitude"), float)
            else None,
            timestamp=str(payload.get("timestamp") or ""),
            banner=str(payload.get("data") or ""),
            vulns=sorted((payload.get("vulns") or {}).keys())
            if isinstance(payload.get("vulns"), Mapping)
            else _str_list(payload.get("vulns")),
            raw=dict(payload),
        )

    # rendering

    @property
    def address(self) -> str:
        """``1.2.3.4:443``, the one label that identifies a row."""
        return f"{self.ip}:{self.port}" if self.port else self.ip

    @property
    def location(self) -> str:
        return ", ".join(part for part in (self.city, self.region, self.country) if part)

    @property
    def product_label(self) -> str:
        return " ".join(part for part in (self.product, self.version) if part)

    @property
    def hostname_label(self) -> str:
        return ", ".join(self.hostnames)

    def banner_text(self) -> str:
        """Banner with markup stripped, for the detail pane and exports."""
        return strip_html(self.banner)

    def summary(self) -> str:
        """One-line description used by the CLI table."""
        bits = [bit for bit in (self.product_label, self.org, self.location) if bit]
        return " | ".join(bits)

    def to_row(self) -> dict[str, Any]:
        """Stable, flat record for CSV/JSON exports."""
        return {
            "ip": self.ip,
            "port": self.port if self.port is not None else "",
            "transport": self.transport,
            "product": self.product,
            "version": self.version,
            "org": self.org,
            "isp": self.isp,
            "asn": self.asn,
            "os": self.os,
            "hostnames": "; ".join(self.hostnames),
            "domains": "; ".join(self.domains),
            "city": self.city,
            "region": self.region,
            "country": self.country,
            "country_code": self.country_code,
            "timestamp": self.timestamp,
            "vulns": "; ".join(self.vulns),
            "banner": self.banner_text(),
        }

    def details(self) -> str:
        """Human-readable block for the GUI detail pane and ``--verbose``."""
        lines = [
            f"Address     {self.address}",
            f"Transport   {self.transport or '-'}",
            f"Product     {self.product_label or '-'}",
            f"Organisation{(' ' + self.org) if self.org else ' -'}",
            f"ISP         {self.isp or '-'}",
            f"ASN         {self.asn or '-'}",
            f"OS          {self.os or '-'}",
            f"Location    {self.location or '-'}",
            f"Hostnames   {self.hostname_label or '-'}",
        ]
        if self.domains:
            lines.append(f"Domains     {', '.join(self.domains)}")
        if self.cpes:
            lines.append(f"CPEs        {', '.join(self.cpes)}")
        if self.tags:
            lines.append(f"Tags        {', '.join(self.tags)}")
        if self.vulns:
            lines.append(f"Vulns       {', '.join(self.vulns)}")
        if self.timestamp:
            lines.append(f"Seen        {self.timestamp}")
        banner = self.banner_text()
        lines.append("")
        lines.append("Banner")
        lines.append(banner if banner else "(no banner text)")
        return "\n".join(lines)


COLUMNS: tuple[tuple[str, str, int], ...] = (
    ("ip", "IP", 130),
    ("port", "Port", 60),
    ("product", "Product", 170),
    ("org", "Organisation", 180),
    ("location", "Location", 170),
    ("hostnames", "Hostnames", 220),
)


def matches_from_payload(payload: Mapping[str, Any] | None) -> list[Match]:
    if not payload:
        return []
    raw = payload.get("matches")
    if not isinstance(raw, list):
        return []
    return [Match.from_payload(item) for item in raw if isinstance(item, Mapping)]


def sort_key(match: Match, column: str) -> tuple[int, Any]:
    """Sort helper: numbers sort numerically, blanks always sink."""
    if column == "port":
        return (0, match.port) if match.port is not None else (1, 0)
    value = {
        "ip": match.ip,
        "product": match.product_label,
        "org": match.org,
        "location": match.location,
        "hostnames": match.hostname_label,
    }.get(column, match.ip)
    return (0, value.lower()) if value else (1, "")
