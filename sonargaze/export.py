"""Exporting results, with provenance on anything that can carry it.

The CSV stays a plain table so it opens in anything. JSON and Markdown get a
``meta`` block with the query, when it ran, how many pages were fetched and which
tool version produced it, so a finding still has its audit trail months later.
"""

from __future__ import annotations

import csv
import json
import re
from collections.abc import Iterable, Mapping, Sequence
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from . import APP_NAME, __version__
from .models import Match

CSV_FIELDS = (
    "ip",
    "port",
    "transport",
    "product",
    "version",
    "org",
    "isp",
    "asn",
    "os",
    "hostnames",
    "domains",
    "city",
    "region",
    "country",
    "country_code",
    "timestamp",
    "vulns",
    "banner",
)

FORMATS = ("csv", "json", "markdown", "jsonl")
_SAFE = re.compile(r"[^A-Za-z0-9._-]+")


class ExportError(Exception):
    """The results could not be written."""


def provenance(query: str, *, total: int | None = None, pages: int | None = None) -> dict[str, Any]:
    """Metadata block shared by the JSON and Markdown exports."""
    meta: dict[str, Any] = {
        "tool": APP_NAME,
        "version": __version__,
        "generated": datetime.now(UTC).replace(microsecond=0).isoformat(),
        "source": "Shodan API",
        "query": query,
    }
    if total is not None:
        meta["total_available"] = total
    if pages is not None:
        meta["pages_fetched"] = pages
    return meta


def default_filename(query: str, extension: str = "csv") -> str:
    """A filename that survives Windows, macOS, and a query with quotes in it."""
    slug = _SAFE.sub("-", query.strip()).strip("-._") or "results"
    slug = slug[:60].rstrip("-.")
    stamp = datetime.now().strftime("%Y%m%d-%H%M")
    return f"{APP_NAME}-{slug}-{stamp}.{extension.lstrip('.')}"


def _rows(matches: Iterable[Match]) -> list[dict[str, Any]]:
    return [match.to_row() for match in matches]


def export_csv(path: str | Path, matches: Sequence[Match]) -> Path:
    path = Path(path).expanduser()
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise ExportError(f"could not create {path.parent}: {exc}") from None
    try:
        with path.open("w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=list(CSV_FIELDS), extrasaction="ignore")
            writer.writeheader()
            for row in _rows(matches):
                writer.writerow(row)
    except OSError as exc:
        raise ExportError(f"could not write {path}: {exc}") from None
    return path


def export_json(
    path: str | Path,
    matches: Sequence[Match],
    meta: Mapping[str, Any] | None = None,
    *,
    include_raw: bool = False,
) -> Path:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    payload: dict[str, Any] = {
        "meta": dict(meta or {}),
        "count": len(matches),
        "matches": _rows(matches),
    }
    if include_raw:
        payload["raw"] = [match.raw for match in matches]
    try:
        path.write_text(json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    except OSError as exc:
        raise ExportError(f"could not write {path}: {exc}") from None
    return path


def export_jsonl(path: str | Path, matches: Sequence[Match]) -> Path:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        with path.open("w", encoding="utf-8") as handle:
            for row in _rows(matches):
                handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    except OSError as exc:
        raise ExportError(f"could not write {path}: {exc}") from None
    return path


def _md_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ").strip()


def export_markdown(
    path: str | Path,
    matches: Sequence[Match],
    meta: Mapping[str, Any] | None = None,
) -> Path:
    path = Path(path).expanduser()
    path.parent.mkdir(parents=True, exist_ok=True)
    meta = dict(meta or {})
    header = [
        f"# {APP_NAME} results",
        "",
        f"- **Query:** `{_md_cell(meta.get('query', '')) or '(none)'}`",
        f"- **Generated:** {meta.get('generated', '(unknown)')}",
        f"- **Tool:** {meta.get('tool', APP_NAME)} {meta.get('version', __version__)}",
        f"- **Source:** {meta.get('source', 'Shodan API')}",
    ]
    if "total_available" in meta:
        header.append(f"- **Reported total:** {meta['total_available']}")
    if "pages_fetched" in meta:
        header.append(f"- **Pages fetched:** {meta['pages_fetched']}")
    header += [f"- **Rows exported:** {len(matches)}", ""]
    table = [
        "| IP | Port | Product | Organisation | Location | Hostnames |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for match in matches:
        table.append(
            "| "
            + " | ".join(
                _md_cell(value)
                for value in (
                    match.ip,
                    match.port if match.port is not None else "",
                    match.product_label,
                    match.org,
                    match.location,
                    match.hostname_label,
                )
            )
            + " |"
        )
    body = header + table + [""]
    try:
        path.write_text("\n".join(body), encoding="utf-8")
    except OSError as exc:
        raise ExportError(f"could not write {path}: {exc}") from None
    return path


def export(
    path: str | Path,
    matches: Sequence[Match],
    *,
    fmt: str | None = None,
    meta: Mapping[str, Any] | None = None,
    include_raw: bool = False,
) -> Path:
    """Dispatch on ``fmt`` or the file extension."""
    # format comes from the flag, else from the extension
    resolved = (fmt or Path(str(path)).suffix.lstrip(".") or "csv").lower()
    if resolved in ("md", "markdown"):
        return export_markdown(path, matches, meta)
    if resolved == "json":
        return export_json(path, matches, meta, include_raw=include_raw)
    if resolved in ("jsonl", "ndjson"):
        return export_jsonl(path, matches)
    if resolved == "csv":
        return export_csv(path, matches)
    raise ExportError(f"unsupported export format {resolved!r}; try csv, json, jsonl or markdown")
