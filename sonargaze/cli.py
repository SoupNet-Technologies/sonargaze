"""Command-line front-end: ``sonargaze search nginx country:CA``."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import APP_NAME, TAGLINE, __version__
from .api import APIError, AuthError, NetworkError, RateLimited, ShodanClient, SonargazeError
from .config import (
    ConfigError,
    clear_api_key,
    find_api_key,
    mask_key,
    require_api_key,
    save_api_key,
)
from .export import default_filename, export
from .models import Match
from .query import QueryError, build_query
from .service import search as run_search

EXIT_OK = 0
EXIT_USAGE = 2
EXIT_AUTH = 3
EXIT_RATE = 4
EXIT_API = 5
EXIT_NETWORK = 6


# printing


def _width() -> int:
    try:
        return max(60, min(200, shutil.get_terminal_size((120, 24)).columns))
    except Exception:
        return 120


def _ellipsis(text: str, width: int) -> str:
    text = text.replace("\n", " ").strip()
    if width <= 1 or len(text) <= width:
        return text
    return text[: max(0, width - 1)] + "\u2026"


def render_table(
    headers: Sequence[str], rows: Sequence[Sequence[str]], widths: Sequence[int]
) -> str:
    """Fixed-width table with a rule line, no dependency on rich/tabulate."""
    cells = [[_ellipsis(str(cell), widths[i]) for i, cell in enumerate(row)] for row in rows]
    lines = [
        "  ".join(_ellipsis(head, widths[i]).ljust(widths[i]) for i, head in enumerate(headers))
    ]
    lines.append("  ".join("-" * widths[i] for i in range(len(headers))))
    for row in cells:
        lines.append("  ".join(row[i].ljust(widths[i]) for i in range(len(headers))).rstrip())
    return "\n".join(lines)


def table_for(matches: Sequence[Match], *, width: int | None = None) -> str:
    total = width or _width()
    fixed = 135  # ip, port, product, org, location, hostnames when everything fits
    scale = max(0.55, min(1.0, total / fixed))
    widths = [13, 5, int(24 * scale), int(26 * scale), int(22 * scale), int(26 * scale)]
    rows = [
        [
            m.ip,
            str(m.port or ""),
            m.product_label,
            m.org,
            m.location,
            m.hostname_label,
        ]
        for m in matches
    ]
    return render_table(["IP", "PORT", "PRODUCT", "ORG", "LOCATION", "HOSTNAMES"], rows, widths)


def _print_error(message: str):
    print(f"{APP_NAME}: {message}", file=sys.stderr)


# parser


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog=APP_NAME,
        description=f"{APP_NAME} {__version__}: {TAGLINE}. Talks only to api.shodan.io.",
    )
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    parser.add_argument(
        "--json",
        action="store_true",
        help="emit JSON on stdout (machine readable; disables the table)",
    )
    # `--json` must work both before and after the subcommand
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--json", action="store_true", default=argparse.SUPPRESS, help="emit JSON on stdout"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_search = sub.add_parser("search", help="search the Shodan dataset", parents=[common])
    p_search.add_argument("query", nargs="+", help="query, in Shodan syntax")
    p_search.add_argument(
        "-p", "--pages", type=int, default=1, help="pages of 100 results (default 1)"
    )
    p_search.add_argument(
        "--facets", default="", help="comma-separated facets, e.g. country,org,port:10"
    )
    p_search.add_argument("-l", "--limit", type=int, default=0, help="show at most N rows")
    p_search.add_argument("-o", "--export", default="", help="write results to this path")
    p_search.add_argument(
        "--format",
        default="",
        choices=("", "csv", "json", "jsonl", "markdown"),
        help="export format (default: from the file extension)",
    )
    p_search.add_argument("--raw", action="store_true", help="include raw Shodan payloads in JSON")
    p_search.add_argument(
        "-v", "--verbose", action="store_true", help="print full details per host"
    )
    p_search.add_argument(
        "--filter",
        action="append",
        default=[],
        metavar="NAME=VALUE",
        help="extra filter (repeatable), e.g. --filter country=CA",
    )

    p_host = sub.add_parser(
        "host", help="everything Shodan knows about one address", parents=[common]
    )
    p_host.add_argument("ip", help="IPv4 address or netblock Shodan tracks")
    p_host.add_argument("--history", action="store_true", help="include banner history")

    sub.add_parser("info", help="account plan, credits and limits", parents=[common])

    p_key = sub.add_parser("key", help="manage the stored API key", parents=[common])
    p_key.add_argument(
        "action",
        nargs="?",
        default="status",
        choices=("status", "set", "clear"),
        help="status (default), set (reads stdin), clear",
    )
    p_key.add_argument(
        "--no-keyring", action="store_true", help="with 'set': write a 0600 env file instead"
    )

    sub.add_parser("filters", help="list the search filters Shodan understands", parents=[common])
    sub.add_parser("facets", help="list the facets Shodan can summarise by", parents=[common])
    sub.add_parser("ports", help="list ports Shodan tracks", parents=[common])
    return parser


# commands


def _client(api_key: str | None = None) -> ShodanClient:
    return ShodanClient(require_api_key(api_key))


def cmd_search(args: argparse.Namespace) -> int:
    base = " ".join(args.query)
    extra_filters: dict[str, str] = {}
    for item in args.filter:
        name, sep, value = item.partition("=")
        if not sep or not name.strip() or not value.strip():
            raise QueryError(f"--filter expects NAME=VALUE, got {item!r}")
        extra_filters[name.strip()] = value.strip()
    query = build_query(base, **extra_filters)

    facets: dict[str, Any] = {}
    for token in (t.strip() for t in args.facets.split(",") if t.strip()):
        name, _, limit = token.partition(":")
        facets[name] = int(limit) if limit.isdigit() else None

    client = _client()
    result = run_search(client, query, pages=max(1, args.pages), facets=facets or None)

    if args.json:
        print(
            json.dumps(
                {
                    "meta": result.meta(),
                    "count": len(result.matches),
                    "facets": result.facets,
                    "matches": [m.to_row() for m in result.matches],
                },
                indent=2,
                ensure_ascii=False,
            )
        )
    else:
        shown = result.matches[: args.limit] if args.limit else result.matches
        if args.verbose:
            for match in shown:
                print(match.details())
                print()
        elif shown:
            print(table_for(shown))
        else:
            print("No results.")
        if result.facets:
            print()
            print("Facets")
            for name, values in result.facets.items():
                rendered = ", ".join(
                    f"{value.get('value')} ({value.get('count')})"
                    for value in values
                    if isinstance(value, dict)
                )
                print(f"  {name}: {rendered}")
        summary = f"{len(result.matches)} of {result.total} result(s) across {result.pages_fetched} page(s)"
        print(f"\n{summary}")

    if args.export:
        # a directory gets a generated name, anything else is used as given
        meta = result.meta()
        target = Path(args.export).expanduser()
        if target.is_dir():
            target = target / default_filename(query, args.format or "csv")
        written = export(
            target,
            result.matches,
            fmt=args.format or None,
            meta=meta,
            include_raw=args.raw,
        )
        print(f"wrote {written} ({len(result.matches)} row(s))")
    return EXIT_OK


def cmd_host(args: argparse.Namespace) -> int:
    client = _client()
    payload = client.host(args.ip, history=args.history)
    if args.json:
        print(json.dumps(payload, indent=2, ensure_ascii=False))
        return EXIT_OK
    print(f"IP          {payload.get('ip_str', args.ip)}")
    for label, key in (
        ("Organisation", "org"),
        ("ISP", "isp"),
        ("ASN", "asn"),
        ("OS", "os"),
        ("Hostnames", "hostnames"),
        ("Domains", "domains"),
        ("Ports", "ports"),
        ("Tags", "tags"),
    ):
        value = payload.get(key)
        if isinstance(value, list):
            value = ", ".join(str(item) for item in value)
        if value:
            print(f"{label:<12}{value}")
    location = payload.get("location") or {}
    if isinstance(location, dict):
        place = ", ".join(
            str(location[k]) for k in ("city", "region_code", "country_name") if location.get(k)
        )
        if place:
            print(f"{'Location':<12}{place}")
    services = payload.get("data") or []
    if isinstance(services, list):
        print(f"\nServices ({len(services)})")
        for entry in services:
            if not isinstance(entry, dict):
                continue
            banner = Match.from_payload(entry)
            print(f"  {banner.address:<22}{banner.product_label or '-'}")
    return EXIT_OK


def cmd_info(args: argparse.Namespace) -> int:
    client = _client()
    info = client.api_info()
    if args.json:
        print(json.dumps(info, indent=2, ensure_ascii=False))
        return EXIT_OK
    print(f"{APP_NAME} {__version__}")
    print(f"plan          {info.get('plan', '?')}")
    print(f"query credits {info.get('query_credits', '?')}")
    print(f"scan credits  {info.get('scan_credits', '?')}")
    print(f"monitored IPs {info.get('monitored_ips', '?')}")
    print(f"unlocked      {'yes' if info.get('unlocked') else 'no'}")
    return EXIT_OK


def cmd_key(args: argparse.Namespace) -> int:
    if args.action == "status":
        key = find_api_key()
        if not key:
            print("no API key configured")
            return EXIT_AUTH
        print(f"key     {mask_key(key)}")
        print("source  " + ("environment" if os.environ.get("SHODAN_API_KEY") else "config"))
        return EXIT_OK
    if args.action == "set":
        if sys.stdin.isatty():
            print("Paste the Shodan API key and press Enter (input is hidden):", file=sys.stderr)
            import getpass

            key = getpass.getpass("API key: ")
        else:
            key = sys.stdin.readline().strip()
        where = save_api_key(key, prefer_keyring=not args.no_keyring)
        print(f"stored in {where}")
        return EXIT_OK
    cleared = clear_api_key()
    print("cleared " + (", ".join(cleared) if cleared else "nothing (no stored key found)"))
    return EXIT_OK


def cmd_filters(args: argparse.Namespace) -> int:
    items = _client().filters()
    if args.json:
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return EXIT_OK
    for item in items:
        if isinstance(item, dict):
            print(f"{item.get('name', '')!s:<18}{item.get('description', '')}")
    return EXIT_OK


def cmd_facets(args: argparse.Namespace) -> int:
    items = _client().facet_options()
    if args.json:
        print(json.dumps(items, indent=2, ensure_ascii=False))
        return EXIT_OK
    for item in items:
        if isinstance(item, dict):
            print(f"{item.get('name', '')!s:<18}{item.get('description', '')}")
        else:
            print(item)
    return EXIT_OK


def cmd_ports(args: argparse.Namespace) -> int:
    ports = _client().ports()
    if args.json:
        print(json.dumps(ports, ensure_ascii=False))
        return EXIT_OK
    print(" ".join(str(port) for port in ports))
    return EXIT_OK


COMMANDS = {
    "search": cmd_search,
    "host": cmd_host,
    "info": cmd_info,
    "key": cmd_key,
    "filters": cmd_filters,
    "facets": cmd_facets,
    "ports": cmd_ports,
}


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    args.json = bool(getattr(args, "json", False))
    try:
        return COMMANDS[args.command](args)
    except QueryError as exc:
        _print_error(str(exc))
        return EXIT_USAGE
    except ConfigError as exc:
        _print_error(str(exc))
        return EXIT_AUTH
    except AuthError as exc:
        _print_error(str(exc))
        return EXIT_AUTH
    except RateLimited as exc:
        _print_error(str(exc))
        return EXIT_RATE
    except NetworkError as exc:
        _print_error(str(exc))
        return EXIT_NETWORK
    except APIError as exc:
        _print_error(str(exc))
        return EXIT_API
    except SonargazeError as exc:
        _print_error(str(exc))
        return EXIT_API
    except KeyboardInterrupt:
        print(file=sys.stderr)
        return 130
    except BrokenPipeError:
        return EXIT_OK
    except ValueError as exc:
        _print_error(str(exc))
        return EXIT_USAGE


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
