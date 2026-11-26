# SPEC - Sonargaze

## Purpose

A Shodan front end with two front ends over one core: a Tk window for reading
results as a table and a CLI for piping them. Both ask the same question, what
is exposed that matches this query, and both answer it out of Shodan's index
without sending anything to the hosts being reported on.

## Quick facts

- Python 3.10+, no runtime dependencies (`urllib`, `tkinter`, `csv`, `json`,
  `html.parser`)
- Optional: `keyring` for key storage; `ruff` for linting
- Entry points: `sonargaze` (GUI), `sonargaze-cli` (CLI), `python -m sonargaze`
- Network: `api.shodan.io` only, always HTTPS

## Layout

```
sonargaze/config.py    key resolution: explicit, SONARGAZE_API_KEY, SHODAN_API_KEY,
                       OS keyring, ./.env, ~/.config/sonargaze/.env
sonargaze/api.py       ShodanClient: one _get() with pacing, retry on 429/5xx/network,
                       key redacted from every message
sonargaze/models.py    Match: nested payload in, flat printable record out
sonargaze/service.py   paginated search: absorb a page, report progress, stop early
sonargaze/cli.py       argparse front end
sonargaze/gui.py       Tk window, worker thread plus queue
sonargaze/export.py    csv, json, jsonl, markdown
tests/                 unittest suite, no network
```

`api.py` is the only module that does I/O. Everything above it takes a client
after the fact, which is why the suite runs without a network.

## Interfaces

### CLI

| Command | Does |
| --- | --- |
| `search QUERY [-p N] [--facets a,b:5] [-l N] [-o PATH] [--format F] [--raw] [-v] [--filter NAME=VALUE]` | search, print a table or `--json`, optionally export |
| `host IP [--history]` | one address, every service Shodan knows |
| `info` | plan, query credits, scan credits, unlocked |
| `key [status\|set\|clear] [--no-keyring]` | key lifecycle, `set` reads stdin |
| `filters`, `facets`, `ports` | vocabulary lookups |

`--json` is accepted before or after the subcommand. Exit codes are fixed: 0 ok,
2 usage or query, 3 auth, 4 rate limited, 5 API, 6 network.

### GUI

Four bands: query row (entry, Search, Load page N, pages spinbox), quick filters
(country, port, product, organisation, Clear), a Treeview with sortable
headings, and a read-only detail pane with a Copy button. The status bar carries
the state on the left and page X of N on the right.

Keys: `Ctrl+Return` or `F5` searches, `Ctrl+L` loads the next page, `Ctrl+E`
exports CSV, `Ctrl+Q` quits, `Return` in any entry field searches.

## Threading

No network call runs on the Tk thread.

1. `start_search()` validates input, resets the table, disables the buttons and
   spawns a daemon thread.
2. The thread calls `client.search()` page by page and pushes
   `("page", page, matches, total, facets, append)` onto a `queue.Queue`.
   Failures push `("error", redacted_message, kind)`.
3. `after(80)` drains the queue on the UI thread and appends rows. The poll loop
   is cancelled from the window's Destroy handler.

Selection maps a Treeview `iid`, which is the index into `self.matches`, back to
the model object. Nothing is serialised into a column.

## Data and storage

- Key: OS keyring where available, otherwise `~/.config/sonargaze/.env` at mode
  0600. Never in the repo, never in argv, never printed unmasked.
- Results: memory only, nothing is written unless you export.
- CSV: plain table, 18 stable columns.
- JSON: `meta` block (tool, version, generated, source, query, total_available,
  pages_fetched) plus `count` and `matches`; `--raw` adds the untouched payloads.
- JSONL: one flat record per line. Markdown: provenance header plus an escaped
  table.
- `default_filename()` slugs the query and stamps the time.

## Failure behaviour

| Condition | Result |
| --- | --- |
| no key | `AuthError` at construction; CLI exits 3 with the three ways to fix it; GUI offers the key dialog |
| 401 | `AuthError`, key redacted |
| 429 | retried honouring `Retry-After`, then `RateLimited` (exit 4) |
| 5xx | retried with backoff, then `APIError` |
| DNS, timeout, socket | retried, then `NetworkError` (exit 6) |
| other 4xx | `APIError` carrying Shodan's own message, no retry |
| empty query, unknown filter, port outside 1..65535 | refused before any request |

## Testing

107 tests, stdlib `unittest`, run under xvfb:

```sh
python -m unittest discover -s tests -t .
```

- `test_api.py` retry ladder, status mapping, key redaction, pacing, parameter
  serialisation, pagination stop conditions
- `test_integration.py` the real urllib transport against a local
  `ThreadingHTTPServer` on 127.0.0.1:0
- `test_models.py`, `test_query.py`, `test_export.py`, `test_config.py`,
  `test_service.py` normalisation, filter validation, round-tripping of hostile
  values, key precedence, page folding
- `test_cli.py` table and JSON output, exports, exit codes, key lifecycle
- `test_gui.py` real widgets under Xvfb with an injected fake client

## Limitations

- Shodan caps how deep a plan may page. `total` is surfaced and paging stops
  there; plan depth is not enforced client-side.
- No facet UI beyond `--facets` in the CLI. The GUI shows country and port
  counts only.
- Host history is CLI only (`host --history`).
- Text only by design: no screenshots, no favicons.
