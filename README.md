# Sonargaze

A Shodan front end in two skins: a Tk window for reading results as a table,
and a command-line tool for piping them somewhere else. Both run the same
search code underneath and both talk to `api.shodan.io` and nothing else.
Sonargaze only queries the index. It never sends a packet to the hosts it
reports on.

Python 3.10+, no third-party dependencies. `urllib` does the HTTP, `tkinter`
draws the window, everything else is stdlib.

## Install

```sh
pip install .          # from a checkout
```

This installs two entry points:

- `sonargaze`: the window (needs a display; on Debian/Ubuntu:
  `sudo apt install python3-tk`)
- `sonargaze-cli`: the command line

Optional: `pip install keyring` to keep the API key in the OS keyring instead
of a config file.

## The API key

```sh
sonargaze-cli key set      # reads the key from stdin or a hidden prompt
sonargaze-cli key status   # shows whether one exists, masked
sonargaze-cli info         # plan, query credits, scan credits
```

Lookup order is `SONARGAZE_API_KEY`, `SHODAN_API_KEY`, the OS keyring, then
`.env` in the working directory or `~/.config/sonargaze/.env`. If a key ever
lands in a config file it is written 0600, and it is never printed.

## CLI usage

```sh
sonargaze-cli search 'nginx country:CA'
sonargaze-cli search 'apache' -p 3 --facets country,org
sonargaze-cli search 'port:3389 has_vuln:true' -o rdp.json --raw
sonargaze-cli search 'http.title:"Admin Panel"' -l 20 -v
sonargaze-cli host 203.0.113.10 --history
sonargaze-cli --json search 'apache' | jq .count
```

`-p` fetches N pages of 100 results, `-l` limits the rows printed, `-o` writes
the results out and `--raw` keeps the untouched Shodan payloads in the JSON.
Exports go by file extension: `.csv`, `.json`, `.jsonl`, `.md`.

Exit codes are fixed: 0 ok, 2 usage or query, 3 auth, 4 rate limited, 5 API
error, 6 network error.

## GUI usage

Launch with `sonargaze` (or `python -m sonargaze.gui` from a checkout). Type a
query, or fill in the country/port/product/organisation boxes and let them
build the query for you. Click a column heading to sort, click a row to read
its banner with the markup stripped out, and use Load page 2 to pull the next
hundred results without losing what is on screen. The network runs on a worker
thread, so the window keeps painting while a search is in flight.

`Ctrl+Return` searches, `Ctrl+L` loads the next page, `Ctrl+E` exports CSV,
`Ctrl+Q` quits. The File menu has the other export formats and the API key
dialog.

## Exports

CSV is a plain 18 column table so it opens anywhere. JSON and Markdown carry a
`meta` block with the query, the timestamp, how many pages were fetched and the
version that produced it, which is the part that matters when a finding turns
up in a report six months later.

Results are third-party host data. The `.gitignore` in this repo keeps `*.csv`
and `*.jsonl` out of git for that reason, and the same caution applies
anywhere you keep them.

## Development

```sh
python3 -m venv .venv && .venv/bin/pip install -e .
.venv/bin/pip install ruff keyring
make check     # ruff check, then the unittest suite under xvfb
```

The tests are stdlib `unittest`, run with
`python -m unittest discover -s tests -t .`. The GUI tests build real widgets
under Xvfb with a fake client injected, so nothing in the suite touches the
network. `tests/test_integration.py` runs a small HTTP server on 127.0.0.1:0 to
exercise the real urllib transport.

```
sonargaze/api.py       Shodan client: retries, 429 handling, key redaction
sonargaze/models.py    Match model, banner cleanup, sorting
sonargaze/query.py     filter validation and query building
sonargaze/service.py   the paginated search the CLI and GUI share
sonargaze/export.py    csv, json, jsonl, markdown
sonargaze/cli.py       argument parsing and printing
sonargaze/gui.py       the Tk window
sonargaze/config.py    key lookup and storage
```

## License

MIT, see [LICENSE](LICENSE).
