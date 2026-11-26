"""Tk front end: worker thread fills a queue, after() drains it on the UI thread."""

from __future__ import annotations

import contextlib
import queue
import sys
import threading
import tkinter as tk
import webbrowser
from pathlib import Path
from tkinter import filedialog, messagebox, ttk
from typing import Any

from . import APP_NAME, PROJECT_URL, TAGLINE, __version__
from .api import ShodanClient, SonargazeError
from .config import ConfigError, find_api_key, mask_key, require_api_key, save_api_key
from .export import ExportError, default_filename, export, provenance
from .models import Match, matches_from_payload, sort_key
from .query import QueryBuilder, QueryError

QUICK_FILTERS = (
    ("country", "Country", 6),
    ("port", "Port", 6),
    ("product", "Product", 14),
    ("org", "Organisation", 16),
)

SHODAN_DOCS = "https://beta.shodan.io/search/filters"


class KeyDialog(tk.Toplevel):
    """Ask for an API key without ever echoing it to the screen or disk in clear."""

    def __init__(self, master: tk.Misc):
        super().__init__(master)
        self.title(f"{APP_NAME}: Shodan API key")
        self.resizable(False, False)
        self.transient(master)
        self.result: str | None = None
        self.use_keyring = tk.BooleanVar(value=True)

        body = ttk.Frame(self, padding=14)
        body.pack(fill="both", expand=True)
        ttk.Label(
            body,
            text="Paste your Shodan API key. It is stored in the OS keyring when "
            "available, otherwise in a 0600 file under your config directory.",
            wraplength=420,
            justify="left",
        ).pack(anchor="w")
        self.entry = ttk.Entry(body, width=44, show="\u2022")
        self.entry.pack(fill="x", pady=(10, 6))
        ttk.Checkbutton(body, text="Save it for next time", variable=self.use_keyring).pack(
            anchor="w"
        )
        buttons = ttk.Frame(body)
        buttons.pack(fill="x", pady=(12, 0))
        ttk.Button(buttons, text="Cancel", command=self._cancel).pack(side="right")
        ttk.Button(buttons, text="Use key", command=self._accept).pack(side="right", padx=(0, 8))
        self.entry.bind("<Return>", lambda _event: self._accept())
        self.bind("<Escape>", lambda _event: self._cancel())
        self.grab_set()
        self.entry.focus_set()

    def _accept(self):
        key = self.entry.get().strip()
        if not key:
            return
        self.result = key
        if self.use_keyring.get():
            with contextlib.suppress(ConfigError):
                save_api_key(key, prefer_keyring=True)
        self.destroy()

    def _cancel(self):
        self.result = None
        self.destroy()

    def ask(self) -> str | None:
        self.wait_window()
        return self.result


class SonargazeApp:
    """Main window. ``client`` can be injected for tests."""

    def __init__(
        self,
        master: tk.Tk,
        *,
        client: ShodanClient | None = None,
        interactive: bool = True,
    ):
        self.master = master
        self.client = client
        self.interactive = interactive
        self._events: queue.Queue[tuple[Any, ...]] = queue.Queue()
        self._busy = False
        self.matches: list[Match] = []
        self.total = 0
        self.pages_fetched = 0
        self.facets: dict[str, Any] = {}
        self.last_query = ""
        self._sort_column = "ip"
        self._sort_descending = False
        self._last_dir = str(Path.home())
        self._filter_entries: dict[str, ttk.Entry] = {}

        self.master.title(f"{APP_NAME} {__version__}: {TAGLINE}")
        self.master.geometry("1120x760")
        self.master.minsize(860, 540)

        self._build_menu()
        self._build_widgets()
        self._set_status("ready")
        # bind close event so the poll loop dies with the window
        self._drain_job = self.master.after(80, self._drain)
        self.master.bind("<Destroy>", self._on_destroy, add="+")
        if interactive:
            self.master.after(120, self._startup_key_check)

    # MARK: layout

    def _build_menu(self):
        menubar = tk.Menu(self.master)

        file_menu = tk.Menu(menubar, tearoff=False)
        file_menu.add_command(label="Set API key\u2026", command=self.prompt_for_key)
        file_menu.add_separator()
        file_menu.add_command(label="Export CSV\u2026", command=lambda: self.export("csv"))
        file_menu.add_command(label="Export JSON\u2026", command=lambda: self.export("json"))
        file_menu.add_command(
            label="Export Markdown\u2026", command=lambda: self.export("markdown")
        )
        file_menu.add_separator()
        file_menu.add_command(label="Quit", accelerator="Ctrl+Q", command=self.master.destroy)
        menubar.add_cascade(label="File", menu=file_menu)

        search_menu = tk.Menu(menubar, tearoff=False)
        search_menu.add_command(
            label="Search", accelerator="Ctrl+Return", command=self.start_search
        )
        search_menu.add_command(
            label="Load next page", accelerator="Ctrl+L", command=self.load_more
        )
        search_menu.add_command(label="Clear results", command=self.clear_results)
        search_menu.add_command(label="Copy details", command=self.copy_details)
        menubar.add_cascade(label="Search", menu=search_menu)

        help_menu = tk.Menu(menubar, tearoff=False)
        help_menu.add_command(
            label="Shodan query syntax", command=lambda: webbrowser.open(SHODAN_DOCS)
        )
        help_menu.add_command(label="Project page", command=lambda: webbrowser.open(PROJECT_URL))
        help_menu.add_command(label="About", command=self.show_about)
        menubar.add_cascade(label="Help", menu=help_menu)

        self.master.config(menu=menubar)
        self.master.bind("<Control-Return>", lambda _event: self.start_search())
        self.master.bind("<F5>", lambda _event: self.start_search())
        self.master.bind("<Control-l>", lambda _event: self.load_more())
        self.master.bind("<Control-e>", lambda _event: self.export("csv"))
        self.master.bind("<Control-q>", lambda _event: self.master.destroy())

    def _build_widgets(self):
        outer = ttk.Frame(self.master, padding=(12, 10, 12, 6))
        outer.pack(fill="both", expand=True)
        outer.columnconfigure(0, weight=1)
        outer.rowconfigure(2, weight=3)
        outer.rowconfigure(4, weight=2)

        query_row = ttk.Frame(outer)
        query_row.grid(row=0, column=0, sticky="ew")
        query_row.columnconfigure(1, weight=1)
        ttk.Label(query_row, text="Query").grid(row=0, column=0, padx=(0, 6))
        self.query_var = tk.StringVar()
        self.query_entry = ttk.Entry(query_row, textvariable=self.query_var)
        self.query_entry.grid(row=0, column=1, sticky="ew")
        self.query_entry.bind("<Return>", lambda _event: self.start_search())
        self.search_button = ttk.Button(query_row, text="Search", command=self.start_search)
        self.search_button.grid(row=0, column=2, padx=(6, 0))
        self.more_button = ttk.Button(
            query_row, text="Load page 2", command=self.load_more, state=tk.DISABLED
        )
        self.more_button.grid(row=0, column=3, padx=(6, 0))
        ttk.Label(query_row, text="pages").grid(row=0, column=4, padx=(10, 4))
        self.pages_var = tk.IntVar(value=1)
        self.pages_spin = ttk.Spinbox(
            query_row, from_=1, to=10, width=4, textvariable=self.pages_var
        )
        self.pages_spin.grid(row=0, column=5)

        filter_row = ttk.Frame(outer)
        filter_row.grid(row=1, column=0, sticky="ew", pady=(8, 8))
        column = 0
        for name, label, width in QUICK_FILTERS:
            ttk.Label(filter_row, text=label).grid(row=0, column=column, padx=(0, 4))
            entry = ttk.Entry(filter_row, width=width)
            entry.grid(row=0, column=column + 1, padx=(0, 12))
            entry.bind("<Return>", lambda _event: self.start_search())
            self._filter_entries[name] = entry
            column += 2
        ttk.Button(filter_row, text="Clear results", command=self.clear_results).grid(
            row=0, column=column
        )

        tree_frame = ttk.Frame(outer)
        tree_frame.grid(row=2, column=0, sticky="nsew")
        tree_frame.columnconfigure(0, weight=1)
        tree_frame.rowconfigure(0, weight=1)

        self.tree = ttk.Treeview(
            tree_frame,
            columns=("ip", "port", "product", "org", "location", "hostnames"),
            show="headings",
            selectmode="browse",
        )
        for name, label, width in (
            ("ip", "IP", 130),
            ("port", "Port", 60),
            ("product", "Product", 170),
            ("org", "Organisation", 180),
            ("location", "Location", 170),
            ("hostnames", "Hostnames", 240),
        ):
            self.tree.heading(name, text=label, command=lambda c=name: self.sort_by(c))
            self.tree.column(name, width=width, stretch=True, anchor="w")
        self.tree.grid(row=0, column=0, sticky="nsew")
        yscroll = ttk.Scrollbar(tree_frame, orient="vertical", command=self.tree.yview)
        yscroll.grid(row=0, column=1, sticky="ns")
        self.tree.configure(yscrollcommand=yscroll.set)
        self.tree.bind("<<TreeviewSelect>>", self._on_select)
        self.tree.bind("<Double-1>", self._on_select)

        # detail pane, read only
        detail_frame = ttk.Frame(outer)
        detail_frame.grid(row=4, column=0, sticky="nsew", pady=(10, 0))
        detail_frame.columnconfigure(0, weight=1)
        detail_frame.rowconfigure(1, weight=1)
        header = ttk.Frame(detail_frame)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", pady=(0, 4))
        header.columnconfigure(0, weight=1)
        ttk.Label(header, text="Details").grid(row=0, column=0, sticky="w")
        ttk.Button(header, text="Copy", command=self.copy_details).grid(row=0, column=1, sticky="e")

        self.detail = tk.Text(
            detail_frame,
            height=12,
            wrap="none",
            state=tk.DISABLED,
            font=("TkFixedFont", 10),
            relief="sunken",
            borderwidth=1,
        )
        self.detail.grid(row=1, column=0, sticky="nsew")
        dscroll = ttk.Scrollbar(detail_frame, orient="vertical", command=self.detail.yview)
        dscroll.grid(row=1, column=1, sticky="ns")
        self.detail.configure(yscrollcommand=dscroll.set)

        # status bar
        status = ttk.Frame(self.master, padding=(12, 0, 12, 8))
        status.pack(fill="x", side="bottom")
        status.columnconfigure(0, weight=1)
        self.status_var = tk.StringVar(value="ready")
        ttk.Label(status, textvariable=self.status_var, anchor="w").grid(
            row=0, column=0, sticky="ew"
        )
        self.counter_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self.counter_var, anchor="e").grid(
            row=0, column=1, sticky="e"
        )

    # MARK: events

    def _set_status(self, text: str):
        self.status_var.set(text)

    def _set_counter(self):
        if not self.matches:
            self.counter_var.set("")
            return
        self.counter_var.set(
            f"page {self.pages_fetched} \u00b7 {len(self.matches)} of {self.total or '?'} results"
        )

    def _busy_state(self, busy: bool):
        self._busy = busy
        state = tk.DISABLED if busy else tk.NORMAL
        self.search_button.configure(state=state)
        self.pages_spin.configure(state=state)
        self.more_button.configure(state=tk.DISABLED if busy else self._more_state())

    def _more_state(self) -> str:
        done = self.pages_fetched * 100 >= self.total > 0
        return tk.DISABLED if (not self.matches or done) else tk.NORMAL

    # MARK: query

    def current_query(self) -> str:
        """Base text plus the quick filters, rendered as Shodan syntax."""
        builder = QueryBuilder(base=self.query_var.get().strip())
        # quick filters turn into shodan syntax
        for name, entry in self._filter_entries.items():
            value = entry.get().strip()
            if value:
                builder.with_filter(name, value)
        if not builder.base and not builder.filters:
            raise QueryError("type a query or fill in a filter first")
        return builder.build()

    def _facets(self) -> dict[str, Any] | None:
        return {"country": 8, "port": 8}

    # MARK: search

    def _ensure_client(self) -> ShodanClient | None:
        if self.client is not None:
            return self.client
        try:
            key = require_api_key()
        except ConfigError:
            if not self.interactive:
                return None
            key = KeyDialog(self.master).ask()
            if not key:
                self._set_status("no API key: File \u25b8 Set API key\u2026")
                return None
        self.client = ShodanClient(key)
        return self.client

    def start_search(self):
        if self._busy:
            return
        try:
            query = self.current_query()
        except QueryError as exc:
            self._set_status(str(exc))
            if self.interactive:
                messagebox.showwarning(APP_NAME, str(exc), parent=self.master)
            return
        client = self._ensure_client()
        if client is None:
            return
        self.last_query = query
        self.matches = []
        self.total = 0
        self.pages_fetched = 0
        self._render_matches()
        pages = 1
        try:
            pages = max(1, min(10, int(self.pages_var.get())))
        except (tk.TclError, ValueError):
            pages = 1
        self._launch(client, query, pages=pages, append=False)

    def load_more(self):
        if self._busy or not self.matches:
            return
        client = self._ensure_client()
        if client is None:
            return
        if not self.last_query:
            self.last_query = self.current_query()
        self._launch(client, self.last_query, pages=1, append=True)

    def _launch(self, client: ShodanClient, query: str, *, pages: int, append: bool):
        self._busy_state(True)
        self._set_status(f"searching page {self.pages_fetched + 1}\u2026")
        thread = threading.Thread(
            target=self._job,
            args=(client, query, pages, append),
            daemon=True,
            name="sonargaze-search",
        )
        thread.start()

    def _job(self, client: ShodanClient, query: str, pages: int, append: bool):
        """Worker thread: fetch pages, hand each one to the UI through the queue."""
        # each page goes to the ui thread through the queue
        first_page = self.pages_fetched + 1 if append else 1
        try:
            for offset in range(pages):
                page = first_page + offset
                payload = client.search(query, page=page, facets=self._facets())
                matches = matches_from_payload(payload)
                total = payload.get("total") or 0
                facets = payload.get("facets") or {}
                self._events.put(("page", page, matches, total, facets, append))
                if len(matches) < 100:
                    break
        except SonargazeError as exc:
            self._events.put(("error", client.redact(str(exc)), type(exc).__name__))
        except Exception as exc:  # pragma: no cover - defensive
            self._events.put(("error", client.redact(f"{type(exc).__name__}: {exc}"), "Error"))
        else:
            self._events.put(("done",))

    def _on_destroy(self, event=None):
        # cancel the poll loop so a destroyed window leaves no pending callbacks
        if event is not None and event.widget is not self.master:
            return
        if self._drain_job is not None:
            with contextlib.suppress(tk.TclError):
                self.master.after_cancel(self._drain_job)
            self._drain_job = None

    def _drain(self):
        """UI thread: consume worker events."""
        while True:
            try:
                event = self._events.get_nowait()
            except queue.Empty:
                break
            self._handle_event(event)
        self._drain_job = self.master.after(80, self._drain)

    def _handle_event(self, event: tuple[Any, ...]):
        kind = event[0]
        if kind == "page":
            _, page, matches, total, facets, append = event
            self._absorb_page(page, matches, total, facets, append)
        elif kind == "error":
            _, message, _name = event
            self._busy_state(False)
            self._set_status(f"search failed: {message}")
            if self.interactive:
                messagebox.showerror(APP_NAME, message, parent=self.master)
        elif kind == "done":
            self._busy_state(False)
            self._set_status(f"{len(self.matches)} result(s) for {self.last_query}")
            self._set_counter()

    def _absorb_page(
        self,
        page: int,
        matches: list[Match],
        total: Any,
        facets: dict[str, Any],
        append: bool,
    ):
        if not append:
            self.matches = []
        self.matches.extend(matches)
        self.pages_fetched = max(self.pages_fetched, page)
        with contextlib.suppress(TypeError, ValueError):
            self.total = int(total)
        if facets:
            self.facets = facets
        self._render_matches()
        self._set_counter()
        self.more_button.configure(state=self._more_state())
        if matches:
            self._set_status(f"page {page}: {len(matches)} result(s)")

    # MARK: results

    def sort_by(self, column: str):
        if column == self._sort_column:
            self._sort_descending = not self._sort_descending
        else:
            self._sort_column = column
            self._sort_descending = False
        self._render_matches()

    def _render_matches(self):
        self.tree.delete(*self.tree.get_children())
        if not self.matches:
            self._set_details("")
            return
        # sort indices, the rows stay put in self.matches
        indices = list(range(len(self.matches)))
        indices.sort(key=lambda i: sort_key(self.matches[i], self._sort_column))
        if self._sort_descending:
            indices.reverse()
        for index in indices:
            match = self.matches[index]
            self.tree.insert(
                "",
                tk.END,
                iid=str(index),
                values=(
                    match.ip,
                    match.port if match.port is not None else "",
                    match.product_label,
                    match.org,
                    match.location,
                    match.hostname_label,
                ),
            )
        self.tree.heading(
            self._sort_column,
            text=self._heading_label(self._sort_column)
            + (" \u25bc" if self._sort_descending else " \u25b2"),
        )

    @staticmethod
    def _heading_label(column: str) -> str:
        return {
            "ip": "IP",
            "port": "Port",
            "product": "Product",
            "org": "Organisation",
            "location": "Location",
            "hostnames": "Hostnames",
        }.get(column, column.title())

    def _on_select(self, _event: object = None):
        selection = self.tree.selection()
        if not selection:
            return
        try:
            index = int(selection[0])
        except (TypeError, ValueError):
            return
        if 0 <= index < len(self.matches):
            self._set_details(self.matches[index].details())

    def _set_details(self, text: str):
        self.detail.configure(state=tk.NORMAL)
        self.detail.delete("1.0", tk.END)
        if text:
            self.detail.insert("1.0", text)
        self.detail.configure(state=tk.DISABLED)

    def copy_details(self):
        text = self.detail.get("1.0", tk.END).strip()
        if not text:
            return
        self.master.clipboard_clear()
        self.master.clipboard_append(text)
        self._set_status("details copied to clipboard")

    def clear_results(self):
        self.matches = []
        self.total = 0
        self.pages_fetched = 0
        self.facets = {}
        self.last_query = ""
        self._render_matches()
        self._set_counter()
        self.more_button.configure(state=tk.DISABLED)
        self._set_status("cleared")

    # MARK: export

    def export(self, fmt: str):
        if not self.matches:
            self._set_status("nothing to export yet")
            return
        # markdown wants .md, everything else keeps its own name
        extension = {"csv": "csv", "json": "json", "markdown": "md"}.get(fmt, fmt)
        path = filedialog.asksaveasfilename(
            parent=self.master,
            title=f"Export {fmt}",
            defaultextension=f".{extension}",
            initialdir=self._last_dir,
            initialfile=default_filename(self.last_query or "results", extension),
            filetypes=[(f"{fmt} files", f"*.{extension}"), ("All files", "*.*")],
        )
        if not path:
            return
        meta = provenance(self.last_query, total=self.total, pages=self.pages_fetched)
        try:
            written = export(path, self.matches, fmt=fmt, meta=meta)
        except ExportError as exc:
            self._set_status(str(exc))
            messagebox.showerror(APP_NAME, str(exc), parent=self.master)
            return
        self._last_dir = str(Path(written).parent)
        self._set_status(f"wrote {written} ({len(self.matches)} rows)")

    # MARK: misc

    def prompt_for_key(self):
        key = KeyDialog(self.master).ask()
        if key:
            self.client = ShodanClient(key)
            self._set_status("API key loaded")

    def _startup_key_check(self):
        key = find_api_key()
        if key:
            self.client = self.client or ShodanClient(key)
            self._set_status(f"ready, key {mask_key(key)}")
        else:
            self._set_status("no API key found: File \u25b8 Set API key\u2026")

    def show_about(self):
        messagebox.showinfo(
            f"About {APP_NAME}",
            f"{APP_NAME} {__version__}\n{TAGLINE}\n\n"
            "Reads Shodan's dataset. Sends no packets to the hosts it reports on.\n"
            "No telemetry, no analytics, no account: the only endpoint it talks to "
            "is api.shodan.io.",
            parent=self.master,
        )


def main(argv: list[str] | None = None) -> int:
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"{APP_NAME}: no display available ({exc}); use the CLI instead", file=sys.stderr)
        return 1
    SonargazeApp(root)
    root.mainloop()
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())


__all__ = ["KeyDialog", "SonargazeApp", "main"]
