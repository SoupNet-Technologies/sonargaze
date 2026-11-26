"""GUI tests. Real Tk widgets under Xvfb, fake API client, no network."""

import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

try:
    import tkinter as tk
except ImportError:  # pragma: no cover - tkinter ships with most Pythons
    tk = None

from sonargaze.api import AuthError
from sonargaze.gui import SonargazeApp

from .helpers import FakeClient, payload


def pump(root, condition, timeout=5.0):
    """Run the Tk event loop until condition() is true or time runs out."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        root.update()
        if condition():
            return True
        time.sleep(0.02)
    return False


class GuiTestBase(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if tk is None:
            raise unittest.SkipTest("tkinter is not installed")
        try:
            cls.root = tk.Tk()
        except tk.TclError:
            raise unittest.SkipTest("no display available (run under xvfb-run)") from None
        cls.root.withdraw()

    @classmethod
    def tearDownClass(cls):
        cls.root.destroy()

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.patchers = []
        self.addCleanup(self._tmp.cleanup)

    def tearDown(self):
        for patcher in self.patchers:
            patcher.stop()

    def app(self, client=None):
        return SonargazeApp(self.root, client=client or FakeClient(), interactive=False)

    def patch_dialog(self, target):
        patcher = mock.patch("sonargaze.gui.filedialog.asksaveasfilename", lambda **kw: str(target))
        patcher.start()
        self.patchers.append(patcher)

    def search(self, app, query="apache", expect=None):
        app.query_var.set(query)
        app.start_search()
        if expect is not None:
            self.assertTrue(pump(self.root, lambda: len(app.matches) == expect), "no results")


class SearchTests(GuiTestBase):
    def test_search_fills_the_tree_and_selection_fills_details(self):
        app = self.app(FakeClient({1: payload(3, total=3)}))
        self.search(app, expect=3)
        self.assertEqual(len(app.tree.get_children()), 3)

        app.tree.selection_set("0")
        app._on_select()
        details = app.detail.get("1.0", tk.END)
        self.assertIn("203.0.113.1:443", details)
        self.assertIn("nginx 1.24.0", details)
        self.assertIn("Banner", details)

    def test_detail_pane_is_read_only(self):
        app = self.app(FakeClient({1: payload(1, total=1)}))
        self.search(app, expect=1)
        self.assertEqual(str(app.detail.cget("state")), "disabled")

    def test_load_more_appends_the_next_page(self):
        app = self.app(FakeClient({1: payload(100, total=120), 2: payload(20, total=120)}))
        self.search(app, expect=100)
        app.load_more()
        self.assertTrue(pump(self.root, lambda: len(app.matches) == 120), "second page missing")
        self.assertEqual(app.pages_fetched, 2)
        self.assertIn("page 2", app.counter_var.get())

    def test_worker_errors_land_in_the_status_bar(self):
        app = self.app(FakeClient(error=AuthError("bad key")))
        app.query_var.set("apache")
        app.start_search()
        self.assertTrue(pump(self.root, lambda: "search failed" in app.status_var.get()))
        self.assertIn("bad key", app.status_var.get())

    def test_clear_results_empties_everything(self):
        app = self.app(FakeClient({1: payload(2, total=2)}))
        self.search(app, expect=2)
        app.clear_results()
        self.assertEqual(app.matches, [])
        self.assertEqual(app.tree.get_children(), ())
        self.assertEqual(app.detail.get("1.0", tk.END).strip(), "")


class QueryTests(GuiTestBase):
    def test_quick_filters_become_query_syntax(self):
        app = self.app()
        app.query_var.set("apache")
        app._filter_entries["country"].insert(0, "CA")
        app._filter_entries["port"].insert(0, "443")
        self.assertEqual(app.current_query(), "apache country:CA port:443")

    def test_empty_query_is_refused_inline(self):
        app = self.app()
        app.start_search()
        self.assertIn("type a query", app.status_var.get())
        self.assertEqual(app.matches, [])

    def test_bad_port_filter_is_reported_not_raised(self):
        app = self.app()
        app.query_var.set("apache")
        app._filter_entries["port"].insert(0, "70000")
        app.start_search()
        self.assertIn("port must be between", app.status_var.get())


class DisplayTests(GuiTestBase):
    def test_sorting_by_port_reorders_rows(self):
        app = self.app(FakeClient({1: payload(3, total=3)}))
        self.search(app, expect=3)
        app.sort_by("port")
        first = app.tree.get_children()[0]
        self.assertEqual(app.matches[int(first)].port, 443)
        app.sort_by("port")
        first = app.tree.get_children()[0]
        self.assertEqual(app.matches[int(first)].port, 445)

    def test_copy_details_puts_text_on_the_clipboard(self):
        app = self.app(FakeClient({1: payload(1, total=1)}))
        self.search(app, expect=1)
        app.tree.selection_set("0")
        app._on_select()
        app.copy_details()
        self.assertIn("copied", app.status_var.get())
        self.assertIn("203.0.113.1", self.root.clipboard_get())


class ExportTests(GuiTestBase):
    def test_export_writes_provenance(self):
        app = self.app(FakeClient({1: payload(2, total=2)}))
        self.search(app, expect=2)
        target = self.dir / "out.json"
        self.patch_dialog(target)
        app.export("json")
        self.assertTrue(target.exists())
        self.assertIn("wrote", app.status_var.get())

    def test_export_without_results_does_nothing(self):
        app = self.app()
        patcher = mock.patch(
            "sonargaze.gui.filedialog.asksaveasfilename",
            lambda **kw: self.fail("export dialog should not open"),
        )
        patcher.start()
        self.patchers.append(patcher)
        app.export("csv")
        self.assertIn("nothing to export", app.status_var.get())


if __name__ == "__main__":
    unittest.main()
