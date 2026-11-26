"""Tests for the sonargaze.cli front end. _client is patched, nothing leaves the box."""

import io
import json
import os
import tempfile
import unittest
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path
from unittest import mock

from sonargaze import cli
from sonargaze.api import APIError, AuthError, NetworkError, RateLimited

from .helpers import FakeClient, keyring_stub


def run_cli(*argv):
    """Run main() in-process; returns (exit_code, stdout, stderr)."""
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(list(argv))
    return code, out.getvalue(), err.getvalue()


class CliTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.client = FakeClient()
        patcher = mock.patch.object(cli, "_client", lambda *a, **k: self.client)
        patcher.start()
        self.addCleanup(patcher.stop)

    def tearDown(self):
        self._tmp.cleanup()


class SearchOutputTests(CliTestBase):
    def test_table(self):
        code, out, _ = run_cli("search", "apache")
        self.assertEqual(code, 0)
        self.assertIn("IP", out)
        self.assertIn("203.0.113.1", out)
        self.assertIn("3 of 3 result(s) across 1 page(s)", out)

    def test_json_is_machine_readable(self):
        code, out, _ = run_cli("search", "apache", "--json")
        data = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(data["count"], 3)
        self.assertEqual(data["meta"]["query"], "apache")
        self.assertEqual(data["matches"][0]["product"], "nginx")

    def test_verbose_prints_details(self):
        code, out, _ = run_cli("search", "apache", "-v")
        self.assertEqual(code, 0)
        self.assertIn("Banner", out)

    def test_export_to_a_file(self):
        target = self.dir / "results.json"
        code, out, _ = run_cli("search", "apache", "-o", str(target), "--raw")
        self.assertEqual(code, 0)
        self.assertTrue(target.exists())
        data = json.loads(target.read_text(encoding="utf-8"))
        self.assertEqual(data["count"], 3)
        self.assertIn("raw", data)
        self.assertIn("wrote", out)

    def test_filters_become_shodan_syntax(self):
        run_cli("search", "apache", "-l", "1", "--filter", "country=CA", "--filter", "port=443")
        self.assertEqual(self.client.calls[0]["query"], "apache country:CA port:443")


class UsageErrorTests(CliTestBase):
    def test_malformed_filter(self):
        code, _, err = run_cli("search", "apache", "--filter", "country")
        self.assertEqual(code, 2)
        self.assertIn("NAME=VALUE", err)

    def test_empty_query(self):
        code, _, err = run_cli("search", "   ")
        self.assertEqual(code, 2)
        self.assertIn("needs at least one term", err)

    def test_no_subcommand(self):
        with self.assertRaises(SystemExit):
            cli.main([])

    def test_version_flag(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit), redirect_stdout(out):
            cli.main(["--version"])
        self.assertIn("sonargaze", out.getvalue())


class ExitCodeTests(CliTestBase):
    def assert_exit(self, error, expected):
        self.client = FakeClient(error=error)
        with mock.patch.object(cli, "_client", lambda *a, **k: self.client):
            code, _, err = run_cli("search", "apache")
        self.assertEqual(code, expected)
        self.assertTrue(err.startswith("sonargaze: "))

    def test_auth(self):
        self.assert_exit(AuthError("bad key"), cli.EXIT_AUTH)

    def test_rate_limited(self):
        self.assert_exit(RateLimited("slow down"), cli.EXIT_RATE)

    def test_api_error(self):
        self.assert_exit(APIError("nope", 400), cli.EXIT_API)

    def test_network(self):
        self.assert_exit(NetworkError("offline"), cli.EXIT_NETWORK)


class OtherCommandTests(CliTestBase):
    def test_host_lists_services(self):
        self.client = FakeClient(pages={1: {"ip_str": "203.0.113.4", "ports": [80, 443]}})
        with mock.patch.object(cli, "_client", lambda *a, **k: self.client):
            code, out, _ = run_cli("host", "203.0.113.4")
        self.assertEqual(code, 0)
        self.assertIn("203.0.113.4", out)

    def test_info_prints_credits(self):
        code, out, _ = run_cli("info")
        self.assertEqual(code, 0)
        self.assertIn("query credits 99", out)

    def test_ports_are_listed(self):
        self.client.ports = lambda: [80, 443]
        code, out, _ = run_cli("ports")
        self.assertEqual(code, 0)
        self.assertIn("80 443", out)


class KeyCommandTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)
        self.env = mock.patch.dict(
            os.environ, {"SONARGAZE_CONFIG_DIR": str(self.dir / "config")}, clear=False
        )
        self.env.start()
        os.environ.pop("SONARGAZE_API_KEY", None)
        os.environ.pop("SHODAN_API_KEY", None)
        self.addCleanup(self.env.stop)
        self.addCleanup(self._tmp.cleanup)
        cwd = str(Path.cwd())
        os.chdir(self.dir)
        self.addCleanup(os.chdir, cwd)

    def test_status_without_a_key(self):

        with keyring_stub(fail=True):
            code, out, _ = run_cli("key", "status")
        self.assertEqual(code, cli.EXIT_AUTH)
        self.assertIn("no API key", out)

    def test_set_reads_stdin_and_stores(self):

        with keyring_stub(fail=True), mock.patch("sys.stdin", io.StringIO("stdin-key\n")):
            code, out, _ = run_cli("key", "set", "--no-keyring")
        self.assertEqual(code, 0)
        self.assertIn("stored in", out)
        stored = (self.dir / "config" / ".env").read_text(encoding="utf-8")
        self.assertIn("SHODAN_API_KEY=stdin-key", stored)


if __name__ == "__main__":
    unittest.main()
