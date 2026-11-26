"""Tests for exports: round-tripping, provenance, hostile values."""

import csv
import json
import tempfile
import unittest
from pathlib import Path

from sonargaze.export import (
    CSV_FIELDS,
    ExportError,
    default_filename,
    export,
    export_csv,
    export_json,
    export_jsonl,
    export_markdown,
    provenance,
)
from sonargaze.models import Match

from .helpers import match_item


def matches(count=2):
    return [Match.from_payload(match_item(i)) for i in range(count)]


class ExportTestBase(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.dir = Path(self._tmp.name)

    def tearDown(self):
        self._tmp.cleanup()


class CsvTests(ExportTestBase):
    def test_round_trips_commas_quotes_and_newlines(self):
        nasty = Match.from_payload(
            match_item(data='<pre>a, b "quoted"\nsecond line</pre>', org="Org, Inc.")
        )
        path = export_csv(self.dir / "out.csv", [nasty])
        with path.open(encoding="utf-8") as handle:
            rows = list(csv.DictReader(handle))
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["org"], "Org, Inc.")
        self.assertIn("second line", rows[0]["banner"])
        self.assertLessEqual(set(CSV_FIELDS), set(rows[0]))

    def test_creates_missing_directories(self):
        path = export_csv(self.dir / "deep" / "nested" / "out.csv", matches(1))
        self.assertTrue(path.exists())


class JsonTests(ExportTestBase):
    def test_carries_provenance_and_count(self):
        meta = provenance("apache country:CA", total=421, pages=2)
        path = export_json(self.dir / "out.json", matches(2), meta)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["count"], 2)
        self.assertEqual(data["meta"]["query"], "apache country:CA")
        self.assertEqual(data["meta"]["total_available"], 421)
        self.assertEqual(data["meta"]["pages_fetched"], 2)
        self.assertEqual(data["meta"]["tool"], "sonargaze")
        self.assertNotIn("raw", data)

    def test_can_include_raw_payloads(self):
        path = export_json(self.dir / "out.json", matches(1), provenance("x"), include_raw=True)
        data = json.loads(path.read_text(encoding="utf-8"))
        self.assertEqual(data["raw"][0]["ip_str"], "203.0.113.1")

    def test_jsonl_writes_one_object_per_line(self):
        path = export_jsonl(self.dir / "out.jsonl", matches(3))
        lines = [line for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
        self.assertEqual(len(lines), 3)
        self.assertEqual(json.loads(lines[0])["ip"], "203.0.113.1")


class MarkdownTests(ExportTestBase):
    def test_escapes_pipes_and_mentions_provenance(self):
        tricky = Match.from_payload(match_item(org="A | B"))
        path = export_markdown(self.dir / "out.md", [tricky], provenance("apache", total=1))
        text = path.read_text(encoding="utf-8")
        self.assertIn("A \\| B", text)
        self.assertIn("**Query:** `apache`", text)
        self.assertTrue(text.startswith("# sonargaze results"))
        self.assertIn("| IP | Port |", text)


class DispatchTests(ExportTestBase):
    def test_by_extension(self):
        for name in ("a.csv", "a.json", "a.md"):
            written = export(self.dir / name, matches(1))
            self.assertTrue(written.exists(), name)

    def test_unknown_format_is_refused(self):
        with self.assertRaises(ExportError):
            export(self.dir / "a.xlsx", matches(1))

    def test_unwritable_path_raises_export_error(self):
        blocker = self.dir / "file"
        blocker.write_text("x", encoding="utf-8")
        with self.assertRaises(ExportError):
            export_csv(blocker / "out.csv", matches(1))


class FilenameTests(unittest.TestCase):
    def test_filesystem_safe(self):
        name = default_filename('apache country:"CA" /weird:*', "csv")
        self.assertTrue(name.startswith("sonargaze-apache-country-CA-weird"))
        self.assertTrue(name.endswith(".csv"))
        self.assertFalse(any(ch in name for ch in '/\\:"*'))
        self.assertLess(len(name), 100)

    def test_empty_query(self):
        self.assertTrue(default_filename("", "json").startswith("sonargaze-results-"))


if __name__ == "__main__":
    unittest.main()
