"""Tests for query building and filter validation."""

import unittest

from sonargaze.query import (
    QueryBuilder,
    QueryError,
    build_query,
    clause,
    compose,
    free_text,
    quote_value,
    summarize_params,
)


class QuotingTests(unittest.TestCase):
    def test_compose_skips_blanks(self):
        self.assertEqual(compose(["nginx", "", "  ", "country:CA"]), "nginx country:CA")

    def test_plain_values_are_not_quoted(self):
        self.assertEqual(quote_value("CA"), "CA")
        self.assertEqual(quote_value(443), "443")

    def test_values_with_spaces_or_colons_are_quoted(self):
        self.assertEqual(quote_value("nginx 1.24"), '"nginx 1.24"')
        self.assertEqual(quote_value("http://x"), '"http://x"')

    def test_quotes_and_backslashes_are_refused(self):
        with self.assertRaises(QueryError):
            quote_value('broken"quote')
        with self.assertRaises(QueryError):
            quote_value("back\\slash")


class ClauseTests(unittest.TestCase):
    def test_unknown_filter_is_refused(self):
        with self.assertRaises(QueryError) as caught:
            clause("definitely_not_a_filter", "x")
        self.assertIn("unknown filter", str(caught.exception))

    def test_numeric_filters_are_validated(self):
        self.assertEqual(clause("port", "443"), "port:443")
        for bad in ("not-a-port", "70000", "0"):
            with self.assertRaises(QueryError):
                clause("port", bad)

    def test_boolean_filters_render_true_false(self):
        self.assertEqual(clause("has_vuln", True), "has_vuln:true")
        self.assertEqual(clause("has_vuln", False), "has_vuln:false")
        self.assertEqual(clause("ssl", True), "ssl:true")


class BuilderTests(unittest.TestCase):
    def test_builder_renders_base_plus_filters(self):
        query = QueryBuilder("apache").with_filters(country="CA", port=8443).build()
        self.assertEqual(query, "apache country:CA port:8443")

    def test_builder_rejects_empty_input(self):
        with self.assertRaises(QueryError):
            QueryBuilder("   ").build()

    def test_build_query_merges_filters(self):
        self.assertEqual(build_query("nginx", country="CA", port=80), "nginx country:CA port:80")

    def test_build_query_needs_something_to_search(self):
        with self.assertRaises(QueryError):
            build_query("")

    def test_summarize_and_free_text_split_tokens(self):
        query = 'nginx country:CA "http.title:Admin Panel"'
        self.assertEqual(summarize_params(query)["country"], "CA")
        self.assertIn("nginx", free_text(query))


if __name__ == "__main__":
    unittest.main()
