"""Tests for the shared search flow."""

import unittest

from sonargaze.service import SearchResult, absorb, page_limit, search

from .helpers import FakeClient, payload


class SearchTests(unittest.TestCase):
    def test_one_page(self):
        result = search(FakeClient(), "apache", pages=1)
        self.assertEqual(len(result.matches), 3)
        self.assertEqual(result.pages_fetched, 1)
        self.assertEqual(result.total, 3)
        self.assertFalse(result.has_more)

    def test_full_page_triggers_the_next_one(self):
        client = FakeClient({1: payload(100, total=150), 2: payload(50, total=150)})
        result = search(client, "apache", pages=5)
        self.assertEqual(len(result.matches), 150)
        self.assertEqual(result.pages_fetched, 2)
        self.assertEqual([call["page"] for call in client.calls], [1, 2])

    def test_pages_option_is_respected(self):
        client = FakeClient({1: payload(100, total=900), 2: payload(100, total=900)})
        result = search(client, "apache", pages=2)
        self.assertEqual(result.pages_fetched, 2)
        self.assertEqual(len(result.matches), 200)

    def test_on_page_callback_sees_progress(self):
        seen = []
        client = FakeClient({1: payload(100, total=120), 2: payload(20, total=120)})
        search(client, "apache", pages=5, on_page=lambda r, p: seen.append(p))
        self.assertEqual(seen, [1, 2])

    def test_facets_are_kept_from_the_payload(self):
        facets = {"country": [{"value": "CA", "count": 12}]}
        result = search(FakeClient({1: payload(3, total=3, facets=facets)}), "x")
        self.assertEqual(result.facets["country"][0]["value"], "CA")

    def test_zero_pages_is_a_usage_error(self):
        with self.assertRaises(ValueError):
            search(FakeClient(), "x", pages=0)


class AbsorbTests(unittest.TestCase):
    def test_page_limit_rounds_up(self):
        self.assertEqual(page_limit(0), 1)
        self.assertEqual(page_limit(1), 1)
        self.assertEqual(page_limit(101), 2)

    def test_absorb_keeps_the_highest_total(self):
        result = SearchResult(query="x")
        absorb(result, payload(2, total=200), 1)
        absorb(result, payload(0, total=0), 2)
        self.assertEqual(result.total, 200)
        self.assertEqual(result.pages_fetched, 2)


if __name__ == "__main__":
    unittest.main()
