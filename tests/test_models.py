"""Tests for result normalisation and rendering."""

import unittest

from sonargaze.models import (
    Match,
    format_location,
    matches_from_payload,
    sort_key,
    strip_html,
)

from .helpers import match_item


class MatchParsingTests(unittest.TestCase):
    def test_minimal_payload_does_not_explode(self):
        match = Match.from_payload({"ip_str": "198.51.100.7", "port": "8080"})
        self.assertEqual(match.address, "198.51.100.7:8080")
        self.assertEqual(match.port, 8080)
        self.assertEqual(match.hostname_label, "")
        self.assertEqual(match.location, "")
        self.assertEqual(match.banner_text(), "")

    def test_full_payload_maps_every_field(self):
        match = Match.from_payload(match_item())
        self.assertEqual(match.ip, "203.0.113.1")
        self.assertEqual(match.port, 443)
        self.assertEqual(match.product_label, "nginx 1.24.0")
        self.assertEqual(match.location, "Edmonton, AB, Canada")
        self.assertEqual(match.hostname_label, "a.example.com, b.example.com")
        self.assertEqual(match.vulns, ["CVE-2021-44228"])
        self.assertIn("CVE-2021-44228", match.details())

    def test_missing_location_is_not_an_error(self):
        match = Match.from_payload({"ip_str": "203.0.113.5"})
        self.assertEqual(match.city, "")
        self.assertEqual(match.location, "")
        with self.assertRaises(TypeError):
            match["location"]

    def test_matches_from_payload_tolerates_junk(self):
        self.assertEqual(matches_from_payload(None), [])
        self.assertEqual(matches_from_payload({"matches": "nope"}), [])
        self.assertEqual(len(matches_from_payload({"matches": [match_item(), "junk"]})), 1)


class BannerTests(unittest.TestCase):
    def test_banner_html_is_stripped_and_keeps_lines(self):
        match = Match.from_payload(match_item(data="<p>line one</p><p>line two</p>"))
        self.assertEqual(match.banner_text(), "line one\nline two")

    def test_scripts_and_styles_are_dropped_from_banners(self):
        banner = (
            "<html><style>body{color:red}</style><script>alert(1)</script><body>hello</body></html>"
        )
        text = strip_html(banner)
        self.assertIn("hello", text)
        self.assertNotIn("alert", text)
        self.assertNotIn("color", text)

    def test_entities_are_decoded(self):
        self.assertEqual(strip_html("&lt;root&gt; &amp; friends"), "<root> & friends")

    def test_malformed_html_still_returns_text(self):
        self.assertIn("unterminated", strip_html("<div><span>unterminated"))


class RenderingTests(unittest.TestCase):
    def test_format_location_skips_blanks(self):
        self.assertEqual(
            format_location({"city": "", "region_code": "AB", "country_name": "Canada"}),
            "AB, Canada",
        )
        self.assertEqual(format_location(None), "")

    def test_details_always_mentions_the_address(self):
        details = Match.from_payload(match_item()).details()
        self.assertIn("203.0.113.1:443", details)
        self.assertIn("Banner", details)

    def test_to_row_is_flat_and_stringy(self):
        row = Match.from_payload(match_item()).to_row()
        self.assertEqual(row["port"], 443)
        self.assertEqual(row["hostnames"], "a.example.com; b.example.com")
        self.assertNotIn("\n", row["hostnames"])
        self.assertIsInstance(row["banner"], str)

    def test_sort_key_sinks_blanks(self):
        with_port = Match.from_payload(match_item(port=443))
        without_port = Match.from_payload({"ip_str": "203.0.113.9"})
        self.assertLess(sort_key(with_port, "port"), sort_key(without_port, "port"))
        ordered = sorted([without_port, with_port], key=lambda m: sort_key(m, "ip"))
        self.assertEqual([m.ip for m in ordered], ["203.0.113.1", "203.0.113.9"])


if __name__ == "__main__":
    unittest.main()
