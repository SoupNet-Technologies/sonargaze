"""Tests for sonargaze.api: retries, error mapping, key hygiene."""

import unittest
import urllib.error

from sonargaze.api import (
    APIError,
    AuthError,
    NetworkError,
    RateLimited,
    ShodanClient,
)

from .helpers import KEY, FakeTransport, payload


def client(transport, **kwargs):
    kwargs.setdefault("sleep", lambda _seconds: None)
    return ShodanClient(KEY, transport=transport, **kwargs)


class ConstructionTests(unittest.TestCase):
    def test_missing_key_is_rejected(self):
        with self.assertRaises(AuthError):
            ShodanClient("   ")


class SearchRequestTests(unittest.TestCase):
    def test_search_sends_key_and_page_parameters(self):
        transport = FakeTransport([(200, {}, payload(2))])
        result = client(transport).search("apache", page=3)
        params = transport.last_params
        self.assertEqual(params["query"], "apache")
        self.assertEqual(params["page"], "3")
        self.assertEqual(params["minify"], "true")
        self.assertEqual(params["key"], KEY)
        self.assertEqual(result["total"], 2)

    def test_facets_are_serialised_with_limits(self):
        transport = FakeTransport([(200, {}, payload())])
        client(transport).search("apache", facets={"country": 5, "org": None})
        self.assertEqual(transport.last_params["facets"], "country:5,org")

    def test_blank_query_and_bad_page_are_rejected_before_any_request(self):
        transport = FakeTransport([(200, {}, payload())])
        api = client(transport)
        with self.assertRaises(ValueError):
            api.search("   ")
        with self.assertRaises(ValueError):
            api.search("apache", page=0)
        self.assertEqual(transport.calls, [])

    def test_min_interval_spaces_requests(self):
        transport = FakeTransport([(200, {}, payload()), (200, {}, payload())])
        sleeps = []
        now = {"t": 0.0}

        def clock():
            return now["t"]

        def sleep(seconds):
            sleeps.append(seconds)
            now["t"] += seconds

        api = ShodanClient(KEY, transport=transport, sleep=sleep, clock=clock, min_interval=1.0)
        api.search("a")
        api.search("b")
        self.assertTrue(sleeps and sleeps[0] > 0)


class ErrorHandlingTests(unittest.TestCase):
    def test_api_key_never_appears_in_error_text(self):
        transport = FakeTransport([(401, {}, {"error": f"invalid key {KEY}"})])
        with self.assertRaises(AuthError) as caught:
            client(transport).search("apache")
        self.assertNotIn(KEY, str(caught.exception))
        self.assertIn("rejected", str(caught.exception))

    def test_unauthorized_maps_to_auth_error(self):
        transport = FakeTransport([(401, {}, {"error": "Invalid API key"})])
        with self.assertRaises(AuthError):
            client(transport).search("apache")

    def test_rate_limit_is_retried_once_then_succeeds(self):
        transport = FakeTransport(
            [(429, {"Retry-After": "2"}, {"error": "slow down"}), (200, {}, payload())]
        )
        sleeps = []
        api = ShodanClient(KEY, transport=transport, sleep=sleeps.append, retries=1)
        self.assertEqual(api.search("apache")["total"], 1)
        self.assertEqual(sleeps[0], 2.0)
        self.assertEqual(api.requests_made, 2)

    def test_rate_limit_exhaustion_raises_rate_limited(self):
        transport = FakeTransport([(429, {"Retry-After": "1"}, {"error": "slow down"})] * 4)
        with self.assertRaises(RateLimited) as caught:
            client(transport, retries=1).search("apache")
        self.assertEqual(caught.exception.retry_after, 1.0)

    def test_server_errors_are_retried_then_raise(self):
        transport = FakeTransport([(500, {}, {"error": "boom"})] * 3)
        with self.assertRaises(APIError) as caught:
            client(transport, retries=1).search("apache")
        self.assertEqual(caught.exception.status, 500)

    def test_network_failure_becomes_network_error(self):
        transport = FakeTransport([urllib.error.URLError("dns")] * 3)
        with self.assertRaises(NetworkError):
            client(transport, retries=1).search("apache")

    def test_timeout_becomes_network_error(self):
        transport = FakeTransport([TimeoutError("timed out")] * 3)
        with self.assertRaises(NetworkError):
            client(transport, retries=0).search("apache")

    def test_client_errors_are_not_retried(self):
        transport = FakeTransport([(400, {}, {"error": "bad query"})])
        with self.assertRaises(APIError) as caught:
            client(transport, retries=3).search("apache")
        self.assertEqual(caught.exception.status, 400)
        self.assertEqual(len(transport.calls), 1)

    def test_unexpected_payload_shape_is_an_api_error(self):
        transport = FakeTransport([(200, {}, "not json"), (200, {}, "still not json")])
        api = client(transport)
        with self.assertRaises(APIError):
            api.api_info()
        with self.assertRaises(APIError):
            api.ports()


class PaginationTests(unittest.TestCase):
    def test_iterate_search_stops_on_short_page(self):
        transport = FakeTransport(
            [(200, {}, payload(2, total=500)), (200, {}, payload(0, total=500))]
        )
        pages = list(client(transport).iterate_search("apache", pages=5))
        self.assertEqual(len(pages), 2)
        self.assertEqual(len(transport.calls), 2)

    def test_iterate_search_rejects_zero_pages(self):
        with self.assertRaises(ValueError):
            list(client(FakeTransport([])).iterate_search("apache", pages=0))


class EndpointTests(unittest.TestCase):
    def test_host_quotes_the_address(self):
        transport = FakeTransport([(200, {}, {"ip_str": "203.0.113.9", "ports": [80]})])
        self.assertEqual(client(transport).host("203.0.113.9")["ports"], [80])
        self.assertIn("/shodan/host/203.0.113.9", transport.calls[0])

    def test_ports_and_info_return_parsed_payloads(self):
        transport = FakeTransport([(200, {}, [80, 443]), (200, {}, {"plan": "dev"})])
        api = client(transport)
        self.assertEqual(api.ports(), [80, 443])
        self.assertEqual(api.api_info()["plan"], "dev")


if __name__ == "__main__":
    unittest.main()
