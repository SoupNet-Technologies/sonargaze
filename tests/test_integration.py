"""End-to-end check of the default urllib transport.

The other client tests inject a fake transport. This one runs a local HTTP
server on 127.0.0.1:0 and proves urllib, JSON decoding, query-string
construction and error mapping agree with each other.
"""

import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import ClassVar
from urllib.parse import parse_qs, urlparse

from sonargaze.api import APIError, AuthError, ShodanClient

from .helpers import match_item

KEY = "local-test-key"


class Handler(BaseHTTPRequestHandler):
    """Serves /shodan/host/search and /api-info, records every request."""

    seen: ClassVar[list[dict[str, str]]] = []

    def do_GET(self):
        parsed = urlparse(self.path)
        params = {k: v[0] for k, v in parse_qs(parsed.query).items()}
        Handler.seen.append({"path": parsed.path, **params})
        if params.get("key") != KEY:
            self._send(401, {"error": "Invalid API key"})
            return
        if parsed.path == "/shodan/host/search":
            if params.get("query") == "trigger-error":
                self._send(400, {"error": "bad search query"})
                return
            self._send(200, {"total": 1, "matches": [match_item()], "query": params.get("query")})
            return
        if parsed.path == "/api-info":
            self._send(200, {"plan": "dev", "query_credits": 5})
            return
        self._send(404, {"error": "nope"})

    def _send(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


class TransportTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Handler.seen = []
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        cls.thread = threading.Thread(target=cls.httpd.serve_forever, daemon=True)
        cls.thread.start()
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"

    @classmethod
    def tearDownClass(cls):
        cls.httpd.shutdown()
        cls.httpd.server_close()

    def setUp(self):
        Handler.seen.clear()

    def test_search_over_real_http(self):
        result = ShodanClient(KEY, base_url=self.base).search("apache country:CA")
        self.assertEqual(result["total"], 1)
        self.assertEqual(result["matches"][0]["ip_str"], "203.0.113.1")
        self.assertEqual(Handler.seen[-1]["query"], "apache country:CA")
        self.assertEqual(Handler.seen[-1]["minify"], "true")

    def test_bad_key_raises_auth_error(self):
        with self.assertRaises(AuthError):
            ShodanClient("wrong-key", base_url=self.base).search("apache")

    def test_api_error_body_survives_as_the_message(self):
        with self.assertRaises(APIError) as caught:
            ShodanClient(KEY, base_url=self.base).search("trigger-error")
        self.assertIn("bad search query", str(caught.exception))

    def test_key_is_never_in_the_error_text(self):
        with self.assertRaises(AuthError) as caught:
            ShodanClient("wrong-key", base_url=self.base).search("apache")
        self.assertNotIn("wrong-key", str(caught.exception))


if __name__ == "__main__":
    unittest.main()
