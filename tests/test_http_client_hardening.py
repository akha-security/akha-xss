"""Regression tests for HTTP client hardening logic."""

import unittest

from akha.core.config import Config
from akha.core.http_client import HTTPClient


class _Resp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _SessionStub:
    def get(self, *args, **kwargs):
        return _Resp(200)

    def post(self, *args, **kwargs):
        return _Resp(200)

    def put(self, *args, **kwargs):
        return _Resp(200)


class TestHttpClientHardening(unittest.TestCase):
    def setUp(self):
        cfg = Config.default()
        cfg.auth_url = "https://example.com/login"
        cfg.auth_data = {"u": "a", "p": "b"}
        cfg.auto_reauth = True

        self.client = HTTPClient(cfg)
        self.client.session = _SessionStub()
        self.client._rate_limit = lambda: None
        self.client._adapt_rate = lambda _r: None
        self.client._sleep_before_retry = lambda _r: None

    def test_reauth_non_401_resets_streak(self):
        self.client._reauth_401_streak = 2
        resp = _Resp(200)

        out = self.client._check_reauth(resp, "https://example.com", method="GET")

        self.assertIs(out, resp)
        self.assertEqual(self.client._reauth_401_streak, 0)

    def test_proxy_health_reported_for_post_variants(self):
        calls = []
        self.client._check_reauth = lambda resp, *_a, **_k: resp
        self.client._apply_rotation_result = lambda proxy, success: calls.append((proxy, success))

        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

        self.client.post("https://example.com", data={"a": "1"}, proxies=proxies)
        self.client.post_json("https://example.com", json_data={"a": "1"}, proxies=proxies)
        self.client.put_json("https://example.com", json_data={"a": "1"}, proxies=proxies)

        self.assertEqual(len(calls), 3)
        self.assertTrue(all(proxy == "http://127.0.0.1:8080" for proxy, _ in calls))
        self.assertTrue(all(success is True for _, success in calls))

    def test_telemetry_snapshot_contains_latency_and_buckets(self):
        self.client.get("https://example.com")
        self.client.post("https://example.com", data={"a": "1"})

        snap = self.client.get_telemetry_snapshot()
        self.assertIn("latency_ms", snap)
        self.assertIn("status_buckets", snap)
        self.assertGreaterEqual(snap["latency_ms"].get("samples", 0), 2)
        self.assertGreaterEqual(snap["status_buckets"].get("2xx", 0), 2)

    def test_auth_snapshot_contains_plugin_and_counters(self):
        snap = self.client.get_auth_snapshot()
        self.assertIn("authenticated", snap)
        self.assertIn("reauth_count", snap)
        self.assertIn("auth_failures", snap)

    def test_plugin_reauth_success_skips_fallback_login(self):
        class _Plugin:
            name = "dummy"

            def handle_reauth(self, _client, _response):
                class _Result:
                    ok = True
                    reason = "ok"
                    details = {}
                return _Result()

        self.client._auth_plugin = _Plugin()
        self.client._reauth_401_streak = 2
        self.client._perform_login = lambda: (_ for _ in ()).throw(AssertionError("fallback login should not run"))

        r = _Resp(401)
        out = self.client._check_reauth(r, "https://example.com", method="GET")
        self.assertEqual(out.status_code, 200)
        self.assertGreaterEqual(self.client._reauth_count, 1)


if __name__ == "__main__":
    unittest.main()
