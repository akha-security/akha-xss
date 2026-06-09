"""Regression tests for HTTP client hardening logic."""

import unittest

from akha.core.config import Config
from akha.core.http_client import HTTPClient, ProxyRotator, _redact_url_for_log, _redact_urls_in_text


class _Resp:
    def __init__(self, status_code=200, headers=None):
        self.status_code = status_code
        self.headers = headers or {}


class _SessionStub:
    headers = {}

    def get(self, *args, **kwargs):
        return _Resp(200)

    def post(self, *args, **kwargs):
        return _Resp(200)

    def put(self, *args, **kwargs):
        return _Resp(200)


class _ProxyFallbackSessionStub:
    headers = {}

    def __init__(self):
        self.calls = []

    def get(self, *args, **kwargs):
        self.calls.append(kwargs)
        proxies = kwargs.get("proxies")
        if proxies and proxies.get("http"):
            raise __import__("requests").exceptions.ProxyError("proxy refused")
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
        self.client._apply_rotation_result = (
            lambda proxy, success, **_telemetry: calls.append((proxy, success))
        )

        proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}

        self.client.post("https://example.com", data={"a": "1"}, proxies=proxies)
        self.client.post_json("https://example.com", json_data={"a": "1"}, proxies=proxies)
        self.client.put_json("https://example.com", json_data={"a": "1"}, proxies=proxies)

        self.assertEqual(len(calls), 3)
        self.assertTrue(all(proxy == "http://127.0.0.1:8080" for proxy, _ in calls))
        self.assertTrue(all(success is True for _, success in calls))

    def test_get_falls_back_to_direct_when_explicit_proxy_is_unreachable(self):
        fallback_session = _ProxyFallbackSessionStub()
        self.client.config.proxy = "http://127.0.0.1:8080"
        self.client.session = _ProxyFallbackSessionStub()
        self.client._check_reauth = lambda resp, *_a, **_k: resp
        self.client._adapt_rate = lambda _r: None
        self.client._adapt_target_rate = lambda *_a, **_k: None
        self.client._end_request = lambda **_k: None
        self.client._create_direct_session = lambda: fallback_session

        resp = self.client.get("https://example.com")

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(self.client.session.calls), 1)
        self.assertTrue(self.client.session.calls[0].get("proxies"))
        self.assertEqual(len(fallback_session.calls), 1)
        self.assertFalse(fallback_session.calls[0].get("proxies"))

    def test_telemetry_snapshot_contains_latency_and_buckets(self):
        self.client.get("https://example.com")
        self.client.post("https://example.com", data={"a": "1"})

        snap = self.client.get_telemetry_snapshot()
        self.assertIn("latency_ms", snap)
        self.assertIn("status_buckets", snap)
        self.assertGreaterEqual(snap["latency_ms"].get("samples", 0), 2)
        self.assertGreaterEqual(snap["status_buckets"].get("2xx", 0), 2)
        self.assertIn("proxy_pool", snap)

    def test_proxy_rotator_snapshot_reports_health(self):
        rotator = ProxyRotator(["http://p1:8080", "http://p2:8080"])
        rotator.report_result("http://p1:8080", success=True, latency_ms=100, status_code=200)
        rotator.report_result("http://p2:8080", success=False, latency_ms=900, error_type="Timeout", timeout=True)

        snap = rotator.snapshot()

        self.assertTrue(snap["enabled"])
        self.assertEqual(snap["total"], 2)
        p1 = next(p for p in snap["proxies"] if p["proxy"] == "http://p1:8080")
        p2 = next(p for p in snap["proxies"] if p["proxy"] == "http://p2:8080")
        self.assertEqual(p1["success_ratio"], 1.0)
        self.assertEqual(p2["timeouts"], 1)

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

    def test_async_batch_get_empty_urls_returns_empty(self):
        out = self.client.async_batch_get([], concurrency=20)
        self.assertEqual(out, [])

    def test_async_batch_get_zero_concurrency_is_clamped(self):
        out = self.client.async_batch_get(["https://example.com"], concurrency=0)
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0][0], "https://example.com")

    def test_sync_batch_get_empty_urls_returns_empty(self):
        out = self.client._sync_batch_get([], timeout=5)
        self.assertEqual(out, [])

    def test_log_url_redaction_masks_payload_query_values(self):
        url = "https://example.com/search?q=%3Csvg%2Fonload%3Dalert(1)%3E&safe=1"

        redacted = _redact_url_for_log(url)

        self.assertIn("q=%5Bredacted%5D", redacted)
        self.assertIn("safe=%5Bredacted%5D", redacted)
        self.assertNotIn("alert", redacted)
        self.assertNotIn("%3Csvg", redacted)

    def test_log_text_redaction_masks_embedded_payload_urls(self):
        text = "failed https://example.com/?x=<script>alert(1)</script> after proxy"

        redacted = _redact_urls_in_text(text)

        self.assertIn("https://example.com/?x=%5Bredacted%5D", redacted)
        self.assertNotIn("<script>", redacted)


if __name__ == "__main__":
    unittest.main()
