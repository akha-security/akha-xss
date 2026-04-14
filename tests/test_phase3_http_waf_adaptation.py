import unittest

from akha.core.config import Config
from akha.core.http_client import HTTPClient, ProxyRotator
from akha.modules.waf_detector import WAFDetector


class _Resp:
    def __init__(self, status_code=200, headers=None, text=""):
        self.status_code = status_code
        self.headers = headers or {}
        self.text = text
        self.cookies = {}


class _WafClientStub:
    def __init__(self, response):
        self._response = response

    def get(self, url):
        return self._response


class TestPhase3HttpWafAdaptation(unittest.TestCase):
    def test_proxy_rotator_quarantines_failed_proxy_when_alternative_exists(self):
        rot = ProxyRotator(["http://p1", "http://p2"])
        rot._cooldown_seconds = 120

        # Force p1 into quarantine.
        for _ in range(5):
            rot.report_failure("http://p1")

        nxt = rot.next()
        self.assertEqual(nxt, "http://p2")

    def test_http_client_target_rate_limit_updates_host_path_timestamps(self):
        cfg = Config.default()
        cfg.per_host_rate_limit = True
        cfg.per_path_rate_limit = True
        cfg.rate_limit = 1000
        cfg.path_rate_multiplier = 1.0

        client = HTTPClient(cfg)
        client._rate_limit = lambda: None

        client._target_rate_limit("https://example.com/api/search?q=x")

        self.assertIn("example.com", client._host_last_request)
        self.assertIn("example.com/api/search", client._path_last_request)

    def test_waf_aggregate_includes_confidence_score_and_evidence(self):
        detector = WAFDetector(_WafClientStub(_Resp()))
        result = detector._aggregate_results([
            {"detected": True, "name": "Cloudflare", "confidence": 60, "method": "probe_xss_1"},
            {"detected": True, "name": "Cloudflare", "confidence": 30, "method": "behaviour_xss_1"},
        ])

        self.assertTrue(result["detected"])
        self.assertIn("confidence_score", result)
        self.assertIn("evidence", result)
        self.assertGreaterEqual(result["confidence_score"]["evidence_count"], 2)

    def test_http_client_marks_challenge_and_applies_target_penalty(self):
        cfg = Config.default()
        client = HTTPClient(cfg)

        challenge = _Resp(
            status_code=403,
            headers={"Server": "cloudflare"},
            text="Attention Required! | Cloudflare",
        )
        url = "https://example.com/protected"

        self.assertTrue(client._is_challenge_response(challenge))
        client._adapt_target_rate(url, challenge)

        self.assertGreater(client._target_penalty.get("example.com", 1.0), 1.0)
        self.assertGreater(client._host_backoff_until.get("example.com", 0), 0)

    def test_http_client_target_penalty_recovers_on_success(self):
        cfg = Config.default()
        client = HTTPClient(cfg)

        url = "https://example.com/api"
        challenge = _Resp(status_code=429, headers={"Retry-After": "1"}, text="rate limit")
        ok = _Resp(status_code=200, headers={}, text="ok")

        client._adapt_target_rate(url, challenge)
        penalized = client._target_penalty.get("example.com", 1.0)
        client._adapt_target_rate(url, ok)
        recovered = client._target_penalty.get("example.com", 1.0)

        self.assertGreater(penalized, 1.0)
        self.assertLess(recovered, penalized)

    def test_http_client_endpoint_backoff_profile_classification(self):
        cfg = Config.default()
        client = HTTPClient(cfg)

        self.assertEqual(client._endpoint_backoff_profile("https://example.com/login", "GET")["profile"], "auth")
        self.assertEqual(client._endpoint_backoff_profile("https://example.com/api/users", "POST")["profile"], "api_write")
        self.assertEqual(client._endpoint_backoff_profile("https://example.com/api/users", "GET")["profile"], "api_read")

    def test_auth_profile_applies_stronger_penalty_than_default(self):
        cfg = Config.default()
        client = HTTPClient(cfg)
        challenge = _Resp(status_code=429, headers={"Retry-After": "1"}, text="challenge")

        client._adapt_target_rate("https://example.com/static", challenge, method="GET")
        default_penalty = client._target_penalty.get("example.com/static", 1.0)

        # Reset path-specific penalty to isolate auth profile effect on path key.
        client._target_penalty["example.com/login"] = 1.0
        client._adapt_target_rate("https://example.com/login", challenge, method="GET")
        auth_penalty = client._target_penalty.get("example.com/login", 1.0)

        self.assertGreater(auth_penalty, default_penalty)

    def test_endpoint_backoff_profile_classification(self):
        cfg = Config.default()
        client = HTTPClient(cfg)

        auth_p = client._endpoint_backoff_profile("https://example.com/login", "POST")
        write_p = client._endpoint_backoff_profile("https://example.com/api/user", "PUT")
        read_p = client._endpoint_backoff_profile("https://example.com/api/list", "GET")

        self.assertEqual(auth_p["profile"], "auth")
        self.assertEqual(write_p["profile"], "api_write")
        self.assertEqual(read_p["profile"], "api_read")

    def test_auth_profile_penalizes_more_than_default(self):
        cfg = Config.default()
        client = HTTPClient(cfg)

        challenge = _Resp(status_code=429, headers={"Retry-After": "1"}, text="rate limit")
        client._adapt_target_rate("https://example.com/static", challenge, method="GET")
        static_penalty = client._target_penalty.get("example.com", 1.0)

        client2 = HTTPClient(cfg)
        client2._adapt_target_rate("https://example.com/login", challenge, method="POST")
        auth_penalty = client2._target_penalty.get("example.com", 1.0)

        self.assertGreater(auth_penalty, static_penalty)

    def test_endpoint_backoff_profile_overrides_are_applied(self):
        cfg = Config.default()
        cfg.endpoint_backoff_profile_overrides = {
            "auth": {
                "penalty_mult": 2.5,
                "path_penalty_mult": 3.0,
                "backoff_extra": 7,
            }
        }
        client = HTTPClient(cfg)

        profile = client._endpoint_backoff_profile("https://example.com/login", "POST")

        self.assertEqual(profile["profile"], "auth")
        self.assertEqual(profile["penalty_mult"], 2.5)
        self.assertEqual(profile["path_penalty_mult"], 3.0)
        self.assertEqual(profile["backoff_extra"], 7)

    def test_endpoint_backoff_profile_overrides_are_clamped(self):
        cfg = Config.default()
        cfg.endpoint_backoff_profile_overrides = {
            "api_read": {
                "penalty_mult": 999,
                "path_penalty_mult": 999,
                "backoff_extra": 999,
            }
        }
        client = HTTPClient(cfg)

        profile = client._endpoint_backoff_profile("https://example.com/api/list", "GET")

        self.assertEqual(profile["profile"], "api_read")
        self.assertEqual(profile["penalty_mult"], 3.0)
        self.assertEqual(profile["path_penalty_mult"], 4.0)
        self.assertEqual(profile["backoff_extra"], 20)


if __name__ == "__main__":
    unittest.main()
