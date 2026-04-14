"""Regression tests for scan flow and resume behavior."""

import unittest
from urllib.parse import urlparse, parse_qs

from akha.core.config import Config
from akha.core.session import Session
from akha.modules.xss.xss_engine import XSSEngine


class _DummyHTTPClient:
    """Minimal HTTP client stub for unit-level engine tests."""

    def get(self, *args, **kwargs):
        raise RuntimeError("not used in this test")


class _DummyPayloadManager:
    def get_payloads(self, *args, **kwargs):
        return []


class _DummyLearningEngine:
    def get_best_payloads(self, *args, **kwargs):
        return []

    def get_best_payloads_ucb(self, *args, **kwargs):
        return []

    def record_success(self, *args, **kwargs):
        return None

    def record_failure(self, *args, **kwargs):
        return None


class _EchoResp:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.reason = "OK"
        self.headers = {"Content-Type": "text/html"}


class _ReflectingHTTPClient:
    """Reflects query parameter values directly into HTML body."""

    def get(self, url, **kwargs):
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        reflected = " ".join(vals[0] for vals in qs.values() if vals)
        return _EchoResp(f"<html><body>{reflected}</body></html>")

    def post(self, url, data=None, **kwargs):
        data = data or {}
        reflected = " ".join(str(v) for v in data.values())
        return _EchoResp(f"<html><body>{reflected}</body></html>")

    def post_json(self, url, json_data=None, **kwargs):
        json_data = json_data or {}
        reflected = " ".join(str(v) for v in json_data.values())
        return _EchoResp(f"<html><body>{reflected}</body></html>")


class TestRegressions(unittest.TestCase):
    def test_build_test_url_sets_query_payload(self):
        cfg = Config.default()
        engine = XSSEngine(
            _DummyHTTPClient(),
            _DummyPayloadManager(),
            _DummyLearningEngine(),
            cfg,
        )

        result = engine._build_test_url(
            "https://example.com/search?q=test",
            "x",
            "<svg/onload=alert(1)>",
            "query",
        )

        self.assertIn("x=%3Csvg%2Fonload%3Dalert%281%29%3E", result)
        self.assertIn("q=test", result)

    def test_session_tested_params_are_location_aware(self):
        session = Session("https://example.com", "full")

        session.mark_tested("https://example.com/a", "id", "POST")
        self.assertTrue(session.is_tested("https://example.com/a", "id", "POST"))
        self.assertFalse(session.is_tested("https://example.com/a", "id", "query"))

    def test_reflected_scan_detects_basic_echo(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.learning_enabled = False
        cfg.aggressive_mode = False
        cfg.min_confidence_threshold = 30

        engine = XSSEngine(
            _ReflectingHTTPClient(),
            _DummyPayloadManager(),
            _DummyLearningEngine(),
            cfg,
        )

        sanity_payload = '<img src=x onerror=alert(1) class=akha>'
        sanity_body = f'<html><body>{sanity_payload}</body></html>'
        self.assertTrue(engine._is_payload_reflected_raw(sanity_body, sanity_payload))

        direct = engine._verify_xss(
            "https://example.com/search?q=test",
            "q",
            sanity_payload,
            "query",
            None,
            baseline_html="<html><body>baseline</body></html>",
        )
        self.assertIsNotNone(direct)

        vulns = engine.scan(
            "https://example.com/search?q=test",
            [{"name": "q", "location": "query"}],
            waf_name=None,
            session=None,
        )

        self.assertTrue(
            len(vulns) >= 1,
            msg=(
                f"vulns={len(vulns)} payloads_tested={engine.payloads_tested} "
                f"candidates={engine.candidates_detected} "
                f"low_conf={engine.filtered_low_confidence} "
                f"unverified={engine.filtered_unverified}"
            ),
        )


if __name__ == "__main__":
    unittest.main()

