"""Regression tests for false-positive hardening rules."""

import unittest

from akha.core.config import Config
from akha.modules.xss.dom_scanner import DOMScanner
from akha.modules.xss.xss_engine import XSSEngine


class _DummyResp:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.reason = "OK"


class _DummyHttp:
    def __init__(self, html_first: str, html_second: str):
        self._first = _DummyResp(html_first)
        self._second = _DummyResp(html_second)
        self._count = 0

    def get(self, url, **kwargs):
        self._count += 1
        return self._first if self._count == 1 else self._second

    def post(self, *args, **kwargs):
        return self.get("", **kwargs)

    def post_json(self, *args, **kwargs):
        return self.get("", **kwargs)


class _ReflectingHttp:
    def get(self, url, **kwargs):
        from urllib.parse import parse_qs, urlparse

        parsed = urlparse(url)
        values = []
        for raw_values in parse_qs(parsed.query, keep_blank_values=True).values():
            values.extend(raw_values)
        return _DummyResp("<html><body>" + " ".join(values) + "</body></html>")


class _DummyPayloadManager:
    pass


class _DummyLearning:
    pass


class TestFalsePositiveHardening(unittest.TestCase):
    def test_preexisting_marker_without_reflection_is_rejected(self):
        cfg = Config.default()
        cfg.verbose = False

        baseline = '<html><body><div class=akha>theme token</div></body></html>'
        html_first = baseline
        html_second = baseline
        http = _DummyHttp(html_first, html_second)

        engine = XSSEngine(http, _DummyPayloadManager(), _DummyLearning(), cfg)
        engine.execution_verifier = None

        result = engine._verify_xss(
            url='https://example.com',
            param_name='q',
            payload='<img class=akha src=x onerror=alert(1)>',
            location='query',
            baseline_html=baseline,
        )

        self.assertIsNone(result)

    def test_marker_without_reverify_is_not_confirmed(self):
        cfg = Config.default()
        cfg.verbose = False

        html_first = '<html><body><img class=akha src=x onerror=alert(1)></body></html>'
        html_second = '<html><body>clean</body></html>'
        http = _DummyHttp(html_first, html_second)

        engine = XSSEngine(http, _DummyPayloadManager(), _DummyLearning(), cfg)
        # Avoid browser side effects in unit test.
        engine.execution_verifier = None

        result = engine._verify_xss(
            url='https://example.com',
            param_name='q',
            payload='<img class=akha src=x onerror=alert(1)>',
            location='POST',
            param_context={'form_action': 'https://example.com', 'form_inputs': {}},
            baseline_html='<html><body>baseline</body></html>',
        )

        # Hardened behavior may either downgrade to potential or reject outright.
        if result is None:
            return
        self.assertEqual(result['severity_level'], 'potential')
        self.assertFalse(result['reverified'])

    def test_dom_canary_only_findings_hidden_in_non_aggressive_mode(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.aggressive_mode = False
        scanner = DOMScanner(cfg, http_client=None)

        scanner._canary_scan = lambda url, params, parsed: ['q']
        scanner._test_dom_payload = lambda test_url, payload: None

        findings = scanner._param_dynamic_analysis('https://example.com/search?q=test')

        self.assertEqual(findings, [])

    def test_dom_param_scan_does_not_report_plain_reflected_xss(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.aggressive_mode = True
        scanner = DOMScanner(cfg, http_client=_ReflectingHttp())

        scanner._canary_scan = lambda url, params, parsed: ['q']
        scanner._test_dom_payload = lambda test_url, payload: {
            'url': test_url,
            'type': 'dom_xss',
            'subtype': 'dynamic_analysis',
            'parameter': 'DOM',
            'payload': payload,
            'confidence': 95,
            'validated': True,
        }

        findings = scanner._param_dynamic_analysis('https://example.com/search?q=test')

        self.assertEqual(findings, [])

    def test_dom_canary_scan_filters_server_reflected_tags(self):
        cfg = Config.default()
        cfg.verbose = False
        scanner = DOMScanner(cfg, http_client=_ReflectingHttp())
        test_url, canaries = scanner._build_canary_url(
            {'q': ['test']},
            __import__('urllib.parse', fromlist=['urlparse']).urlparse('https://example.com/search?q=test'),
        )

        reflected = scanner._server_reflected_canary_params(test_url, canaries)

        self.assertEqual(reflected, {'q'})

    def test_dom_static_proximity_only_signal_is_suppressed(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.aggressive_mode = False
        scanner = DOMScanner(cfg, http_client=None)
        html = """
        <script>
          const url = location.href;
          console.log(url);
          function render(value) {
            document.body.innerHTML = value;
          }
        </script>
        """

        findings = scanner.scan("https://example.com/?q=x", response_text=html)

        self.assertEqual(findings, [])

    def test_dom_static_strong_taint_chain_is_reported(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.aggressive_mode = False
        cfg.dom_xss_enabled = False
        scanner = DOMScanner(cfg, http_client=None)
        html = """
        <script>
          const payload = location.hash;
          document.body.innerHTML = payload;
        </script>
        """

        findings = scanner.scan("https://example.com/#x", response_text=html)

        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["subtype"], "static_analysis")
        self.assertGreaterEqual(findings[0]["confidence"], 70)

    def test_dom_unvalidated_dynamic_injection_is_suppressed_by_default(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.aggressive_mode = False
        scanner = DOMScanner(cfg, http_client=None)

        finding = {
            "type": "dom_xss",
            "subtype": "dynamic_analysis",
            "confidence": 80,
            "validated": False,
        }

        self.assertFalse(scanner._is_reportable_dom_finding(finding, 50))


if __name__ == '__main__':
    unittest.main()
