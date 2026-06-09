"""Regression tests for module-level false-positive hardening."""

import unittest

from akha.core.config import Config
from akha.modules.xss.angular_scanner import AngularJSScanner
from akha.modules.xss.graphql_scanner import GraphQLScanner
from akha.modules.xss.websocket_scanner import WebSocketScanner


class _GraphQLDetectHttpStub:
    def __init__(self, text, as_json_error=False):
        self._text = text
        self._as_json_error = as_json_error

    def post(self, url, data=None, headers=None, timeout=None):
        class _Resp:
            def __init__(self, text, as_json_error):
                self.text = text
                self.status_code = 200
                self._as_json_error = as_json_error

            def json(self):
                if self._as_json_error:
                    raise ValueError("not json")
                import json
                return json.loads(self.text)

        return _Resp(self._text, self._as_json_error)


class _WSHttpStub:
    def get(self, url, timeout=None, headers=None, allow_redirects=None):
        class _Resp:
            status_code = 101
            text = ""
        return _Resp()


class TestModuleHardening(unittest.TestCase):
    def test_angular_canary_low_collision(self):
        cfg = Config.default()
        scanner = AngularJSScanner(http_client=None, config=cfg)

        # Old canary-like noise should not trigger
        self.assertIsNone(scanner._check_response("the number 49 appears", "{{7*7}}"))

        # New canary should trigger only when result appears and payload itself does not
        self.assertEqual(scanner._check_response("... 41897569 ...", scanner.CANARY_PAYLOAD), "evaluated")

    def test_angular_unknown_includes_sandbox_payload_families(self):
        cfg = Config.default()
        scanner = AngularJSScanner(http_client=None, config=cfg)

        payloads = scanner._select_payloads("unknown")

        self.assertIn(scanner.SANDBOX_V12_PAYLOADS[0], payloads)
        self.assertIn(scanner.SANDBOX_V13_PAYLOADS[0], payloads)
        self.assertIn(scanner.SANDBOX_V14_PAYLOADS[0], payloads)
        self.assertIn(scanner.SANDBOX_V15_PAYLOADS[0], payloads)

    def test_graphql_detect_ignores_non_json_error_text(self):
        cfg = Config.default()
        http = _GraphQLDetectHttpStub("<html>errors happened</html>", as_json_error=True)
        scanner = GraphQLScanner(http, cfg)

        self.assertIsNone(scanner.detect_graphql("https://example.com"))

    def test_websocket_static_findings_require_aggressive_mode(self):
        cfg = Config.default()
        cfg.aggressive_mode = False
        scanner = WebSocketScanner(_WSHttpStub(), cfg)
        scanner._ws_available = False

        findings = scanner.scan("https://example.com", html="")
        self.assertEqual(findings, [])

        cfg2 = Config.default()
        cfg2.aggressive_mode = True
        scanner2 = WebSocketScanner(_WSHttpStub(), cfg2)
        scanner2._ws_available = False
        findings2 = scanner2.scan("https://example.com", html="")
        self.assertTrue(len(findings2) >= 1)


if __name__ == "__main__":
    unittest.main()

