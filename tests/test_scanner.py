"""
Test scanner module
"""

import unittest
from urllib.parse import parse_qs, urlparse

from akha.core.scanner import Scanner
from akha.core.config import Config
from akha.core.session import Session


class TestScanner(unittest.TestCase):
    """Test scanner functionality"""
    
    def setUp(self):
        """Setup test"""
        self.config = Config.default()
        self.config.quiet = True
        self.scanner = Scanner(self.config)
    
    def test_scanner_init(self):
        """Test scanner initialization"""
        self.assertIsNotNone(self.scanner)
        self.assertIsNotNone(self.scanner.http_client)
        self.assertIsNotNone(self.scanner.payload_manager)
    
    def test_config_default(self):
        """Test default configuration"""
        config = Config.default()
        self.assertEqual(config.scan_mode, 'full')
        self.assertEqual(config.payload_strategy, 'auto')
        self.assertEqual(config.max_depth, 3)

    def test_budget_check_time_limit(self):
        self.scanner.session = Session('https://example.com', 'full')
        self.scanner.config.scan_budget_seconds = 1
        self.scanner.session.start_time -= 5
        self.assertTrue(self.scanner._check_scan_budget())

    def test_scope_guard_clamps_max_pages(self):
        cfg = Config.default()
        cfg.max_pages = 999999
        cfg.scope_guard_max_pages = 2000
        cfg.strict_scope_guard = True
        scanner = Scanner(cfg)
        self.assertEqual(scanner.config.max_pages, 2000)

    def test_budget_utilization_works(self):
        self.scanner.session = Session('https://example.com', 'full')
        self.scanner.config.scan_budget_seconds = 100
        self.scanner.session.start_time -= 50
        util = self.scanner._budget_utilization()
        self.assertGreaterEqual(util, 0.5)

    def test_budget_fallback_disables_heavy_modules(self):
        self.scanner.session = Session('https://example.com', 'full')
        self.scanner.config.scan_budget_seconds = 10
        self.scanner.config.budget_auto_fallback = True
        self.scanner.config.budget_fallback_trigger = 0.5
        self.scanner.session.start_time -= 8

        self.scanner._maybe_apply_budget_fallback()
        self.assertTrue(self.scanner._budget_degraded)
        self.assertFalse(self.scanner.config.test_mxss)
        self.assertFalse(self.scanner.config.test_angular)

    def test_waf_cautious_mode_reduces_scan_cost(self):
        self.scanner.config.auto_waf_cautious = True
        self.scanner.config.max_pages = 1500
        self.scanner.config.risk_priority_top_k = 300
        self.scanner.config.max_payloads_per_param = 0
        self.scanner.config.max_payloads_per_endpoint = 0

        self.scanner._apply_waf_cautious_mode({"detected": True, "confidence": 95})

        self.assertTrue(self.scanner.config.waf_cautious_applied)
        self.assertLessEqual(self.scanner.config.max_pages, 350)
        self.assertLessEqual(self.scanner.config.max_depth, 2)
        self.assertLessEqual(self.scanner.config.risk_priority_top_k, 220)
        self.assertEqual(self.scanner.config.max_payloads_per_param, 5)
        self.assertEqual(self.scanner.config.max_payloads_per_endpoint, 30)
        self.assertLessEqual(self.scanner.config.threads, 4)
        self.assertLessEqual(self.scanner.config.rate_limit, 3)
        self.assertLessEqual(self.scanner.config.timeout, 6)
        self.assertFalse(self.scanner.config.stored_xss_enabled)
        self.assertFalse(self.scanner.config.test_mxss)
        self.assertFalse(self.scanner.config.test_angular)
        self.assertFalse(self.scanner.config.test_graphql)
        self.assertFalse(self.scanner.config.dynamic_crawling)
        self.assertFalse(self.scanner.config.parse_js)

    def test_waf_cautious_mode_respects_disable_flag(self):
        self.scanner.config.auto_waf_cautious = False

        self.scanner._apply_waf_cautious_mode({"detected": True, "confidence": 95})

        self.assertFalse(self.scanner.config.waf_cautious_applied)

    def test_url_mode_tests_parameters_from_exact_target_url(self):
        cfg = Config.default()
        cfg.quiet = True
        cfg.output_format = "json"
        scanner = Scanner(cfg)
        scanner._phase_waf_detection = lambda _url: {"detected": False, "name": None, "confidence": 0}
        scanner._phase_csp_analysis = lambda _url: {"has_csp": False}
        scanner._generate_reports = lambda *_a, **_k: {}
        scanner.controller.stop_monitoring = lambda: None
        scanner.dom_scanner.scan = lambda *_a, **_k: []
        scanner.dom_scanner.close = lambda: None

        scanner.param_finder.find_parameters = lambda url: [
            {"name": "q", "value": "", "type": "query", "location": "url"}
        ]
        calls = []

        def _fake_scan_reflected(url, params, waf_name=None, session=None):
            calls.append((url, params))
            return []

        scanner.exploiter.scan_reflected = _fake_scan_reflected

        scanner.scan("https://example.com/search?q=", scan_mode="url")

        self.assertGreaterEqual(len(calls), 1)
        self.assertEqual(calls[0][0], "https://example.com/search?q=")
        self.assertEqual(calls[0][1][0]["name"], "q")
        self.assertEqual(scanner.session.statistics["params_found"], 1)

    def test_url_mode_blank_query_parse_regression(self):
        parsed = urlparse("https://example.com/search?q=&empty")
        params = parse_qs(parsed.query, keep_blank_values=True)

        self.assertIn("q", params)
        self.assertIn("empty", params)


if __name__ == '__main__':
    unittest.main()
