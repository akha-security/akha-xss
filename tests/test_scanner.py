"""
Test scanner module
"""

import unittest
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


if __name__ == '__main__':
    unittest.main()
