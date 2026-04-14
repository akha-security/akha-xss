"""Contract tests for pipeline boundaries (Phase 6)."""

import unittest

from akha.core.pipeline import ScanAnalyzer, ScanExploiter, ScanReporter


class _WafStub:
    def detect(self, _target):
        return {"detected": False, "name": "None", "confidence": 0}


class _CspStub:
    def analyze(self, _target):
        return {"has_csp": False, "xss_exploitable": True, "details": []}


class _XssStub:
    def scan(self, _url, _params, _waf_name, session=None):
        return [{"type": "reflected_xss", "parameter": "q"}]


class _HtmlGen:
    def __init__(self, _cfg):
        pass

    def generate(self, _data):
        return "out/report.html"


class _JsonGen:
    def __init__(self, _cfg):
        pass

    def generate(self, _data):
        return "out/report.json"


class _Cfg:
    report_format = "both"


class TestPipelineContracts(unittest.TestCase):
    def test_analyzer_contract(self):
        analyzer = ScanAnalyzer(_WafStub(), _CspStub())
        self.assertIn("detected", analyzer.detect_waf("https://example.com"))
        self.assertIn("has_csp", analyzer.analyze_csp("https://example.com"))

    def test_exploiter_contract(self):
        exploiter = ScanExploiter(_XssStub())
        out = exploiter.scan_reflected("https://example.com", [{"name": "q"}], None)
        self.assertIsInstance(out, list)
        self.assertEqual(out[0]["parameter"], "q")

    def test_reporter_contract(self):
        reporter = ScanReporter(_Cfg(), _HtmlGen, _JsonGen)
        paths = reporter.generate({"target": "https://example.com"})
        self.assertIn("html", paths)
        self.assertIn("json", paths)


if __name__ == "__main__":
    unittest.main()
