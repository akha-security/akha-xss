"""Tests for modern HTML report rendering and technical details."""

import os
import tempfile
import unittest
from types import SimpleNamespace

from akha.reports.html_generator import HTMLReportGenerator


class TestHtmlReportModernization(unittest.TestCase):
    def _report_data(self):
        return {
            "target": "https://example.com",
            "scan_mode": "full",
            "start_time": 1710000000,
            "duration": 12.4,
            "statistics": {
                "urls_crawled": 10,
                "params_found": 6,
                "payloads_tested": 30,
            },
            "telemetry": {
                "latency_ms": {"p50": 50, "p95": 180},
                "status_buckets": {"2xx": 20, "4xx": 1, "5xx": 0},
            },
            "module_metrics": {
                "xss": {"duration_seconds": 3.12},
            },
            "scan_policy": {
                "profile": "quick",
                "auto_waf_cautious": True,
                "waf_cautious_applied": True,
                "max_pages": 150,
                "risk_top_k": 80,
                "threads": 4,
                "rate_limit": 3,
            },
            "phase_timeline": [
                {
                    "phase": "waf_detection",
                    "runs": 1,
                    "duration_seconds": 0.5,
                    "errors": 0,
                }
            ],
            "learning": {},
            "waf": {"detected": False},
            "csp": {"has_csp": True},
            "vulnerabilities": [
                {
                    "type": "reflected_xss",
                    "severity_level": "confirmed",
                    "parameter": "q",
                    "url": "https://example.com/search?q=payload",
                    "test_url": "https://example.com/search?q=%3Csvg%2Fonload%3Dalert(1)%3E",
                    "confidence": 95,
                    "exploitability_score": 91,
                    "payload": "<svg/onload=alert(1)>",
                    "request": "GET /search?q=%3Csvg%2Fonload%3Dalert(1)%3E HTTP/1.1\nHost: example.com",
                    "response": "HTTP/1.1 200 OK\n\nbefore \x00AKHA_HL_S\x00<svg/onload=alert(1)>\x00AKHA_HL_E\x00 after",
                    "proof": "Payload reflected and executed.",
                    "browser_matrix": {
                        "chromium": {"executed": True, "method": "js_variable", "error": None}
                    },
                    "validated": True,
                }
            ],
        }

    def test_html_report_contains_modern_actions_and_http_details(self):
        with tempfile.TemporaryDirectory() as tmp:
            cfg = SimpleNamespace(output_dir=tmp)
            generator = HTMLReportGenerator(cfg)
            path = generator.generate(self._report_data())

            self.assertTrue(os.path.exists(path))
            with open(path, "r", encoding="utf-8") as handle:
                content = handle.read()

            self.assertIn("Copy PoC", content)
            self.assertIn("Triage Summary", content)
            self.assertIn("Reproduction Steps", content)
            self.assertIn("Exploit path:", content)
            self.assertIn("Description", content)
            self.assertIn("Impact", content)
            self.assertIn("Recommendation", content)
            self.assertIn("CWE-79", content)
            self.assertIn("CVSS-like", content)
            self.assertIn("Phase Timeline", content)
            self.assertIn("Scan Policy", content)
            self.assertIn("waf_detection", content)
            self.assertIn("WAF cautious", content)
            self.assertIn("HTTP Request", content)
            self.assertIn("HTTP Response", content)
            self.assertIn("class=\"vuln-hit\"", content)
            self.assertIn("https://example.com/search?q=%3Csvg%2Fonload%3Dalert(1)%3E", content)


if __name__ == "__main__":
    unittest.main()
