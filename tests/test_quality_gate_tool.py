"""Tests for report quality gate comparisons."""

import unittest

from tools.quality_gate import evaluate_quality_gate


class TestQualityGateTool(unittest.TestCase):
    def test_quality_gate_passes_within_thresholds(self):
        baseline = {
            "duration": 100,
            "statistics": {"requests_sent": 200},
            "telemetry": {"latency_ms": {"p95": 100}},
            "vulnerabilities": [{"severity_level": "confirmed"}],
        }
        current = {
            "duration": 110,
            "statistics": {"requests_sent": 220},
            "telemetry": {"latency_ms": {"p95": 120}},
            "vulnerabilities": [{"severity_level": "confirmed"}],
        }
        passed, summary = evaluate_quality_gate(
            current,
            baseline,
            max_duration_regression_pct=20,
            max_request_regression_pct=25,
            min_confirmed_ratio_pct=50,
            max_p95_latency_regression_pct=30,
            max_confirmed_ratio_drop_pct=20,
        )
        self.assertTrue(passed)
        self.assertTrue(summary["passed"])

    def test_quality_gate_fails_on_regression(self):
        baseline = {
            "duration": 100,
            "statistics": {"requests_sent": 200},
            "telemetry": {"latency_ms": {"p95": 100}},
            "vulnerabilities": [{"severity_level": "confirmed"}],
        }
        current = {
            "duration": 160,
            "statistics": {"requests_sent": 310},
            "telemetry": {"latency_ms": {"p95": 160}},
            "vulnerabilities": [{"severity_level": "potential"}],
        }
        passed, summary = evaluate_quality_gate(
            current,
            baseline,
            max_duration_regression_pct=20,
            max_request_regression_pct=25,
            min_confirmed_ratio_pct=10,
            max_p95_latency_regression_pct=30,
            max_confirmed_ratio_drop_pct=20,
        )
        self.assertFalse(passed)
        self.assertFalse(summary["passed"])
        self.assertGreaterEqual(len(summary["reasons"]), 1)

    def test_quality_gate_fails_on_confirmed_ratio_drift(self):
        baseline = {
            "duration": 100,
            "statistics": {"requests_sent": 200},
            "telemetry": {"latency_ms": {"p95": 100}},
            "vulnerabilities": [
                {"severity_level": "confirmed"},
                {"severity_level": "confirmed"},
                {"severity_level": "potential"},
            ],
        }
        current = {
            "duration": 100,
            "statistics": {"requests_sent": 200},
            "telemetry": {"latency_ms": {"p95": 100}},
            "vulnerabilities": [
                {"severity_level": "potential"},
                {"severity_level": "potential"},
                {"severity_level": "potential"},
            ],
        }
        passed, summary = evaluate_quality_gate(
            current,
            baseline,
            max_duration_regression_pct=20,
            max_request_regression_pct=25,
            min_confirmed_ratio_pct=0,
            max_p95_latency_regression_pct=30,
            max_confirmed_ratio_drop_pct=20,
        )
        self.assertFalse(passed)
        self.assertGreater(summary.get("confirmed_ratio_drop_pct", 0), 20)


if __name__ == "__main__":
    unittest.main()
