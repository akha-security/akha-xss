"""Golden target fixture regression tests for report outputs (Phase 6)."""

import json
import os
import tempfile
import unittest
from pathlib import Path

from akha.core.config import Config
from akha.reports.json_generator import JSONReportGenerator


class TestGoldenTargetRegression(unittest.TestCase):
    def test_json_report_contains_evidence_chain_and_telemetry(self):
        fixture_path = Path(__file__).parent / "fixtures" / "golden_target_report.json"
        with open(fixture_path, "r", encoding="utf-8") as f:
            report_data = json.load(f)

        cfg = Config.default()
        with tempfile.TemporaryDirectory() as td:
            cfg.output_dir = td
            path = JSONReportGenerator(cfg).generate(report_data)
            self.assertTrue(os.path.exists(path))

            with open(path, "r", encoding="utf-8") as rf:
                out = json.load(rf)

            self.assertIn("telemetry", out)
            self.assertIn("latency_ms", out["telemetry"])
            self.assertGreaterEqual(out["telemetry"].get("request_count", 0), 1)
            self.assertIn("auth", out)

            vulns = out.get("vulnerabilities", [])
            self.assertGreaterEqual(len(vulns), 1)
            chain = vulns[0].get("evidence_chain", {})
            self.assertEqual(chain.get("probe"), True)
            self.assertEqual(chain.get("reflection"), True)
            self.assertEqual(chain.get("verification"), True)
            self.assertEqual(chain.get("execution"), True)

            insights = out.get("report_insights", {})
            self.assertIn("fix_first", insights)
            self.assertGreaterEqual(len(insights.get("fix_first", [])), 1)
            self.assertIn("remediation_priority", insights["fix_first"][0])
            self.assertIn("framework_hints", insights["fix_first"][0])


if __name__ == "__main__":
    unittest.main()
