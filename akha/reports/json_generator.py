"""
JSON report generator for AKHA XSS Scanner.
"""

import json
import os
import time
from collections import Counter
from typing import Dict

from .utils import (
    with_triage_context,
    remediation_priority,
    exploit_path,
    framework_hints,
)


class JSONReportGenerator:
    """Generates a JSON report from scan results."""

    def __init__(self, config):
        self.config = config

    def generate(self, report_data: Dict) -> str:
        """Generate a JSON report file and return the file path."""
        output_dir = getattr(self.config, 'output_dir', 'output')
        os.makedirs(output_dir, exist_ok=True)

        timestamp = int(time.time())
        filename = f"scan_report_{timestamp}.json"
        filepath = os.path.join(output_dir, filename)

        vulnerabilities = report_data.get("vulnerabilities", [])
        enriched_vulns = [with_triage_context(v) for v in vulnerabilities]
        prioritized = sorted(enriched_vulns, key=self._priority_key)

        confirmed = sum(1 for v in prioritized if str(v.get("severity_level", "")).lower() == "confirmed")
        potential = sum(1 for v in prioritized if str(v.get("severity_level", "")).lower() == "potential")
        low = sum(1 for v in prioritized if str(v.get("severity_level", "")).lower() == "low")
        total = len(prioritized)

        if total:
            avg_confidence = int(sum(int(v.get("confidence", 0) or 0) for v in prioritized) / total)
            avg_exploitability = int(sum(int(v.get("exploitability_score", 0) or 0) for v in prioritized) / total)
        else:
            avg_confidence = 0
            avg_exploitability = 0

        risk_score = min(100, int((confirmed * 28) + (potential * 14) + (low * 5) + (avg_exploitability * 0.25)))

        param_counter = Counter(str(v.get("parameter", "?") or "?") for v in prioritized)
        top_parameter, top_parameter_count = (param_counter.most_common(1)[0] if param_counter else ("N/A", 0))

        reflection_hits = sum(1 for v in prioritized if (v.get("evidence_chain") or {}).get("reflection"))
        execution_hits = sum(1 for v in prioritized if (v.get("evidence_chain") or {}).get("execution"))

        smart_insights = []
        if top_parameter_count > 1 and top_parameter != "N/A":
            smart_insights.append(
                f"Reflected XSS detected in parameter '{top_parameter}' across {top_parameter_count} findings"
            )
        if report_data.get("waf", {}).get("detected") and execution_hits > 0:
            smart_insights.append("WAF present but execution evidence still observed")
        if not report_data.get("csp", {}).get("has_csp"):
            smart_insights.append("CSP header missing, increasing script execution risk")
        if not smart_insights:
            smart_insights.append("No high-risk anomaly detected from current evidence chain metrics")

        fix_first = [
            {
                "parameter": v.get("parameter"),
                "url": v.get("url"),
                "severity_level": v.get("severity_level"),
                "confidence": v.get("confidence"),
                "exploitability_score": v.get("exploitability_score"),
                "remediation_priority": remediation_priority(v),
                "exploit_path": exploit_path(v),
                "framework_hints": framework_hints(v),
            }
            for v in prioritized[:10]
        ]

        payload = {
            "scanner": "AKHA XSS Scanner",
            "version": "1.0.0",
            "target": report_data.get("target", ""),
            "scan_mode": report_data.get("scan_mode", ""),
            "start_time": report_data.get("start_time"),
            "end_time": report_data.get("end_time"),
            "duration": report_data.get("duration"),
            "statistics": report_data.get("statistics", {}),
            "telemetry": report_data.get("telemetry", {}),
            "auth": report_data.get("auth", {}),
            "module_metrics": report_data.get("module_metrics", {}),
            "phase_timeline": report_data.get("phase_timeline", []),
            "scan_policy": report_data.get("scan_policy", {}),
            "budget_fallback": report_data.get("budget_fallback", {}),
            "learning": report_data.get("learning", {}),
            "vulnerabilities": prioritized,
            "report_insights": {
                "confirmed_count": confirmed,
                "potential_count": potential,
                "low_count": low,
                "total_count": total,
                "risk_score": risk_score,
                "avg_confidence": avg_confidence,
                "avg_exploitability": avg_exploitability,
                "top_parameter": {
                    "name": top_parameter,
                    "count": top_parameter_count,
                },
                "reflection_hits": reflection_hits,
                "execution_hits": execution_hits,
                "smart_insights": smart_insights,
                "fix_first": fix_first,
            },
            "waf": report_data.get("waf", {}),
            "csp": report_data.get("csp", {}),
            "blind_xss": report_data.get("blind_xss"),
            "oast_callbacks": report_data.get("oast_callbacks", []),
        }

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(payload, f, indent=2, default=str)

        return filepath

    def _priority_key(self, vuln: Dict):
        sev = str(vuln.get("severity_level", "potential")).lower()
        sev_rank = {"confirmed": 0, "potential": 1, "low": 2}.get(sev, 3)
        confidence = int(vuln.get("confidence", 0) or 0)
        exploitability = int(vuln.get("exploitability_score", 0) or 0)
        return (sev_rank, -confidence, -exploitability)
