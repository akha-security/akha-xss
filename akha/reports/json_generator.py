"""
JSON report generator for AKHA XSS Scanner.
"""

import json
import os
import time
from typing import Dict


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
        enriched_vulns = [self._with_evidence_chain(v) for v in vulnerabilities]
        prioritized = sorted(enriched_vulns, key=self._priority_key)

        confirmed = sum(1 for v in prioritized if str(v.get("severity_level", "")).lower() == "confirmed")
        potential = sum(1 for v in prioritized if str(v.get("severity_level", "")).lower() == "potential")

        fix_first = [
            {
                "parameter": v.get("parameter"),
                "url": v.get("url"),
                "severity_level": v.get("severity_level"),
                "confidence": v.get("confidence"),
                "exploitability_score": v.get("exploitability_score"),
                "remediation_priority": self._remediation_priority(v),
                "exploit_path": self._exploit_path(v),
                "framework_hints": self._framework_hints(v),
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
            "budget_fallback": report_data.get("budget_fallback", {}),
            "learning": report_data.get("learning", {}),
            "vulnerabilities": prioritized,
            "report_insights": {
                "confirmed_count": confirmed,
                "potential_count": potential,
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

    def _with_evidence_chain(self, vuln: Dict) -> Dict:
        out = dict(vuln)
        if out.get("evidence_chain"):
            return out

        context = out.get("context", {}) or {}
        has_context = bool(context.get("Location") or context.get("Type"))
        validated = bool(out.get("validated") or out.get("severity_level") == "confirmed")
        browser_matrix = out.get("browser_matrix", {}) or {}
        executed = any(bool(details.get("executed")) for details in browser_matrix.values())

        out["evidence_chain"] = {
            "probe": bool(out.get("test_url") or out.get("parameter")),
            "reflection": has_context,
            "verification": validated,
            "execution": executed,
        }
        return out

    def _priority_key(self, vuln: Dict):
        sev = str(vuln.get("severity_level", "potential")).lower()
        sev_rank = {"confirmed": 0, "potential": 1, "low": 2}.get(sev, 3)
        confidence = int(vuln.get("confidence", 0) or 0)
        exploitability = int(vuln.get("exploitability_score", 0) or 0)
        return (sev_rank, -confidence, -exploitability)

    def _remediation_priority(self, vuln: Dict) -> str:
        sev = str(vuln.get("severity_level", "potential")).lower()
        conf = int(vuln.get("confidence", 0) or 0)
        if sev == "confirmed" and conf >= 85:
            return "P1"
        if sev == "confirmed":
            return "P2"
        if sev == "potential" and conf >= 70:
            return "P2"
        if sev == "potential":
            return "P3"
        return "P4"

    def _exploit_path(self, vuln: Dict) -> str:
        chain = vuln.get("evidence_chain", {}) or {}
        bits = [
            "probe" if chain.get("probe") else "-probe",
            "reflection" if chain.get("reflection") else "-reflection",
            "verification" if chain.get("verification") else "-verification",
            "execution" if chain.get("execution") else "-execution",
        ]
        return " -> ".join(bits)

    def _framework_hints(self, vuln: Dict) -> Dict:
        """Suggest framework-specific remediation hints from URL/context cues."""
        url = str(vuln.get("url", "") or "").lower()
        param = str(vuln.get("parameter", "") or "").lower()
        context = vuln.get("context", {}) or {}
        ctype = str(context.get("Type", "") or context.get("Location", "") or "").lower()

        framework = "generic"
        if any(k in url for k in ("/api/", "/graphql", "json")):
            framework = "api"
        if any(k in url for k in ("next", "react", "_next")):
            framework = "react"
        elif any(k in url for k in ("/wp-", "wordpress")):
            framework = "wordpress"
        elif any(k in url for k in ("django", "csrftoken", "admin/")):
            framework = "django"
        elif any(k in url for k in ("laravel", "_token", "sanctum")):
            framework = "laravel"

        if framework == "react":
            guidance = [
                "Avoid dangerouslySetInnerHTML for untrusted data.",
                "Encode user-controlled values before HTML sinks.",
                "Prefer component rendering over raw HTML insertion.",
            ]
        elif framework == "django":
            guidance = [
                "Keep autoescape enabled in templates.",
                "Use |escape for user-controlled template variables.",
                "Avoid marking untrusted data as safe.",
            ]
        elif framework == "laravel":
            guidance = [
                "Use escaped blade output {{ $var }} for untrusted data.",
                "Restrict raw output {!! $var !!} to trusted HTML only.",
                "Validate and normalize request input before rendering.",
            ]
        elif framework == "api":
            guidance = [
                "Apply output encoding in frontend render path for API fields.",
                "Validate and sanitize high-risk text fields server-side.",
                "Adopt strict content-type and CSP where applicable.",
            ]
        elif framework == "wordpress":
            guidance = [
                "Use esc_html/esc_attr/esc_url in templates.",
                "Validate shortcode/widget inputs before render.",
                "Avoid direct echo of request parameters.",
            ]
        else:
            guidance = [
                "Apply context-aware output encoding at sink.",
                "Validate and canonicalize untrusted input.",
                "Use CSP and avoid dangerous DOM APIs for user data.",
            ]

        sink = "unknown"
        if "script" in ctype or "javascript" in ctype:
            sink = "javascript"
        elif "attr" in ctype:
            sink = "attribute"
        elif "html" in ctype:
            sink = "html"

        return {
            "framework": framework,
            "sink": sink,
            "parameter": param,
            "guidance": guidance,
        }
