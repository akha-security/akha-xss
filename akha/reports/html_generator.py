"""
HTML report generator for AKHA XSS Scanner.
"""

import html
import os
import time
from datetime import datetime
from typing import Dict, List


def _esc(value) -> str:
    """HTML-escape a value for safe embedding."""
    return html.escape(str(value) if value is not None else "")


def _severity_color(severity: str) -> str:
    mapping = {
        "confirmed": "#e74c3c",
        "potential": "#e67e22",
        "low": "#f1c40f",
    }
    return mapping.get(severity.lower(), "#95a5a6")


def _confidence_color(confidence) -> str:
    try:
        c = int(confidence)
    except (TypeError, ValueError):
        return "#95a5a6"
    if c >= 80:
        return "#2ecc71"
    if c >= 50:
        return "#e67e22"
    return "#e74c3c"


def _build_vuln_rows(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return (
      '<tr><td colspan="7" style="text-align:center;color:#7f8c8d;">'
            "No vulnerabilities detected.</td></tr>"
        )
    rows = []
    for i, v in enumerate(vulnerabilities, 1):
        vtype = _esc(v.get("type", "reflected").replace("_", " ").title())
        severity = _esc(v.get("severity_level", "potential"))
        sev_color = _severity_color(v.get("severity_level", "potential"))
        param = _esc(v.get("parameter", "?"))
        url = _esc(v.get("url", ""))
        confidence = v.get("confidence", "?")
        exploitability = v.get("exploitability_score", "?")
        conf_color = _confidence_color(confidence)
        payload_val = _esc(v.get("payload", ""))
        browser_matrix = v.get("browser_matrix", {}) or {}
        browser_bits = []
        for name, details in browser_matrix.items():
          executed = "PASS" if details.get("executed") else "FAIL"
          method = details.get("method") or "-"
          browser_bits.append(f"{_esc(name)}={executed} ({_esc(method)})")
        browser_summary = " | ".join(browser_bits) if browser_bits else "N/A"
        chain = v.get("evidence_chain", {}) or {}
        chain_summary = (
          f"probe={bool(chain.get('probe', False))}, "
          f"reflection={bool(chain.get('reflection', False))}, "
          f"verification={bool(chain.get('verification', False))}, "
          f"execution={bool(chain.get('execution', False))}"
        )

        rows.append(
            f"<tr>"
            f'<td style="text-align:center;color:#7f8c8d;">{i}</td>'
            f"<td>{vtype}</td>"
            f'<td style="color:{sev_color};font-weight:bold;">{severity.upper()}</td>'
            f"<td>{param}</td>"
            f'<td style="font-size:0.85em;word-break:break-all;">{url}</td>'
            f'<td style="text-align:center;color:{conf_color};font-weight:bold;">'
            f"{_esc(str(confidence))}{'%' if isinstance(confidence, int) else ''}</td>"
            f'<td style="text-align:center;">{_esc(str(exploitability))}</td>'
            f"</tr>"
            f'<tr><td colspan="7" style="background:#1a1a2e;font-size:0.82em;'
            f'color:#bdc3c7;padding:6px 12px;">'
            f"<strong>Payload:</strong> <code>{payload_val}</code></td></tr>"
            f'<tr><td colspan="7" style="background:#121228;font-size:0.80em;'
            f'color:#9fb3c8;padding:6px 12px;">'
            f"<strong>Browser Matrix:</strong> {_esc(browser_summary)}</td></tr>"
            f'<tr><td colspan="7" style="background:#0f1526;font-size:0.80em;'
            f'color:#a8bfd8;padding:6px 12px;">'
            f"<strong>Evidence Chain:</strong> {_esc(chain_summary)}</td></tr>"
        )
    return "\n".join(rows)


def _with_evidence_chain(v: Dict) -> Dict:
    out = dict(v)
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


def _priority_key(vuln: Dict):
    sev = str(vuln.get("severity_level", "potential")).lower()
    sev_rank = {"confirmed": 0, "potential": 1, "low": 2}.get(sev, 3)
    confidence = int(vuln.get("confidence", 0) or 0)
    exploitability = int(vuln.get("exploitability_score", 0) or 0)
    return (sev_rank, -confidence, -exploitability)


def _build_fix_first_rows(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return '<tr><td colspan="5" style="text-align:center;color:#7f8c8d;">No prioritized items.</td></tr>'
    rows = []
    for i, v in enumerate(sorted(vulnerabilities, key=_priority_key)[:5], 1):
        chain = v.get("evidence_chain", {}) or {}
        path = " -> ".join([
            "probe" if chain.get("probe") else "-probe",
            "reflection" if chain.get("reflection") else "-reflection",
            "verification" if chain.get("verification") else "-verification",
            "execution" if chain.get("execution") else "-execution",
        ])
        rows.append(
            f"<tr>"
            f"<td>{i}</td>"
            f"<td>{_esc(v.get('severity_level', 'potential')).upper()}</td>"
            f"<td>{_esc(v.get('parameter', '?'))}</td>"
            f"<td>{_esc(v.get('url', ''))}</td>"
            f"<td>{_esc(path)}</td>"
            f"</tr>"
        )
    return "\n".join(rows)


class HTMLReportGenerator:
    """Generates an HTML report from scan results."""

    def __init__(self, config):
        self.config = config

    def generate(self, report_data: Dict) -> str:
        """Generate an HTML report file and return the file path."""
        output_dir = getattr(self.config, 'output_dir', 'output')
        os.makedirs(output_dir, exist_ok=True)

        timestamp = int(time.time())
        filename = f"scan_report_{timestamp}.html"
        filepath = os.path.join(output_dir, filename)

        target = report_data.get("target", "")
        scan_mode = report_data.get("scan_mode", "full")
        stats = report_data.get("statistics", {})
        learning = report_data.get("learning", {}) or {}
        telemetry = report_data.get("telemetry", {}) or {}
        module_metrics = report_data.get("module_metrics", {}) or {}
        vulnerabilities = report_data.get("vulnerabilities", [])
        vulnerabilities = [_with_evidence_chain(v) for v in vulnerabilities]
        waf = report_data.get("waf", {})
        csp = report_data.get("csp", {})
        duration_raw = report_data.get("duration", 0)
        start_ts = report_data.get("start_time")

        try:
            start_str = datetime.fromtimestamp(float(start_ts)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            start_str = "N/A"

        try:
            duration_str = f"{float(duration_raw):.1f}s"
        except (TypeError, ValueError):
            duration_str = "N/A"

        vuln_count = len(vulnerabilities)
        vuln_color = "#e74c3c" if vuln_count > 0 else "#2ecc71"
        vuln_rows = _build_vuln_rows(vulnerabilities)

        waf_name = waf.get("name", "None") if waf.get("detected") else "None detected"
        csp_status = "Present" if csp.get("has_csp") else "Not present"

        blind_xss = report_data.get("blind_xss") or {}
        blind_injections = len(blind_xss.get("injections", [])) if blind_xss else 0
        oast_callbacks = len(report_data.get("oast_callbacks", []))
        failure_reasons = learning.get("failure_reasons", {}) if isinstance(learning, dict) else {}
        top_failure_reasons = sorted(
          failure_reasons.items(), key=lambda x: int(x[1]), reverse=True
        )[:3]
        failure_summary = ", ".join(f"{k}:{v}" for k, v in top_failure_reasons) if top_failure_reasons else "N/A"
        latency = telemetry.get("latency_ms", {}) if isinstance(telemetry, dict) else {}
        status_buckets = telemetry.get("status_buckets", {}) if isinstance(telemetry, dict) else {}
        telemetry_summary = (
          f"p50={latency.get('p50', 0)}ms, p95={latency.get('p95', 0)}ms, "
          f"2xx={status_buckets.get('2xx', 0)}, 4xx={status_buckets.get('4xx', 0)}, 5xx={status_buckets.get('5xx', 0)}"
        )
        module_summary = ", ".join(
            f"{name}:{round(float(meta.get('duration_seconds', 0.0)), 2)}s"
            for name, meta in sorted(module_metrics.items())[:4]
        ) if module_metrics else "N/A"
        fix_first_rows = _build_fix_first_rows(vulnerabilities)

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AKHA XSS Scanner — Report</title>
<style>
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: #0d0d1a; color: #ecf0f1; font-family: 'Segoe UI', Arial, sans-serif;
          font-size: 14px; line-height: 1.6; padding: 24px; }}
  h1 {{ color: #00d4ff; font-size: 1.8em; margin-bottom: 4px; }}
  h2 {{ color: #00d4ff; font-size: 1.1em; margin: 24px 0 10px; border-bottom: 1px solid #1e3a5f;
        padding-bottom: 6px; }}
  .subtitle {{ color: #7f8c8d; margin-bottom: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
           gap: 12px; margin-bottom: 24px; }}
  .card {{ background: #16213e; border: 1px solid #1e3a5f; border-radius: 8px;
           padding: 16px 20px; }}
  .card .label {{ color: #7f8c8d; font-size: 0.82em; text-transform: uppercase;
                  letter-spacing: 0.05em; margin-bottom: 4px; }}
  .card .value {{ font-size: 1.3em; font-weight: bold; }}
  table {{ width: 100%; border-collapse: collapse; background: #16213e;
           border: 1px solid #1e3a5f; border-radius: 8px; overflow: hidden; }}
  thead tr {{ background: #1e3a5f; }}
  th {{ padding: 10px 12px; text-align: left; color: #00d4ff; font-weight: 600;
        font-size: 0.88em; text-transform: uppercase; letter-spacing: 0.04em; }}
  td {{ padding: 10px 12px; border-bottom: 1px solid #1a2840; vertical-align: top; }}
  tr:last-child td {{ border-bottom: none; }}
  code {{ background: #0d0d1a; color: #e74c3c; padding: 2px 6px; border-radius: 3px;
          font-size: 0.88em; word-break: break-all; }}
  .footer {{ margin-top: 32px; color: #7f8c8d; font-size: 0.82em; text-align: center; }}
</style>
</head>
<body>
<h1>⚡ AKHA XSS Scanner</h1>
<p class="subtitle">Scan Report — Generated {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}</p>

<h2>Scan Overview</h2>
<div class="grid">
  <div class="card">
    <div class="label">Target</div>
    <div class="value" style="font-size:0.95em;word-break:break-all;">{_esc(target)}</div>
  </div>
  <div class="card">
    <div class="label">Mode</div>
    <div class="value">{_esc(scan_mode.upper())}</div>
  </div>
  <div class="card">
    <div class="label">Start Time</div>
    <div class="value" style="font-size:0.95em;">{_esc(start_str)}</div>
  </div>
  <div class="card">
    <div class="label">Duration</div>
    <div class="value">{_esc(duration_str)}</div>
  </div>
  <div class="card">
    <div class="label">URLs Crawled</div>
    <div class="value">{_esc(str(stats.get('urls_crawled', 0)))}</div>
  </div>
  <div class="card">
    <div class="label">Params Found</div>
    <div class="value">{_esc(str(stats.get('params_found', 0)))}</div>
  </div>
  <div class="card">
    <div class="label">Payloads Tested</div>
    <div class="value">{_esc(str(stats.get('payloads_tested', 0)))}</div>
  </div>
  <div class="card">
    <div class="label">Learning Failures</div>
    <div class="value" style="font-size:0.9em;">{_esc(failure_summary)}</div>
  </div>
  <div class="card">
    <div class="label">HTTP Telemetry</div>
    <div class="value" style="font-size:0.82em;">{_esc(telemetry_summary)}</div>
  </div>
  <div class="card">
    <div class="label">Module Timing</div>
    <div class="value" style="font-size:0.82em;">{_esc(module_summary)}</div>
  </div>
  <div class="card">
    <div class="label">Vulnerabilities</div>
    <div class="value" style="color:{vuln_color};">{vuln_count}</div>
  </div>
  <div class="card">
    <div class="label">WAF</div>
    <div class="value" style="font-size:0.95em;">{_esc(waf_name)}</div>
  </div>
  <div class="card">
    <div class="label">CSP</div>
    <div class="value" style="font-size:0.95em;">{_esc(csp_status)}</div>
  </div>
  {f'<div class="card"><div class="label">Blind XSS Injected</div>'
   f'<div class="value">{blind_injections}</div></div>' if blind_injections else ''}
  {f'<div class="card"><div class="label">OAST Callbacks</div>'
   f'<div class="value" style="color:#e74c3c;">{oast_callbacks}</div></div>' if oast_callbacks else ''}
</div>

<h2>Detected Vulnerabilities</h2>
<table>
  <thead>
    <tr>
      <th style="width:40px;">#</th>
      <th>Type</th>
      <th>Severity</th>
      <th>Parameter</th>
      <th>URL</th>
      <th style="width:70px;">Conf.</th>
      <th style="width:90px;">Exploit.</th>
    </tr>
  </thead>
  <tbody>
    {vuln_rows}
  </tbody>
</table>

<h2>Fix-First Prioritization</h2>
<table>
  <thead>
    <tr>
      <th style="width:40px;">#</th>
      <th style="width:120px;">Severity</th>
      <th>Parameter</th>
      <th>URL</th>
      <th>Exploit Path</th>
    </tr>
  </thead>
  <tbody>
    {fix_first_rows}
  </tbody>
</table>

<div class="footer">
  AKHA XSS Scanner v1.0.0 &mdash; Report generated at {_esc(datetime.now().strftime('%Y-%m-%d %H:%M:%S'))}
</div>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath
