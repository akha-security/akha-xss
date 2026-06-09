"""HTML report generator for AKHA XSS Scanner."""

import html
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from typing import Dict, List

from ..modules.xss.constants import REPORT_START, REPORT_END

_HIT_OPEN = "[[AKHA_HIT_OPEN]]"
_HIT_CLOSE = "[[AKHA_HIT_CLOSE]]"

# Full report is embedded in HTML for "Export JSON" — cap huge fields to avoid browser OOM.
_EMBED_MAX_RESP = 64_000
_EMBED_MAX_REQ = 32_000
_EMBED_MAX_CRAWL_URLS = 100


def _slim_for_html_embed(report_data: Dict) -> Dict:
    slim = dict(report_data)
    vulns = slim.get("vulnerabilities") or []
    out_v = []
    for v in vulns:
        if not isinstance(v, dict):
            out_v.append(v)
            continue
        sv = dict(v)
        r = sv.get("response")
        if isinstance(r, str) and len(r) > _EMBED_MAX_RESP:
            sv["response"] = (
                r[:_EMBED_MAX_RESP]
                + "\n\n... [truncated for embedded JSON export — see full scan JSON artifact]\n"
            )
        rq = sv.get("request")
        if isinstance(rq, str) and len(rq) > _EMBED_MAX_REQ:
            sv["request"] = rq[:_EMBED_MAX_REQ] + "\n\n... [truncated]\n"
        out_v.append(sv)
    slim["vulnerabilities"] = out_v
    crawl = slim.get("crawled_urls")
    if isinstance(crawl, list) and len(crawl) > _EMBED_MAX_CRAWL_URLS:
        slim["crawled_urls"] = crawl[:_EMBED_MAX_CRAWL_URLS]
        slim["crawled_urls_truncated_note"] = len(crawl) - _EMBED_MAX_CRAWL_URLS
    return slim


def _esc(value) -> str:
    return html.escape(str(value) if value is not None else "")


def _attr(value) -> str:
    return html.escape(str(value) if value is not None else "", quote=True)


def _safe_url(value) -> str:
    """Return URL only if it starts with http/https, otherwise return '#'."""
    s = str(value) if value is not None else ""
    if s.lower().lstrip().startswith(("http://", "https://")):
        return html.escape(s, quote=True)
    return "#"


def _js_arg(value) -> str:
    """Return a JS string literal safe for inline handlers (HTML-entity encoded for use in HTML attributes)."""
    s = str(value) if value is not None else ""
    encoded = (
        json.dumps(s)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("'", "\\u0027")
        .replace('"', "&quot;")   # HTML-encode double quotes for use inside onclick="..."
    )
    return encoded


def _severity_color(severity: str) -> str:
    mapping = {
        "confirmed": "#f87171",
        "potential": "#fb923c",
        "low": "#34d399",
    }
    return mapping.get(str(severity).lower(), "#64748b")


def _severity_rank(severity: str) -> int:
    return {"confirmed": 0, "potential": 1, "low": 2}.get(str(severity).lower(), 3)


def _tier_rank(tier: str) -> int:
    return {"confirmed": 0, "high": 1, "medium": 2, "low": 3}.get(
        str(tier or "").lower(), 4
    )


def _priority_key(vuln: Dict):
    """Order: confirmed finding first, then scorer tier, exploitability, confidence."""
    sl = str(vuln.get("severity_level", "potential")).lower()
    ct = str(vuln.get("confidence_tier") or "").lower()
    confirmed_first = 0 if sl == "confirmed" else 1
    tr = _tier_rank(ct) if ct else 3
    confidence = int(vuln.get("confidence", 0) or 0)
    exploitability = int(vuln.get("exploitability_score", 0) or 0)
    return (confirmed_first, tr, -exploitability, -confidence)


from .utils import (
    with_evidence_chain as _with_evidence_chain,
    remediation_priority as _remediation_priority,
    exploit_path as _exploit_path,
    framework_hints as _framework_hints,
    triage_summary as _triage_summary,
    finding_description as _finding_description,
    impact_summary as _impact_summary,
    primary_recommendation as _primary_recommendation,
    reproduction_steps as _reproduction_steps,
    with_triage_context as _with_triage_context,
)


def _mark_hits(text: str, payload: str) -> str:
    if not text:
        return ""
    marked = text
    if REPORT_START in marked and REPORT_END in marked:
        marked = marked.replace(REPORT_START, _HIT_OPEN).replace(REPORT_END, _HIT_CLOSE)
    elif payload:
        marked = marked.replace(payload, f"{_HIT_OPEN}{payload}{_HIT_CLOSE}")
    return marked


def _render_http_block(raw_text: str, payload: str) -> str:
    marked = _mark_hits(str(raw_text or ""), str(payload or ""))
    escaped = _esc(marked)
    escaped = escaped.replace(_esc(_HIT_OPEN), '<span class="vuln-hit">')
    escaped = escaped.replace(_esc(_HIT_CLOSE), "</span>")
    return escaped


def _build_fix_first_rows(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return '<tr><td colspan="5" class="dim">No prioritized items.</td></tr>'

    rows = []
    for idx, v in enumerate(sorted(vulnerabilities, key=_priority_key)[:8], 1):
        chain = v.get("evidence_chain", {}) or {}
        path_parts = [
            ("probe",   chain.get("probe")),
            ("reflect", chain.get("reflection")),
            ("verify",  chain.get("verification")),
            ("execute", chain.get("execution")),
        ]
        path_html = " &rarr; ".join(
            f"<span class='chain-step {'chain-hit' if ok else 'chain-miss'}'>{label}</span>"
            for label, ok in path_parts
        )
        severity = str(v.get("severity_level", "potential")).lower()
        conf = int(v.get("confidence", 0) or 0)
        rows.append(
            f"<tr>"
            f"<td class='mono dim'>#{idx}</td>"
            f"<td><span class='sev-badge sev-{_esc(severity)}'>{_esc(severity)}</span></td>"
            f"<td class='mono'>{_esc(v.get('parameter', '?'))}</td>"
            f"<td class='mono url-cell'>{_esc(v.get('url', ''))}</td>"
            f"<td class='conf-cell'>"
            f"<span class='conf-bar-wrap'><span class='conf-bar' style='width:{conf}%'></span></span>"
            f"<span class='conf-label'>{conf}%</span>"
            f"</td>"
            f"</tr>"
        )
    return "\n".join(rows)


def _build_vuln_cards(vulnerabilities: List[Dict]) -> str:
    if not vulnerabilities:
        return (
            '<div class="empty-state">'
            '<div class="empty-icon">&#10003;</div>'
            '<div>No vulnerabilities detected.</div>'
            '</div>'
        )

    cards = []
    for idx, v in enumerate(vulnerabilities, 1):
        severity = str(v.get("severity_level", "potential")).lower()
        severity_rank = _severity_rank(severity)
        sev_color = _severity_color(severity)
        payload = str(v.get("payload", "") or "")
        request_raw = str(v.get("request", "") or "")
        response_raw = str(v.get("response", "") or "")
        proof = str(v.get("proof", "") or "")
        validation_proof = str(v.get("validation_proof", "") or "")
        confidence = int(v.get("confidence", 0) or 0)
        exploitability = int(v.get("exploitability_score", 0) or 0)
        full_link = str(v.get("test_url", "") or "") or str(v.get("url", "") or "")
        vuln_type = _esc(v.get("type", "reflected_xss")).replace("_", " ").title()

        browser_matrix = v.get("browser_matrix", {}) or {}
        browser_bits = []
        for name, details in browser_matrix.items():
            state = "pass" if details.get("executed") else "fail"
            icon = "&#10003;" if details.get("executed") else "&#10007;"
            method = _esc(details.get("method") or "-")
            browser_bits.append(
                f"<span class='browser-tag browser-{state}'>{icon} {_esc(name)} "
                f"<span class='dim'>({method})</span></span>"
            )
        browser_summary = "".join(browser_bits) if browser_bits else "<span class='dim'>N/A</span>"

        chain = v.get("evidence_chain", {}) or {}
        chain_steps = [
            ("Probe",   chain.get("probe")),
            ("Reflect", chain.get("reflection")),
            ("Verify",  chain.get("verification")),
            ("Execute", chain.get("execution")),
        ]
        chain_html = "".join(
            f"<span class='chain-pill {'chain-pill-on' if ok else 'chain-pill-off'}'>{label}</span>"
            for label, ok in chain_steps
        )

        search_blob = " ".join([
            str(v.get("type", "")),
            str(v.get("parameter", "")),
            str(v.get("url", "")),
            str(v.get("payload", "")),
            str(v.get("proof", "")),
        ]).lower()

        framework_hints = v.get("framework_hints", {}) or {}
        fw_name = _esc(framework_hints.get("framework", ""))
        fw_sink = _esc(framework_hints.get("sink", ""))
        fw_guidance = framework_hints.get("guidance", []) or []
        remediation_priority = _esc(v.get("remediation_priority", ""))
        triage_summary = str(v.get("triage_summary", "") or "")
        description = str(v.get("description", "") or "")
        impact = str(v.get("impact", "") or "")
        recommendation = str(v.get("primary_recommendation", "") or "")
        exploit_path = str(v.get("exploit_path", "") or "")
        classification = v.get("classification", {}) or {}
        cvss_like = v.get("cvss_like_score", "")
        reproduction_steps = v.get("reproduction_steps", []) or []
        replay_artifact = v.get("replay", {}) or {}

        rem_section = ""
        if fw_guidance:
            guidance_items = "".join(f"<li>{_esc(g)}</li>" for g in fw_guidance)
            rem_section = (
                f"<details class='vc-details'><summary>Remediation Hints</summary>"
                f"<div class='remediation-block'>"
                f"<div class='rem-meta'>"
                f"<span class='rem-tag'>Framework: {fw_name}</span>"
                f"<span class='rem-tag'>Sink: {fw_sink}</span>"
                f"</div>"
                f"<ul>{guidance_items}</ul>"
                f"</div></details>"
            )

        val_proof_section = ""
        if validation_proof:
            val_proof_section = (
                f"<div class='pre-wrap'>"
                f"<button class='copy-btn' onclick='copyFromPre(this)'>Copy</button>"
                f"<pre>{_esc(validation_proof)}</pre>"
                f"</div>"
            )

        prio_badge = (
            f"<span class='prio-badge'>{remediation_priority}</span>"
            if remediation_priority else ""
        )

        repro_items = "".join(f"<li>{_esc(step)}</li>" for step in reproduction_steps)
        replay_lines = ""
        if isinstance(replay_artifact, dict) and replay_artifact:
            replay_lines = "".join(
                f"<div><span class='dim'>{_esc(k)}:</span> <span class='mono'>{_esc(val)}</span></div>"
                for k, val in replay_artifact.items()
                if k in ("method", "url", "parameter", "location", "payload")
            )
        replay_section = f"<div class='replay-mini'>{replay_lines}</div>" if replay_lines else ""

        ctier = str(v.get("confidence_tier") or "").strip().lower()
        tier_badge = ""
        if ctier:
            tier_badge = (
                f"<span class='tier-pill tier-{_attr(ctier)}' "
                f"title='Scorer tier (confidence model)'>{_esc(ctier)}</span>"
            )

        cards.append(
            f"<div class='vuln-card' data-severity='{_attr(severity)}'"
            f" data-severity-rank='{severity_rank}'"
            f" data-confidence='{confidence}'"
            f" data-exploitability='{exploitability}'"
            f" data-search='{_attr(search_blob)}'>"

            f"<div class='vc-header'>"
            f"<div class='vc-header-left'>"
            f"<span class='vc-index dim'>#{idx}</span>"
            f"<span class='vc-type'>{vuln_type}</span>"
            f"<span class='sev-badge sev-{_esc(severity)}'>{_esc(severity)}</span>"
            f"{tier_badge}"
            f"{prio_badge}"
            f"</div>"
            f"<div class='vc-header-right'>"
            f"<span class='expl-label'>Exploitability</span>"
            f"<span class='expl-bar-wrap'>"
            f"<span class='expl-bar' style='width:{exploitability}%;background:{sev_color};'></span>"
            f"</span>"
            f"<span class='expl-num'>{exploitability}</span>"
            f"</div>"
            f"</div>"

            f"<div class='vc-url'>"
            f"<span class='dim'>Target&nbsp;</span>"
            f"<a class='mono' href='{_safe_url(full_link)}' target='_blank' rel='noopener noreferrer'>"
            f"{_esc(full_link or 'N/A')}</a>"
            f"</div>"

            f"<div class='vc-meta'>"
            f"<div class='vc-meta-item'>"
            f"<span class='meta-label'>Confidence</span>"
            f"<span class='meta-val'>{confidence}<span class='dim'>%</span></span>"
            f"</div>"
            f"<div class='vc-meta-item'>"
            f"<span class='meta-label'>Browsers</span>"
            f"<span class='meta-val browser-list'>{browser_summary}</span>"
            f"</div>"
            f"<div class='vc-meta-item'>"
            f"<span class='meta-label'>Evidence Chain</span>"
            f"<span class='meta-val'>{chain_html}</span>"
            f"</div>"
            f"<div class='vc-meta-item'>"
            f"<span class='meta-label'>Mapping</span>"
            f"<span class='meta-val mono'>{_esc(classification.get('cwe', 'N/A'))} · {_esc(classification.get('owasp', 'N/A'))}</span>"
            f"</div>"
            f"<div class='vc-meta-item'>"
            f"<span class='meta-label'>CVSS-like</span>"
            f"<span class='meta-val mono'>{_esc(cvss_like)}/10</span>"
            f"</div>"
            f"</div>"

            f"<div class='triage-box'>"
            f"<div class='triage-title'>Triage Summary</div>"
            f"<div>{_esc(triage_summary)}</div>"
            f"<div class='triage-path'><span class='dim'>Exploit path:</span> "
            f"<span class='mono'>{_esc(exploit_path)}</span></div>"
            f"</div>"

            f"<div class='explain-grid'>"
            f"<div class='explain-item'><span>Description</span><p>{_esc(description)}</p></div>"
            f"<div class='explain-item'><span>Impact</span><p>{_esc(impact)}</p></div>"
            f"<div class='explain-item'><span>Recommendation</span><p>{_esc(recommendation)}</p></div>"
            f"</div>"

            f"<div class='vc-actions'>"
            f"<button class='btn-sm' onclick=\"previewPayload({_js_arg(payload)})\">&#128065; Preview</button>"
            f"<button class='btn-sm' onclick=\"copyText({_js_arg(payload)})\">&#128203; Copy Payload</button>"
            f"<button class='btn-sm' onclick=\"copyText({_js_arg(full_link)})\">&#128279; Copy PoC</button>"
            f"<button class='btn-sm btn-outline' onclick=\"openPoc({_js_arg(full_link)})\">&#8599; Open PoC</button>"
            f"</div>"

            f"<details class='vc-details'><summary>Proof &amp; Validation</summary>"
            f"<div class='pre-wrap'>"
            f"<button class='copy-btn' onclick='copyFromPre(this)'>Copy</button>"
            f"<pre>{_esc(proof or 'No proof captured.')}</pre>"
            f"</div>"
            f"{val_proof_section}"
            f"</details>"

            f"<details class='vc-details' open><summary>Reproduction Steps</summary>"
            f"<div class='repro-block'>"
            f"<ol>{repro_items or '<li>No reproduction steps captured.</li>'}</ol>"
            f"{replay_section}"
            f"</div>"
            f"</details>"

            f"<details class='vc-details'><summary>HTTP Request</summary>"
            f"<div class='pre-wrap'>"
            f"<button class='copy-btn' onclick='copyFromPre(this)'>Copy</button>"
            f"<pre>{_render_http_block(request_raw, payload)}</pre>"
            f"</div>"
            f"</details>"

            f"<details class='vc-details'><summary>HTTP Response</summary>"
            f"<div class='pre-wrap'>"
            f"<button class='copy-btn' onclick='copyFromPre(this)'>Copy</button>"
            f"<pre>{_render_http_block(response_raw, payload)}</pre>"
            f"</div>"
            f"</details>"

            f"{rem_section}"

            f"</div>"
        )
    return "\n".join(cards)


class HTMLReportGenerator:
    """Generates a modern HTML report from scan results."""

    def __init__(self, config):
        self.config = config

    def generate(self, report_data: Dict) -> str:
        output_dir = getattr(self.config, "output_dir", "output")
        os.makedirs(output_dir, exist_ok=True)

        timestamp = int(time.time())
        filepath = os.path.join(output_dir, f"scan_report_{timestamp}.html")

        target = report_data.get("target", "")
        scan_mode = report_data.get("scan_mode", "full")
        stats = report_data.get("statistics", {})
        learning = report_data.get("learning", {}) or {}
        telemetry = report_data.get("telemetry", {}) or {}
        module_metrics = report_data.get("module_metrics", {}) or {}
        vulnerabilities = [_with_triage_context(v) for v in report_data.get("vulnerabilities", [])]
        vulnerabilities = sorted(vulnerabilities, key=_priority_key)
        waf = report_data.get("waf", {})
        csp = report_data.get("csp", {})
        scan_policy = report_data.get("scan_policy", {}) or {}
        phase_timeline = report_data.get("phase_timeline", []) or []

        start_ts = report_data.get("start_time")
        duration_raw = report_data.get("duration", 0)
        try:
            start_str = datetime.fromtimestamp(float(start_ts)).strftime("%Y-%m-%d %H:%M:%S")
        except (TypeError, ValueError, OSError):
            start_str = "N/A"
        try:
            duration_str = f"{float(duration_raw):.1f}s"
        except (TypeError, ValueError):
            duration_str = "N/A"

        blind_xss = report_data.get("blind_xss") or {}
        blind_injection_items = blind_xss.get("injections", []) if blind_xss else []
        blind_injections = len(blind_injection_items)
        oast_callback_items = report_data.get("oast_callbacks", []) or []
        oast_callbacks = len(oast_callback_items)

        def _fmt_ts(value: object) -> str:
          try:
            return datetime.fromtimestamp(float(value)).strftime("%Y-%m-%d %H:%M:%S")
          except (TypeError, ValueError, OSError):
            return "N/A"

        max_blind_rows = 200
        blind_trim_note = ""
        if blind_injections > max_blind_rows:
          blind_trim_note = (
            f"<div class='dim' style='font-size:12px;margin-bottom:8px;'>"
            f"Showing first {max_blind_rows} of {blind_injections} injections."
            f"</div>"
          )
        blind_rows = []
        for item in blind_injection_items[:max_blind_rows]:
          callback_url = str(item.get("callback_url", "") or "")
          payload = str(item.get("payload", "") or "")
          blind_rows.append(
            "<tr>"
            f"<td class='mono'>{_esc(_fmt_ts(item.get('timestamp')))}</td>"
            f"<td class='mono'>{_esc(item.get('parameter', ''))}</td>"
            f"<td class='mono url-cell'>{_esc(item.get('url', ''))}</td>"
            f"<td class='mono'>{_esc(item.get('technique', ''))}</td>"
            f"<td><a href=\"{_safe_url(callback_url)}\" target=\"_blank\" rel=\"noopener noreferrer\">{_esc(callback_url)}</a></td>"
            f"<td><button class='btn-sm' onclick='previewPayload({_js_arg(payload)})'>View</button></td>"
            "</tr>"
          )
        if not blind_rows:
          blind_rows.append(
            "<tr><td colspan='6' class='dim'>No blind XSS injections recorded.</td></tr>"
          )

        max_oast_rows = 200
        oast_trim_note = ""
        if oast_callbacks > max_oast_rows:
          oast_trim_note = (
            f"<div class='dim' style='font-size:12px;margin-bottom:8px;'>"
            f"Showing first {max_oast_rows} of {oast_callbacks} callbacks."
            f"</div>"
          )
        oast_rows = []
        for hit in oast_callback_items[:max_oast_rows]:
          raw_request = str(hit.get("raw_request", "") or "")
          oast_rows.append(
            "<tr>"
            f"<td class='mono'>{_esc(_fmt_ts(hit.get('timestamp')))}</td>"
            f"<td class='mono'>{_esc(hit.get('protocol', ''))}</td>"
            f"<td class='mono'>{_esc(hit.get('remote_address', ''))}</td>"
            f"<td class='mono'>{_esc(hit.get('unique_id', ''))}</td>"
            f"<td><button class='btn-sm' onclick='previewPayload({_js_arg(raw_request)})'>View</button></td>"
            "</tr>"
          )
        if not oast_rows:
          oast_rows.append(
            "<tr><td colspan='5' class='dim'>No OAST callbacks captured during scan.</td></tr>"
          )

        failure_reasons = learning.get("failure_reasons", {}) if isinstance(learning, dict) else {}
        top_failure = sorted(failure_reasons.items(), key=lambda x: int(x[1]), reverse=True)[:3]
        failure_summary = ", ".join(f"{k}:{v}" for k, v in top_failure) if top_failure else "N/A"

        latency = telemetry.get("latency_ms", {}) if isinstance(telemetry, dict) else {}
        status_buckets = telemetry.get("status_buckets", {}) if isinstance(telemetry, dict) else {}
        telemetry_summary = (
            f"p50={latency.get('p50', 0)}ms, p95={latency.get('p95', 0)}ms, "
            f"2xx={status_buckets.get('2xx', 0)}, 4xx={status_buckets.get('4xx', 0)}, 5xx={status_buckets.get('5xx', 0)}"
        )
        module_summary = ", ".join(
            f"{name}:{round(float(meta.get('duration_seconds', 0.0)), 2)}s"
            for name, meta in sorted(module_metrics.items())[:6]
        ) if module_metrics else "N/A"

        confirmed_count = sum(1 for v in vulnerabilities if str(v.get("severity_level", "")).lower() == "confirmed")
        potential_count = sum(1 for v in vulnerabilities if str(v.get("severity_level", "")).lower() == "potential")
        low_count = sum(1 for v in vulnerabilities if str(v.get("severity_level", "")).lower() == "low")
        total_vulns = len(vulnerabilities)

        if total_vulns:
            avg_conf = int(sum(int(v.get("confidence", 0) or 0) for v in vulnerabilities) / total_vulns)
            avg_expl = int(sum(int(v.get("exploitability_score", 0) or 0) for v in vulnerabilities) / total_vulns)
        else:
            avg_conf = 0
            avg_expl = 0

        risk_score = min(100, int((confirmed_count * 28) + (potential_count * 14) + (low_count * 5) + (avg_expl * 0.25)))

        param_counter = Counter(str(v.get("parameter", "?") or "?") for v in vulnerabilities)
        top_param, top_param_count = (param_counter.most_common(1)[0] if param_counter else ("N/A", 0))

        reflection_true = sum(1 for v in vulnerabilities if (v.get("evidence_chain") or {}).get("reflection"))
        execution_true = sum(1 for v in vulnerabilities if (v.get("evidence_chain") or {}).get("execution"))

        smart_insights = []
        if top_param_count > 1 and top_param != "N/A":
            smart_insights.append(f"Reflected XSS pattern concentrated on parameter '{top_param}' across {top_param_count} findings.")
        if waf.get("detected") and execution_true > 0:
            smart_insights.append("WAF is present but execution evidence exists, indicating partial bypass conditions.")
        if not csp.get("has_csp"):
            smart_insights.append("No CSP detected: reflected payloads have a higher probability of script execution.")
        if execution_true == 0 and reflection_true > 0:
            smart_insights.append("Reflection exists but execution is not yet confirmed. Prioritize sink-level hardening.")
        if not smart_insights:
            smart_insights.append("No high-risk behavioral anomaly detected from current evidence chain metrics.")

        vuln_cards = _build_vuln_cards(vulnerabilities)
        fix_first_rows = _build_fix_first_rows(vulnerabilities)

        waf_name = waf.get("name", "None") if waf.get("detected") else "None detected"
        csp_status = "Present" if csp.get("has_csp") else "Absent"
        export_data = dict(report_data)
        export_data["vulnerabilities"] = vulnerabilities
        report_json = (
            json.dumps(_slim_for_html_embed(export_data), default=str)
            .replace("&", "\\u0026")
            .replace("<", "\\u003c")
            .replace(">", "\\u003e")
            .replace("\u2028", "\\u2028")
            .replace("\u2029", "\\u2029")
        )

        risk_color = (
            "var(--crit)" if risk_score > 70
            else "var(--warn)" if risk_score > 30
            else "var(--safe)"
        )
        topbar_badge_sev = "confirmed" if confirmed_count > 0 else "low"

        module_row = (
            f'<div><strong>Modules</strong>&nbsp;{_esc(module_summary)}</div>'
            if module_summary != "N/A" else ""
        )
        policy_rows = "".join(
            f"<div class='policy-pill'><span>{_esc(label)}</span><strong>{_esc(value)}</strong></div>"
            for label, value in (
                ("Profile", scan_policy.get("profile", "balanced")),
                ("WAF cautious", "yes" if scan_policy.get("waf_cautious_applied") else "no"),
                ("Auto WAF", "on" if scan_policy.get("auto_waf_cautious", True) else "off"),
                ("Pages", scan_policy.get("max_pages", "N/A")),
                ("Risk top-k", scan_policy.get("risk_top_k", "N/A")),
                ("Threads", scan_policy.get("threads", "N/A")),
                ("Rate", scan_policy.get("rate_limit", "N/A")),
            )
        )
        if not policy_rows:
            policy_rows = "<div class='dim'>No scan policy metadata captured.</div>"

        timeline_rows = []
        for item in phase_timeline:
            if not isinstance(item, dict):
                continue
            timeline_rows.append(
                "<tr>"
                f"<td class='mono'>{_esc(item.get('phase', 'unknown'))}</td>"
                f"<td>{_esc(item.get('runs', 0))}</td>"
                f"<td>{_esc(item.get('duration_seconds', 0))}s</td>"
                f"<td>{_esc(item.get('errors', 0))}</td>"
                "</tr>"
            )
        if not timeline_rows:
            timeline_rows.append("<tr><td colspan='4' class='dim'>No phase timeline captured.</td></tr>")
        timeline_table = "".join(timeline_rows)

        insights_html = "".join(
            f'<div class="insight-item"><span class="insight-dot"></span><span>{_esc(t)}</span></div>'
            for t in smart_insights
        )

        blind_section = ""
        if blind_injections > 0 or oast_callbacks > 0:
          blind_section = (
            "<div class=\"section-label\">Blind XSS and OAST</div>"
            "<div class=\"table-wrap\">"
            "<div class=\"table-head\"><h2>Blind XSS Injections</h2>"
            "<span class=\"dim\" style=\"font-size:12px;\">Payloads injected with collaborator URLs</span></div>"
            f"{blind_trim_note}"
            "<div style=\"overflow-x:auto;\">"
            "<table><thead><tr>"
            "<th style=\"width:150px;\">Time</th>"
            "<th style=\"width:140px;\">Parameter</th>"
            "<th>URL</th>"
            "<th style=\"width:140px;\">Technique</th>"
            "<th>Callback URL</th>"
            "<th style=\"width:90px;\">Payload</th>"
            "</tr></thead><tbody>"
            f"{''.join(blind_rows)}"
            "</tbody></table></div></div>"
            "<div class=\"table-wrap\">"
            "<div class=\"table-head\"><h2>OAST Callbacks</h2>"
            "<span class=\"dim\" style=\"font-size:12px;\">Callbacks observed during scan runtime</span></div>"
            f"{oast_trim_note}"
            "<div style=\"overflow-x:auto;\">"
            "<table><thead><tr>"
            "<th style=\"width:150px;\">Time</th>"
            "<th style=\"width:90px;\">Protocol</th>"
            "<th style=\"width:150px;\">Source</th>"
            "<th style=\"width:180px;\">Unique ID</th>"
            "<th style=\"width:90px;\">Request</th>"
            "</tr></thead><tbody>"
            f"{''.join(oast_rows)}"
            "</tbody></table></div></div>"
          )

        html_content = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>AKHA XSS Security Report &mdash; {_esc(target)}</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:ital,opsz,wght@0,9..40,400;0,9..40,500;0,9..40,600;0,9..40,700&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
<style>
*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0;}}
:root{{
  --bg:#f4f7fb;
  --bg-elevated:#ffffff;
  --bg-card:#ffffff;
  --bg-inset:#f8fafc;
  --bg-hover:#eef4fb;
  --border:#d9e2ee;
  --border-hi:#b9c7d8;
  --text:#172033;
  --text-muted:#566276;
  --text-dim:#8793a5;
  --crit:#dc2626;
  --crit-bg:#fff1f2;
  --crit-bdr:#fecdd3;
  --warn:#b45309;
  --warn-bg:#fffbeb;
  --warn-bdr:#fde68a;
  --safe:#047857;
  --safe-bg:#ecfdf5;
  --safe-bdr:#a7f3d0;
  --accent:#0f6abf;
  --accent-dim:#e7f1ff;
  --accent-text:#ffffff;
  --sans:'DM Sans',-apple-system,BlinkMacSystemFont,'Segoe UI',system-ui,sans-serif;
  --mono:'JetBrains Mono',ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;
  --r:12px;
  --rs:8px;
  --shadow:0 10px 28px rgba(17,24,39,.08),0 1px 2px rgba(17,24,39,.04);
}}
body{{
  background:
    linear-gradient(180deg,#eef5ff 0%,#f7f9fc 280px,var(--bg) 560px),
    radial-gradient(900px 360px at 12% -12%,rgba(15,106,191,.12),transparent 60%),
    var(--bg);
  color:var(--text);
  font-family:var(--sans);
  font-size:14px;
  line-height:1.65;
  -webkit-font-smoothing:antialiased;
}}
.wrap{{max-width:1240px;margin:0 auto;padding:32px 20px 88px;}}

/* Topbar */
.topbar{{display:flex;align-items:center;justify-content:space-between;padding:0 28px;height:56px;background:rgba(255,255,255,.88);backdrop-filter:saturate(140%) blur(12px);border-bottom:1px solid var(--border);position:sticky;top:0;z-index:40;}}
.topbar-brand{{display:flex;align-items:center;gap:10px;font-weight:700;font-size:13px;letter-spacing:.04em;}}
.topbar-brand .dot{{width:8px;height:8px;border-radius:50%;background:var(--crit);box-shadow:0 0 6px var(--crit);flex-shrink:0;}}
.topbar-right{{display:flex;align-items:center;gap:10px;}}

/* Page header */
.page-header{{
  padding:40px 32px 32px;
  margin:0 0 36px;
  background:linear-gradient(135deg,#ffffff 0%,#eef6ff 100%);
  border:1px solid var(--border);
  border-radius:var(--r);
  box-shadow:var(--shadow);
}}
.page-header h1{{font-size:clamp(22px,3vw,28px);font-weight:700;letter-spacing:-.035em;margin-bottom:10px;color:var(--text);}}
.page-subtitle{{color:var(--text-muted);font-size:13px;display:flex;align-items:center;gap:14px;flex-wrap:wrap;}}
.page-subtitle .sep{{color:var(--text-dim);}}

/* Labels */
.section-label{{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.1em;color:var(--text-muted);margin-bottom:14px;}}

/* KPI grid */
.kpi-grid{{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-bottom:32px;}}
.kpi-card{{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);padding:20px 22px;box-shadow:var(--shadow);transition:transform .18s ease,border-color .18s ease;}}
.kpi-card:hover{{border-color:var(--border-hi);transform:translateY(-2px);}}
.kpi-label{{font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-bottom:8px;}}
.kpi-value{{font-family:var(--mono);font-size:28px;font-weight:700;letter-spacing:-.02em;line-height:1;}}
.kpi-sub{{font-size:11.5px;color:var(--text-muted);margin-top:8px;}}
.kpi-sep{{height:1px;background:var(--border);margin:12px 0;}}

/* Summary grid */
.summary-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-bottom:34px;}}
.card{{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);padding:22px 24px;box-shadow:var(--shadow);}}

/* Severity blocks */
.sev-row{{display:grid;grid-template-columns:repeat(3,1fr);gap:10px;margin-top:16px;}}
.sev-block{{border-radius:var(--rs);padding:14px 16px;text-align:center;}}
.sev-block.confirmed{{background:var(--crit-bg);border:1px solid var(--crit-bdr);}}
.sev-block.potential{{background:var(--warn-bg);border:1px solid var(--warn-bdr);}}
.sev-block.low{{background:var(--safe-bg);border:1px solid var(--safe-bdr);}}
.sev-num{{font-family:var(--mono);font-size:22px;font-weight:700;}}
.sev-block.confirmed .sev-num{{color:var(--crit);}}
.sev-block.potential .sev-num{{color:var(--warn);}}
.sev-block.low .sev-num{{color:var(--safe);}}
.sev-name{{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.08em;color:var(--text-muted);margin-top:4px;}}

/* Risk */
.risk-num{{font-family:var(--mono);font-size:38px;font-weight:800;letter-spacing:-.04em;line-height:1;}}
.progress-track{{height:5px;background:var(--border);border-radius:999px;overflow:hidden;margin-top:14px;}}
.progress-fill{{height:100%;border-radius:999px;}}
.risk-meta{{display:flex;justify-content:space-between;font-size:12px;color:var(--text-muted);margin-top:12px;}}

/* Stat rows */
.stat-row{{display:flex;justify-content:space-between;align-items:center;padding:9px 0;border-bottom:1px solid var(--border);font-size:13px;}}
.stat-row:last-child{{border-bottom:none;}}
.stat-row-val{{font-family:var(--mono);font-weight:600;}}

/* Insights */
.insight-list{{display:flex;flex-direction:column;gap:8px;margin-top:4px;}}
.insight-item{{display:flex;gap:10px;align-items:flex-start;font-size:12.5px;color:var(--text-muted);line-height:1.5;}}
.insight-dot{{width:6px;height:6px;border-radius:50%;background:var(--border-hi);flex-shrink:0;margin-top:6px;}}
.telemetry-block{{margin-top:14px;padding-top:14px;border-top:1px solid var(--border);font-size:12px;color:var(--text-muted);display:flex;flex-direction:column;gap:4px;}}
.telemetry-block strong{{color:var(--text);font-weight:500;}}
.policy-grid{{display:grid;grid-template-columns:repeat(7,minmax(0,1fr));gap:8px;margin-top:14px;}}
.policy-pill{{border:1px solid var(--border);background:var(--bg-inset);border-radius:var(--rs);padding:10px 12px;display:flex;flex-direction:column;gap:3px;min-width:0;}}
.policy-pill span{{font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}
.policy-pill strong{{font-size:12px;color:var(--text);font-family:var(--mono);font-weight:700;white-space:nowrap;overflow:hidden;text-overflow:ellipsis;}}

/* Toolbar */
.toolbar{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;margin:32px 0 20px;padding:14px 18px;background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);}}
.toolbar-spacer{{flex:1;}}
input[type="text"]{{background:var(--bg-inset);border:1px solid var(--border);color:var(--text);border-radius:var(--rs);padding:7px 12px;font-size:13px;outline:none;font-family:var(--sans);width:240px;transition:border-color .15s;}}
input[type="text"]:focus{{border-color:var(--border-hi);}}
input[type="text"]::placeholder{{color:var(--text-dim);}}
select{{background:var(--bg-inset);border:1px solid var(--border);color:var(--text);border-radius:var(--rs);padding:7px 12px;font-size:13px;outline:none;font-family:var(--sans);cursor:pointer;transition:border-color .15s;}}
select:focus{{border-color:var(--border-hi);}}
button{{background:var(--bg-hover);border:1px solid var(--border);color:var(--text-muted);padding:7px 14px;border-radius:var(--rs);font-weight:500;font-size:12.5px;cursor:pointer;transition:all .15s;font-family:var(--sans);white-space:nowrap;}}
button:hover{{background:var(--bg-card);border-color:var(--border-hi);color:var(--text);}}
button:focus-visible{{outline:2px solid var(--border-hi);outline-offset:2px;}}
button.btn-primary{{background:var(--accent);color:var(--accent-text);border-color:var(--accent);font-weight:600;}}
button.btn-primary:hover{{opacity:.88;}}
button.btn-sm{{padding:5px 11px;font-size:12px;}}
button.btn-outline{{border-color:var(--border-hi);}}

/* Table */
.table-wrap{{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;margin-bottom:32px;}}
.table-head{{display:flex;align-items:center;justify-content:space-between;padding:16px 22px;border-bottom:1px solid var(--border);}}
.table-head h2{{font-size:14px;font-weight:600;letter-spacing:-.01em;}}
table{{width:100%;border-collapse:collapse;font-size:12.5px;}}
thead th{{background:var(--bg-inset);color:var(--text-muted);font-weight:600;font-size:11px;text-transform:uppercase;letter-spacing:.07em;padding:10px 18px;text-align:left;border-bottom:1px solid var(--border);white-space:nowrap;}}
tbody td{{padding:11px 18px;border-bottom:1px solid var(--border);vertical-align:middle;}}
tbody tr:last-child td{{border-bottom:none;}}
tbody tr:hover td{{background:var(--bg-hover);}}
.url-cell{{font-family:var(--mono);color:var(--text-muted);max-width:320px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.conf-cell{{display:flex;align-items:center;gap:8px;}}
.conf-bar-wrap{{width:60px;height:4px;background:var(--border);border-radius:999px;overflow:hidden;flex-shrink:0;}}
.conf-bar{{height:100%;background:var(--border-hi);border-radius:999px;}}
.conf-label{{font-family:var(--mono);color:var(--text-muted);font-size:12px;}}
.chain-step{{display:inline-block;font-size:10.5px;padding:1px 6px;border-radius:3px;margin-right:2px;font-family:var(--mono);}}
.chain-hit{{background:var(--safe-bg);color:var(--safe);}}
.chain-miss{{background:var(--bg-hover);color:var(--text-dim);}}

/* Vuln cards */
.vuln-list{{display:flex;flex-direction:column;gap:12px;margin-bottom:48px;}}
.vuln-card{{background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);overflow:hidden;transition:border-color .15s;}}
.vuln-card:hover{{border-color:var(--border-hi);}}
.vuln-card[data-severity="confirmed"]{{border-left:3px solid var(--crit);}}
.vuln-card[data-severity="potential"]{{border-left:3px solid var(--warn);}}
.vuln-card[data-severity="low"]{{border-left:3px solid var(--safe);}}
.vc-header{{display:flex;align-items:center;justify-content:space-between;gap:16px;padding:14px 20px;border-bottom:1px solid var(--border);}}
.vc-header-left{{display:flex;align-items:center;gap:10px;flex-wrap:wrap;}}
.vc-index{{font-family:var(--mono);font-size:12px;}}
.vc-type{{font-weight:600;font-size:14px;letter-spacing:-.01em;}}
.vc-header-right{{display:flex;align-items:center;gap:10px;flex-shrink:0;}}
.expl-label{{font-size:11px;color:var(--text-muted);white-space:nowrap;}}
.expl-bar-wrap{{width:80px;height:4px;background:var(--border);border-radius:999px;overflow:hidden;}}
.expl-bar{{height:100%;border-radius:999px;}}
.expl-num{{font-family:var(--mono);font-size:12px;color:var(--text-muted);}}
.vc-url{{padding:10px 20px;font-size:12.5px;color:var(--text-muted);border-bottom:1px solid var(--border);overflow:hidden;text-overflow:ellipsis;white-space:nowrap;}}
.vc-url a{{font-family:var(--mono);color:var(--text-muted);text-decoration:none;transition:color .15s;}}
.vc-url a:hover{{color:var(--text);}}
.vc-meta{{display:grid;grid-template-columns:100px 1fr 1fr;gap:0;border-bottom:1px solid var(--border);}}
.vc-meta-item{{padding:12px 20px;border-right:1px solid var(--border);display:flex;flex-direction:column;gap:4px;}}
.vc-meta-item:last-child{{border-right:none;}}
.meta-label{{font-size:10.5px;font-weight:600;text-transform:uppercase;letter-spacing:.07em;color:var(--text-muted);}}
.meta-val{{font-size:13px;}}
.chain-pill{{display:inline-block;font-size:10.5px;padding:2px 8px;border-radius:999px;margin-right:4px;font-family:var(--mono);font-weight:600;}}
.chain-pill-on{{background:var(--safe-bg);color:var(--safe);border:1px solid var(--safe-bdr);}}
.chain-pill-off{{background:var(--bg-inset);color:var(--text-dim);border:1px solid var(--border);}}
.browser-tag{{display:inline-block;font-size:11px;padding:2px 8px;border-radius:4px;margin-right:4px;font-family:var(--mono);}}
.browser-pass{{background:var(--safe-bg);color:var(--safe);}}
.browser-fail{{background:var(--bg-inset);color:var(--text-muted);}}
.browser-list{{display:flex;flex-wrap:wrap;gap:4px;align-items:center;}}
.triage-box{{padding:14px 20px;border-bottom:1px solid var(--border);background:linear-gradient(90deg,rgba(56,189,248,.08),transparent);font-size:13px;color:var(--text-muted);}}
.triage-title{{font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text);margin-bottom:4px;}}
.triage-path{{margin-top:7px;font-size:12px;}}
.explain-grid{{display:grid;grid-template-columns:repeat(3,1fr);gap:0;border-bottom:1px solid var(--border);background:#fff;}}
.explain-item{{padding:14px 20px;border-right:1px solid var(--border);}}
.explain-item:last-child{{border-right:none;}}
.explain-item span{{display:block;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:var(--text);margin-bottom:5px;}}
.explain-item p{{font-size:12.5px;color:var(--text-muted);line-height:1.55;}}
.vc-actions{{display:flex;gap:8px;flex-wrap:wrap;padding:12px 20px;border-bottom:1px solid var(--border);background:var(--bg-inset);}}
.vc-details{{border-bottom:1px solid var(--border);}}
.vc-details:last-child{{border-bottom:none;}}
.vc-details summary{{padding:11px 20px;cursor:pointer;font-size:12.5px;font-weight:600;color:var(--text-muted);user-select:none;list-style:none;display:flex;align-items:center;gap:8px;transition:color .15s,background .15s;}}
.vc-details summary::before{{content:'›';font-size:16px;transition:transform .2s;line-height:1;display:inline-block;}}
.vc-details[open] summary::before{{transform:rotate(90deg);}}
.vc-details summary:hover{{color:var(--text);background:var(--bg-hover);}}
.vc-details summary::-webkit-details-marker{{display:none;}}
.pre-wrap{{position:relative;background:#0f172a;border-top:1px solid var(--border);padding:16px 20px;margin:0;font-family:var(--mono);font-size:11.5px;overflow-x:auto;color:#dbeafe;}}
.pre-wrap pre{{white-space:pre-wrap;word-break:break-all;}}
.copy-btn{{position:absolute;top:10px;right:10px;padding:3px 9px;font-size:11px;}}
.vuln-hit{{background:rgba(248,113,113,.15);color:var(--crit);font-weight:700;padding:0 2px;border-radius:2px;}}
.repro-block{{padding:16px 20px;background:var(--bg-inset);border-top:1px solid var(--border);color:var(--text-muted);}}
.repro-block ol{{padding-left:20px;display:flex;flex-direction:column;gap:7px;}}
.repro-block li{{font-size:12.5px;}}
.replay-mini{{margin-top:14px;padding:12px;border:1px solid var(--border);border-radius:var(--rs);background:var(--bg-card);font-size:11.5px;display:flex;flex-direction:column;gap:4px;}}
.remediation-block{{padding:16px 20px;background:var(--bg-inset);border-top:1px solid var(--border);}}
.rem-meta{{display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;}}
.rem-tag{{font-size:11px;padding:2px 8px;border-radius:4px;background:var(--bg-hover);border:1px solid var(--border-hi);color:var(--text-muted);font-family:var(--mono);}}
.remediation-block ul{{list-style:none;display:flex;flex-direction:column;gap:6px;}}
.remediation-block li{{font-size:12.5px;color:var(--text-muted);padding-left:14px;position:relative;}}
.remediation-block li::before{{content:'▸';position:absolute;left:0;color:var(--text-dim);}}

/* Severity badges */
.sev-badge{{display:inline-flex;align-items:center;padding:2px 9px;border-radius:4px;font-size:10.5px;font-weight:700;text-transform:uppercase;letter-spacing:.06em;}}
.sev-confirmed{{background:var(--crit-bg);color:var(--crit);border:1px solid var(--crit-bdr);}}
.sev-potential{{background:var(--warn-bg);color:var(--warn);border:1px solid var(--warn-bdr);}}
.sev-low{{background:var(--safe-bg);color:var(--safe);border:1px solid var(--safe-bdr);}}
.prio-badge{{font-size:10.5px;font-family:var(--mono);font-weight:700;color:var(--text-muted);border:1px solid var(--border-hi);border-radius:4px;padding:1px 7px;}}

/* Scorer tier (high / medium / low / confirmed) */
.tier-pill{{display:inline-flex;align-items:center;margin-left:6px;padding:2px 10px;border-radius:999px;font-size:10px;font-weight:700;font-family:var(--mono);letter-spacing:.06em;text-transform:uppercase;border:1px solid var(--border-hi);}}
.tier-pill.tier-confirmed{{background:var(--crit-bg);color:var(--crit);border-color:var(--crit-bdr);}}
.tier-pill.tier-high{{background:rgba(251,113,133,.12);color:#fda4af;border-color:rgba(251,113,133,.35);}}
.tier-pill.tier-medium{{background:var(--warn-bg);color:var(--warn);border-color:var(--warn-bdr);}}
.tier-pill.tier-low{{background:var(--safe-bg);color:#6ee7b7;border-color:var(--safe-bdr);}}

/* Empty state */
.empty-state{{text-align:center;padding:60px 24px;color:var(--text-muted);background:var(--bg-card);border:1px solid var(--border);border-radius:var(--r);}}
.empty-icon{{font-size:32px;margin-bottom:12px;color:var(--safe);}}

/* Utils */
.dim{{color:var(--text-muted);}}
.mono{{font-family:var(--mono);}}

/* Modal */
.modal{{display:none;position:fixed;inset:0;background:rgba(0,0,0,.7);backdrop-filter:blur(6px);z-index:100;align-items:center;justify-content:center;padding:24px;}}
.modal.open{{display:flex;}}
.modal-box{{background:var(--bg-card);border:1px solid var(--border-hi);border-radius:var(--r);width:100%;max-width:720px;max-height:80vh;display:flex;flex-direction:column;box-shadow:0 32px 64px rgba(0,0,0,.6);}}
.modal-head{{padding:16px 22px;border-bottom:1px solid var(--border);display:flex;justify-content:space-between;align-items:center;}}
.modal-head h3{{font-size:14px;font-weight:600;}}
.modal-body{{padding:22px;overflow-y:auto;font-family:var(--mono);font-size:12.5px;white-space:pre-wrap;word-break:break-all;color:#a0aec0;}}

/* Footer */
.footer{{padding-top:24px;border-top:1px solid var(--border);text-align:center;color:var(--text-dim);font-size:12px;letter-spacing:.02em;}}

/* Responsive */
@media(max-width:1024px){{
  .kpi-grid{{grid-template-columns:repeat(2,1fr);}}
  .summary-grid{{grid-template-columns:repeat(2,1fr);}}
  .policy-grid{{grid-template-columns:repeat(3,1fr);}}
}}
@media(max-width:720px){{
  .kpi-grid,.summary-grid{{grid-template-columns:1fr;}}
  .policy-grid{{grid-template-columns:1fr;}}
  .vc-meta,.explain-grid{{grid-template-columns:1fr;}}
  .vc-meta-item{{border-right:none;border-bottom:1px solid var(--border);}}
  .vc-meta-item:last-child{{border-bottom:none;}}
  .explain-item{{border-right:none;border-bottom:1px solid var(--border);}}
  .explain-item:last-child{{border-bottom:none;}}
  .vc-header{{flex-wrap:wrap;}}
  .toolbar{{gap:8px;}}
  input[type="text"]{{width:100%;}}
}}
@media print{{
  .topbar,.toolbar{{display:none;}}
  .vuln-card{{break-inside:avoid;}}
}}
</style>
</head>
<body>

<nav class="topbar">
  <div class="topbar-brand">
    <span class="dot"></span>AKHA XSS Scanner
  </div>
  <div class="topbar-right">
    <span class="dim" style="font-size:12px;">{_esc(target)}</span>
    <span class="sev-badge sev-{_esc(topbar_badge_sev)}">{_esc(scan_mode.upper())}</span>
  </div>
</nav>

<div class="wrap">

  <header class="page-header">
    <h1>Security Analysis Report</h1>
    <div class="page-subtitle">
      <span class="mono">{_esc(target)}</span>
      <span class="sep">&bull;</span>
      <span>Generated {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}</span>
      <span class="sep">&bull;</span>
      <span>Duration: {_esc(duration_str)}</span>
      <span class="sep">&bull;</span>
      <span>Started: {_esc(start_str)}</span>
    </div>
  </header>

  <div class="section-label">Scan Statistics</div>
  <div class="kpi-grid">
    <div class="kpi-card">
      <div class="kpi-label">URLs Crawled</div>
      <div class="kpi-value">{_esc(stats.get('urls_crawled', 0))}</div>
      <div class="kpi-sep"></div>
      <div class="kpi-sub">Parameters found: <strong>{_esc(stats.get('params_found', 0))}</strong></div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">Payloads Tested</div>
      <div class="kpi-value">{_esc(stats.get('payloads_tested', 0))}</div>
      <div class="kpi-sep"></div>
      <div class="kpi-sub">Requests sent: <strong>{_esc(stats.get('requests_sent', 0))}</strong></div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">WAF</div>
      <div class="kpi-value" style="font-size:18px;margin-top:4px;">{_esc(waf_name)}</div>
      <div class="kpi-sep"></div>
      <div class="kpi-sub">CSP: <strong>{_esc(csp_status)}</strong></div>
    </div>
    <div class="kpi-card">
      <div class="kpi-label">OAST Callbacks</div>
      <div class="kpi-value">{oast_callbacks}</div>
      <div class="kpi-sep"></div>
      <div class="kpi-sub">Blind injections: <strong>{blind_injections}</strong></div>
    </div>
  </div>

  <div class="section-label">Executive Summary</div>
  <div class="summary-grid">
    <div class="card">
      <div class="kpi-label" style="margin-bottom:4px;">Total Findings</div>
      <div class="kpi-value" style="margin-bottom:0;">{total_vulns}</div>
      <div class="sev-row">
        <div class="sev-block confirmed">
          <div class="sev-num">{confirmed_count}</div>
          <div class="sev-name">Confirmed</div>
        </div>
        <div class="sev-block potential">
          <div class="sev-num">{potential_count}</div>
          <div class="sev-name">Potential</div>
        </div>
        <div class="sev-block low">
          <div class="sev-num">{low_count}</div>
          <div class="sev-name">Low</div>
        </div>
      </div>
    </div>
    <div class="card">
      <div class="kpi-label" style="margin-bottom:8px;">Global Risk Score</div>
      <div class="risk-num" style="color:{risk_color};">{risk_score}<span style="font-size:18px;color:var(--text-muted);">/100</span></div>
      <div class="progress-track">
        <div class="progress-fill" style="width:{risk_score}%;background:{risk_color};"></div>
      </div>
      <div class="risk-meta">
        <span>Avg Confidence: <strong>{avg_conf}%</strong></span>
        <span>Avg Exploitability: <strong>{avg_expl}</strong></span>
      </div>
    </div>
    <div class="card">
      <div class="kpi-label" style="margin-bottom:8px;">Attack Vectors</div>
      <div class="stat-row">
        <span class="dim">Top Parameter</span>
        <span class="stat-row-val mono">{_esc(top_param)} <span class="dim">({top_param_count})</span></span>
      </div>
      <div class="stat-row">
        <span class="dim">Reflection Hits</span>
        <span class="stat-row-val">{reflection_true}</span>
      </div>
      <div class="stat-row">
        <span class="dim">Execution Hits</span>
        <span class="stat-row-val">{execution_true}</span>
      </div>
      <div class="stat-row">
        <span class="dim">Blind Injections</span>
        <span class="stat-row-val">{blind_injections}</span>
      </div>
    </div>
  </div>

  <div class="card" style="margin-bottom:32px;">
    <div class="kpi-label" style="margin-bottom:12px;">Smart Insights</div>
    <div class="insight-list">{insights_html}</div>
    <div class="telemetry-block">
      <div><strong>Telemetry</strong>&nbsp;{_esc(telemetry_summary)}</div>
      <div><strong>Learning</strong>&nbsp;Failure reasons: {_esc(failure_summary)}</div>
      {module_row}
    </div>
    <div class="kpi-label" style="margin:16px 0 8px;">Scan Policy</div>
    <div class="policy-grid">{policy_rows}</div>
  </div>

  <div class="table-wrap">
    <div class="table-head">
      <h2>Phase Timeline</h2>
      <span class="dim" style="font-size:12px;">Runtime distribution by scanner stage</span>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th>Phase</th>
            <th style="width:90px;">Runs</th>
            <th style="width:130px;">Duration</th>
            <th style="width:90px;">Errors</th>
          </tr>
        </thead>
        <tbody>{timeline_table}</tbody>
      </table>
    </div>
  </div>

  <div class="toolbar">
    <input id="vulnSearch" type="text" placeholder="Search parameters, URLs, payloads&hellip;" oninput="applyFilters()">
    <select id="severityFilter" onchange="applyFilters()">
      <option value="all">All Severities</option>
      <option value="confirmed">Confirmed</option>
      <option value="potential">Potential</option>
      <option value="low">Low</option>
    </select>
    <select id="sortBy" onchange="applySort()">
      <option value="severity">Sort: Priority</option>
      <option value="exploitability">Sort: Exploitability</option>
      <option value="confidence">Sort: Confidence</option>
    </select>
    <button onclick="toggleAllDetails(true)">Expand All</button>
    <button onclick="toggleAllDetails(false)">Collapse All</button>
    <div class="toolbar-spacer"></div>
    <button onclick="downloadJson()">&#11015; Export JSON</button>
    <button class="btn-primary" onclick="window.print()">&#128438; Export PDF</button>
  </div>

  <div class="table-wrap">
    <div class="table-head">
      <h2>Prioritized Action Items</h2>
      <span class="dim" style="font-size:12px;">Top findings by risk</span>
    </div>
    <div style="overflow-x:auto;">
      <table>
        <thead>
          <tr>
            <th style="width:40px;">#</th>
            <th style="width:110px;">Severity</th>
            <th style="width:130px;">Parameter</th>
            <th>URL</th>
            <th style="width:120px;">Confidence</th>
          </tr>
        </thead>
        <tbody>{fix_first_rows}</tbody>
      </table>
    </div>
  </div>

  {blind_section}

  <div class="section-label">Detailed Findings ({total_vulns})</div>
  <div class="vuln-list" id="vulnList">{vuln_cards}</div>

  <footer class="footer">
    AKHA XSS Security Scanner &bull; Automated Analysis Dashboard &bull; {datetime.now(timezone.utc).strftime('%Y-%m-%d')}
  </footer>

</div>

<div class="modal" id="payloadModal">
  <div class="modal-box">
    <div class="modal-head">
      <h3>Payload Preview</h3>
      <button onclick="closePayloadModal()">&#10005; Close</button>
    </div>
    <div class="modal-body" id="payloadModalContent"></div>
  </div>
</div>

<script id="report-json" type="application/json">{report_json}</script>
<script>
function copyText(value) {{
  if (!value) return;
  navigator.clipboard.writeText(value).catch(function() {{}});
}}
function openPoc(value) {{
  if (!value) return;
  var text = String(value || '').trim();
  if (!/^https?:\\/\\//i.test(text)) return;
  window.open(text, '_blank', 'noopener,noreferrer');
}}
function copyFromPre(btn) {{
  var pre = btn.nextElementSibling;
  if (!pre || pre.tagName !== 'PRE') {{
    var wrap = btn.closest('.pre-wrap');
    if (wrap) pre = wrap.querySelector('pre') || wrap;
  }}
  if (pre) copyText(pre.innerText || '');
  var old = btn.innerText;
  btn.innerText = 'Copied!';
  setTimeout(function() {{ btn.innerText = old; }}, 1500);
}}
function previewPayload(payload) {{
  var modal = document.getElementById('payloadModal');
  var body = document.getElementById('payloadModalContent');
  body.textContent = payload || '';
  modal.classList.add('open');
  document.body.style.overflow = 'hidden';
}}
function closePayloadModal() {{
  document.getElementById('payloadModal').classList.remove('open');
  document.body.style.overflow = '';
}}
document.getElementById('payloadModal').addEventListener('click', function(e) {{
  if (e.target.id === 'payloadModal') closePayloadModal();
}});
function applyFilters() {{
  var q = (document.getElementById('vulnSearch').value || '').trim().toLowerCase();
  var sev = (document.getElementById('severityFilter').value || 'all').toLowerCase();
  var cards = document.querySelectorAll('.vuln-card');
  cards.forEach(function(card) {{
    var severity = (card.getAttribute('data-severity') || '').toLowerCase();
    var text = (card.getAttribute('data-search') || '').toLowerCase();
    var sevOk = sev === 'all' || severity === sev;
    var textOk = !q || text.indexOf(q) !== -1;
    card.style.display = (sevOk && textOk) ? '' : 'none';
  }});
}}
function applySort() {{
  var sortBy = (document.getElementById('sortBy').value || 'severity');
  var container = document.getElementById('vulnList');
  var cards = Array.prototype.slice.call(container.querySelectorAll('.vuln-card'));
  cards.sort(function(a, b) {{
    if (sortBy === 'confidence') {{
      return parseInt(b.getAttribute('data-confidence') || '0', 10) - parseInt(a.getAttribute('data-confidence') || '0', 10);
    }}
    if (sortBy === 'exploitability') {{
      return parseInt(b.getAttribute('data-exploitability') || '0', 10) - parseInt(a.getAttribute('data-exploitability') || '0', 10);
    }}
    return parseInt(a.getAttribute('data-severity-rank') || '9', 10) - parseInt(b.getAttribute('data-severity-rank') || '9', 10);
  }});
  cards.forEach(function(card) {{ container.appendChild(card); }});
  applyFilters();
}}
function toggleAllDetails(state) {{
  document.querySelectorAll('.vuln-card details').forEach(function(item) {{
    item.open = !!state;
  }});
}}
function downloadJson() {{
  try {{
    var raw = document.getElementById('report-json').textContent || '{{}}';
    var blob = new Blob([raw], {{ type: 'application/json' }});
    var url = URL.createObjectURL(blob);
    var a = document.createElement('a');
    a.href = url;
    a.download = 'akha_report_export.json';
    document.body.appendChild(a);
    a.click();
    a.remove();
    URL.revokeObjectURL(url);
  }} catch (e) {{}}
}}
</script>
</body>
</html>"""

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html_content)

        return filepath
