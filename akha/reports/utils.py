"""
Shared triage utilities for HTML and JSON report generators.

These functions enrich vulnerability findings with evidence chains,
framework-specific hints, remediation priorities, and human-readable
summaries.  Both ``html_generator`` and ``json_generator`` import from
here so the scoring / triage logic lives in a single place.
"""

from typing import Dict, List


# ── evidence chain ─────────────────────────────────────────────────

def with_evidence_chain(v: Dict) -> Dict:
    """Attach a four-stage evidence chain to a vulnerability dict."""
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


# ── remediation priority ───────────────────────────────────────────

def remediation_priority(vuln: Dict) -> str:
    """Return a P1–P4 priority label based on severity and confidence."""
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


# ── exploit path ───────────────────────────────────────────────────

def exploit_path(vuln: Dict) -> str:
    """Render evidence chain as a human-readable path string."""
    chain = vuln.get("evidence_chain", {}) or {}
    bits = [
        "probe" if chain.get("probe") else "-probe",
        "reflection" if chain.get("reflection") else "-reflection",
        "verification" if chain.get("verification") else "-verification",
        "execution" if chain.get("execution") else "-execution",
    ]
    return " -> ".join(bits)


# ── framework hints ───────────────────────────────────────────────

_GUIDANCE_MAP = {
    "react": [
        "Avoid dangerouslySetInnerHTML for untrusted data.",
        "Encode user-controlled values before HTML sinks.",
        "Prefer component rendering over raw HTML insertion.",
    ],
    "django": [
        "Keep autoescape enabled in templates.",
        "Use |escape for user-controlled template variables.",
        "Avoid marking untrusted data as safe.",
    ],
    "laravel": [
        "Use escaped blade output {{ $var }} for untrusted data.",
        "Restrict raw output {!! $var !!} to trusted HTML only.",
        "Validate and normalize request input before rendering.",
    ],
    "api": [
        "Apply output encoding in frontend render path for API fields.",
        "Validate and sanitize high-risk text fields server-side.",
        "Adopt strict content-type and CSP where applicable.",
    ],
    "wordpress": [
        "Use esc_html/esc_attr/esc_url in templates.",
        "Validate shortcode/widget inputs before render.",
        "Avoid direct echo of request parameters.",
    ],
}

_DEFAULT_GUIDANCE = [
    "Apply context-aware output encoding at sink.",
    "Validate and canonicalize untrusted input.",
    "Use CSP and avoid dangerous DOM APIs for user data.",
]


def framework_hints(vuln: Dict) -> Dict:
    """Suggest framework-specific remediation hints from URL/context cues."""
    url = str(vuln.get("url", "") or "").lower()
    context = vuln.get("context", {}) or {}
    ctype = str(context.get("Type", "") or context.get("Location", "") or "").lower()
    param = str(vuln.get("parameter", "") or "").lower()

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
        "guidance": _GUIDANCE_MAP.get(framework, _DEFAULT_GUIDANCE),
    }


# ── triage summary ────────────────────────────────────────────────

def triage_summary(vuln: Dict) -> str:
    """One-line natural-language summary of a finding."""
    vuln_type = str(vuln.get("type", "xss")).replace("_", " ").upper()
    parameter = vuln.get("parameter") or "unknown"
    confidence = vuln.get("confidence", 0)
    severity = str(vuln.get("severity_level", "potential")).lower()
    chain = vuln.get("evidence_chain", {}) or {}
    execution = "execution observed" if chain.get("execution") else "execution not confirmed"
    return (
        f"{vuln_type} on parameter '{parameter}' is ranked {severity} "
        f"with {confidence}% confidence; {execution}."
    )


# ── finding description ──────────────────────────────────────────

def finding_description(vuln: Dict) -> str:
    """Context-aware description paragraph for a finding."""
    vuln_type = str(vuln.get("type", "xss")).lower()
    parameter = vuln.get("parameter") or "the affected input"
    if "dom" in vuln_type:
        return (
            f"User-controlled data reaches a browser-side sink through {parameter}. "
            "The finding should be reviewed as a client-side execution path."
        )
    if "stored" in vuln_type:
        return (
            f"Input submitted through {parameter} appears to persist and reappear later. "
            "Stored payloads can affect other users who view the vulnerable page."
        )
    if "blind" in vuln_type:
        return (
            "An out-of-band callback was observed, which means the payload was processed "
            "outside the immediate HTTP response path."
        )
    return (
        f"The application reflects input from {parameter} into the response in a risky context. "
        "If a browser can execute the reflected payload, an attacker may run JavaScript as the victim."
    )


# ── impact summary ───────────────────────────────────────────────

def impact_summary(vuln: Dict) -> str:
    """Describe the potential impact of a finding."""
    chain = vuln.get("evidence_chain", {}) or {}
    severity = str(vuln.get("severity_level", "potential")).lower()
    if chain.get("execution") or severity == "confirmed":
        return (
            "Confirmed browser execution can enable session theft, account actions as the victim, "
            "phishing overlays, or data exposure depending on application privileges."
        )
    if chain.get("reflection"):
        return (
            "The payload is reflected or reaches a risky sink, but execution is not fully proven. "
            "Treat this as a prioritized review item and confirm exploitability manually."
        )
    return "The evidence is limited. Use the captured request and proof fields to validate real-world impact."


# ── primary recommendation ───────────────────────────────────────

def primary_recommendation(vuln: Dict) -> str:
    """Return the single most important remediation action."""
    hints = vuln.get("framework_hints", {}) or {}
    guidance = hints.get("guidance", []) or []
    if guidance:
        return str(guidance[0])
    return "Apply context-aware output encoding and avoid rendering untrusted input as executable markup."


def classification(vuln: Dict) -> Dict:
    """Return stable CWE/OWASP taxonomy metadata for report consumers."""
    vuln_type = str(vuln.get("type", "xss")).lower()
    if "xss" in vuln_type or "dom" in vuln_type:
        return {
            "cwe": "CWE-79",
            "owasp": "A03:2021-Injection",
            "category": "Cross-Site Scripting",
        }
    return {
        "cwe": "CWE-20",
        "owasp": "A03:2021-Injection",
        "category": "Input Validation",
    }


def cvss_like_score(vuln: Dict) -> float:
    """Small CVSS-like 0.0-10.0 score for prioritization without claiming formal CVSS."""
    confidence = int(vuln.get("confidence", 0) or 0)
    exploitability = int(vuln.get("exploitability_score", 0) or 0)
    severity = str(vuln.get("severity_level", "potential")).lower()
    base = (confidence * 0.04) + (exploitability * 0.05)
    if severity == "confirmed":
        base += 1.0
    elif severity == "potential":
        base += 0.4
    return round(max(0.0, min(10.0, base)), 1)


# ── reproduction steps ───────────────────────────────────────────

def reproduction_steps(vuln: Dict) -> List[str]:
    """Build ordered reproduction steps from finding evidence."""
    steps = []
    target = vuln.get("test_url") or vuln.get("url")
    payload = vuln.get("payload")
    parameter = vuln.get("parameter")
    if target:
        steps.append(f"Open or request the proof URL: {target}")
    if parameter and payload:
        steps.append(f"Inject the payload into parameter '{parameter}': {payload}")
    if vuln.get("request"):
        steps.append("Replay the captured HTTP request from the report evidence.")
    if vuln.get("validated"):
        steps.append("Confirm the browser/runtime validation proof shown in the finding.")
    else:
        steps.append("Manually verify execution in a browser before treating it as confirmed.")
    return steps


# ── composite enrichment ─────────────────────────────────────────

def with_triage_context(v: Dict) -> Dict:
    """Enrich a vulnerability dict with all triage fields."""
    out = with_evidence_chain(v)
    out.setdefault("remediation_priority", remediation_priority(out))
    out.setdefault("exploit_path", exploit_path(out))
    out.setdefault("framework_hints", framework_hints(out))
    out.setdefault("triage_summary", triage_summary(out))
    out.setdefault("description", finding_description(out))
    out.setdefault("impact", impact_summary(out))
    out.setdefault("primary_recommendation", primary_recommendation(out))
    out.setdefault("classification", classification(out))
    out.setdefault("cvss_like_score", cvss_like_score(out))
    out.setdefault("reproduction_steps", reproduction_steps(out))
    return out
