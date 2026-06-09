# Example Report Snapshot

This is a shortened, sanitized example of the fields AKHA includes in HTML and JSON reports.

## Executive Summary

- Target: `https://example.test`
- Profile: `quick`
- WAF cautious mode: `yes`
- Duration: `38.2s`
- URLs crawled: `42`
- Parameters discovered: `18`
- Findings: `1 confirmed`, `2 potential`, `0 low`

## Finding Example

| Field | Example |
| --- | --- |
| Type | Reflected XSS |
| Severity | Confirmed |
| Confidence | 95% |
| Exploitability | 91 |
| CVSS-like | 9.4/10 |
| CWE | CWE-79 |
| OWASP | A03:2021-Injection |
| Parameter | `q` |

## Triage Fields

- Description: User input is reflected into a risky browser context.
- Impact: Browser execution may allow account actions as the victim, phishing overlays, or sensitive data exposure depending on privileges.
- Recommendation: Apply context-aware output encoding at the sink and avoid rendering untrusted input as executable markup.
- Evidence chain: `probe -> reflection -> verification -> execution`
- Reproduction steps: Open the proof URL, replay the captured request, and verify the browser/runtime proof.

## Runtime Context

Reports also include:

- Scan policy: profile, auto WAF cautious status, page cap, payload caps, threads, and rate limit.
- Phase timeline: WAF detection, CSP analysis, crawling, parameter discovery, XSS testing, and report generation timings.
- Request and response evidence with highlighted payload hits.
- Browser verification matrix when Playwright validation is enabled.
