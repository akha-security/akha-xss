# Changelog

## 1.0.0

- Added Playwright-backed browser verification support as a required dependency.
- Added modern HTML and JSON reports with triage summaries, reproduction steps, remediation guidance, CWE/OWASP mapping, and CVSS-like prioritization.
- Added WAF-aware cautious mode for slower, protected production targets.
- Added real scan profiles: `quick`, `balanced`, and `deep`.
- Added `doctor` and `presets` CLI commands.
- Added Windows setup scripts.
- Added proxy TLS fallback control with explicit `--allow-ssl-fallback`.
- Added task queue, budget fallback, resume checkpoints, and scope guardrails for long scans.
