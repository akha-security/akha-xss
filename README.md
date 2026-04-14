<div align="center">
<img width="1408" height="768" alt="banner" src="https://github.com/user-attachments/assets/c416f11f-282d-42fc-a67c-d5cbc361ce97" />

  <br/>
  
  <h1>🎯 AKHA XSS Scanner</h1>
  <p><strong>AKHA-XSS Detection Framework</strong></p>
  <p>
    Engineered for security researchers, bug bounty hunters, and DevSecOps pipelines. AKHA delivers high-impact Cross-Site Scripting (XSS) vulnerability detection with a near-zero false positive rate, backed by headless browser verification and intelligent payload mutators.
  </p>

  <p>
    <a href="#features">Features</a> •
    <a href="#adaptive-payload-learning-why-akha-is-different">Adaptive Learning</a> •
    <a href="#how-it-works">How It Works</a> •
    <a href="#installation">Installation</a> •
    <a href="#usage-guide">Usage</a> •
    <a href="#architecture">Architecture</a> •
    <a href="README-TR.md">🇹🇷 Türkçe (Turkish)</a>
  </p>
</div>

---

## 📖 Overview

Traditional static XSS scanners blindly spray massive, noisy payload lists against every endpoint, leading to IP bans, corrupted databases, and a frustrating barrage of false positives. 

**AKHA takes a radically different approach.** Operating like an automated Application Security Engineer, AKHA employs a **Probe-First Methodology**. Before attempting any exploit, it sends highly specific, harmless canary probes to dynamically analyze the application's behavior, identify the exact rendering context (e.g., HTML, attribute, JavaScript, CSS), and map out the active Web Application Firewalls (WAF) or sanitization rules. 

Only after fully understanding the target's defense mechanisms does AKHA generate and deploy a minimal, laser-focused set of context-specific payloads.

---

## ✨ Features at a Glance

### 🔍 Advanced Detection & Modern Attack Surfaces
- **Reflected & Stored XSS:** Intelligent state tracking to catch persistent vulnerabilities across complex application flows.
- **Deep DOM-Based Analysis:** Traces user input through client-side sinks to identify DOM execution flaws.
- **Out-of-Band (Blind) XSS:** Native integration with OAST services (like Burp Collaborator or custom setups) for delayed execution detection.
- **Framework-Specific Sinks:** Built-in checks for **AngularJS CSTI** (Client-Side Template Injection).
- **Modern Paradigms:** Dedicated scanners for **GraphQL** endpoints, **WebSockets**, and **Mutation XSS (mXSS)** anomalies.

### 🧠 Smart Parameter Discovery
- **Arjun-Inspired Differential Fuzzing:** Does not rely solely on static wordlists. It builds baseline response models and uses differential batch-testing to uncover hidden parameters.
- **Multi-Vector Injection:** Simultaneously tests GET/POST parameters, RESTful path segments, HTTP Headers, and Cookies.

### 🛡️ Enterprise & DevSecOps Ready
- **Validation via Browser Engine:** Integrates with Playwright (Headless Chromium) to strictly execute payloads and capture actual `alert` events, guaranteeing a 0% false positive rate on "Confirmed" findings.
- **Adaptive Rate Limiting:** Automatically throttles concurrency when catching HTTP 429/503 responses, seamlessly bypassing aggressive rate-limiters.
- **Seamless Integrations:** Output findings directly to JSON for CI/CD pipelines, generate beautiful HTML reports, or push real-time alerts via Webhooks (Discord, Slack, Telegram).
- **Session Resumption:** Interrupted scans can be resumed exactly where they stopped, preventing wasted time on massive scopes.

### 🌐 Dynamic SPA Crawling (Playwright-Powered)
- **JavaScript-Rendered Discovery:** Automatically spins up a headless Chromium browser to navigate and discover endpoints hidden behind React, Vue, Angular, and other SPA frameworks — links that traditional HTML parsers can never see.
- **Enabled by default** for every scan. Disable with `--no-dynamic` if you only need static crawling.

### ⚡ Async Batch HTTP Engine (httpx)
- **High-Performance Networking:** Uses `httpx.AsyncClient` under the hood to fire concurrent requests through a single event loop, achieving speeds comparable to Go-based tools like Dalfox.
- **Automatic Fallback:** If `httpx` is not installed, the engine gracefully falls back to threaded `requests` — no crashes, no configuration needed.

### 🔄 Smart Session & Auth Management
- **Auto Re-Authentication:** When long-running scans encounter session expiration (HTTP 401/403), AKHA automatically re-logs in using the configured `--auth-url` credentials and resumes scanning without losing progress.
- **Thread-Safe:** Uses locking to prevent parallel re-login storms across concurrent workers.

### 🔀 IP Rotation & Proxy Pool
- **Round-Robin Proxy Rotation:** Feed AKHA a list of proxies via `--proxy-list proxies.txt` and it will automatically rotate through them on each request.
- **Auto-Ban & Recovery:** Proxies that fail consecutively are temporarily banned. When a 429/503 rate-limit is detected, AKHA instantly rotates to the next healthy proxy.

### 🕵️ Built-in Blind XSS OAST (Interactsh)
- **Zero-Config OAST:** Use `--oast` to automatically register with an Interactsh server, generate unique callback URLs, and inject them as Blind XSS payloads.
- **Real-Time Alerts:** A background polling thread watches for DNS/HTTP callbacks and instantly prints a red alert in your terminal the moment a Blind XSS fires — even hours or days later.
- **Report Integration:** All captured OAST callbacks are automatically included in the final scan report.

---

## 🧠 Adaptive Payload Learning (Why AKHA Is Different)

Most scanners treat payloads as a static list. AKHA does not.

AKHA continuously learns from real scan outcomes and keeps a running payload performance memory in `data/learning/payload_stats.json`.
For each payload, it tracks:

- `success_count`: How often the payload led to a validated finding.
- `fail_count`: How often it failed to produce a valid result.
- `waf_blocked`: How often it appeared to be blocked by a WAF.

This feeds a Bayesian-style score (with smoothing and WAF penalty) so payloads are ranked by practical effectiveness instead of static ordering.

AKHA also uses a UCB-style strategy to balance:

- **Exploitation:** Prefer payloads that already perform well in similar contexts.
- **Exploration:** Still try under-tested payloads to discover new bypass opportunities.

Result in practice:

- Fewer wasted requests
- Faster convergence on working payload families
- Better behavior against WAF-heavy targets
- Smarter scans over time per domain/context, not just per run

---

## 🧠 Deep Dive: How AKHA Works (The Pipeline)

The true differentiator of AKHA is its execution pipeline. For every discovered endpoint and parameter, AKHA follows the same deterministic workflow:

### 1. 🐣 Canary Probing
AKHA injects a unique, harmless alphanumeric string (e.g., `akhaPROBE123`) alongside a battery of special characters (`<`, `>`, `"`, `'`, `/`, `(`, `)`). It then analyzes the HTTP response to determine if the input is reflected, and specifically, *where* it is reflected.

### 2. 🧩 Context Mapping
Reflection isn't enough. AKHA parses the DOM to categorize the exact injection sink:
* **HTML Body:** `<div>[PROBE]</div>`
* **HTML Attribute:** `<input value="[PROBE]">`
* **JavaScript Context:** `<script>var x = "[PROBE]";</script>`
* **CSS Context:** `<style>body { color: [PROBE]; }</style>`
* **URL/Action Context:** `<a href="[PROBE]">`

### 3. 🛡️ Sanitization & WAF Profiling
By checking which special characters from the probe survived, which were URL/HTML encoded, and which were entirely stripped, AKHA builds a real-time sanitization profile. It knows immediately if `<` is filtered but `"` is allowed.

### 4. 🧮 Smart Payload Generation
AKHA references its payload database and applies **Adaptive Payload Intelligence**. If the context is JS and `"` is blocked but `'` is allowed, it dynamically generates a payload like `'-alert(1)-'`. It leverages UCB (Upper Confidence Bound) algorithms to select payloads historically known to bypass similar contexts or identified WAFs (e.g., Cloudflare, Akamai).

### 5. 🎯 Multi-Stage Verification
When a payload reflects, AKHA verifies execution potential:
* **Marker Trace:** Checks for deterministic payload markers in the parsed DOM.
* **Raw Reflection Match:** Ensures the critical execution characters bypassed encoding.
* **Browser Emulation:** If configured, the engine spins up Chromium, injects the payload, and listens for the `alert()` event loop.

### 6. ⚖️ Confidence Scoring
Findings are assigned a sophisticated **Confidence Score (0-100%)** based on the cryptographic traces left during verification.

| Score | Severity | Description |
| :--- | :--- | :--- |
| **80 - 100%** | **Confirmed** | Absolute proof of execution. Validated via Headless Browser or flawless unencoded DOM parsing. |
| **50 - 79%** | **Potential** | Strong reflection in a dangerous context, but execution couldn't be automatically triggered. High priority for manual review. |
| **0 - 49%** | **Low** | Weak or partial reflection. Likely mitigated by framework encoding, but worth logging. |

---

## ⚙️ Installation

### Prerequisites
- Python 3.9+
- pip

### Standard Installation
Recommended for fast, CLI-based CI/CD environments.
```bash
git clone https://github.com/akha-security/akha-xss.git
cd akha-xss
pip install -e .
```

### 🏆 Full Installation (Recommended)
This includes Playwright requirements, enabling the zero-false-positive Execution Verifier.
```bash
pip install -e .[browser]
playwright install chromium
```

---

## 🚀 Usage Guide

Invoke the tool via the `akha-xss` command. 

### Basic Scanning
```bash
# Rapid test against a single target
akha-xss scan --url https://domain.com

# Test multiple targets from a file
akha-xss scan --file targets.txt
```

### Scan Profiles (Depth vs Speed)
Control how aggressively AKHA fuzzes for parameters and how many payload variants it tries.
```bash
# 🏎️ Quick: Minimal fuzzing, highly targeted payloads. Best for initial triage.
akha-xss scan --url https://domain.com --profile quick

# ⚖️ Balanced (Default): The sweet spot between deep discovery and scan duration.
akha-xss scan --url https://domain.com --profile balanced

# 🕵️ Deep: Exhaustive parameter discovery and heavy payload mutation.
akha-xss scan --url https://domain.com --profile deep

# 💥 Aggressive: Maximize threads, disable SSL checks, target everything
akha-xss scan --url https://domain.com --deep-scan --aggressive
```

### Authentication & Headers
```bash
# Cookie-based authentication
akha-xss scan --url https://domain.com --cookie "SESSIONID=xyz123; UID=99"

# Bearer Token
akha-xss scan --url https://domain.com --bearer-token "eyJhbGci..."

# Custom Headers
akha-xss scan --url https://domain.com -H "X-Custom-Auth: supersecret"
```

### Auth Plugin Integration Guide

Use auth plugins when simple `--auth-url` + `--auth-data` is not enough.

- `csrf-preflight`: Best for classic form logins where CSRF tokens are dynamic per request.
- `bearer-refresh`: Best for API sessions where access tokens expire and must be refreshed.

Recommended flow:
1. Start with plain auth flags (`--auth-url`, `--auth-data`, `--cookie`, `--bearer-token`).
2. If login succeeds once but later fails with 401/403, enable `--auth-plugin`.
3. Add plugin options via `--auth-plugin-options` and tune only required fields.

Example (CSRF form login):
```bash
akha-xss scan --url https://domain.com \
  --auth-url https://domain.com/login \
  --auth-data '{"username":"admin","password":"pass"}' \
  --auth-plugin csrf-preflight \
  --auth-plugin-options '{"preflight_url":"https://domain.com/login","token_fields":["csrf_token","_token"]}'
```

Example (Bearer refresh flow):
```bash
akha-xss scan --url https://api.domain.com \
  --bearer-token "eyJhbGci..." \
  --auth-plugin bearer-refresh \
  --auth-plugin-options '{"refresh_url":"https://api.domain.com/auth/refresh","payload_json":{"refresh_token":"xyz"}}'
```

Operational tips:
- Keep `--no-reauth` disabled when using auth plugins.
- Prefer the smallest possible plugin options payload to avoid login drift.
- Validate auth lifecycle in JSON report `auth` section (`reauth_count`, `auth_failures`, `last_event`).

Quick troubleshooting:
- Symptom: Login fails on first attempt.
  Fix: Use `csrf-preflight` and set accurate CSRF field names via `token_fields`.
- Symptom: Scan repeatedly hits 401/403 mid-run.
  Fix: Enable `bearer-refresh` and provide `refresh_url` with refresh payload.
- Symptom: Plugin is enabled but reauth never increments.
  Fix: Check JSON report `auth.last_event` to verify plugin reason/details.

### Scope & Filtering
Prevent the crawler from falling into logout URLs or administrative black holes.
```bash
akha-xss scan --url https://domain.com \
              --include "/api/v1/.*" \
              --exclude "/logout" --exclude "/admin/.*"
```

### Module Toggling
Customize the attack surface.
```bash
# Force API mode (Focus on POST bodies, JSON payloads, headers)
akha-xss scan --url https://api.domain.com --api-mode --test-post

# Enable WebSockets & Headers, Disable heavy DOM checks
akha-xss scan --url https://domain.com --websockets --test-headers --no-dom-xss
```

### Blind XSS Configuration
Automatically inject OAST payloads that will ping you back if a staff member triggers the XSS weeks later in an admin panel.
```bash
# Use your own collaborator / XSS Hunter URL
akha-xss scan --url https://domain.com --blind-xss-url https://your-id.oastify.com

# Or use the built-in Interactsh OAST client (zero configuration needed)
akha-xss scan --url https://domain.com --oast
```

### Proxy Rotation & Stealth
Avoid IP bans and WAF rate-limits by rotating through a pool of proxies.
```bash
# Single proxy (e.g., Burp Suite)
akha-xss scan --url https://domain.com --proxy http://127.0.0.1:8080

# Proxy pool rotation (one URL per line in the file)
akha-xss scan --url https://domain.com --proxy-list proxies.txt
```

### Session Management
```bash
# Auto re-login when session expires during long scans
akha-xss scan --url https://domain.com \
              --auth-url https://domain.com/login \
              --auth-data '{"username": "admin", "password": "pass"}'

# Disable auto re-authentication if needed
akha-xss scan --url https://domain.com --no-reauth
```

### Reporting & Notifications
```bash
# Output JSON for vulnerability management platforms
akha-xss scan --url https://domain.com --format json --json-output results.json

# Fire a Discord webhook when a High Confidence finding is hit
akha-xss scan --url https://domain.com \
              --webhook-url https://discord.com/api/webhooks/your-hook \
              --webhook-platform discord
```

---

## 🚀 Core Capability Set

AKHA ships with a complete adaptive scanning stack by default.

### Verification and Evidence Quality
- **Structural DOM evidence** and **reproducibility ratio** are part of confidence scoring.
- **Exploitability score** is reported alongside confidence for practical triage.
- **Multi-browser execution verification** supports Firefox in addition to Chromium.
- Findings include a **browser evidence matrix** for execution visibility.

### Discovery and Prioritization
- **Risk-based endpoint prioritization** guides crawl and discovery order.
- **Canonical deduplication** merges semantically equivalent endpoints.
- **Stateful SPA discovery** runs with bounded transition budgets.
- **Discovery profiles** are available (`auto`, `anonymous`, `authenticated`, `admin`).

### WAF and Traffic Adaptation
- **Per-host** and **per-path** throttling run on top of global limits.
- Proxy pools support **quarantine + cooldown recovery** lifecycle.
- **Challenge-aware target backoff** applies adaptive penalties.
- **Endpoint-class backoff profiles** are built-in (`default`, `api_read`, `api_write`, `auth`).
- Config/CLI supports optional backoff profile **overrides**.
- WAF detection exposes richer **confidence_score** and **evidence** structures.

### Payload Intelligence
- Learning tracks **failure taxonomy** (`blocked`, `encoded`, `stripped`, `inert`).
- Payload ranking uses **endpoint-profile-aware UCB** strategy.
- **Grammar-guided minimal payload generation** prefers short context-fit candidates.
- **Similarity-based warm start** reduces cold-start gaps across related surfaces.
- Learning exports aggregated **failure_reasons** for tuning.

### Performance, Scale, and Observability
- **Hard scan budgets** are available for duration, request count, and payload attempts.
- **Per-parameter** and **per-endpoint** payload caps are enforced.
- A **lease/ack distributed-ready task queue** model supports resumable worker scheduling.
- **Periodic resume checkpoints** are available for long-running scans.
- Reports include **HTTP telemetry** (latency percentiles, status buckets, pool utilization).
- **Budget-pressure auto-fallback** can disable optional heavy modules.
- Worker scheduling supports **dynamic task lease** and **retry-to-dead-letter** behavior.
- Reports include **module-level timing metrics**.

### Quality and Release Guardrails
- **Pipeline contract tests** validate analyzer/exploiter/reporter boundaries.
- **Golden target regression fixture** keeps report outputs stable.
- Reports include **evidence chain** fields (probe -> reflection -> verification -> execution).
- **Scope guardrails** protect safer full-scan defaults.
- `tools/quality_gate.py` provides CI quality gates against baseline reports.

### Key `scan --help` Options

```bash
# Verification
--execution-verify-firefox

# Authentication
--auth-plugin csrf-preflight
--auth-plugin-options '{"preflight_url":"https://domain.com/login"}'

# Discovery
--no-stateful-spa
--spa-state-budget 8
--discovery-profile auto
--no-risk-prioritization
--risk-top-k 300

# WAF and traffic adaptation
--no-per-host-rate-limit
--no-per-path-rate-limit
--path-rate-multiplier 0.75
--proxy-cooldown-seconds 60
--no-endpoint-backoff-profiles
--endpoint-backoff-overrides '{"auth": {"penalty_mult": 2.2}}'

# Payload intelligence
--no-payload-failure-taxonomy
--no-payload-context-bandit
--no-payload-minimal-grammar
--no-payload-similarity-warm-start
--ucb-exploration 1.4
--payload-context-weight 0.25
--payload-encoding-weight 0.15
--payload-waf-weight 0.10

# Budgets and scheduling
--max-scan-seconds 900
--max-requests 20000
--max-payloads 8000
--max-payloads-per-param 20
--max-payloads-per-endpoint 120
--task-lease-seconds 120
--task-worker-id worker-a
--no-distributed-task-queue
--resume-checkpoint-seconds 30
--no-dynamic-task-lease
--task-max-retries 3
--no-budget-auto-fallback
--budget-fallback-trigger 0.85

# Safety
--no-scope-guard
--scope-guard-max-pages 8000
```

### Example: Advanced Adaptive Scan

```bash
akha-xss scan --url https://domain.com \
  --profile deep \
  --execution-verify-firefox \
  --discovery-profile authenticated \
  --spa-state-budget 12 \
  --risk-top-k 500 \
  --path-rate-multiplier 0.6 \
  --proxy-cooldown-seconds 120 \
  --no-payload-context-bandit \
  --no-payload-similarity-warm-start \
  --max-scan-seconds 1800 \
  --max-requests 50000 \
  --resume-checkpoint-seconds 30 \
  --endpoint-backoff-overrides '{"auth":{"penalty_mult":2.4,"backoff_extra":6}}'

### CI Quality Gate Example

```bash
python tools/quality_gate.py \
  --baseline output/baseline_report.json \
  --current output/scan_report_latest.json \
  --max-duration-regression 20 \
  --max-request-regression 25 \
  --min-confirmed-ratio 40 \
  --max-p95-latency-regression 30 \
  --max-confirmed-ratio-drop 20
```

### Example: Auth Plugin Flow

```bash
# CSRF preflight-assisted login form authentication
akha-xss scan --url https://domain.com \
  --auth-url https://domain.com/login \
  --auth-data '{"username":"admin","password":"pass"}' \
  --auth-plugin csrf-preflight \
  --auth-plugin-options '{"preflight_url":"https://domain.com/login","token_fields":["csrf_token","_token"]}'

# Bearer token refresh plugin for API sessions
akha-xss scan --url https://api.domain.com \
  --bearer-token eyJhbGci... \
  --auth-plugin bearer-refresh \
  --auth-plugin-options '{"refresh_url":"https://api.domain.com/auth/refresh","payload_json":{"refresh_token":"xyz"}}'
```

---

## 🏛️ Architecture & Extensibility

AKHA is built with a strictly decoupled architecture, making it incredibly easy for security engineers to write custom modules.

* `akha.core`: Handles orchestration, distributed thread pools, the adaptive `HTTPClient` (with async httpx batch support, proxy rotation, and auto-reauth), and session persistence mechanics.
* `akha.modules.xss`: Contains the context-aware execution engines (`XSSEngine`, `Injector`, `SmartValidator`, `Verifier`).
* `akha.modules.interactsh_client`: Built-in Interactsh OAST client for automated Blind XSS callback detection.
* `akha.payloads`: Manages the local SQLite/JSON payload databases, WAF permutation logic, and the adaptive learning engine.

If you wish to add a new engine (e.g., an SSRF or SQLi engine), you can simply extend the abstract `Pipeline` class in `akha.core.pipeline` and register your module via the CLI plugin registry.

---

## ⚠️ Disclaimer & Ethical Use

**AKHA XSS Scanner is developed for educational and authorized professional security testing purposes only.**

* Do NOT employ this tool against systems, networks, or applications that you do not hold explicit, documented permission to test.
* Given the aggressive nature of `--deep-scan` and parameter fuzzing, this tool has the potential to cause denial-of-service, unintended database modifications, or operational disruption.
* Use staging environments whenever possible. The developers assume zero liability and are not responsible for any misuse, damage, or legal consequences caused by the operation of this software. You act entirely at your own risk.

---

<div align="center">
<b>Developed with ❤️ for the Security Community. Licensed under MIT.</b>
</div>
# akha-xss
#
