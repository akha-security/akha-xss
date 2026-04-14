"""
Argument parser builder for AKHA CLI.

Constructs a production-grade ``argparse.ArgumentParser`` with grouped
arguments, sub-commands, and a clean help menu modelled after tools like
sqlmap, nuclei, and httpx.

The parser is built lazily via ``build_parser()`` so plugin arguments can
be injected before parsing.
"""

from __future__ import annotations

import argparse
import textwrap
import logging
from typing import TYPE_CHECKING

from akha.cli.output import VERSION

if TYPE_CHECKING:
    from akha.cli.plugins import PluginRegistry

__all__ = ["build_parser"]

logger = logging.getLogger("akha.cli.base")




class AkhaHelpFormatter(argparse.RawDescriptionHelpFormatter):
    """Wider columns and grouped headings for a clean ``--help`` output."""

    def __init__(self, prog, indent_increment=2, max_help_position=40, width=100):
        super().__init__(
            prog,
            indent_increment=indent_increment,
            max_help_position=max_help_position,
            width=min(width, 100),
        )




def build_parser(
    registry: PluginRegistry | None = None,
) -> argparse.ArgumentParser:
    """Return the fully-built AKHA argument parser.

    Parameters
    ----------
    registry : PluginRegistry, optional
        If provided, give each registered plugin a chance to inject
        additional arguments into the ``scan`` sub-parser.
    """


    root = argparse.ArgumentParser(
          prog="akha-xss",
        description=textwrap.dedent(f"""\
  AKHA XSS Scanner v{VERSION}
    AKHA-XSS Detection Framework
        """),
        epilog=textwrap.dedent("""\
examples:
      akha-xss scan --url https://example.com
      akha-xss scan --url https://example.com/page?id=1 --mode url
      akha-xss scan --file targets.txt --threads 20 --json-output report.json
    akha-xss scan --url https://example.com --cookie "session=abc" --profile deep --aggressive
    akha-xss scan --url https://example.com --blind-xss-url https://oast.example/callback
      akha-xss scan --url https://example.com --verified-only --format both
            akha-xss scan --url https://example.com --execution-verify-firefox --spa-state-budget 12 --risk-top-k 500
            akha-xss scan --url https://example.com --no-payload-failure-taxonomy --no-payload-context-bandit --no-payload-minimal-grammar --no-payload-similarity-warm-start
            akha-xss scan --url https://example.com --max-scan-seconds 900 --max-requests 20000 --resume-checkpoint-seconds 30
            akha-xss scan --url https://example.com --task-worker-id worker-a --task-lease-seconds 120
            akha-xss scan --url https://example.com --budget-fallback-trigger 0.85 --task-max-retries 3 --ucb-exploration 1.4
      akha-xss payloads generate payloads.txt
      akha-xss payloads list
      akha-xss stats
        """),
        formatter_class=AkhaHelpFormatter,
        add_help=True,
    )

    root.add_argument(
        "-V", "--version",
        action="version",
        version=f"%(prog)s {VERSION}",
    )


    subparsers = root.add_subparsers(
        dest="command",
        title="commands",
        metavar="COMMAND",
    )


    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan targets for XSS vulnerabilities",
        description="Scan one or more URLs for reflected, stored, and DOM-based XSS.",
        formatter_class=AkhaHelpFormatter,
    )
    _add_scan_arguments(scan_parser)

    if registry:
        for plugin in registry:
            try:
                plugin.add_arguments(scan_parser)
            except Exception:
                logger.debug("Plugin argument injection failed", exc_info=True)


    payload_parser = subparsers.add_parser(
        "payloads",
        help="Manage XSS payloads",
        description="Generate or list available XSS payload categories.",
        formatter_class=AkhaHelpFormatter,
    )
    payload_sub = payload_parser.add_subparsers(
        dest="payload_action",
        title="actions",
        metavar="ACTION",
    )

    gen_parser = payload_sub.add_parser(
        "generate",
        help="Export payloads to a file",
        formatter_class=AkhaHelpFormatter,
    )
    gen_parser.add_argument("outfile", metavar="FILE", help="Output file path")
    gen_parser.add_argument(
        "--format", "-f",
        choices=["txt", "json"],
        default="txt",
        help="Output format (default: txt)",
    )

    payload_sub.add_parser(
        "list",
        help="List available payload categories",
        formatter_class=AkhaHelpFormatter,
    )


    subparsers.add_parser(
        "stats",
        help="Show learning-engine statistics",
        formatter_class=AkhaHelpFormatter,
    )

    return root




def _add_scan_arguments(parser: argparse.ArgumentParser) -> None:
    """Register all ``scan`` sub-command arguments in logical groups."""


    target = parser.add_argument_group("target")
    target_mx = target.add_mutually_exclusive_group(required=False)
    target_mx.add_argument(
        "--url", "-u",
        metavar="URL",
        help="Single target URL to scan",
    )
    target_mx.add_argument(
        "--file", "-l",
        metavar="FILE",
        help="File containing target URLs (one per line)",
    )
    target.add_argument(
        "--mode", "-m",
        choices=["full", "url"],
        default="full",
        help="Scan mode: full=crawl entire site, url=single endpoint (default: full)",
    )
    target.add_argument(
        "--max-pages",
        type=int,
        default=1500,
        metavar="N",
        help="Maximum pages to crawl in full mode (default: 1500)",
    )
    target.add_argument(
        "--max-depth",
        type=int,
        default=3,
        metavar="N",
        help="Maximum crawl depth from start URL (default: 3)",
    )
    target.add_argument(
        "--resume",
        metavar="FILE",
        help="Resume interrupted scan from state file",
    )


    auth = parser.add_argument_group("authentication")
    auth.add_argument(
        "--cookie",
        metavar="STRING",
        help='Cookie string: "name1=val1; name2=val2"',
    )
    auth.add_argument(
        "--header", "-H",
        metavar="HEADER",
        action="append",
        default=[],
        help='Custom header "Name: Value" (repeatable)',
    )
    auth.add_argument(
        "--auth-url",
        metavar="URL",
        help="Login URL for form-based authentication",
    )
    auth.add_argument(
        "--auth-data",
        metavar="JSON",
        help='Login form data as JSON: \'{"user":"x","pass":"y"}\'',
    )
    auth.add_argument(
        "--bearer-token",
        metavar="TOKEN",
        help="Bearer token for API authentication",
    )
    auth.add_argument(
        "--auth-plugin",
        choices=["csrf-preflight", "bearer-refresh"],
        help="Optional auth flow plugin for dynamic login/reauth handling",
    )
    auth.add_argument(
        "--auth-plugin-options",
        metavar="JSON",
        help='Plugin options as JSON, e.g. {"refresh_url":"https://app/auth/refresh"}',
    )


    scope = parser.add_argument_group("scope control")
    scope.add_argument(
        "--include",
        metavar="REGEX",
        action="append",
        default=[],
        help="Include URL pattern (repeatable regex)",
    )
    scope.add_argument(
        "--exclude",
        metavar="REGEX",
        action="append",
        default=[],
        help="Exclude URL pattern (repeatable regex)",
    )
    scope.add_argument(
        "--no-risk-prioritization",
        dest="risk_prioritization",
        action="store_false",
        help="Disable risk-based endpoint prioritization",
    )
    scope.add_argument(
        "--risk-top-k",
        dest="risk_priority_top_k",
        type=int,
        default=300,
        metavar="N",
        help="Keep top-N prioritized endpoints for deep processing (default: 300, 0 = unlimited)",
    )


    detection = parser.add_argument_group("detection")
    detection.add_argument(
        "--payload-strategy", "-p",
        choices=["auto", "builtin", "custom", "hybrid"],
        default="auto",
        help="Payload selection strategy (default: auto)",
    )
    detection.add_argument(
        "--custom-payloads",
        metavar="FILE",
        help="Path to custom payloads file",
    )
    detection.add_argument(
        "--encode",
        choices=[
            "auto", "all", "none", "url", "double-url", "html",
            "html-hex", "unicode", "js-octal", "base64",
            "mixed-case", "null-byte", "comment",
        ],
        default="auto",
        help="Payload encoding strategy for WAF bypass (default: auto)",
    )
    dom_group = detection.add_mutually_exclusive_group()
    dom_group.add_argument(
        "--dom-xss",
        dest="dom_xss_enabled",
        action="store_true",
        help="Enable DOM-based XSS scanning (default)",
    )
    dom_group.add_argument(
        "--no-dom-xss",
        dest="dom_xss_enabled",
        action="store_false",
        help="Disable DOM-based XSS scanning",
    )

    stored_group = detection.add_mutually_exclusive_group()
    stored_group.add_argument(
        "--stored-xss",
        dest="stored_xss_enabled",
        action="store_true",
        help="Enable stored XSS checking (default)",
    )
    stored_group.add_argument(
        "--no-stored-xss",
        dest="stored_xss_enabled",
        action="store_false",
        help="Disable stored XSS checking",
    )

    detection.set_defaults(dom_xss_enabled=True, stored_xss_enabled=True)
    detection.add_argument(
        "--deep-scan",
        action="store_true",
        default=False,
        help="Enable deep parameter discovery",
    )
    detection.add_argument(
        "--no-dynamic",
        dest="dynamic_crawling",
        action="store_false",
        help="Disable full Playwright-based dynamic SPA crawling",
    )
    detection.add_argument(
        "--no-stateful-spa",
        dest="stateful_spa_discovery",
        action="store_false",
        help="Disable interactive SPA state transitions during dynamic crawling",
    )
    detection.add_argument(
        "--spa-state-budget",
        type=int,
        default=8,
        metavar="N",
        help="Maximum interactive SPA transitions per page (default: 8)",
    )
    detection.add_argument(
        "--discovery-profile",
        choices=["auto", "anonymous", "authenticated", "admin"],
        default="auto",
        help="Discovery profile for crawl strategy (default: auto)",
    )
    detection.add_argument(
        "--no-payload-failure-taxonomy",
        dest="payload_failure_taxonomy",
        action="store_false",
        help="Disable failure-reason taxonomy in payload learning",
    )
    detection.add_argument(
        "--no-payload-context-bandit",
        dest="payload_context_bandit",
        action="store_false",
        help="Disable endpoint-profile-aware payload ranking",
    )
    detection.add_argument(
        "--no-payload-minimal-grammar",
        dest="payload_minimal_grammar",
        action="store_false",
        help="Disable context-minimal grammar-guided payload generation",
    )
    detection.add_argument(
        "--no-payload-similarity-warm-start",
        dest="payload_similarity_warm_start",
        action="store_false",
        help="Disable similarity-based warm-start beyond per-domain history",
    )
    detection.add_argument(
        "--aggressive",
        action="store_true",
        default=False,
        help="Test multiple payloads per parameter",
    )
    detection.add_argument(
        "--profile",
        choices=["quick", "balanced", "deep"],
        default="balanced",
        help="Scan intensity preset (default: balanced)",
    )
    detection.add_argument(
        "--api-mode",
        action="store_true",
        default=False,
        help="Enable API/JSON body XSS scanning",
    )
    detection.add_argument(
        "--test-post",
        action="store_true",
        default=False,
        help="Enable POST and JSON-body parameter testing (default: GET-only)",
    )
    detection.add_argument(
        "--probe-sensitive",
        action="store_true",
        default=False,
        help="Probe sensitive paths like /.env and analyze leaked secret patterns",
    )

    mxss_group = detection.add_mutually_exclusive_group()
    mxss_group.add_argument(
        "--mxss",
        dest="test_mxss",
        action="store_true",
        help="Enable Mutation XSS engine (default)",
    )
    mxss_group.add_argument(
        "--no-mxss",
        dest="test_mxss",
        action="store_false",
        help="Disable Mutation XSS engine",
    )

    angular_group = detection.add_mutually_exclusive_group()
    angular_group.add_argument(
        "--angular",
        dest="test_angular",
        action="store_true",
        help="Enable AngularJS CSTI scanning (default)",
    )
    angular_group.add_argument(
        "--no-angular",
        dest="test_angular",
        action="store_false",
        help="Disable AngularJS CSTI scanning",
    )

    graphql_group = detection.add_mutually_exclusive_group()
    graphql_group.add_argument(
        "--graphql",
        dest="test_graphql",
        action="store_true",
        help="Enable GraphQL XSS scanning (default)",
    )
    graphql_group.add_argument(
        "--no-graphql",
        dest="test_graphql",
        action="store_false",
        help="Disable GraphQL XSS scanning",
    )

    ws_group = detection.add_mutually_exclusive_group()
    ws_group.add_argument(
        "--websockets",
        dest="test_websockets",
        action="store_true",
        help="Enable WebSocket XSS scanning",
    )
    ws_group.add_argument(
        "--no-websockets",
        dest="test_websockets",
        action="store_false",
        help="Disable WebSocket XSS scanning (default)",
    )

    headers_group = detection.add_mutually_exclusive_group()
    headers_group.add_argument(
        "--headers",
        dest="test_headers",
        action="store_true",
        help="Enable header parameter testing (disabled by default)",
    )
    headers_group.add_argument(
        "--no-headers",
        dest="test_headers",
        action="store_false",
        help="Disable header parameter testing",
    )

    cookies_group = detection.add_mutually_exclusive_group()
    cookies_group.add_argument(
        "--cookies",
        dest="test_cookies",
        action="store_true",
        help="Enable cookie parameter testing (disabled by default)",
    )
    cookies_group.add_argument(
        "--no-cookies",
        dest="test_cookies",
        action="store_false",
        help="Disable cookie parameter testing",
    )

    path_group = detection.add_mutually_exclusive_group()
    path_group.add_argument(
        "--path-params",
        dest="test_path_params",
        action="store_true",
        help="Enable path-segment parameter testing (disabled by default)",
    )
    path_group.add_argument(
        "--no-path-params",
        dest="test_path_params",
        action="store_false",
        help="Disable path-segment parameter testing",
    )

    detection.set_defaults(
        test_mxss=True,
        test_angular=True,
        test_graphql=True,
        test_websockets=False,
        test_headers=False,
        test_cookies=False,
        test_path_params=False,
    )

    detection.add_argument(
        "--blind-xss-url",
        "--blind-callback",
        "--collaborator-url",
        dest="collaborator_url",
        metavar="URL",
        help="Blind XSS callback URL (Burp Collaborator, interactsh, webhook, etc.)",
    )
    detection.add_argument(
        "--oast",
        dest="oast_enabled",
        action="store_true",
        default=False,
        help="Enable built-in Interactsh OAST polling for automatic Blind XSS detection",
    )
    detection.add_argument(
        "--verified-only",
        action="store_true",
        default=False,
        help="Show only browser-verified / confirmed vulnerabilities",
    )
    detection.add_argument(
        "--execution-verify-firefox",
        action="store_true",
        default=False,
        help="Run optional Firefox-based execution verification in addition to Chromium",
    )
    detection.add_argument(
        "--min-confidence",
        type=int,
        metavar="N",
        default=60,
        help="Minimum confidence score (0-100, default: 60)",
    )


    output = parser.add_argument_group("output")
    output.add_argument(
        "--output", "-o",
        metavar="DIR",
        default="output",
        help="Output directory for reports (default: output)",
    )
    output.add_argument(
        "--format",
        choices=["html", "json", "both"],
        default="html",
        help="Report format (default: html)",
    )
    output.add_argument(
        "--json-output",
        metavar="FILE",
        help="Write JSON results to FILE (independent of --format)",
    )
    output.add_argument(
        "-v", "--verbose",
        action="store_true",
        default=False,
        help="Verbose output",
    )
    output.add_argument(
        "-q", "--quiet",
        action="store_true",
        default=False,
        help="Quiet mode — minimal output",
    )


    perf = parser.add_argument_group("performance")
    perf.add_argument(
        "--threads", "-t",
        type=int,
        default=10,
        metavar="N",
        help="Concurrent threads (default: 10)",
    )
    perf.add_argument(
        "--timeout",
        type=int,
        default=10,
        metavar="SECONDS",
        help="HTTP request timeout in seconds (default: 10)",
    )
    perf.add_argument(
        "--rate-limit",
        type=int,
        default=10,
        metavar="N",
        help="Max requests per second (default: 10)",
    )
    perf.add_argument(
        "--max-scan-seconds",
        type=int,
        default=0,
        metavar="SECONDS",
        help="Hard cap for total scan duration in seconds (0 = unlimited)",
    )
    perf.add_argument(
        "--max-requests",
        type=int,
        default=0,
        metavar="N",
        help="Hard cap for total HTTP requests across the scan (0 = unlimited)",
    )
    perf.add_argument(
        "--max-payloads",
        type=int,
        default=0,
        metavar="N",
        help="Hard cap for total payload attempts across the scan (0 = unlimited)",
    )
    perf.add_argument(
        "--max-payloads-per-param",
        type=int,
        default=0,
        metavar="N",
        help="Hard cap for payload attempts per parameter (0 = planner default)",
    )
    perf.add_argument(
        "--max-payloads-per-endpoint",
        type=int,
        default=0,
        metavar="N",
        help="Hard cap for payload attempts per endpoint (0 = unlimited)",
    )
    perf.add_argument(
        "--no-distributed-task-queue",
        dest="distributed_task_queue",
        action="store_false",
        help="Disable lease/ack task queue scheduling and use direct local submission",
    )
    perf.add_argument(
        "--task-lease-seconds",
        type=int,
        default=120,
        metavar="SECONDS",
        help="Lease duration for claimed scan tasks before requeue (default: 120)",
    )
    perf.add_argument(
        "--task-worker-id",
        metavar="ID",
        help="Optional worker identity for task claims (default: auto local worker)",
    )
    perf.add_argument(
        "--no-budget-auto-fallback",
        dest="budget_auto_fallback",
        action="store_false",
        help="Disable automatic fallback mode when budget pressure is high",
    )
    perf.add_argument(
        "--budget-fallback-trigger",
        type=float,
        default=0.85,
        metavar="RATIO",
        help="Budget utilization ratio to trigger fallback mode (default: 0.85)",
    )
    perf.add_argument(
        "--no-dynamic-task-lease",
        dest="dynamic_task_lease",
        action="store_false",
        help="Disable adaptive task lease duration based on observed runtime",
    )
    perf.add_argument(
        "--task-max-retries",
        type=int,
        default=3,
        metavar="N",
        help="Max retries per task before dead-lettering (default: 3)",
    )
    perf.add_argument(
        "--ucb-exploration",
        type=float,
        default=1.4,
        metavar="F",
        help="Payload learning exploration factor (default: 1.4)",
    )
    perf.add_argument(
        "--payload-context-weight",
        type=float,
        default=0.25,
        metavar="W",
        help="Context contribution weight in payload ranking (default: 0.25)",
    )
    perf.add_argument(
        "--payload-encoding-weight",
        type=float,
        default=0.15,
        metavar="W",
        help="Encoding contribution weight in payload ranking (default: 0.15)",
    )
    perf.add_argument(
        "--payload-waf-weight",
        type=float,
        default=0.10,
        metavar="W",
        help="WAF-confidence modulation weight in payload ranking (default: 0.10)",
    )
    perf.add_argument(
        "--resume-checkpoint-seconds",
        type=int,
        default=20,
        metavar="SECONDS",
        help="Write periodic resume checkpoints every N seconds (default: 20)",
    )
    perf.add_argument(
        "--no-scope-guard",
        dest="strict_scope_guard",
        action="store_false",
        help="Disable safe scope guardrails for max-pages and broad full scans",
    )
    perf.add_argument(
        "--scope-guard-max-pages",
        type=int,
        default=5000,
        metavar="N",
        help="Max allowed pages when scope guard is active (default: 5000)",
    )
    perf.add_argument(
        "--no-per-host-rate-limit",
        dest="per_host_rate_limit",
        action="store_false",
        help="Disable host-aware throttling",
    )
    perf.add_argument(
        "--no-per-path-rate-limit",
        dest="per_path_rate_limit",
        action="store_false",
        help="Disable path-aware throttling",
    )
    perf.add_argument(
        "--path-rate-multiplier",
        type=float,
        default=0.75,
        metavar="R",
        help="Path-specific rate multiplier relative to global rate (default: 0.75)",
    )
    perf.add_argument(
        "--proxy-cooldown-seconds",
        type=int,
        default=60,
        metavar="SECONDS",
        help="Proxy quarantine cooldown after repeated failures (default: 60)",
    )
    perf.add_argument(
        "--no-endpoint-backoff-profiles",
        dest="endpoint_backoff_profiles",
        action="store_false",
        help="Disable endpoint-class-aware challenge backoff profiles",
    )
    perf.add_argument(
        "--endpoint-backoff-overrides",
        metavar="JSON",
        help='JSON overrides for backoff profiles, e.g. {"auth":{"penalty_mult":2.2}}',
    )
    perf.add_argument(
        "--proxy",
        metavar="URL",
        help="HTTP/HTTPS proxy URL (example: http://127.0.0.1:8080)",
    )
    perf.add_argument(
        "--proxy-list",
        metavar="FILE",
        help="Path to text file with proxy URLs (one per line) for IP rotation",
    )
    perf.add_argument(
        "--no-reauth",
        dest="auto_reauth",
        action="store_false",
        help="Disable automatic re-login when session expires (401/403)",
    )
    perf.add_argument(
        "--no-verify-ssl",
        action="store_true",
        default=False,
        help="Disable TLS certificate verification (insecure)",
    )
    perf.add_argument(
        "--allow-ssl-fallback",
        action="store_true",
        default=False,
        help="If TLS verify fails, retry once without verification (insecure)",
    )


    notify = parser.add_argument_group("notifications")
    notify.add_argument(
        "--webhook-url",
        metavar="URL",
        help="Webhook URL for notifications (Discord/Slack/Telegram)",
    )
    notify.add_argument(
        "--webhook-platform",
        choices=["auto", "discord", "slack", "telegram"],
        default="auto",
        help="Webhook platform (default: auto-detect)",
    )
    notify.add_argument(
        "--telegram-chat-id",
        metavar="ID",
        help="Telegram chat ID (required for Telegram)",
    )


    parser.add_argument(
        "--config", "-c",
        metavar="FILE",
        help="YAML configuration file path",
    )

    detection.set_defaults(stateful_spa_discovery=True)
    detection.set_defaults(
        payload_failure_taxonomy=True,
        payload_context_bandit=True,
        payload_minimal_grammar=True,
        payload_similarity_warm_start=True,
    )
    perf.set_defaults(
        distributed_task_queue=True,
        budget_auto_fallback=True,
        dynamic_task_lease=True,
        per_host_rate_limit=True,
        per_path_rate_limit=True,
        endpoint_backoff_profiles=True,
        strict_scope_guard=True,
    )
    scope.set_defaults(risk_prioritization=True)
