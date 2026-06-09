"""
Command handlers for every AKHA CLI sub-command.

Each handler receives the parsed ``argparse.Namespace`` and the plugin
``PluginRegistry``, performs the work, and returns an integer exit-code
(0 = success).

Add new commands by writing a ``handle_<name>(args, registry)`` function
and wiring it in ``akha.cli.base`` / ``akha.cli.__init__``.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import platform
import sys
from typing import TYPE_CHECKING, Any, Dict, List

from akha.cli.output import (
    console,
    print_banner,
    print_error,
    print_info,
    print_multi_target_summary,
    print_payload_table,
    print_scan_summary,
    print_stats,
    print_success,
    print_warning,
)

if TYPE_CHECKING:
    import argparse
    from akha.cli.plugins import PluginRegistry

__all__ = [
    "handle_scan",
    "handle_payloads",
    "handle_stats",
    "handle_doctor",
    "handle_presets",
]




def handle_scan(args: argparse.Namespace, registry: PluginRegistry) -> int:
    """Execute the ``scan`` sub-command."""

    from akha.core.config import Config
    from akha.core.scanner import Scanner


    targets = _resolve_targets(args)
    if not targets:
        return 1


    cfg = _build_config(args)
    if cfg is None:
        return 1

    quiet = args.quiet


    registry.fire_pre_scan(cfg)


    is_multi = len(targets) > 1
    all_results: List[Dict[str, Any]] = []

    if is_multi and not quiet:
        print_info(f"Multi-Target Scan: {len(targets)} targets")

    for idx, target_url in enumerate(targets, 1):
        if is_multi and not quiet:
            from rich.rule import Rule
            console.print()
            console.print(Rule(
                f" 🎯 Target {idx}/{len(targets)} │ {target_url} ",
                style="bold magenta",
                align="left",
            ))

        target_cfg = copy.deepcopy(cfg)
        target_cfg.target_url = target_url

        scanner = Scanner(target_cfg)
        result = scanner.scan(target_url, args.mode)
        result["target"] = target_url
        all_results.append(result)

        for vuln in result.get("vulnerabilities", []):
            registry.fire_on_finding(vuln)

        print_scan_summary(result, quiet=quiet)


    registry.fire_post_scan({"targets": targets, "results": all_results})


    if is_multi:
        print_multi_target_summary(all_results, quiet=quiet)


    if args.verified_only:
        for result in all_results:
            original = result.get("vulnerabilities", [])
            result["vulnerabilities"] = [
                v for v in original if v.get("validated") or v.get("status") == "Confirmed"
            ]
        if not quiet:
            total = sum(len(r.get("vulnerabilities", [])) for r in all_results)
            print_info(f"Verified-only: {total} confirmed vulnerabilities")


    if args.json_output:
        _write_json(all_results, args.json_output, quiet=quiet)

    return 0




def handle_payloads(args: argparse.Namespace, registry: PluginRegistry) -> int:
    """Execute the ``payloads`` sub-command."""
    action = getattr(args, "payload_action", None)

    if action == "generate":
        return _payloads_generate(args)
    elif action == "list":
        return _payloads_list()
    else:
        print_error("Usage: akha payloads {generate|list}")
        return 1


def _payloads_generate(args: argparse.Namespace) -> int:
    from akha.payloads.database import PayloadDatabase

    database = PayloadDatabase()
    payloads = database.get_all()

    fmt = getattr(args, "format", "txt")
    outfile = args.outfile

    if fmt == "txt":
        with open(outfile, "w") as f:
            for p in payloads:
                f.write(p + "\n")
    else:
        with open(outfile, "w") as f:
            json.dump(payloads, f, indent=2)

    print_success(f"Generated {len(payloads)} payloads → {outfile}")
    return 0


def _payloads_list() -> int:
    from akha.payloads.database import PayloadDatabase

    database = PayloadDatabase()
    categories = [
        ("basic", len(database.get_by_category("basic")), "Basic XSS payloads"),
        ("event_handlers", len(database.get_by_category("event_handlers")), "Event handler based"),
        ("svg_based", len(database.get_by_category("svg_based")), "SVG element based"),
        ("polyglot", len(database.get_by_category("polyglot")), "Multiple context payloads"),
        ("context_html", len(database.get_by_category("context_html")), "HTML context specific"),
        ("context_attribute", len(database.get_by_category("context_attribute")), "Attribute context"),
        ("context_javascript", len(database.get_by_category("context_javascript")), "JavaScript context"),
        ("context_url", len(database.get_by_category("context_url")), "URL context"),
        ("waf_bypass_cloudflare", len(database.get_by_category("waf_bypass_cloudflare")), "Cloudflare bypass"),
        ("waf_bypass_akamai", len(database.get_by_category("waf_bypass_akamai")), "Akamai bypass"),
    ]
    print_payload_table(categories)
    return 0




def handle_stats(args: argparse.Namespace, registry: PluginRegistry) -> int:
    """Display learning-engine statistics."""
    from akha.core.config import Config
    from akha.payloads.learning import LearningEngine

    cfg = Config.default()
    engine = LearningEngine(cfg)
    print_stats(engine.get_stats())
    return 0


def handle_presets(args: argparse.Namespace, registry: PluginRegistry) -> int:
    """Print ready-to-copy commands for common scan scenarios."""
    presets = [
        (
            "Quick first pass",
            "akha-xss scan --url https://target.example --profile quick --max-pages 100 --risk-top-k 50",
        ),
        (
            "WAF-protected target",
            "akha-xss scan --url https://target.example --profile quick --max-pages 100 --risk-top-k 50 "
            "--max-payloads-per-param 5 --max-payloads-per-endpoint 30 --threads 4 --rate-limit 3 "
            "--no-stored-xss --no-mxss --no-angular --no-graphql",
        ),
        (
            "Authenticated app",
            "akha-xss scan --url https://target.example --cookie \"SESSION=...\" --profile balanced --browser-verify",
        ),
        (
            "API/JSON target",
            "akha-xss scan --url https://api.target.example --api-mode --test-post --format both",
        ),
    ]
    console.print("[bold]Recommended AKHA scan presets[/bold]")
    for title, command in presets:
        console.print(f"\n[cyan]{title}[/cyan]\n  [white]{command}[/white]")
    return 0


def handle_doctor(args: argparse.Namespace, registry: PluginRegistry) -> int:
    """Check local runtime health for common installation problems."""
    checks = []

    def add(name: str, ok: bool, detail: str):
        checks.append((name, ok, detail))

    py_ok = sys.version_info >= (3, 9)
    add("Python", py_ok, f"{platform.python_version()} at {sys.executable}")

    required_modules = {
        "requests": "requests",
        "httpx": "httpx",
        "rich": "rich",
        "yaml": "pyyaml",
        "playwright": "playwright",
        "selenium": "selenium",
    }
    missing = []
    for mod, package in required_modules.items():
        if importlib.util.find_spec(mod) is None:
            missing.append(package)
    add("Python packages", not missing, "ok" if not missing else "missing: " + ", ".join(sorted(set(missing))))

    pw_runtime_ok = False
    pw_detail = "playwright package missing"
    if importlib.util.find_spec("playwright") is not None:
        try:
            from playwright.sync_api import sync_playwright
            with sync_playwright() as p:
                executable_path = p.chromium.executable_path
                browser = p.chromium.launch(headless=True)
                browser.close()
            pw_runtime_ok = True
            pw_detail = f"Chromium runtime available at {executable_path}"
        except Exception as exc:
            msg = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
            install_hint = "Run: python -m playwright install chromium"
            if "spawn EPERM" in str(exc):
                install_hint = "Chromium exists, but process launch was blocked by OS/sandbox policy"
            pw_detail = f"Chromium launch failed: {msg}. {install_hint}"
    add("Playwright Chromium", pw_runtime_ok, pw_detail)

    output_dir = os.path.abspath("output")
    try:
        os.makedirs(output_dir, exist_ok=True)
        probe = os.path.join(output_dir, ".akha_write_test")
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
        add("Output directory", True, output_dir)
    except Exception as exc:
        add("Output directory", False, f"{output_dir}: {exc}")

    proxy_env = os.environ.get("HTTPS_PROXY") or os.environ.get("HTTP_PROXY") or ""
    add("Proxy environment", True, proxy_env or "not configured")

    console.print("[bold]AKHA Doctor[/bold]")
    failed = 0
    for name, ok, detail in checks:
        mark = "[green]OK[/green]" if ok else "[red]FAIL[/red]"
        if not ok:
            failed += 1
        console.print(f"{mark} [bold]{name}[/bold] - {detail}")
    return 0 if failed == 0 else 1




def _resolve_targets(args: argparse.Namespace) -> List[str]:
    """Build a deduplicated target list from ``--url`` / ``--file``."""
    targets: List[str] = []

    if args.file:
        try:
            with open(args.file, "r") as fh:
                for line in fh:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        if not line.startswith(("http://", "https://")):
                            line = "https://" + line
                        targets.append(line)
        except Exception as exc:
            print_error(f"Cannot read target file: {exc}")
            return []
        if not targets:
            print_error("No valid targets found in the file.")
            return []

    if args.url:
        url = args.url
        if not url.startswith(("http://", "https://")):
            url = "https://" + url
        targets.insert(0, url)

    if not targets:
        print_error("Provide a target with --url or --file.")
        return []

    seen = set()
    unique: List[str] = []
    for t in targets:
        if t not in seen:
            seen.add(t)
            unique.append(t)
    return unique


def _normalize_proxy_url(raw_proxy: str) -> str:
    """Normalize and validate proxy URL for requests.Session.proxies."""
    from urllib.parse import urlparse

    proxy = (raw_proxy or "").strip()
    if not proxy:
        return ""

    if "://" not in proxy:
        proxy = f"http://{proxy}"

    parsed = urlparse(proxy)
    if parsed.scheme not in ("http", "https") or not parsed.netloc:
        raise ValueError(
            "Invalid proxy format. Use http://host:port or https://host:port"
        )
    return proxy


def _normalize_output_dir(args: argparse.Namespace) -> str | None:
    """Return a safe report output directory or None when a CLI typo is likely."""
    output_dir = str(getattr(args, "output", "output") or "output").strip()
    if not output_dir:
        return "output"

    if output_dir.lower() == "ast" and not bool(getattr(args, "oast_enabled", False)):
        print_error(
            "`-oast` is parsed as `-o ast` by the CLI. "
            "Use `--oast` to enable OAST, or `--output ./ast` if you really want that folder."
        )
        return None

    return output_dir


def _build_config(args: argparse.Namespace):
    """Map CLI arguments to a ``Config`` dataclass."""
    from akha.core.config import Config

    if args.config:
        try:
            cfg = Config.from_file(args.config)
        except Exception as exc:
            print_error(f"Cannot load config: {exc}")
            return None
    else:
        cfg = Config.default()

    try:
        proxy_url = _normalize_proxy_url(getattr(args, 'proxy', None))
    except ValueError as exc:
        print_error(str(exc))
        return None

    output_dir = _normalize_output_dir(args)
    if output_dir is None:
        return None

    base_overrides = {
        'scan_mode': args.mode,
        'payload_strategy': args.payload_strategy,
        'max_pages': max(1, int(getattr(args, 'max_pages', cfg.max_pages))),
        'max_depth': max(0, int(getattr(args, 'max_depth', cfg.max_depth))),
        'output_dir': output_dir,
        'report_format': getattr(args, 'format', 'html'),
        'threads': args.threads,
        'timeout': args.timeout,
        'verbose': args.verbose,
        'quiet': args.quiet,
        'rate_limit': getattr(args, 'rate_limit', None),
        'scan_budget_seconds': max(0, int(getattr(args, 'max_scan_seconds', 0) or 0)),
        'scan_budget_requests': max(0, int(getattr(args, 'max_requests', 0) or 0)),
        'scan_budget_payloads': max(0, int(getattr(args, 'max_payloads', 0) or 0)),
        'max_payloads_per_param': max(0, int(getattr(args, 'max_payloads_per_param', 0) or 0)),
        'max_payloads_per_endpoint': max(0, int(getattr(args, 'max_payloads_per_endpoint', 0) or 0)),
        'budget_auto_fallback': bool(getattr(args, 'budget_auto_fallback', True)),
        'budget_fallback_trigger': max(0.1, min(0.99, float(getattr(args, 'budget_fallback_trigger', 0.85) or 0.85))),
        'distributed_task_queue': bool(getattr(args, 'distributed_task_queue', True)),
        'dynamic_task_lease': bool(getattr(args, 'dynamic_task_lease', True)),
        'task_lease_seconds': max(10, int(getattr(args, 'task_lease_seconds', 120) or 120)),
        'task_max_retries': max(0, int(getattr(args, 'task_max_retries', 3) or 3)),
        'task_worker_id': getattr(args, 'task_worker_id', None),
        'resume_checkpoint_interval_seconds': max(0, int(getattr(args, 'resume_checkpoint_seconds', 20) or 0)),
        'strict_scope_guard': bool(getattr(args, 'strict_scope_guard', True)),
        'scope_guard_max_pages': max(100, int(getattr(args, 'scope_guard_max_pages', 5000) or 5000)),
        'proxy': proxy_url or None,
        'allow_ssl_fallback': bool(getattr(args, 'allow_ssl_fallback', False)),
        'custom_payloads_file': args.custom_payloads if args.custom_payloads else None,
        'encode_strategy': args.encode if args.encode else None,
        'include_patterns': args.include if args.include else None,
        'exclude_patterns': args.exclude if args.exclude else None,
        'dom_xss_enabled': bool(getattr(args, 'dom_xss_enabled', True)),
        'dom_min_confidence': max(0, min(100, int(getattr(args, 'dom_min_confidence', 50) or 50))),
        'stored_xss_enabled': bool(getattr(args, 'stored_xss_enabled', True)),
        'deep_scan': args.deep_scan,
        'dynamic_crawling': bool(getattr(args, 'dynamic_crawling', True)),
        'stateful_spa_discovery': bool(getattr(args, 'stateful_spa_discovery', True)),
        'spa_state_transition_budget': max(0, int(getattr(args, 'spa_state_budget', 8))),
        'discovery_profile': getattr(args, 'discovery_profile', 'auto'),
        'aggressive_mode': args.aggressive,
        'scan_profile': getattr(args, 'profile', 'balanced'),
        'auto_waf_cautious': bool(getattr(args, 'auto_waf_cautious', True)),
        'api_mode': args.api_mode,
        'test_post_methods': args.test_post,
        'proxy_list': getattr(args, 'proxy_list', None),
        'proxy_cooldown_seconds': max(10, int(getattr(args, 'proxy_cooldown_seconds', 60))),
        'per_host_rate_limit': bool(getattr(args, 'per_host_rate_limit', True)),
        'per_path_rate_limit': bool(getattr(args, 'per_path_rate_limit', True)),
        'path_rate_multiplier': max(0.1, min(1.0, float(getattr(args, 'path_rate_multiplier', 0.75) or 0.75))),
        'endpoint_backoff_profiles': bool(getattr(args, 'endpoint_backoff_profiles', True)),
        'auto_reauth': bool(getattr(args, 'auto_reauth', True)),
        'auth_plugin': getattr(args, 'auth_plugin', None),
        'probe_sensitive': bool(getattr(args, 'probe_sensitive', False)),
        'test_mxss': bool(getattr(args, 'test_mxss', True)),
        'test_angular': bool(getattr(args, 'test_angular', True)),
        'test_graphql': bool(getattr(args, 'test_graphql', True)),
        'test_websockets': bool(getattr(args, 'test_websockets', False)),
        'test_headers': bool(getattr(args, 'test_headers', False)),
        'test_cookies': bool(getattr(args, 'test_cookies', False)),
        'test_path_params': bool(getattr(args, 'test_path_params', False)),
        'verified_only': bool(getattr(args, 'verified_only', False)),
        'browser_execution_verify': bool(getattr(args, 'browser_execution_verify', False)),
        'auto_install_playwright': bool(getattr(args, 'auto_install_playwright', False)),
        'execution_verify_firefox': bool(getattr(args, 'execution_verify_firefox', False)),
        'browser_verify_min_score': int(getattr(args, 'browser_verify_min_score', 2) or 2),
        'browser_verify_timeout_ms': int(getattr(args, 'browser_verify_timeout_ms', 8000) or 8000),
        'browser_verify_max_concurrency': int(getattr(args, 'browser_verify_concurrency', 3) or 3),
        'stored_xss_cleanup_enabled': bool(getattr(args, 'stored_xss_cleanup_enabled', True)),
        'stored_xss_cleanup_on_detect': bool(getattr(args, 'stored_xss_cleanup_on_detect', True)),
        'payload_failure_taxonomy': bool(getattr(args, 'payload_failure_taxonomy', True)),
        'payload_context_bandit': bool(getattr(args, 'payload_context_bandit', True)),
        'payload_minimal_grammar': bool(getattr(args, 'payload_minimal_grammar', True)),
        'payload_similarity_warm_start': bool(getattr(args, 'payload_similarity_warm_start', True)),
        'crawler_aggressiveness': getattr(args, 'crawler_aggressiveness', 'balanced'),
        'ucb_exploration_factor': max(0.0, float(getattr(args, 'ucb_exploration', 1.4) or 1.4)),
        'payload_context_weight': max(0.0, float(getattr(args, 'payload_context_weight', 0.25) or 0.25)),
        'payload_encoding_weight': max(0.0, float(getattr(args, 'payload_encoding_weight', 0.15) or 0.15)),
        'payload_waf_confidence_weight': max(0.0, min(1.0, float(getattr(args, 'payload_waf_weight', 0.10) or 0.10))),
        'risk_prioritization': bool(getattr(args, 'risk_prioritization', True)),
        'risk_priority_top_k': max(0, int(getattr(args, 'risk_priority_top_k', 300) or 0)),
        'min_confidence_threshold': max(0, min(100, int(getattr(args, 'min_confidence', 60)))),
        'collaborator_url': getattr(args, 'collaborator_url', None),
        'oast_enabled': bool(getattr(args, 'oast_enabled', False)),
        'webhook_url': args.webhook_url if args.webhook_url else None,
        'webhook_platform': args.webhook_platform if args.webhook_platform and args.webhook_platform != 'auto' else None,
        'telegram_chat_id': args.telegram_chat_id if args.telegram_chat_id else None,
        'resume_file': args.resume if args.resume else None,
        'structured_logging': bool(getattr(args, 'structured_logging', False)),
        'log_level': getattr(args, 'log_level', 'INFO'),
    }

    endpoint_backoff_overrides_raw = getattr(args, 'endpoint_backoff_overrides', None)
    if endpoint_backoff_overrides_raw:
        try:
            parsed = json.loads(endpoint_backoff_overrides_raw)
            if not isinstance(parsed, dict):
                print_error("--endpoint-backoff-overrides must be a JSON object")
                return None
            base_overrides['endpoint_backoff_profile_overrides'] = parsed
        except json.JSONDecodeError:
            print_error("--endpoint-backoff-overrides must be valid JSON")
            return None

    cfg.apply_overrides(base_overrides)
    _apply_profile_defaults(cfg, args)

    if getattr(args, "no_verify_ssl", False):
        cfg.verify_ssl = False

    # In proxy mode keep TLS verification enabled by default.
    # Users can still disable it explicitly via --no-verify-ssl.
    if cfg.proxy and cfg.verify_ssl and not cfg.quiet:
        print_warning(
            "Proxy mode detected: TLS verification remains enabled by default"
        )

    if cfg.proxy and cfg.verify_ssl and not cfg.allow_ssl_fallback and not cfg.quiet:
        print_warning(
            "TLS fallback is disabled; use --allow-ssl-fallback only for trusted intercepting proxies"
        )

    if args.cookie:
        cfg.cookies = args.cookie
    if args.header:
        headers_dict = {}
        for h in args.header:
            if ":" in h:
                name, value = h.split(":", 1)
                headers_dict[name.strip()] = value.strip()
        if headers_dict:
            cfg.custom_headers = headers_dict
    if args.auth_url:
        cfg.auth_url = args.auth_url
    if args.auth_data:
        try:
            cfg.auth_data = json.loads(args.auth_data)
        except json.JSONDecodeError:
            print_error("--auth-data must be valid JSON")
            return None
    if getattr(args, 'auth_plugin_options', None):
        try:
            plugin_options = json.loads(args.auth_plugin_options)
            if not isinstance(plugin_options, dict):
                print_error("--auth-plugin-options must be a JSON object")
                return None
            cfg.auth_plugin_options = plugin_options
        except json.JSONDecodeError:
            print_error("--auth-plugin-options must be valid JSON")
            return None
    if args.bearer_token:
        cfg.bearer_token = args.bearer_token

    return cfg


def _apply_profile_defaults(cfg, args) -> None:
    """Make quick/balanced/deep profiles affect real scan cost while respecting explicit overrides."""
    profile = str(getattr(cfg, "scan_profile", "balanced") or "balanced").lower()

    if profile == "quick":
        if int(getattr(args, "max_pages", 1500) or 1500) == 1500:
            cfg.max_pages = min(cfg.max_pages, 200)
        if int(getattr(args, "risk_priority_top_k", 300) or 300) == 300:
            cfg.risk_priority_top_k = min(cfg.risk_priority_top_k, 80)
        if int(getattr(args, "max_payloads_per_param", 0) or 0) == 0:
            cfg.max_payloads_per_param = 8
        if int(getattr(args, "max_payloads_per_endpoint", 0) or 0) == 0:
            cfg.max_payloads_per_endpoint = 50
        if int(getattr(args, "threads", 10) or 10) == 10:
            cfg.threads = min(cfg.threads, 6)
        if int(getattr(args, "rate_limit", 10) or 10) == 10:
            cfg.rate_limit = min(cfg.rate_limit, 5)
        cfg.stored_xss_enabled = False if bool(getattr(args, "stored_xss_enabled", True)) else cfg.stored_xss_enabled
        cfg.test_mxss = False if bool(getattr(args, "test_mxss", True)) else cfg.test_mxss
        cfg.test_angular = False if bool(getattr(args, "test_angular", True)) else cfg.test_angular
        cfg.test_graphql = False if bool(getattr(args, "test_graphql", True)) else cfg.test_graphql
        cfg.stateful_spa_discovery = False

    elif profile == "deep":
        if int(getattr(args, "max_pages", 1500) or 1500) == 1500:
            cfg.max_pages = max(cfg.max_pages, 3000)
        if int(getattr(args, "risk_priority_top_k", 300) or 300) == 300:
            cfg.risk_priority_top_k = max(cfg.risk_priority_top_k, 800)
        if int(getattr(args, "threads", 10) or 10) == 10:
            cfg.threads = max(cfg.threads, 12)
        cfg.deep_scan = True
        cfg.stateful_spa_discovery = True

    cfg.__post_init__()


def _write_json(
    results: List[Dict[str, Any]],
    path: str,
    *,
    quiet: bool = False,
) -> None:
    """Serialise scan results to a JSON file (or stdout if path is ``-``)."""
    payload = {
        "scanner": "AKHA XSS Scanner",
        "version": "1.0.0",
        "targets": len(results),
        "results": results,
    }

    try:
        if path == "-":
            json.dump(payload, sys.stdout, indent=2, default=str)
            sys.stdout.write("\n")
        else:
            with open(path, "w") as f:
                json.dump(payload, f, indent=2, default=str)
            if not quiet:
                print_success(f"JSON report written → {path}")
    except Exception as exc:
        print_error(f"Failed to write JSON: {exc}")
