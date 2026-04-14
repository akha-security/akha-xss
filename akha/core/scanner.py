"""
Main scanner orchestrator with keyboard controls and multi-type XSS support
"""

import os
import sys
import time
import re
import signal
import threading
import logging
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import List, Dict, Optional
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeElapsedColumn, TaskProgressColumn
from akha.cli.output import (
    console, print_banner, print_scan_config, print_phase, print_result,
    print_detail, print_vuln_alert, print_scan_results, print_info,
)

from akha.modules.waf_detector import WAFDetector
from akha.modules.crawler import Crawler
from akha.modules.param_finder import ParamFinder
from akha.modules.xss.xss_engine import XSSEngine
from akha.modules.xss.csp_analyzer import CSPAnalyzer
from akha.modules.xss.dom_scanner import DOMScanner
from akha.modules.xss.mxss_engine import MXSSEngine
from akha.modules.xss.angular_scanner import AngularJSScanner
from akha.modules.xss.graphql_scanner import GraphQLScanner
from akha.modules.xss.websocket_scanner import WebSocketScanner
from akha.payloads.manager import PayloadManager
from akha.payloads.learning import LearningEngine
from akha.reports.html_generator import HTMLReportGenerator
from akha.reports.json_generator import JSONReportGenerator
from akha.core.http_client import HTTPClient
from akha.core.config import Config
from akha.core.session import Session
from akha.core.pipeline import ScanCollector, ScanAnalyzer, ScanExploiter, ScanReporter
from akha.core.task_queue import DistributedTaskQueue
from akha.utils.notifier import Notifier
from akha.modules.interactsh_client import InteractshClient


logger = logging.getLogger("akha.scanner")


class ScanController:
    """Controls scan pause/resume/stop via keyboard"""
    
    def __init__(self):
        self.paused = False
        self.stopped = False
        self._lock = threading.Lock()
        self._monitor_thread = None
        self._original_sigint = None
        self._scanner = None
        self._sigint_count = 0
        self._tty_fd = None
        self._tty_old_settings = None
    
    def start_monitoring(self, scanner):
        """Start keyboard monitoring"""
        self._scanner = scanner
        self._sigint_count = 0
        
        self._original_sigint = signal.getsignal(signal.SIGINT)
        signal.signal(signal.SIGINT, self._handle_sigint)
        
        self._monitor_thread = threading.Thread(target=self._keyboard_monitor, daemon=True)
        self._monitor_thread.start()
    
    def stop_monitoring(self):
        """Stop keyboard monitoring"""
        with self._lock:
            self.stopped = True

        self._restore_terminal_mode()

        if self._monitor_thread and self._monitor_thread.is_alive():
            self._monitor_thread.join(timeout=0.5)

        if self._original_sigint:
            try:
                signal.signal(signal.SIGINT, self._original_sigint)
            except (OSError, ValueError):
                pass
        self._original_sigint = None

    def _restore_terminal_mode(self):
        """Best-effort restore for Unix terminal settings (WSL/Linux/macOS)."""
        if self._tty_fd is None or self._tty_old_settings is None:
            return
        try:
            import termios
            termios.tcsetattr(self._tty_fd, termios.TCSADRAIN, self._tty_old_settings)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)
        finally:
            self._tty_fd = None
            self._tty_old_settings = None
    
    def _handle_sigint(self, signum, frame):
        """Handle CTRL+C - force stop"""
        with self._lock:
            self._sigint_count += 1
            
            if self._sigint_count >= 3:
                console.print("\n[bold red][!] Force exit![/bold red]")
                os._exit(1)
            
            if self._sigint_count == 1:
                self.stopped = True
                console.print("\n[bold yellow][!] CTRL+C detected - Stopping scan gracefully...[/bold yellow]")
                console.print("[yellow]   Generating report for findings so far...[/yellow]")
                console.print("[dim]   Press CTRL+C again to force stop[/dim]")
            else:
                self.stopped = True
                console.print("\n[bold red][!] Force stopping scan...[/bold red]")
        
        if self._scanner:
            self._scanner._stop_scan()
    
    def _keyboard_monitor(self):
        """Monitor keyboard for stop via P/Space keys"""
        try:
            if sys.platform == 'win32':
                import msvcrt
                while True:
                    with self._lock:
                        if self.stopped:
                            break
                    
                    try:
                        if msvcrt.kbhit():
                            key = msvcrt.getch()
                            if key in (b'p', b'P', b' '):
                                self._graceful_stop()
                    except Exception:
                        logger.debug("Keyboard monitor read failed on Windows", exc_info=True)
                    
                    time.sleep(0.15)
            else:
                import select
                import tty
                import termios

                try:
                    if sys.stdin.isatty():
                        fd = sys.stdin.fileno()
                        self._tty_fd = fd
                        self._tty_old_settings = termios.tcgetattr(fd)
                        tty.setcbreak(fd)
                except Exception:
                    self._tty_fd = None
                    self._tty_old_settings = None
                
                try:
                    while True:
                        with self._lock:
                            if self.stopped:
                                break
                        
                        if select.select([sys.stdin], [], [], 0.15)[0]:
                            key = sys.stdin.read(1)
                            if key in ('p', 'P', ' '):
                                self._graceful_stop()
                finally:
                    self._restore_terminal_mode()
        except Exception:
            logger.debug("Keyboard monitor loop failed", exc_info=True)
    
    def _graceful_stop(self):
        """Stop scan and generate report"""
        with self._lock:
            if self.stopped:
                return
            self.stopped = True
            console.print("\n[bold yellow][!] Stopping scan... Generating report for findings so far.[/bold yellow]")
        if self._scanner:
            self._scanner._stop_scan()


class Scanner:
    """Main scanner class with full feature support"""
    
    def __init__(self, config: Config):
        self.config = config
        self._last_checkpoint_ts = 0.0
        self._budget_stop_reason = ""
        self._budget_degraded = False
        self._module_metrics: Dict[str, Dict] = {}
        self._apply_scope_guardrails()
        self._task_worker_id = config.task_worker_id or f"local-{os.getpid()}"
        self.http_client = HTTPClient(config)
        self.payload_manager = PayloadManager(config)
        self.learning_engine = LearningEngine(config)
        
        self.waf_detector = WAFDetector(self.http_client)
        self.crawler = Crawler(self.http_client, config)
        self.param_finder = ParamFinder(self.http_client, config)
        self.xss_engine = XSSEngine(
            self.http_client,
            self.payload_manager,
            self.learning_engine,
            config
        )
        self.csp_analyzer = CSPAnalyzer(self.http_client)
        self.dom_scanner = DOMScanner(config, self.http_client)
        self.mxss_engine = MXSSEngine(
            self.http_client, config,
            execution_verifier=None,  # Playwright verifier injected later if available
        )
        self.angular_scanner = AngularJSScanner(self.http_client, config)
        self.graphql_scanner = GraphQLScanner(self.http_client, config)
        self.websocket_scanner = WebSocketScanner(self.http_client, config)

        self.collector = ScanCollector(self.crawler, self.param_finder, config)
        self.analyzer = ScanAnalyzer(self.waf_detector, self.csp_analyzer)
        self.exploiter = ScanExploiter(self.xss_engine)
        self.reporter = ScanReporter(self.config, HTMLReportGenerator, JSONReportGenerator)
        
        self.session = None
        
        self.notifier = None
        if config.webhook_url:
            self.notifier = Notifier(
                webhook_url=config.webhook_url,
                platform=config.webhook_platform or 'auto',
                telegram_chat_id=config.telegram_chat_id,
                quiet=config.quiet,
            )
        
        self.controller = ScanController()
        self._interrupted = False

        # Phase 5: OAST / Interactsh client
        self.interactsh: Optional[InteractshClient] = None
        if getattr(config, 'oast_enabled', False):
            self.interactsh = InteractshClient(
                server_url=config.collaborator_url or None,
            )

    def _apply_scope_guardrails(self):
        """Clamp risky broad-scan defaults unless user explicitly disables guardrail."""
        if not bool(getattr(self.config, 'strict_scope_guard', True)):
            return
        max_allowed = max(100, int(getattr(self.config, 'scope_guard_max_pages', 5000) or 5000))
        if int(getattr(self.config, 'max_pages', 0) or 0) > max_allowed:
            self.config.max_pages = max_allowed

    def _budget_snapshot(self) -> Dict:
        elapsed = self.session.get_duration() if self.session else 0.0
        requests_sent = int(getattr(self.http_client, 'request_count', 0) or 0)
        payloads_tested = int(getattr(self.xss_engine, 'payloads_tested', 0) or 0)
        return {
            'elapsed_seconds': elapsed,
            'requests_sent': requests_sent,
            'payloads_tested': payloads_tested,
        }

    def _budget_utilization(self) -> float:
        """Return max utilization ratio across active budget dimensions."""
        snap = self._budget_snapshot()
        ratios = [0.0]
        sec_cap = int(getattr(self.config, 'scan_budget_seconds', 0) or 0)
        req_cap = int(getattr(self.config, 'scan_budget_requests', 0) or 0)
        payload_cap = int(getattr(self.config, 'scan_budget_payloads', 0) or 0)
        if sec_cap > 0:
            ratios.append(float(snap['elapsed_seconds']) / float(sec_cap))
        if req_cap > 0:
            ratios.append(float(snap['requests_sent']) / float(req_cap))
        if payload_cap > 0:
            ratios.append(float(snap['payloads_tested']) / float(payload_cap))
        return max(ratios)

    def _maybe_apply_budget_fallback(self):
        """Degrade optional heavy modules when budget pressure is high."""
        if self._budget_degraded:
            return
        if not bool(getattr(self.config, 'budget_auto_fallback', True)):
            return
        trigger = float(getattr(self.config, 'budget_fallback_trigger', 0.85) or 0.85)
        if self._budget_utilization() < max(0.1, min(trigger, 0.99)):
            return

        self._budget_degraded = True
        self.config.test_mxss = False
        self.config.test_angular = False
        self.config.test_websockets = False
        self.config.deep_scan = False
        self.config.stateful_spa_discovery = False
        if not self.config.quiet:
            print_detail("Budget pressure high: switched to fallback mode (disabled heavy optional modules)")

    def _phase_start(self, name: str):
        bucket = self._module_metrics.setdefault(name, {'runs': 0, 'duration_seconds': 0.0, 'errors': 0})
        bucket['runs'] += 1
        return time.time()

    def _phase_end(self, name: str, started_at: float, *, error: bool = False):
        bucket = self._module_metrics.setdefault(name, {'runs': 0, 'duration_seconds': 0.0, 'errors': 0})
        bucket['duration_seconds'] += max(0.0, time.time() - started_at)
        if error:
            bucket['errors'] += 1

    def _check_scan_budget(self) -> bool:
        """Return True when any configured scan budget cap is exceeded."""
        snap = self._budget_snapshot()
        sec_cap = int(getattr(self.config, 'scan_budget_seconds', 0) or 0)
        req_cap = int(getattr(self.config, 'scan_budget_requests', 0) or 0)
        payload_cap = int(getattr(self.config, 'scan_budget_payloads', 0) or 0)

        if sec_cap > 0 and snap['elapsed_seconds'] >= sec_cap:
            self._budget_stop_reason = f"time budget reached ({sec_cap}s)"
            return True
        if req_cap > 0 and snap['requests_sent'] >= req_cap:
            self._budget_stop_reason = f"request budget reached ({req_cap})"
            return True
        if payload_cap > 0 and snap['payloads_tested'] >= payload_cap:
            self._budget_stop_reason = f"payload budget reached ({payload_cap})"
            return True
        return False

    def _maybe_checkpoint(self):
        """Persist resume state periodically to improve long-run resilience."""
        interval = int(getattr(self.config, 'resume_checkpoint_interval_seconds', 20) or 0)
        if interval <= 0 or not self.session:
            return
        now = time.time()
        if (now - self._last_checkpoint_ts) < interval:
            return
        try:
            self.session.save_resume_state(self.config.output_dir)
            self._last_checkpoint_ts = now
        except Exception:
            logger.debug("Periodic checkpoint save failed", exc_info=True)

    def _build_reflected_task_queue(self, crawled_urls: List[Dict]) -> DistributedTaskQueue:
        """Build or restore reflected scan task queue for worker-friendly resumability."""
        if bool(getattr(self.config, 'distributed_task_queue', True)) and self.session:
            state = self.session.get_task_queue_state()
            if state and state.get('queue_name') == 'reflected_xss':
                return DistributedTaskQueue.from_snapshot(state)

        q = DistributedTaskQueue()
        q.enqueue_many([
            {
                'task_type': 'reflected_xss',
                'payload': {'url_data': url_data},
                'meta': {
                    'url': url_data.get('url', ''),
                    'task_key': f"reflected:{url_data.get('url', '')}",
                },
            }
            for url_data in crawled_urls
        ])
        return q
    
    def _stop_scan(self):
        """Stop all scanning modules"""
        self._interrupted = True
        self.crawler.stop()
        self.xss_engine.stop()
        # Phase 5: Gracefully shut down OAST polling
        if self.interactsh:
            try:
                self.interactsh.close()
            except Exception:
                logger.debug("Interactsh close failed", exc_info=True)
    
    def _pause_scan(self):
        """Pause all scanning modules"""
        self.crawler.pause()
        self.xss_engine.pause()
    
    def _resume_scan(self):
        """Resume all scanning modules"""
        self.crawler.resume()
        self.xss_engine.resume()

    def _endpoint_risk_score(self, url_data: Dict) -> int:
        """Heuristic score to prioritize endpoints likely to yield exploitable findings."""
        url = (url_data.get('url') or '').lower()
        forms = url_data.get('forms') or []
        params = url_data.get('parameters') or []
        score = 0

        if forms:
            score += 12
        if params:
            score += min(len(params), 8)

        high_value_tokens = (
            'search', 'query', 'q=', 'redirect', 'return=', 'next=',
            'callback', 'message', 'comment', 'feedback', 'profile',
            'graphql', '/api/', '/auth/', '/login', '/account',
        )
        for token in high_value_tokens:
            if token in url:
                score += 4

        if '?' in url:
            score += 3

        method = (url_data.get('method') or '').upper()
        if method in ('POST', 'PUT', 'PATCH'):
            score += 5

        depth = int(url_data.get('depth') or 0)
        score -= min(depth, 5)

        return score

    def _prioritize_crawled_urls(self, crawled_urls: List[Dict]) -> List[Dict]:
        """Sort URLs by risk score while preserving deterministic fallback order."""
        if not crawled_urls:
            return crawled_urls

        if not bool(getattr(self.config, 'risk_prioritization', True)):
            return crawled_urls

        with_index = list(enumerate(crawled_urls))
        with_index.sort(
            key=lambda item: (
                -self._endpoint_risk_score(item[1]),
                int(item[1].get('depth') or 0),
                item[0],
            )
        )
        prioritized = [item[1] for item in with_index]

        top_k = int(getattr(self.config, 'risk_priority_top_k', 0) or 0)
        if top_k > 0:
            return prioritized[:top_k]
        return prioritized
    
    def scan(self, target_url: str, scan_mode: str = "full") -> Dict:
        """Main scan method"""
        if self.config.resume_file and os.path.exists(self.config.resume_file):
            self.session = Session.restore(self.config.resume_file)
            if not self.config.quiet:
                console.print(f"[bold green][*] Resuming previous scan ({len(self.session.vulnerabilities)} vulns found so far)[/bold green]")
        else:
            self.session = Session(target_url, scan_mode)
        
        self.controller.start_monitoring(self)
        self._last_checkpoint_ts = time.time()
        self._budget_stop_reason = ""
        self._budget_degraded = False
        self._module_metrics = {}
        
        if not self.config.quiet:
            print_banner()
            features = []

            if self.config.dom_xss_enabled:
                features.append("DOM XSS")
            if self.config.stored_xss_enabled:
                features.append("Stored XSS")
            if getattr(self.config, 'test_mxss', True) and scan_mode == "full":
                features.append("mXSS")
            if getattr(self.config, 'test_angular', True) and scan_mode == "full":
                features.append("Angular CSTI")
            if getattr(self.config, 'test_graphql', True) and scan_mode == "full":
                features.append("GraphQL XSS")
            if getattr(self.config, 'test_websockets', False) and scan_mode == "full":
                features.append("WebSocket XSS")

            if getattr(self.config, 'test_post_methods', False):
                features.append("POST/JSON Params")
            if getattr(self.config, 'test_headers', False):
                features.append("Header Params")
            if getattr(self.config, 'test_cookies', False):
                features.append("Cookie Params")
            if getattr(self.config, 'test_path_params', False):
                features.append("Path Params")

            if getattr(self.config, 'deep_scan', False):
                features.append("Deep Scan")
            if getattr(self.config, 'aggressive_mode', False):
                features.append("Aggressive")
            if getattr(self.config, 'verified_only', False):
                features.append("Verified Only")

            if self.config.collaborator_url:
                features.append("Blind XSS (Collaborator)")
            if self.interactsh:
                features.append("OAST (Interactsh)")
            if getattr(self.http_client, '_proxy_rotator', None) and self.http_client._proxy_rotator.available:
                features.append("Proxy Rotation")
            if getattr(self.config, 'dynamic_crawling', False):
                features.append("Dynamic SPA Crawling")
            if self.notifier:
                features.append("Webhook Notifications")

            print_scan_config(
                target_url, scan_mode, self.config,
                authenticated=self.http_client.authenticated,
                features=features or None,
            )
        
        if self.notifier:
            self.notifier.notify_scan_start(target_url, scan_mode)

        # Phase 5: Register and start OAST polling
        if self.interactsh:
            if self.interactsh.register():
                def _on_blind_hit(hit):
                    if not self.config.quiet:
                        console.print(
                            f"[bold red][!] BLIND XSS CALLBACK DETECTED![/bold red] "
                            f"Protocol: {hit.get('protocol', '?')} | "
                            f"From: {hit.get('remote_address', '?')}"
                        )

                self.interactsh.start_polling(on_interaction=_on_blind_hit, interval=5)
                if not self.config.quiet:
                    print_info(f"OAST polling active: {self.interactsh.interaction_url}")
                # Make the OAST URL available to XSS engine as collaborator
                if not self.config.collaborator_url:
                    self.config.collaborator_url = self.interactsh.get_interaction_url()
            else:
                if not self.config.quiet:
                    print_info("OAST registration failed — continuing without Interactsh")
                self.interactsh = None
        
        try:
            if not self.config.quiet:
                print_phase(1, "WAF Detection", "[WAF]")

            _t = self._phase_start('waf_detection')
            try:
                waf_result = self.analyzer.detect_waf(target_url)
            except Exception:
                self._phase_end('waf_detection', _t, error=True)
                raise
            self._phase_end('waf_detection', _t)
            
            if self._interrupted:
                return self._handle_interruption(target_url, waf_result, [])
            
            if waf_result['detected']:
                if not self.config.quiet:
                    print_result(False, f"WAF Detected: [bold]{waf_result['name']}[/bold] (Confidence: {waf_result['confidence']}%)")
                    print_info("Applying bypass techniques...")
            else:
                if not self.config.quiet:
                    print_result(True, "No WAF detected")
            
            if not self.config.quiet:
                print_phase(2, "Content Security Policy", "[CSP]")

            _t = self._phase_start('csp_analysis')
            try:
                csp_result = self.analyzer.analyze_csp(target_url)
            except Exception:
                self._phase_end('csp_analysis', _t, error=True)
                raise
            self._phase_end('csp_analysis', _t)
            
            if csp_result['has_csp']:
                summary = self.csp_analyzer.get_summary(csp_result)
                if not self.config.quiet:
                    if csp_result['xss_exploitable']:
                        print_result(False, summary)
                    else:
                        print_result(True, summary)
                    for detail in csp_result['details'][:3]:
                        print_detail(detail)
            else:
                if not self.config.quiet:
                    print_result(False, "No CSP header found - XSS payloads will execute if reflected")
            
            if self._interrupted:
                return self._handle_interruption(target_url, waf_result, [])
            
            crawled_urls = []
            
            if scan_mode == "full":
                if self.session.get_crawled_urls_data():
                    crawled_urls = self.session.get_crawled_urls_data()
                    if not self.config.quiet:
                        print_phase(3, f"Using {len(crawled_urls)} Previously Crawled URLs", "[CRAWL]")
                else:
                    if not self.config.quiet:
                        print_phase(3, "Crawling Target", "[CRAWL]")
                    
                    with Progress(
                        SpinnerColumn(),
                        TextColumn("[progress.description]{task.description}"),
                        BarColumn(complete_style="green", finished_style="green"),
                        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                        TimeElapsedColumn(),
                        transient=False,
                        console=console,
                    ) as progress:
                        task = progress.add_task("Crawling...", total=1, completed=0)
                        _t = self._phase_start('crawling')
                        try:
                            crawled_urls = self.crawler.crawl(target_url, progress, task)
                        except Exception:
                            self._phase_end('crawling', _t, error=True)
                            raise
                        self._phase_end('crawling', _t)
                    
                    self.session.set_crawled_urls_data(crawled_urls)
                
                if not crawled_urls:
                    if not self.config.quiet:
                        print_result(False, "Crawler returned no results - using target URL directly")
                        crawl_reason = getattr(self.crawler, 'last_error', None)
                        if crawl_reason:
                            print_detail(f"Crawler reason: {crawl_reason}")
                        if self.config.proxy:
                            print_detail(
                                "Proxy is enabled. Check Burp listener/upstream settings and keep Intercept off while crawling."
                            )
                    crawled_urls = [{'url': target_url, 'method': 'GET', 'parameters': [], 'forms': [], 'js_files': []}]

                self.session.statistics['urls_crawled'] = len(crawled_urls)

                crawled_urls = self._prioritize_crawled_urls(crawled_urls)

                if not self.config.quiet:
                    print_result(True, f"Found {len(crawled_urls)} URLs")
                    blocked_like = False
                    if crawled_urls:
                        blocked_like = all((u.get('status_code') or 0) >= 400 for u in crawled_urls)
                        if not blocked_like:
                            for u in crawled_urls[:5]:
                                body = (u.get('response_text') or '')[:2000]
                                if re.search(r'cloudflare|cf-chl|attention required|captcha', body, re.I):
                                    blocked_like = True
                                    break
                    if blocked_like:
                        print_result(
                            False,
                            "Target appears behind anti-bot/WAF challenge (403/blocked page). "
                            "Crawler cannot enumerate real URLs without a valid browser session.",
                        )
                
                if self._interrupted:
                    return self._handle_interruption(target_url, waf_result, crawled_urls)
                
                if not self.config.quiet:
                    print_phase(4, "Parameter Discovery", "[PARAM]")
                
                total_params_found = 0
                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(complete_style="cyan", finished_style="green"),
                    TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                    TextColumn("[dim]|[/dim]"),
                    TextColumn("[cyan]{task.fields[params]}[/cyan]"),
                    TimeElapsedColumn(),
                    transient=False,
                    console=console,
                ) as progress:
                    task = progress.add_task(
                        "Discovering params...", total=len(crawled_urls), params="0 params"
                    )
                    
                    def _find_params_for_url(url_data):
                        """Find parameters for a single URL (thread-safe)"""
                        cached_html = url_data.get('response_text')
                        url = url_data['url']
                        
                        params = self.param_finder.find_parameters(
                            url, response_text=cached_html or None
                        )
                        
                        if getattr(self.config, 'test_headers', False):
                            header_params = self.param_finder.find_header_parameters(url)
                            params.extend(header_params)
                        
                        if getattr(self.config, 'test_cookies', False):
                            cookie_params = self.param_finder.find_cookie_parameters(url)
                            params.extend(cookie_params)
                        
                        if getattr(self.config, 'test_path_params', False):
                            path_params = self.param_finder.find_path_parameters(url)
                            params.extend(path_params)
                        
                        return url_data, params
                    
                    param_workers = max(1, min(self.config.threads, len(crawled_urls), 10))
                    _t = self._phase_start('parameter_discovery')
                    with ThreadPoolExecutor(max_workers=param_workers) as executor:
                        futures = [executor.submit(_find_params_for_url, ud) for ud in crawled_urls]
                        
                        for future in as_completed(futures):
                            if self._interrupted:
                                break
                            try:
                                url_data, params = future.result()
                            except Exception:
                                progress.update(task, advance=1, params=f"{total_params_found} params")
                                continue
                            
                            if params:
                                existing = url_data.get('parameters', [])
                                pre_existing_len = len(existing)
                                existing_keys = set()
                                for ep in existing:
                                    key = (ep.get('name', ''), ep.get('location', ''))
                                    existing_keys.add(key)
                                
                                for new_param in params:
                                    key = (new_param.get('name', ''), new_param.get('location', ''))
                                    if key not in existing_keys:
                                        existing.append(new_param)
                                        existing_keys.add(key)
                                
                                url_data['parameters'] = existing
                                added_now = max(0, len(existing) - pre_existing_len)
                                total_params_found += added_now
                                self.session.increment_stat('params_found', added_now)
                            
                            progress.update(task, advance=1, params=f"{total_params_found} params")
                            self._phase_end('parameter_discovery', _t)
                
                if not self.config.quiet:
                    print_result(True, f"Found {self.session.statistics['params_found']} parameters")
            
            else:
                crawled_urls = [{'url': target_url, 'method': 'GET', 'parameters': []}]
                
                if not self.config.quiet:
                    print_phase(3, "Parameter Discovery", "[PARAM]")
                
                params = self.param_finder.find_parameters(target_url)
                if params:
                    crawled_urls[0]['parameters'] = params
                    self.session.increment_stat('params_found', len(params))
                    if not self.config.quiet:
                        print_result(True, f"Found {len(params)} parameters")
                else:
                    if not self.config.quiet:
                        print_result(False, "No parameters found")
            
            if self._interrupted:
                return self._handle_interruption(target_url, waf_result, crawled_urls)
            
            step_num = 5 if scan_mode == "full" else 4
            if not self.config.quiet:
                print_phase(step_num, "XSS Vulnerability Testing", "[XSS]")
            
            total_params_to_test = sum(
                len(ud.get('parameters', [])) or 1 for ud in crawled_urls
            )
            
            self.xss_engine.payloads_tested = 0
            self.xss_engine.candidates_detected = 0
            self.xss_engine.filtered_low_confidence = 0
            self.xss_engine.filtered_unverified = 0
            vulns_found_count = 0
            _vulns_lock = threading.Lock()
            
            xss_workers = max(1, min(self.config.threads, len(crawled_urls), 10))
            
            def _test_single_url(url_data):
                """Test a single URL for XSS (runs in thread pool)"""
                if self._interrupted:
                    return []
                
                from urllib.parse import urlparse as _scope_urlparse
                url_to_test = url_data.get('url', '')
                parsed_url = _scope_urlparse(url_to_test)
                url_path = parsed_url.path or '/'
                
                if self.config.include_patterns:
                    import re as _re
                    if not any(_re.search(p, url_path, _re.IGNORECASE) for p in self.config.include_patterns):
                        return []  # URL doesn't match any include pattern
                
                if self.config.exclude_patterns:
                    import re as _re
                    if any(_re.search(p, url_path, _re.IGNORECASE) for p in self.config.exclude_patterns):
                        return []  # URL matches an exclude pattern
                
                params = url_data.get('parameters', [])
                if not params:
                    params = [{'name': 'test', 'location': 'query'}]
                
                if not getattr(self.config, 'test_post_methods', False):
                    has_non_post = any(
                        p.get('location', 'query') not in ('POST', 'json_body')
                        for p in params
                    )
                    if not has_non_post:
                        seen = set()
                        query_variants = []
                        for p in params:
                            name = p.get('name', '')
                            if name and name not in seen:
                                seen.add(name)
                                query_variants.append({'name': name, 'location': 'query'})
                        if not query_variants:
                            query_variants = [{'name': 'test', 'location': 'query'}]
                        params = list(params) + query_variants
                
                return self.exploiter.scan_reflected(
                    url_data['url'],
                    params,
                    waf_result['name'] if waf_result['detected'] else None,
                    session=self.session
                )
            
            dom_urls = [u for u in crawled_urls[:20] if u.get('response_text')]
            all_params_for_mxss = []
            if getattr(self.config, 'test_mxss', True) and scan_mode == "full":
                for ud in crawled_urls[:30]:
                    for p in ud.get('parameters', []):
                        if p.get('location', 'query') in ('query', 'url', 'GET', 'path'):
                            all_params_for_mxss.append((ud['url'], p))
            angular_urls = crawled_urls[:20] if (getattr(self.config, 'test_angular', True) and scan_mode == "full") else []
            ws_urls = crawled_urls[:10] if (getattr(self.config, 'test_websockets', False) and scan_mode == "full") else []
            stored_units = 1 if (self.config.stored_xss_enabled and scan_mode == "full") else 0
            graphql_units = 1 if (getattr(self.config, 'test_graphql', True) and scan_mode == "full") else 0

            total_xss_units = (
                len(crawled_urls)
                + stored_units
                + len(dom_urls)
                + len(all_params_for_mxss)
                + len(angular_urls)
                + graphql_units
                + len(ws_urls)
            )
            if total_xss_units <= 0:
                total_xss_units = 1

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                TextColumn("[dim]|[/dim]"),
                TextColumn("[cyan]{task.fields[module]}[/cyan]"),
                TextColumn("[dim]|[/dim]"),
                TextColumn("[cyan]{task.fields[payloads]} payloads[/cyan]"),
                TextColumn("[dim]|[/dim]"),
                TextColumn("[red]{task.fields[vulns]} vulns[/red]"),
                TextColumn("[dim]|[/dim]"),
                TimeElapsedColumn(),
                console=console,
            ) as progress:
                task = progress.add_task(
                    "Testing XSS...", total=total_xss_units,
                    module="Reflected XSS", payloads="0", vulns="0"
                )

                with ThreadPoolExecutor(max_workers=xss_workers) as executor:
                    reflected_queue = self._build_reflected_task_queue(crawled_urls)
                    lease_seconds = max(10, int(getattr(self.config, 'task_lease_seconds', 120) or 120))
                    max_attempts = max(1, int(getattr(self.config, 'task_max_retries', 3) or 3) + 1)
                    task_durations: List[float] = []

                    while not self._interrupted:
                        self._maybe_apply_budget_fallback()
                        reflected_queue.release_expired()
                        if bool(getattr(self.config, 'dynamic_task_lease', True)) and task_durations:
                            avg_task = sum(task_durations[-20:]) / max(1, len(task_durations[-20:]))
                            lease_seconds = max(10, int(max(avg_task * 3.0, float(getattr(self.config, 'task_lease_seconds', 120) or 120))))
                        claimed = reflected_queue.claim(
                            worker_id=self._task_worker_id,
                            max_items=xss_workers,
                            lease_seconds=lease_seconds,
                            task_type='reflected_xss',
                            max_attempts=max_attempts,
                        )

                        if not claimed:
                            if reflected_queue.pending_count == 0 and reflected_queue.inflight_count == 0:
                                break
                            self.session.set_task_queue_state(
                                reflected_queue.snapshot(queue_name='reflected_xss')
                            )
                            self._maybe_checkpoint()
                            time.sleep(0.05)
                            continue

                        futures = {
                            executor.submit(_test_single_url, item['payload']['url_data']): item
                            for item in claimed
                        }

                        for future in as_completed(futures):
                            if self._interrupted:
                                import sys
                                if sys.version_info >= (3, 9):
                                    executor.shutdown(wait=False, cancel_futures=True)
                                else:
                                    executor.shutdown(wait=False)
                                break

                            item = futures[future]
                            task_id = item['id']
                            started = time.time()
                            try:
                                vulns = future.result()
                                reflected_queue.ack([task_id])
                            except Exception:
                                reflected_queue.nack([task_id], requeue=True)
                                if self.config.verbose:
                                    import traceback
                                    traceback.print_exc()
                                vulns = []
                            task_durations.append(max(0.0, time.time() - started))

                            if vulns:
                                for vuln in vulns:
                                    with _vulns_lock:
                                        self.session.add_vulnerability(vuln)
                                        vulns_found_count += 1
                                    if not self.config.quiet:
                                        vuln_type = vuln.get('type', 'reflected').replace('_', ' ').title()
                                        conf = vuln.get('confidence', '')
                                        print_vuln_alert(
                                            vuln_type,
                                            vuln['parameter'],
                                            vuln.get('url', ''),
                                            conf if isinstance(conf, int) else None,
                                            use_console=progress.console,
                                        )
                                    if self.notifier:
                                        self.notifier.notify_vulnerability(vuln, target_url)

                            self.session.set_task_queue_state(
                                reflected_queue.snapshot(queue_name='reflected_xss')
                            )
                            self._maybe_checkpoint()
                            if self._check_scan_budget():
                                self._interrupted = True
                                self._stop_scan()
                                break

                            progress.update(
                                task,
                                advance=1,
                                module="Reflected XSS",
                                payloads=str(self.xss_engine.payloads_tested),
                                vulns=str(vulns_found_count),
                            )

                    if reflected_queue.pending_count == 0 and reflected_queue.inflight_count == 0:
                        self.session.set_task_queue_state({})

                    dead_letters = reflected_queue.dead_letters()
                    if dead_letters and not self.config.quiet:
                        print_detail(f"Dead-letter tasks: {len(dead_letters)}")

                if self.xss_engine.payloads_tested == 0 and not self._interrupted:
                    try:
                        fallback_param = [{
                            'name': '__akha_force_test__',
                            'location': 'query',
                        }]
                        forced_vulns = self.exploiter.scan_reflected(
                            target_url,
                            fallback_param,
                            waf_result['name'] if waf_result['detected'] else None,
                            session=self.session,
                        )
                        if forced_vulns:
                            for vuln in forced_vulns:
                                self.session.add_vulnerability(vuln)
                                vulns_found_count += 1
                                if not self.config.quiet:
                                    vuln_type = vuln.get('type', 'reflected').replace('_', ' ').title()
                                    conf = vuln.get('confidence', '')
                                    print_vuln_alert(
                                        vuln_type,
                                        vuln['parameter'],
                                        vuln.get('url', ''),
                                        conf if isinstance(conf, int) else None,
                                        use_console=progress.console,
                                    )
                    except Exception:
                        logger.debug("Forced fallback reflected scan failed", exc_info=True)

                if self.config.stored_xss_enabled and scan_mode == "full" and not self._interrupted:
                    stored_vulns = self.xss_engine.check_stored_xss(crawled_urls)
                    if stored_vulns:
                        for vuln in stored_vulns:
                            self.session.add_vulnerability(vuln)
                            vulns_found_count += 1
                            if not self.config.quiet:
                                print_vuln_alert(
                                    "Stored XSS",
                                    vuln.get('injection_point', 'unknown'),
                                    vuln['url'],
                                    use_console=progress.console,
                                )
                    progress.update(
                        task,
                        advance=1,
                        module="Stored XSS",
                        payloads=str(self.xss_engine.payloads_tested),
                        vulns=str(vulns_found_count),
                    )

                if not self._interrupted:
                    total_dom = len(dom_urls)
                    for idx, url_data in enumerate(dom_urls, 1):
                        if self._interrupted:
                            self.dom_scanner.interrupted = True
                            break
                        dom_vulns = self.dom_scanner.scan(
                            url_data['url'],
                            response_text=url_data.get('response_text'),
                        )
                        for dv in dom_vulns:
                            self.session.add_vulnerability(dv)
                            vulns_found_count += 1
                            if not self.config.quiet:
                                print_vuln_alert(
                                    "DOM XSS",
                                    dv.get('parameter', 'sink'),
                                    dv['url'],
                                    use_console=progress.console,
                                )
                        progress.update(
                            task,
                            advance=1,
                            module=f"DOM XSS {idx}/{total_dom}" if total_dom else "DOM XSS",
                            payloads=str(self.xss_engine.payloads_tested),
                            vulns=str(vulns_found_count),
                        )
                        self._maybe_checkpoint()
                        if self._check_scan_budget():
                            self._interrupted = True
                            self._stop_scan()
                            break

                self.dom_scanner.close()

                if getattr(self.config, 'test_mxss', True) and scan_mode == "full" and not self._interrupted:
                    total_mxss = len(all_params_for_mxss)
                    for idx, (mxss_url, mxss_param) in enumerate(all_params_for_mxss, 1):
                        if self._interrupted:
                            break
                        try:
                            mxss_findings = self.mxss_engine.scan(mxss_url, [mxss_param])
                            for mf in mxss_findings:
                                self.session.add_vulnerability(mf)
                                vulns_found_count += 1
                                if not self.config.quiet:
                                    print_vuln_alert(
                                        f"mXSS ({mf.get('subtype', '')})",
                                        mf['parameter'],
                                        mf['url'],
                                        use_console=progress.console,
                                    )
                        except Exception:
                            logger.debug("mXSS scan failed for %s", mxss_url, exc_info=True)
                        progress.update(
                            task,
                            advance=1,
                            module=f"mXSS {idx}/{total_mxss}" if total_mxss else "mXSS",
                            payloads=str(self.xss_engine.payloads_tested),
                            vulns=str(vulns_found_count),
                        )
                        self._maybe_checkpoint()
                        if self._check_scan_budget():
                            self._interrupted = True
                            self._stop_scan()
                            break

                if getattr(self.config, 'test_angular', True) and scan_mode == "full" and not self._interrupted:
                    total_angular = len(angular_urls)
                    for idx, ud in enumerate(angular_urls, 1):
                        if self._interrupted:
                            break
                        try:
                            angular_findings = self.angular_scanner.scan(
                                ud['url'], ud.get('parameters', [])
                            )
                            for af in angular_findings:
                                self.session.add_vulnerability(af)
                                vulns_found_count += 1
                                if not self.config.quiet:
                                    print_vuln_alert(
                                        "Angular CSTI",
                                        af['parameter'],
                                        af['url'],
                                        use_console=progress.console,
                                    )
                        except Exception:
                            logger.debug("Angular scan failed for %s", ud.get('url', ''), exc_info=True)
                        progress.update(
                            task,
                            advance=1,
                            module=f"Angular CSTI {idx}/{total_angular}" if total_angular else "Angular CSTI",
                            payloads=str(self.xss_engine.payloads_tested),
                            vulns=str(vulns_found_count),
                        )
                        self._maybe_checkpoint()
                        if self._check_scan_budget():
                            self._interrupted = True
                            self._stop_scan()
                            break

                if getattr(self.config, 'test_graphql', True) and scan_mode == "full" and not self._interrupted:
                    try:
                        graphql_findings = self.graphql_scanner.scan(target_url)
                        for gf in graphql_findings:
                            self.session.add_vulnerability(gf)
                            vulns_found_count += 1
                            if not self.config.quiet:
                                print_vuln_alert(
                                    "GraphQL XSS",
                                    gf.get('graphql_field', '?'),
                                    target_url,
                                    use_console=progress.console,
                                )
                    except Exception:
                        logger.debug("GraphQL scan failed for %s", target_url, exc_info=True)
                    progress.update(
                        task,
                        advance=1,
                        module="GraphQL XSS",
                        payloads=str(self.xss_engine.payloads_tested),
                        vulns=str(vulns_found_count),
                    )

                if getattr(self.config, 'test_websockets', False) and scan_mode == "full" and not self._interrupted:
                    total_ws = len(ws_urls)
                    for idx, ud in enumerate(ws_urls, 1):
                        if self._interrupted:
                            break
                        try:
                            ws_findings = self.websocket_scanner.scan(
                                ud['url'], ud.get('response_text', '')
                            )
                            for wf in ws_findings:
                                self.session.add_vulnerability(wf)
                                vulns_found_count += 1
                                if not self.config.quiet:
                                    print_vuln_alert(
                                        "WebSocket XSS",
                                        wf.get('websocket_url', '?'),
                                        use_console=progress.console,
                                    )
                        except Exception:
                            logger.debug("WebSocket scan failed for %s", ud.get('url', ''), exc_info=True)
                        progress.update(
                            task,
                            advance=1,
                            module=f"WebSocket XSS {idx}/{total_ws}" if total_ws else "WebSocket XSS",
                            payloads=str(self.xss_engine.payloads_tested),
                            vulns=str(vulns_found_count),
                        )
                        self._maybe_checkpoint()
                        if self._check_scan_budget():
                            self._interrupted = True
                            self._stop_scan()
                            break
            
            if self._interrupted:
                return self._handle_interruption(target_url, waf_result, crawled_urls)

            if self.xss_engine.payloads_tested == 0 and not self.config.quiet:
                print_result(
                    False,
                    "No payload requests were sent. Check target reachability, scope filters, and method flags (e.g. --test-post).",
                )
            elif vulns_found_count == 0 and not self.config.quiet:
                dropped_low_conf = getattr(self.xss_engine, 'filtered_low_confidence', 0)
                dropped_unverified = getattr(self.xss_engine, 'filtered_unverified', 0)
                candidates = getattr(self.xss_engine, 'candidates_detected', 0)

                if candidates > 0:
                    print_result(
                        False,
                        (
                            "XSS candidates were detected but filtered "
                            f"(low-confidence: {dropped_low_conf}, verified-only: {dropped_unverified}). "
                            "Try --aggressive or lower confidence threshold via config."
                        ),
                    )
            
            blind_xss_tracking = None
            if hasattr(self.xss_engine, 'blind_injector') and self.xss_engine.blind_injector:
                injector = self.xss_engine.blind_injector
                if injector.injection_count > 0:
                    tracking_path = injector.save_tracking()
                    blind_xss_tracking = injector.get_tracking_data()
                    if not self.config.quiet:
                        print_result(True, f"{injector.injection_count} payloads injected")
                        print_detail(f"Tracking file: {tracking_path}")
                        print_detail("Monitor your collaborator for callbacks")
            
            if self.session:
                self.session.statistics['requests_sent'] = int(self.http_client.request_count)
                self.session.increment_stat('payloads_tested', self.xss_engine.payloads_tested)
                self.session.end()
            self.controller.stop_monitoring()
            
            if self.config.learning_enabled:
                self.learning_engine.flush()
            
            if not self.config.quiet:
                self._print_summary(csp_result, blind_xss_tracking)
            
            report_paths = self._generate_reports(target_url, waf_result, crawled_urls, csp_result)
            
            if not self.config.quiet and report_paths:
                for fmt, path in report_paths.items():
                    print_result(True, f"[REPORT] {fmt.upper()} Report: [link=file://{path}]{path}[/link]")
            
            resume_path = os.path.join(self.config.output_dir, 'resume', 'scan_state.json')
            if os.path.exists(resume_path):
                try:
                    os.remove(resume_path)
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
            
            if self.notifier:
                self.notifier.notify_scan_complete(
                    target_url,
                    self.session.statistics,
                    len(self.session.vulnerabilities),
                    self.session.get_duration(),
                )
            
            if hasattr(self, 'xss_engine'):
                self.xss_engine.cleanup()

            return {
                'success': True,
                'vulnerabilities': self.session.vulnerabilities,
                'statistics': self.session.statistics,
            }
        
        except Exception as e:
            self.controller.stop_monitoring()
            if self.session:
                self.session.add_error(str(e))
                self.session.end()
            if hasattr(self, 'dom_scanner'):
                try:
                    self.dom_scanner.close()
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
            if hasattr(self, 'xss_engine'):
                try:
                    self.xss_engine.cleanup()
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
            if not self.config.quiet:
                console.print(f"\n[bold red][ERROR] Error during scan: {e}[/bold red]")
            return {'success': False, 'error': str(e)}
    
    def _handle_interruption(self, target_url: str, waf_result: Dict, crawled_urls: List[Dict]) -> Dict:
        """Handle scan interruption - generate report with findings so far"""
        self.controller.stop_monitoring()
        self.dom_scanner.interrupted = True
        self.session.increment_stat('payloads_tested', self.xss_engine.payloads_tested)
        self.session.statistics['requests_sent'] = int(self.http_client.request_count)
        
        if self.config.learning_enabled:
            self.learning_engine.flush()
        
        blind_xss_tracking = None
        if hasattr(self.xss_engine, 'blind_injector') and self.xss_engine.blind_injector:
            injector = self.xss_engine.blind_injector
            if injector.injection_count > 0:
                injector.save_tracking()
                blind_xss_tracking = injector.get_tracking_data()
        
        self.session.end()
        
        if not self.config.quiet:
            console.print("\n[bold yellow][!] Scan interrupted - generating report for findings so far.[/bold yellow]")
            if self._budget_stop_reason:
                print_detail(f"Budget stop reason: {self._budget_stop_reason}")
            self._print_summary(None, blind_xss_tracking)
        
        resume_path = self.session.save_resume_state(self.config.output_dir)
        if not self.config.quiet:
            print_result(False, f"[SAVE] Scan state saved. Resume with: [bold]--resume {resume_path}[/bold]")
        
        if self.session.vulnerabilities:
            report_paths = self._generate_reports(target_url, waf_result, crawled_urls, None)
            if not self.config.quiet and report_paths:
                for fmt, path in report_paths.items():
                    print_result(True, f"[REPORT] {fmt.upper()} Report (partial): [link=file://{path}]{path}[/link]")
        
        if hasattr(self, 'dom_scanner'):
            try:
                self.dom_scanner.close()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
        if hasattr(self, 'xss_engine'):
            try:
                self.xss_engine.cleanup()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)

        return {
            'success': True,
            'interrupted': True,
            'vulnerabilities': self.session.vulnerabilities,
            'statistics': self.session.statistics,
            'resume_file': resume_path,
        }
    
    def _format_duration(self, seconds: float) -> str:
        """Format duration in human-readable hours/minutes/seconds"""
        total = int(seconds)
        if total < 60:
            return f"{seconds:.2f} seconds"
        hours = total // 3600
        minutes = (total % 3600) // 60
        secs = total % 60
        parts = []
        if hours > 0:
            parts.append(f"{hours} hour{'s' if hours != 1 else ''}")
        if minutes > 0:
            parts.append(f"{minutes} minute{'s' if minutes != 1 else ''}")
        if secs > 0 or not parts:
            parts.append(f"{secs} second{'s' if secs != 1 else ''}")
        return " ".join(parts)
    
    def _print_summary(self, csp_result: Optional[Dict] = None, blind_xss_tracking: Optional[Dict] = None):
        """Print scan summary using the professional boxed layout."""
        if not self.session:
            return
        duration = self.session.get_duration()
        csp_summary = ""
        if csp_result and csp_result.get('has_csp'):
            csp_summary = self.csp_analyzer.get_summary(csp_result)
        print_scan_results(
            self.session,
            self._format_duration(duration),
            csp_result=csp_result,
            blind_xss_tracking=blind_xss_tracking,
            csp_summary=csp_summary,
        )
    
    def _generate_reports(self, target_url: str, waf_result: Dict, 
                          crawled_urls: List[Dict], csp_result: Optional[Dict] = None) -> Dict:
        """Generate reports in configured formats"""
        blind_xss_data = None
        if hasattr(self.xss_engine, 'blind_injector') and self.xss_engine.blind_injector:
            injector = self.xss_engine.blind_injector
            if injector.injection_count > 0:
                blind_xss_data = injector.get_tracking_data()
        
        report_data = {
            'target': target_url,
            'scan_mode': self.config.scan_mode,
            'vulnerabilities': self.session.vulnerabilities,
            'statistics': self.session.statistics,
            'telemetry': self.http_client.get_telemetry_snapshot(),
            'auth': self.http_client.get_auth_snapshot(),
            'module_metrics': self._module_metrics,
            'budget_fallback': {
                'enabled': bool(getattr(self.config, 'budget_auto_fallback', True)),
                'trigger': float(getattr(self.config, 'budget_fallback_trigger', 0.85) or 0.85),
                'activated': bool(self._budget_degraded),
            },
            'learning': self.learning_engine.get_stats() if self.config.learning_enabled else {},
            'waf': waf_result,
            'crawled_urls': crawled_urls,
            'start_time': self.session.start_time,
            'end_time': self.session.end_time,
            'duration': self.session.get_duration(),
            'csp': csp_result or {},
            'blind_xss': blind_xss_data,
        }

        # Phase 5: Append OAST callbacks to report & close client
        if self.interactsh:
            oast_hits = self.interactsh.get_all_callbacks()
            report_data['oast_callbacks'] = oast_hits
            if oast_hits and not self.config.quiet:
                console.print(f"[bold green][+] {len(oast_hits)} Blind XSS callback(s) captured via OAST[/bold green]")
            try:
                self.interactsh.close()
            except Exception:
                logger.debug("Interactsh close in report phase failed", exc_info=True)
        
        try:
            return self.reporter.generate(report_data)
        except Exception as e:
            logger.debug("Report generation failed", exc_info=True)
            if self.config.verbose:
                console.print(f"[red]Report generation error: {e}[/red]")
            return {}

