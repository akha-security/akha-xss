"""
Advanced web crawler for endpoint discovery
Inspired by Katana, Gospider, and Burp Suite crawling strategies.

Key features:
- Comprehensive HTML tag/attribute extraction (all link-bearing attributes)
- robots.txt and sitemap.xml parsing
- Wayback Machine (web.archive.org) URL discovery
- Deep JavaScript analysis (webpack, API routes, path patterns)
- HTML comment and meta tag URL extraction
- Path pattern deduplication (avoids crawling same template)
- Common endpoint probing
- Concurrent fetching with configurable workers
"""

import re
import json as _json
import xml.etree.ElementTree as ET
import logging
import hashlib
from urllib.parse import urljoin, urlparse, parse_qs, urlunparse, urlencode, quote
from typing import List, Dict, Set, Optional, Tuple
from bs4 import BeautifulSoup
import time
from collections import deque, defaultdict
import warnings
from concurrent.futures import ThreadPoolExecutor, as_completed

from akha.core.async_runner import AsyncRunner

try:
    from bs4 import XMLParsedAsHTMLWarning, MarkupResemblesLocatorWarning
    warnings.filterwarnings("ignore", category=XMLParsedAsHTMLWarning)
    warnings.filterwarnings("ignore", category=MarkupResemblesLocatorWarning)
except ImportError:
    class MarkupResemblesLocatorWarning(Warning):
        pass
    pass

warnings.filterwarnings("ignore", message=".*looks like.*")

logger = logging.getLogger("akha.crawler")


class Crawler:
    """Advanced web crawler with concurrent support and deep endpoint discovery"""

    URL_ATTRIBUTES = [
        'href', 'src', 'action', 'formaction', 'data-url', 'data-href',
        'data-src', 'data-action', 'data-link', 'data-uri', 'data-endpoint',
        'data-ajax', 'data-load', 'data-target', 'data-redirect',
        'poster', 'cite', 'background', 'longdesc', 'usemap',
        'ping', 'profile', 'xmlns',
        'data-background', 'data-image', 'data-source',
        'content',  # for meta tags with URLs
    ]

    SRCSET_TAGS = ['img', 'source', 'picture']

    COMMON_PATHS = [
        '/robots.txt', '/sitemap.xml', '/sitemap_index.xml',
        '/api', '/api/', '/api/v1/', '/api/v2/', '/api/v3/',
        '/graphql', '/graphiql',
        '/swagger.json', '/swagger/v1/swagger.json',
        '/openapi.json', '/api-docs',
        '/wp-json/', '/wp-json/wp/v2/',
        '/.well-known/security.txt',
        '/crossdomain.xml', '/clientaccesspolicy.xml',
        '/humans.txt', '/security.txt',
        '/admin/', '/login', '/register', '/signup',
        '/dashboard', '/panel', '/console',
        '/search', '/contact',
        '/wp-admin/', '/wp-login.php',
        '/administrator/', '/admin.php',
        '/user/login', '/account/login',
        '/.env', '/config.json', '/manifest.json',
        '/package.json', '/composer.json',
    ]

    JS_ENDPOINT_PATTERNS = [
        r'["\'](https?://[^\s"\'<>]+)["\']',
        r'["\'](/[a-zA-Z0-9_/\-.]+(?:\?[^"\']*)?)["\']',
        r'(?:url|endpoint|api_?url|base_?url|api_?path|route|path)\s*[:=]\s*["\']([^"\']+)["\']',
        r'fetch\s*\(\s*["\']([^"\']+)["\']',
        r'axios\.(?:get|post|put|delete|patch|head|options)\s*\(\s*["\']([^"\']+)["\']',
        r'\.open\s*\(\s*["\'][A-Z]+["\']\s*,\s*["\']([^"\']+)["\']',
        r'`(/[a-zA-Z0-9_/${}.\-]+)`',
        r'\$\.(?:ajax|get|post|getJSON)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:url|action)\s*:\s*["\']([^"\']+)["\']',
        r'(?:window|document)\.location(?:\.href)?\s*=\s*["\']([^"\']+)["\']',
        r'location\.(?:assign|replace)\s*\(\s*["\']([^"\']+)["\']',
        r'(?:path|to|redirect|component|from)\s*:\s*["\'](/[^"\']+)["\']',
        r'(?:navigate|push|replace|go)\s*\(\s*["\']([^"\']+)["\']',
        r'<(?:Route|Link|NavLink|Redirect)\s+[^>]*(?:to|path|href)\s*=\s*["\']([^"\']+)["\']',
        r'(?:query|mutation|subscription)\s+\w+\s*\{',
        r'__webpack_require__\.\w+\s*\+\s*["\']([^"\']+)["\']',
        r'(?:chunk|bundle|asset)s?\s*:\s*\{[^}]*["\']([^"\']+\.js)["\']',
    ]

    IGNORE_EXTENSIONS = frozenset([
        '.jpg', '.jpeg', '.png', '.gif', '.svg', '.ico', '.webp', '.bmp',
        '.avif', '.tiff', '.tif',
        '.css', '.woff', '.woff2', '.ttf', '.eot', '.otf',
        '.pdf', '.zip', '.tar', '.gz', '.rar', '.7z', '.bz2', '.xz',
        '.mp3', '.mp4', '.avi', '.mkv', '.mov', '.wmv', '.flv', '.ogg',
        '.wav', '.flac', '.aac', '.m4a', '.webm',
        '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.exe', '.dll', '.so', '.dmg', '.msi', '.deb', '.rpm',
        '.map',  # source maps (we parse them separately)
    ])

    SENSITIVE_PATHS = ['/.env', '/config.json', '/package.json', '/composer.json']
    SENSITIVE_PATTERNS = re.compile(
        r'(api[_-]?key|secret|password|token|db_pass|private_key)\s*[=:]\s*\S+',
        re.IGNORECASE,
    )

    def __init__(self, http_client, config):
        self.client = http_client
        self.config = config
        self.discovery_profile = self._resolve_discovery_profile()
        self.visited = set()
        self.visited_normalized = set()  # Normalized URLs to avoid duplicates
        self.results = []
        self.js_files = set()
        self.errors = 0
        self.max_errors = 30  # Stop if too many errors
        self.last_error = None

        self._path_patterns = defaultdict(int)  # pattern -> count
        self._max_same_pattern = 8 if config.deep_scan else 5

        self._base_url_override = {}  # page_url -> base_href

        self._include_patterns = []
        self._exclude_patterns = []
        if config.include_patterns:
            for p in config.include_patterns:
                try:
                    self._include_patterns.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass
        if config.exclude_patterns:
            for p in config.exclude_patterns:
                try:
                    self._exclude_patterns.append(re.compile(p, re.IGNORECASE))
                except re.error:
                    pass

        self._paused = False
        self._stopped = False

    def _resolve_discovery_profile(self) -> str:
        """Resolve discovery profile from config and authentication state."""
        profile = str(getattr(self.config, 'discovery_profile', 'auto') or 'auto').strip().lower()
        if profile in ('anonymous', 'authenticated', 'admin'):
            return profile

        authenticated = bool(getattr(self.client, 'authenticated', False))
        return 'authenticated' if authenticated else 'anonymous'

    @staticmethod
    def _state_fingerprint(url: str, html: str) -> str:
        """Generate compact fingerprint for SPA state deduplication."""
        route = ''
        try:
            parsed = urlparse(url or '')
            route = f"{parsed.path}?{parsed.query}".strip('?')
        except Exception:
            route = url or ''

        snippet = (html or '')[:4000]
        digest = hashlib.sha1(snippet.encode('utf-8', errors='ignore')).hexdigest()[:12]
        return f"{route}|{digest}"

    def _likely_markup(self, text: str) -> bool:
        """Fast check to avoid parsing plain-text bodies as HTML."""
        if not text:
            return False
        sample = text[:3000].lstrip()
        if not sample:
            return False
        return '<' in sample and '>' in sample

    def _build_soup(self, text: str, max_len: int, parser: str = 'html.parser'):
        """Safely construct BeautifulSoup without noisy locator warnings."""
        if not text:
            return None
        snippet = text[:max_len]
        if not self._likely_markup(snippet):
            return None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
                return BeautifulSoup(snippet, parser)
        except Exception:
            return None

    def stop(self):
        """Stop crawling"""
        self._stopped = True

    def pause(self):
        """Pause crawling"""
        self._paused = True

    def resume(self):
        """Resume crawling"""
        self._paused = False

    def crawl(self, start_url: str, progress=None, task=None) -> List[Dict]:
        """
        Crawl website starting from start_url with multi-source URL discovery.

        Args:
            start_url: Starting URL
            progress: Rich progress object (optional)
            task: Progress task ID (optional)

        Returns:
            List of discovered URLs with metadata
        """
        base_domain = urlparse(start_url).netloc
        queue = deque()  # (url, depth)
        discovered_count = 0
        self.last_error = None

        try:
            initial_resp = self.client.get(start_url, timeout=min(self.config.timeout, 15))
            resolved_url = initial_resp.url
            resolved_domain = urlparse(resolved_url).netloc
            challenge_detected = self._looks_like_bot_challenge(initial_resp)

            self._valid_domains = {base_domain.lower(), resolved_domain.lower()}

            for d in list(self._valid_domains):
                if d.startswith('www.'):
                    self._valid_domains.add(d[4:])
                else:
                    self._valid_domains.add(f'www.{d}')

            try:
                result = self._parse_response(resolved_url, initial_resp, 0)
                if result:
                    self.results.append(result)
                    discovered_count += 1
                    self.visited.add(resolved_url)
                    self.visited_normalized.add(self._normalize_url(resolved_url))

                    ct = initial_resp.headers.get('Content-Type', '').lower()
                    if 'text/html' in ct or 'application/xhtml' in ct:
                        initial_links = self._extract_all_links(resolved_url, initial_resp.text, resolved_domain)
                        for link in initial_links:
                            if self._is_challenge_noise_url(link):
                                continue
                            norm = self._normalize_url(link)
                            if norm not in self.visited_normalized:
                                queue.append((link, 1))

                        try:
                            form_links = self._submit_forms_for_discovery(resolved_url, initial_resp.text, resolved_domain)
                            for link in form_links:
                                if self._is_challenge_noise_url(link):
                                    continue
                                norm = self._normalize_url(link)
                                if norm not in self.visited_normalized:
                                    queue.append((link, 1))
                        except Exception:
                            logger.debug("Suppressed exception", exc_info=True)

                    if challenge_detected or getattr(self.config, 'dynamic_crawling', False):
                        rendered_links, rendered_html = self._browser_render_discovery(
                            resolved_url,
                            resolved_domain,
                        )
                        for link in rendered_links:
                            if self._is_challenge_noise_url(link):
                                continue
                            norm = self._normalize_url(link)
                            if norm not in self.visited_normalized:
                                queue.append((link, 1))

                        if rendered_html:
                            result['response_text'] = rendered_html[:500000]

                        if self.config.verbose and rendered_links:
                            print(f"[crawler] Browser dynamic discovery found {len(rendered_links)} URLs")

                    if result.get('js_files'):
                        self.js_files.update(result['js_files'])
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)

            if resolved_url != start_url:
                norm_start = self._normalize_url(start_url)
                if norm_start not in self.visited_normalized:
                    queue.append((start_url, 0))

        except Exception as e:
            self.last_error = f"Initial crawl request failed: {e}"
            self._valid_domains = {base_domain.lower()}
            if base_domain.lower().startswith('www.'):
                self._valid_domains.add(base_domain.lower()[4:])
            else:
                self._valid_domains.add(f'www.{base_domain.lower()}')
            queue.append((start_url, 0))

        passive_urls = self._passive_discovery(start_url, base_domain)
        for purl in passive_urls:
            norm = self._normalize_url(purl)
            if norm not in self.visited_normalized:
                queue.append((purl, 1))

        while queue and len(self.results) < self.config.max_pages:
            if self._stopped:
                break

            while self._paused:
                time.sleep(0.5)
                if self._stopped:
                    break

            if self._stopped:
                break

            if self.errors >= self.max_errors:
                break

            batch = []
            batch_limit = 30 if self.config.deep_scan else 20
            batch_size = min(batch_limit, self.config.threads, len(queue))
            candidates = self._pop_priority_batch(queue, batch_size)
            for url, depth in candidates:

                normalized = self._normalize_url(url)
                if normalized in self.visited_normalized or depth > self.config.max_depth:
                    continue

                if not self._is_in_scope(url, base_domain):
                    continue

                pattern = self._get_path_pattern(url)
                if pattern and self._path_patterns[pattern] >= self._max_same_pattern:
                    continue
                if pattern:
                    self._path_patterns[pattern] += 1

                self.visited.add(url)
                self.visited_normalized.add(normalized)
                batch.append((url, depth))

            if not batch:
                continue

            with ThreadPoolExecutor(max_workers=min(len(batch), self.config.threads)) as executor:
                futures = {
                    executor.submit(self._fetch_and_parse, url, depth, base_domain): (url, depth)
                    for url, depth in batch
                }

                for future in as_completed(futures):
                    url, depth = futures[future]
                    try:
                        result, links = future.result()
                        if result:
                            self.results.append(result)
                            discovered_count += 1
                            self.errors = 0

                        if depth < self.config.max_depth and links:
                            for link in links:
                                normalized_link = self._normalize_url(link)
                                if normalized_link not in self.visited_normalized:
                                    queue.append((link, depth + 1))

                    except Exception as e:
                        self.errors += 1
                        if self.config.verbose:
                            print(f"Error crawling {url}: {e}")

            if progress and task is not None:
                current_found = len(self.results)
                pending = len(queue)
                total_estimate = max(current_found + pending, discovered_count + 1, current_found + 1)
                total_estimate = min(total_estimate, self.config.max_pages)

                progress.update(
                    task,
                    completed=current_found,
                    total=total_estimate,
                    description=f"Crawling... ({current_found} pages found, {pending} queued)"
                )

            time.sleep(0.02)

        if progress and task is not None:
            final_count = len(self.results)
            progress.update(task, completed=final_count, total=final_count,
                          description=f"Crawling complete ({final_count} pages)")
            time.sleep(0.1)

        if self.config.parse_js and self.js_files:
            self._deep_parse_javascript_files(base_domain)

        return self.results

    def _url_risk_score(self, url: str, depth: int = 0) -> int:
        """Heuristic risk score used to prioritize crawl queue candidates."""
        u = (url or '').lower()
        score = 0

        if '?' in u:
            score += 3

        hot_tokens = (
            'search', 'query', 'redirect', 'return=', 'next=', 'callback',
            '/api/', '/graphql', '/auth/', '/login', '/account', '/profile',
            '/comment', '/feedback', '/contact',
        )
        for token in hot_tokens:
            if token in u:
                score += 4

        if u.endswith(('.php', '.asp', '.aspx', '.jsp')):
            score += 2

        score -= min(max(depth, 0), 6)
        return score

    def _pop_priority_batch(self, queue: deque, batch_size: int) -> List[Tuple[str, int]]:
        """Pop a crawl batch from queue, optionally prioritizing high-risk URLs."""
        if not queue or batch_size <= 0:
            return []

        if not bool(getattr(self.config, 'risk_prioritization', True)):
            out = []
            for _ in range(min(batch_size, len(queue))):
                out.append(queue.popleft())
            return out

        lookahead = min(len(queue), max(batch_size * 4, batch_size))
        window = [queue.popleft() for _ in range(lookahead)]
        window.sort(key=lambda item: -self._url_risk_score(item[0], item[1]))

        selected = window[:batch_size]
        leftovers = window[batch_size:]
        for item in leftovers:
            queue.appendleft(item)

        return selected

    @staticmethod
    def _is_challenge_noise_url(url: str) -> bool:
        """Return True for known anti-bot helper paths that are not crawl targets."""
        try:
            p = urlparse(url)
            path = (p.path or '').lower()
            host = (p.netloc or '').lower()
        except Exception:
            return False

        if path.startswith('/cdn-cgi/'):
            return True
        if 'cloudflare.com' in host:
            return True
        if '/5xx-error-landing' in path:
            return True
        return False

    def _looks_like_bot_challenge(self, response) -> bool:
        """Detect common anti-bot/challenge responses (Cloudflare/Akamai/etc.)."""
        try:
            status = int(getattr(response, 'status_code', 0) or 0)
            server = (response.headers.get('Server', '') or '').lower()
            body = (response.text or '')[:12000].lower()

            challenge_markers = (
                'cf-chl', 'cloudflare', 'attention required', 'captcha',
                'access denied', 'just a moment', 'bot challenge',
                'akamai', 'incapsula', 'perimeterx',
            )

            if status in (403, 429, 503):
                if any(m in body for m in challenge_markers):
                    return True
                if any(w in server for w in ('cloudflare', 'akamai', 'sucuri')):
                    return True

            return any(m in body for m in ('cf-chl', 'attention required', 'just a moment'))
        except Exception:
            return False

    def _browser_render_discovery(self, url: str, base_domain: str) -> Tuple[List[str], str]:
        """Try one browser-render pass to extract links behind JS/challenge flows."""
        timeout = max(15, min(self.config.timeout * 4, 60))
        try:
            return AsyncRunner().run(
                self._browser_render_discovery_async(url, base_domain),
                timeout=timeout,
            )
        except Exception:
            logger.debug("Browser-render discovery failed", exc_info=True)
            return [], ""

    async def _browser_render_discovery_async(self, url: str, base_domain: str) -> Tuple[List[str], str]:
        """Async Playwright-based renderer used as a crawler fallback."""
        try:
            from playwright.async_api import async_playwright
        except Exception:
            return [], ""

        links: Set[str] = set()
        html = ""
        browser = None
        context = None
        page = None

        try:
            async with async_playwright() as pw:
                browser = await pw.chromium.launch(
                    headless=True,
                    args=[
                        "--no-sandbox",
                        "--disable-dev-shm-usage",
                        "--disable-gpu",
                        "--disable-background-networking",
                    ],
                )
                context = await browser.new_context(
                    ignore_https_errors=True,
                    user_agent=getattr(self.config, 'user_agent', None),
                )
                page = await context.new_page()

                async def _collect_from_current_page() -> str:
                    page_html = await page.content()

                    raw_candidates = await page.eval_on_selector_all(
                        'a[href],link[href],script[src],img[src],form[action]',
                        (
                            'els => els.map(e => '
                            "e.getAttribute('href') || e.getAttribute('src') || e.getAttribute('action')"
                            ').filter(Boolean)'
                        ),
                    )
                    for candidate in raw_candidates or []:
                        self._add_link(str(candidate), url, base_domain, links)

                    for candidate in self._extract_all_links(url, page_html, base_domain):
                        links.add(candidate)

                    return page_html

                await page.goto(
                    url,
                    wait_until='domcontentloaded',
                    timeout=max(self.config.timeout * 1000, 15000),
                )
                try:
                    await page.wait_for_load_state('networkidle', timeout=5000)
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)

                html = await _collect_from_current_page()

                if bool(getattr(self.config, 'stateful_spa_discovery', True)):
                    transition_budget = max(0, int(getattr(self.config, 'spa_state_transition_budget', 8) or 0))
                    if transition_budget > 0:
                        seen_states = {self._state_fingerprint(page.url, html)}
                        click_selectors = (
                            'a[href], button, [role="button"], [data-testid*="tab"], '
                            '[data-testid*="menu"], [aria-controls], [routerlink], [data-href]'
                        )
                        candidates = await page.query_selector_all(click_selectors)
                        steps = 0
                        for element in candidates:
                            if steps >= transition_budget:
                                break
                            try:
                                visible = await element.is_visible()
                                enabled = await element.is_enabled()
                                if not visible or not enabled:
                                    continue
                                await element.click(timeout=1200)
                                try:
                                    await page.wait_for_load_state('networkidle', timeout=2000)
                                except Exception:
                                    logger.debug("Suppressed exception", exc_info=True)

                                state_html = await _collect_from_current_page()
                                state_fp = self._state_fingerprint(page.url, state_html)
                                if state_fp not in seen_states:
                                    seen_states.add(state_fp)
                                    steps += 1
                                    if not html:
                                        html = state_html

                                try:
                                    await page.go_back(timeout=1500)
                                except Exception:
                                    logger.debug("Suppressed exception", exc_info=True)
                            except Exception:
                                logger.debug("Suppressed exception", exc_info=True)
        except Exception:
            logger.debug("Playwright render pass failed for %s", url, exc_info=True)
        finally:
            try:
                if page:
                    await page.close()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            try:
                if context:
                    await context.close()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            try:
                if browser:
                    await browser.close()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)

        return list(links), html


    def _passive_discovery(self, start_url: str, base_domain: str) -> List[str]:
        """
        Discover URLs from passive sources before active crawling.
        Inspired by Katana, Gospider passive mode.
        """
        urls = set()

        parsed = urlparse(start_url)
        base = f"{parsed.scheme}://{parsed.netloc}"

        robots_urls = self._parse_robots_txt(base, base_domain)
        urls.update(robots_urls)

        sitemap_urls = self._parse_sitemap(base, base_domain)
        urls.update(sitemap_urls)

        probe_urls = self._probe_common_paths(base, base_domain)
        urls.update(probe_urls)

        if getattr(self.config, 'probe_sensitive', False):
            self._probe_sensitive_files(base, base_domain)

        archive_urls = self._fetch_wayback_urls(base_domain)
        urls.update(archive_urls)

        return list(urls)

    def _parse_robots_txt(self, base_url: str, base_domain: str) -> Set[str]:
        """Parse robots.txt for Disallow/Allow/Sitemap entries"""
        urls = set()
        self._sitemap_urls_from_robots = []

        try:
            resp = self.client.get(f"{base_url}/robots.txt", timeout=8)
            if resp.status_code != 200:
                return urls

            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith('#'):
                    continue

                if line.lower().startswith('sitemap:'):
                    sitemap_url = line.split(':', 1)[1].strip()
                    self._sitemap_urls_from_robots.append(sitemap_url)
                    continue

                match = re.match(r'(?:dis)?allow:\s*(.+)', line, re.IGNORECASE)
                if match:
                    path = match.group(1).strip()
                    if path and path != '/' and '*' not in path:
                        path = path.split('?')[0].split('#')[0]
                        full_url = urljoin(base_url, path)
                        if self._is_in_scope(full_url, base_domain):
                            urls.add(full_url)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)

        return urls

    def _parse_sitemap(self, base_url: str, base_domain: str, depth: int = 0,
                       specific_urls: List[str] = None) -> Set[str]:
        """Recursively parse sitemap.xml and sitemap index files"""
        urls = set()

        if depth > 3:  # Prevent infinite recursion
            return urls

        if specific_urls:
            sitemap_urls_to_try = list(specific_urls)
        else:
            sitemap_urls_to_try = list(getattr(self, '_sitemap_urls_from_robots', []))
            if depth == 0:
                sitemap_urls_to_try.extend([
                    f"{base_url}/sitemap.xml",
                    f"{base_url}/sitemap_index.xml",
                    f"{base_url}/sitemap1.xml",
                    f"{base_url}/sitemap.xml.gz",
                    f"{base_url}/sitemaps.xml",
                    f"{base_url}/post-sitemap.xml",
                    f"{base_url}/page-sitemap.xml",
                    f"{base_url}/category-sitemap.xml",
                ])

        seen_sitemaps = set()
        for sitemap_url in sitemap_urls_to_try:
            if sitemap_url in seen_sitemaps:
                continue
            seen_sitemaps.add(sitemap_url)

            try:
                resp = self.client.get(sitemap_url, timeout=10)
                if resp.status_code != 200:
                    continue

                content = resp.text[:2_000_000]  # 2MB limit

                try:
                    root = ET.fromstring(content)
                    ns = ''
                    ns_match = re.match(r'\{(.+?)\}', root.tag)
                    if ns_match:
                        ns = ns_match.group(0)

                    child_sitemap_urls = []
                    for sitemap_elem in root.findall(f'{ns}sitemap'):
                        loc_elem = sitemap_elem.find(f'{ns}loc')
                        if loc_elem is not None and loc_elem.text:
                            child_sitemap_urls.append(loc_elem.text.strip())
                    
                    if child_sitemap_urls:
                        child_urls = self._parse_sitemap(
                            base_url, base_domain, depth + 1,
                            specific_urls=child_sitemap_urls
                        )
                        urls.update(child_urls)

                    for url_elem in root.findall(f'{ns}url'):
                        loc_elem = url_elem.find(f'{ns}loc')
                        if loc_elem is not None and loc_elem.text:
                            full_url = loc_elem.text.strip()
                            if self._is_in_scope(full_url, base_domain):
                                urls.add(full_url)

                except ET.ParseError:
                    found = re.findall(r'<loc>(.*?)</loc>', content, re.IGNORECASE)
                    for u in found:
                        u = u.strip()
                        if self._is_in_scope(u, base_domain):
                            urls.add(u)

            except Exception:
                continue

            if len(urls) >= 500:
                break

        return urls

    def _probe_common_paths(self, base_url: str, base_domain: str) -> Set[str]:
        """Probe common paths to discover endpoints"""
        urls = set()

        path_limit = 50 if self.config.deep_scan else 30
        paths_to_probe = self.COMMON_PATHS[:path_limit]
        if not getattr(self.config, 'probe_sensitive', False):
            paths_to_probe = [p for p in paths_to_probe if p not in self.SENSITIVE_PATHS]

        with ThreadPoolExecutor(max_workers=min(10, self.config.threads)) as executor:
            futures = {}
            for path in paths_to_probe:
                full_url = f"{base_url}{path}"
                if self._is_in_scope(full_url, base_domain):
                    futures[executor.submit(self._probe_path, full_url)] = full_url

            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        urls.add(result)
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)

        return urls

    def _probe_path(self, url: str) -> Optional[str]:
        """Check if a path exists (returns URL if 2xx/3xx, None otherwise)"""
        try:
            resp = self.client.get(url, timeout=6)
            if resp.status_code < 400:
                return resp.url or url
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)
        return None

    def _fetch_wayback_urls(self, domain: str) -> Set[str]:
        """Fetch URLs from Wayback Machine CDX API (like Katana/Gospider/waybackurls)"""
        urls = set()

        try:
            cdx_url = (
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
                f"&filter=statuscode:200&limit=150"
            )
            resp = self.client.get(cdx_url, timeout=8)
            if resp.status_code != 200:
                return urls

            try:
                data = resp.json()
                clean_domain = domain.lower().lstrip('www.').lstrip('.')
                for row in data[1:]:
                    if row and row[0]:
                        wb_url = row[0]
                        parsed = urlparse(wb_url)
                        path_lower = parsed.path.lower()
                        if not any(path_lower.endswith(ext) for ext in self.IGNORE_EXTENSIONS):
                            netloc = parsed.netloc.lower()
                            if netloc == clean_domain or netloc.endswith('.' + clean_domain):
                                urls.add(wb_url)
            except (ValueError, IndexError, KeyError):
                pass

        except Exception:

            logger.debug("Suppressed exception", exc_info=True)

        return urls

    def _probe_sensitive_files(self, base_url: str, base_domain: str) -> List[Dict]:
        """Probe sensitive files and collect high-signal leaks only."""
        findings = []
        for path in self.SENSITIVE_PATHS:
            url = f"{base_url}{path}"
            if not self._is_in_scope(url, base_domain):
                continue
            try:
                resp = self.client.get(url, timeout=5)
                if resp.status_code == 200 and self.SENSITIVE_PATTERNS.search(resp.text):
                    findings.append({'url': url, 'type': 'sensitive_file_exposed'})
                    if self.config.verbose:
                        print(f"[sensitive] Potential secret exposure: {url}")
            except Exception:
                continue
        return findings


    def _fetch_and_parse(self, url: str, depth: int, base_domain: str) -> Tuple:
        """Fetch a URL and parse it, returning (result, links)"""
        links = []

        try:
            crawl_timeout = min(self.config.timeout, 10)
            response = self.client.get(url, timeout=crawl_timeout)

            if response.status_code >= 400:
                return None, links

            content_type = response.headers.get('Content-Type', '').lower()
            if ('text/html' in content_type or 'application/xhtml' in content_type) and depth < self.config.max_depth:
                try:
                    form_links = self._submit_forms_for_discovery(url, response.text, base_domain)
                    links.extend(form_links)
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)

            content_length = response.headers.get('Content-Length', 0)
            try:
                if content_length and int(content_length) > 2 * 1024 * 1024:
                    return None, links
            except (ValueError, TypeError):
                pass

            if len(response.content) > 3 * 1024 * 1024:  # 3MB
                return None, links

            result = self._parse_response(url, response, depth)

            if depth < self.config.max_depth:
                if 'text/html' in content_type or 'application/xhtml' in content_type:
                    links.extend(self._extract_all_links(url, response.text, base_domain))
                    if getattr(self.config, 'dynamic_crawling', False):
                        dynamic_links, dynamic_html = self._browser_render_discovery(url, base_domain)
                        links.extend(dynamic_links)
                        if dynamic_html:
                            result['response_text'] = dynamic_html[:500000]

            return result, links

        except Exception as e:
            if not self.last_error:
                self.last_error = f"Fetch failed for {url}: {e}"
            if self.config.verbose:
                print(f"Error fetching {url}: {e}")
            return None, links

    def _normalize_url(self, url: str) -> str:
        """Normalize URL to avoid duplicate crawling"""
        parsed = urlparse(url)

        path = parsed.path.rstrip('/') if parsed.path != '/' else '/'

        if parsed.query:
            params = sorted(parse_qs(parsed.query, keep_blank_values=True).items())
            query = '&'.join(f"{k}={v[0]}" if v and v[0] else k for k, v in params)
        else:
            query = ''

        normalized = urlunparse((
            parsed.scheme,
            parsed.netloc.lower(),
            path,
            '',
            query,
            ''
        ))
        return normalized

    def _get_path_pattern(self, url: str) -> Optional[str]:
        """
        Convert URL path to a pattern for deduplication.
        /user/123/profile -> /user/{id}/profile
        /post/my-first-post -> /post/{slug}
        This prevents crawling hundreds of pages with the same template.
        """
        parsed = urlparse(url)
        parts = parsed.path.strip('/').split('/')

        if len(parts) <= 1:
            return None  # Don't deduplicate root-level paths

        pattern_parts = []
        for part in parts:
            if re.match(r'^\d+$', part):
                pattern_parts.append('{id}')
            elif re.match(r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$', part, re.IGNORECASE):
                pattern_parts.append('{uuid}')
            elif re.match(r'^[0-9a-f]{16,}$', part, re.IGNORECASE):
                pattern_parts.append('{hash}')
            elif re.match(r'^\d{4}[-/]\d{2}[-/]\d{2}$', part):
                pattern_parts.append('{date}')
            elif re.match(r'^(?:19|20)\d{2}$', part):
                pattern_parts.append('{year}')
            elif len(part) > 50:
                pattern_parts.append('{slug}')
            elif re.match(r'^[a-z0-9][a-z0-9-]{7,39}$', part) and '-' in part:
                pattern_parts.append('{slug}')
            elif re.match(r'^[a-z0-9]{8,20}$', part) and any(c.isdigit() for c in part):
                pattern_parts.append('{id}')
            else:
                pattern_parts.append(part)

        pattern = '/' + '/'.join(pattern_parts)

        if parsed.query:
            param_names = sorted(parse_qs(parsed.query).keys())
            pattern += '?' + '&'.join(param_names)

        return pattern

    def _parse_response(self, url: str, response, depth: int) -> Dict:
        """Parse HTTP response and extract data"""
        content_type = response.headers.get('Content-Type', '')

        result = {
            'url': url,
            'method': 'GET',
            'status_code': response.status_code,
            'content_type': content_type,
            'depth': depth,
            'discovery_profile': self.discovery_profile,
            'parameters': self._extract_parameters(url),
            'forms': [],
            'js_files': [],
            'response_text': '',
        }

        ct_lower = content_type.lower()
        is_html = any(ct in ct_lower for ct in ['text/html', 'application/xhtml', 'text/xml', 'application/xml'])

        if is_html:
            result['response_text'] = response.text[:500000]
            if 'xml' in ct_lower and 'html' not in ct_lower:
                parser = 'xml'
            else:
                parser = 'html.parser'
            soup = self._build_soup(response.text, 500000, parser)
            if soup is None and parser != 'html.parser':
                soup = self._build_soup(response.text, 500000, 'html.parser')
            if soup is None:
                return result

            base_tag = soup.find('base', href=True)
            if base_tag:
                self._base_url_override[url] = urljoin(url, base_tag['href'])

            result['forms'] = self._extract_forms(soup, url)

            for form in result['forms']:
                form_action = form.get('action', url)
                form_method = form.get('method', 'GET')

                sibling_inputs = {}
                for other_inp in form.get('inputs', []):
                    if other_inp.get('name'):
                        sibling_inputs[other_inp['name']] = other_inp.get('value', '')

                for inp in form.get('inputs', []):
                    if inp.get('name'):
                        inp_type = inp.get('type', 'text').lower()
                        if inp_type == 'hidden':
                            continue

                        result['parameters'].append({
                            'name': inp['name'],
                            'value': inp.get('value', ''),
                            'type': 'form',
                            'location': form_method,
                            'form_action': form_action,
                            'form_inputs': sibling_inputs,
                        })

            js_files = self._extract_js_files(soup, url)
            result['js_files'] = js_files
            self.js_files.update(js_files)

        if self.config.api_mode and 'application/json' in ct_lower:
            try:
                json_body = _json.loads(response.text)
                if isinstance(json_body, dict):
                    api_params = self._extract_json_params(url, json_body)
                    result['parameters'].extend(api_params)
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)

        return result


    def _extract_all_links(self, base_url: str, html: str, base_domain: str) -> List[str]:
        """
        Comprehensive link extraction from HTML — covers all HTML tags,
        attributes, inline JS, CSS, comments, meta tags, and more.
        """
        links = set()

        effective_base = self._base_url_override.get(base_url, base_url)

        soup = self._build_soup(html, 500000, 'html.parser')
        if soup is None:
            return list(links)

        base_tag = soup.find('base', href=True)
        if base_tag:
            effective_base = urljoin(base_url, base_tag['href'])

        for tag in soup.find_all(True):
            for attr in self.URL_ATTRIBUTES:
                value = tag.get(attr)
                if value and isinstance(value, str):
                    if attr == 'content':
                        if not re.match(r'https?://|/', value):
                            continue
                    self._add_link(value, effective_base, base_domain, links)

            srcset = tag.get('srcset')
            if srcset and isinstance(srcset, str):
                for part in srcset.split(','):
                    part = part.strip().split()[0] if part.strip() else ''
                    if part:
                        self._add_link(part, effective_base, base_domain, links)

            if tag.name == 'meta':
                http_equiv = tag.get('http-equiv', '').lower()
                if http_equiv == 'refresh':
                    content = tag.get('content', '')
                    url_match = re.search(r'url\s*=\s*["\']?([^"\';\s]+)', content, re.IGNORECASE)
                    if url_match:
                        self._add_link(url_match.group(1), effective_base, base_domain, links)

                prop = tag.get('property', '') or tag.get('name', '')
                if prop.lower() in ('og:url', 'og:image', 'twitter:url', 'twitter:image'):
                    content = tag.get('content', '')
                    if content:
                        self._add_link(content, effective_base, base_domain, links)

        for script in soup.find_all('script', src=False):
            text = script.string or ''
            if text:
                js_links = self._extract_urls_from_js(text, effective_base, base_domain)
                links.update(js_links)

        from bs4 import Comment
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            comment_text = str(comment)
            comment_urls = re.findall(r'(?:href|src|action|url)\s*=\s*["\']([^"\']+)["\']', comment_text, re.IGNORECASE)
            for curl in comment_urls:
                self._add_link(curl, effective_base, base_domain, links)

            plain_urls = re.findall(r'(https?://[^\s<>"\']+)', comment_text)
            for purl in plain_urls:
                self._add_link(purl, effective_base, base_domain, links)

            rel_paths = re.findall(r'["\'](/[a-zA-Z0-9_/\-\.?&=%]+)["\']', comment_text)
            for rpath in rel_paths:
                self._add_link(rpath, effective_base, base_domain, links)

        for style_tag in soup.find_all('style'):
            css_text = style_tag.string or ''
            if css_text:
                css_urls = re.findall(r'url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)', css_text)
                for curl in css_urls:
                    self._add_link(curl, effective_base, base_domain, links)

        for tag in soup.find_all(style=True):
            style_val = tag.get('style', '')
            css_urls = re.findall(r'url\s*\(\s*["\']?([^"\')\s]+)["\']?\s*\)', style_val)
            for curl in css_urls:
                self._add_link(curl, effective_base, base_domain, links)

        for tag in soup.find_all(True):
            for attr_name, attr_val in tag.attrs.items():
                if attr_name.startswith('data-') and isinstance(attr_val, str) and len(attr_val) > 5:
                    if attr_val.startswith('{') or attr_val.startswith('['):
                        try:
                            data_obj = _json.loads(attr_val)
                            data_urls = self._extract_urls_from_json(data_obj)
                            for durl in data_urls:
                                self._add_link(durl, effective_base, base_domain, links)
                        except (ValueError, TypeError):
                            pass

        state_patterns = [
            r'(?:__NEXT_DATA__|__INITIAL_STATE__|__NUXT__|__APP_DATA__|window\.__data)\s*=\s*(\{.+?\})\s*;?\s*</script>',
            r'type\s*=\s*["\']application/json["\']\s*>(.*?)</script>',
        ]
        for pattern in state_patterns:
            for match in re.finditer(pattern, html, re.DOTALL | re.IGNORECASE):
                try:
                    state_data = _json.loads(match.group(1))
                    state_urls = self._extract_urls_from_json(state_data)
                    for surl in state_urls:
                        self._add_link(surl, effective_base, base_domain, links)
                except (ValueError, TypeError):
                    pass

        raw_urls = re.findall(
            r'(?:href|src|action|url|endpoint|redirect|next|return_url|continue|goto)\s*=\s*["\']([^"\']+)["\']',
            html, re.IGNORECASE
        )
        for rurl in raw_urls:
            self._add_link(rurl, effective_base, base_domain, links)

        return list(links)

    def _extract_urls_from_js(self, js_text: str, base_url: str, base_domain: str) -> Set[str]:
        """Extract URLs from JavaScript code using multiple pattern strategies"""
        urls = set()

        if len(js_text) < 10:
            return urls

        for pattern in self.JS_ENDPOINT_PATTERNS:
            try:
                matches = re.findall(pattern, js_text)
                for match in matches:
                    if not match or len(match) < 2:
                        continue
                    if any(x in match for x in ['${', '{{', '<%', 'node_modules', '.min.js',
                                                  '*.', 'example.com', 'localhost',
                                                  'schema.org', 'w3.org', 'xmlns']):
                        continue
                    if match.startswith('/') and len(match) <= 2:
                        continue
                    self._add_link(match, base_url, base_domain, urls)
            except re.error:
                continue

        obj_paths = re.findall(r'["\']([/][a-zA-Z][\w/\-\.]{2,})["\']', js_text)
        for path in obj_paths:
            if not any(x in path for x in ['node_modules', '.min.', 'example']):
                self._add_link(path, base_url, base_domain, urls)

        sourcemap_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', js_text)
        if sourcemap_match:
            map_url = sourcemap_match.group(1)
            if not map_url.startswith('data:'):
                self._add_link(map_url, base_url, base_domain, urls)

        return urls

    def _extract_urls_from_json(self, data, max_depth: int = 5) -> Set[str]:
        """Recursively extract URL-like values from JSON data"""
        urls = set()
        if max_depth <= 0:
            return urls

        if isinstance(data, dict):
            for key, value in data.items():
                if isinstance(value, str):
                    if value.startswith(('http://', 'https://', '/')):
                        urls.add(value)
                    elif key.lower() in ('url', 'href', 'link', 'path', 'endpoint',
                                         'redirect', 'src', 'action', 'uri', 'api',
                                         'route', 'page', 'next', 'prev', 'canonical'):
                        if value and not value.startswith('#') and '/' in value:
                            urls.add(value)
                elif isinstance(value, (dict, list)):
                    urls.update(self._extract_urls_from_json(value, max_depth - 1))
        elif isinstance(data, list):
            for item in data[:100]:  # Limit list items
                if isinstance(item, str):
                    if item.startswith(('http://', 'https://', '/')):
                        urls.add(item)
                elif isinstance(item, (dict, list)):
                    urls.update(self._extract_urls_from_json(item, max_depth - 1))

        return urls

    def _add_link(self, href: str, base_url: str, base_domain: str, links: set):
        """Process and add a link if valid"""
        if not href:
            return

        href = href.strip()
        if href.startswith(('javascript:', 'mailto:', 'tel:', '#', 'data:', 'blob:', 'about:')):
            return

        if len(href) > 2000:
            return

        try:
            absolute_url = urljoin(base_url, href)
            absolute_url = absolute_url.split('#')[0]

            if absolute_url and self._is_in_scope(absolute_url, base_domain):
                links.add(absolute_url)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)

    def _extract_parameters(self, url: str) -> List[Dict]:
        """Extract parameters from URL"""
        parsed = urlparse(url)
        params = []

        if parsed.query:
            query_params = parse_qs(parsed.query)
            for name, values in query_params.items():
                for value in values:
                    params.append({
                        'name': name,
                        'value': value,
                        'type': 'query',
                        'location': 'url',
                    })

        return params

    def _extract_json_params(self, url: str, json_body: dict,
                             prefix: str = '') -> List[Dict]:
        """Extract testable parameters from a JSON response body."""
        params = []
        for key, value in json_body.items():
            full_key = f"{prefix}.{key}" if prefix else key
            if isinstance(value, dict):
                params.extend(self._extract_json_params(url, value, full_key))
            elif isinstance(value, str):
                params.append({
                    'name': full_key,
                    'value': value,
                    'type': 'json',
                    'location': 'json_body',
                    'form_action': url,
                    'json_body': json_body,
                })
        return params

    def _extract_forms(self, soup: BeautifulSoup, base_url: str) -> List[Dict]:
        """Extract forms from HTML"""
        forms = []

        if not soup:
            return forms

        effective_base = self._base_url_override.get(base_url, base_url)

        for form in soup.find_all('form'):
            form_data = {
                'action': urljoin(effective_base, form.get('action', '')),
                'method': form.get('method', 'GET').upper(),
                'enctype': form.get('enctype', 'application/x-www-form-urlencoded'),
                'inputs': [],
            }

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                input_data = {
                    'name': input_tag.get('name', ''),
                    'type': input_tag.get('type', 'text'),
                    'value': input_tag.get('value', ''),
                }

                if input_data['name']:
                    form_data['inputs'].append(input_data)

            forms.append(form_data)

        return forms

    def _extract_js_files(self, soup: BeautifulSoup, base_url: str) -> List[str]:
        """Extract JavaScript file URLs from all sources"""
        js_files = set()

        effective_base = self._base_url_override.get(base_url, base_url)

        for script in soup.find_all('script', src=True):
            src = script.get('src')
            if src:
                js_files.add(urljoin(effective_base, src))

        for link in soup.find_all('link'):
            rel = link.get('rel', [])
            as_attr = link.get('as', '')
            if isinstance(rel, list):
                rel = ' '.join(rel)
            if ('preload' in rel or 'prefetch' in rel) and as_attr == 'script':
                href = link.get('href')
                if href:
                    js_files.add(urljoin(effective_base, href))

            if 'modulepreload' in rel:
                href = link.get('href')
                if href:
                    js_files.add(urljoin(effective_base, href))

        for script in soup.find_all('script', type='importmap'):
            text = script.string or ''
            try:
                import_map = _json.loads(text)
                imports = import_map.get('imports', {})
                for path in imports.values():
                    if isinstance(path, str) and path.endswith('.js'):
                        js_files.add(urljoin(effective_base, path))
            except (ValueError, TypeError):
                pass

        return list(js_files)


    def _deep_parse_javascript_files(self, base_domain: str):
        """
        Deep JS file analysis with webpack chunk discovery, source map parsing,
        and recursive import following.
        """
        unique_js = list(self.js_files)[:80]  # Increased from 30 to 80
        processed_js = set()
        new_js_files = set()

        for js_url in unique_js:
            if js_url in processed_js:
                continue
            processed_js.add(js_url)

            try:
                response = self.client.get(js_url, timeout=10)
                if response.status_code != 200:
                    continue
                content = response.text[:500000]  # 500KB limit

                parsed_base = urlparse(js_url)
                js_base = f"{parsed_base.scheme}://{parsed_base.netloc}"

                for pattern in self.JS_ENDPOINT_PATTERNS:
                    try:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if not match or len(match) < 2:
                                continue
                            if any(x in match for x in ['${', '{{', '<%', 'node_modules', '.min.js',
                                                          'example.com', 'localhost', 'schema.org',
                                                          'w3.org', 'xmlns']):
                                continue

                            if match.startswith('/'):
                                full_url = f"{js_base}{match}"
                            elif match.startswith('http'):
                                full_url = match
                            else:
                                continue

                            normalized = self._normalize_url(full_url)
                            if normalized not in self.visited_normalized:
                                if self._is_in_scope(full_url, base_domain):
                                    self.results.append({
                                        'url': full_url,
                                        'method': 'GET',
                                        'status_code': None,
                                        'content_type': '',
                                        'source': 'javascript',
                                        'depth': 0,
                                        'parameters': self._extract_parameters(full_url),
                                        'forms': [],
                                        'js_files': [],
                                    })
                                    self.visited_normalized.add(normalized)
                    except re.error:
                        continue

                chunk_patterns = [
                    r'["\'](/static/js/\d+\.[a-f0-9]+\.chunk\.js)["\']',
                    r'["\'](/static/js/[^"\']+\.js)["\']',
                    r'["\'](/_next/static/[^"\']+\.js)["\']',
                    r'["\']([^"\']*chunk[^"\']*\.js)["\']',
                    r'["\']([^"\']*bundle[^"\']*\.js)["\']',
                    r'(?:__webpack_require__|webpackChunkName)\s*[^"\']*["\']([^"\']+)["\']',
                    r'(?:import|from)\s+["\']([^"\']+\.js)["\']',
                    r'\.(?:src|href)\s*=\s*["\']([^"\']+\.js)["\']',
                ]
                for cp in chunk_patterns:
                    for chunk_path in re.findall(cp, content):
                        chunk_url = urljoin(js_url, chunk_path)
                        if chunk_url not in processed_js:
                            new_js_files.add(chunk_url)

                sourcemap_match = re.search(r'//[#@]\s*sourceMappingURL\s*=\s*(\S+)', content)
                if sourcemap_match:
                    map_path = sourcemap_match.group(1)
                    if not map_path.startswith('data:'):
                        map_url = urljoin(js_url, map_path)
                        self._parse_source_map(map_url, js_base, base_domain)

            except Exception:
                continue

        for chunk_url in list(new_js_files)[:50]:
            if chunk_url in processed_js:
                continue
            processed_js.add(chunk_url)

            try:
                response = self.client.get(chunk_url, timeout=8)
                if response.status_code != 200:
                    continue
                content = response.text[:300000]

                parsed_base = urlparse(chunk_url)
                js_base = f"{parsed_base.scheme}://{parsed_base.netloc}"

                for pattern in self.JS_ENDPOINT_PATTERNS:
                    try:
                        matches = re.findall(pattern, content)
                        for match in matches:
                            if not match or len(match) < 2:
                                continue
                            if any(x in match for x in ['${', '{{', '<%', 'node_modules',
                                                          '.min.js', 'example.com', 'localhost']):
                                continue

                            if match.startswith('/'):
                                full_url = f"{js_base}{match}"
                            elif match.startswith('http'):
                                full_url = match
                            else:
                                continue

                            normalized = self._normalize_url(full_url)
                            if normalized not in self.visited_normalized:
                                if self._is_in_scope(full_url, base_domain):
                                    self.results.append({
                                        'url': full_url,
                                        'method': 'GET',
                                        'status_code': None,
                                        'content_type': '',
                                        'source': 'javascript_chunk',
                                        'depth': 0,
                                        'parameters': self._extract_parameters(full_url),
                                        'forms': [],
                                        'js_files': [],
                                    })
                                    self.visited_normalized.add(normalized)
                    except re.error:
                        continue

            except Exception:
                continue

    def _parse_source_map(self, map_url: str, js_base: str, base_domain: str):
        """Parse JavaScript source map for additional source files and paths"""
        try:
            resp = self.client.get(map_url, timeout=8)
            if resp.status_code != 200:
                return

            data = _json.loads(resp.text[:1_000_000])

            sources = data.get('sources', [])
            for source in sources[:200]:
                if isinstance(source, str) and '/' in source:
                    if any(x in source for x in ['node_modules', 'webpack', '__webpack']):
                        continue
                    src_url = urljoin(map_url, source)
                    normalized = self._normalize_url(src_url)
                    if normalized not in self.visited_normalized:
                        if self._is_in_scope(src_url, base_domain):
                            self.visited_normalized.add(normalized)

        except Exception:

            logger.debug("Suppressed exception", exc_info=True)


    def _submit_forms_for_discovery(self, page_url: str, html: str, base_domain: str) -> List[str]:
        """Submit forms (GET and POST) with dummy data to discover new pages/endpoints"""
        discovered_links = []

        soup = self._build_soup(html, 300000, 'html.parser')
        if soup is None:
            return discovered_links

        forms = soup.find_all('form')
        if not forms:
            return discovered_links

        form_limit = 12 if self.config.deep_scan else 6
        for form in forms[:form_limit]:
            try:
                action = form.get('action', '')
                method = form.get('method', 'GET').upper()
                effective_base = self._base_url_override.get(page_url, page_url)
                form_url = urljoin(effective_base, action) if action else page_url

                if not self._is_in_scope(form_url, base_domain):
                    continue

                form_data = {}
                for inp in form.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name')
                    if not name:
                        continue

                    inp_type = inp.get('type', 'text').lower()
                    value = inp.get('value', '')

                    if inp_type in ('submit', 'button', 'image', 'reset'):
                        if value:
                            form_data[name] = value
                        continue

                    if inp_type == 'hidden' and value:
                        form_data[name] = value
                        continue

                    if inp_type == 'email':
                        form_data[name] = 'test@test.com'
                    elif inp_type == 'number':
                        form_data[name] = '1'
                    elif inp_type in ('checkbox', 'radio'):
                        form_data[name] = value or 'on'
                    elif inp_type == 'url':
                        form_data[name] = 'https://example.com'
                    elif inp_type == 'password':
                        form_data[name] = 'test123'
                    elif inp_type == 'date':
                        form_data[name] = '2025-01-01'
                    elif inp_type == 'tel':
                        form_data[name] = '5551234567'
                    else:
                        form_data[name] = value or 'test'

                if not form_data:
                    continue

                crawl_timeout = min(self.config.timeout, 8)
                if method == 'POST':
                    resp = self.client.post(form_url, data=form_data, timeout=crawl_timeout)
                else:
                    resp = self.client.get(form_url, params=form_data, timeout=crawl_timeout)

                if resp.status_code < 400:
                    resp_ct = resp.headers.get('Content-Type', '').lower()
                    if 'text/html' in resp_ct or 'application/xhtml' in resp_ct:
                        resp_links = self._extract_all_links(form_url, resp.text, base_domain)
                        discovered_links.extend(resp_links)

                        if resp.url and resp.url != form_url:
                            if self._is_in_scope(resp.url, base_domain):
                                discovered_links.append(resp.url)

            except Exception:
                continue

        return discovered_links


    def _is_in_scope(self, url: str, base_domain: str) -> bool:
        """Check if URL is in crawling scope"""
        try:
            parsed = urlparse(url)
        except Exception:
            return False

        if parsed.scheme not in ('http', 'https'):
            return False

        url_domain = parsed.netloc.lower()
        url_domain_no_port = url_domain.split(':')[0]
        valid_domains = getattr(self, '_valid_domains', {base_domain.lower()})

        def _root_domain(host: str) -> str:
            host = (host or '').split(':')[0].strip('.').lower()
            parts = host.split('.')
            if len(parts) >= 2:
                return '.'.join(parts[-2:])
            return host

        url_root = _root_domain(url_domain_no_port)

        domain_match = False
        for vd in valid_domains:
            vd_no_port = vd.split(':')[0]
            vd_root = _root_domain(vd_no_port)
            if (
                url_domain_no_port == vd_no_port
                or url_domain_no_port.endswith('.' + vd_no_port)
                or vd_no_port.endswith('.' + url_domain_no_port)
                or (url_root and vd_root and url_root == vd_root)
            ):
                domain_match = True
                break
        if not domain_match:
            return False

        if self._include_patterns:
            matched = any(p.search(parsed.path) for p in self._include_patterns)
            if not matched:
                return False

        if self._exclude_patterns:
            excluded = any(p.search(parsed.path) for p in self._exclude_patterns)
            if excluded:
                return False

        path_lower = parsed.path.lower()
        ext_match = re.search(r'\.\w+$', path_lower.split('?')[0])
        if ext_match:
            ext = ext_match.group()
            if ext in self.IGNORE_EXTENSIONS:
                return False

        return True
