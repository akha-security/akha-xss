"""
DOM-based XSS Scanner
Uses Playwright (preferred) or Selenium headless browser to detect DOM XSS vulnerabilities.
Falls back to static analysis when no browser engine is available.
"""

import re
import time
import logging
import warnings
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

from akha.modules.xss.dom_flow_analyzer import DOMFlowAnalyzer

logger = logging.getLogger("akha.dom_scanner")


class DOMScanner:
    """Scans for DOM-based XSS vulnerabilities using headless browser"""
    
    HIGH_RISK_SOURCES = [
        'location.hash', 'location.search', 'location.href',
        'document.URL', 'document.documentURI', 'document.referrer',
        'window.name', 'document.cookie',
    ]
    MEDIUM_RISK_SOURCES = [
        'document.URLUnencoded', 'document.baseURI',
        'location.pathname', 'location.protocol',
        'window.location',
        'postMessage',
    ]
    LOW_RISK_SOURCES = [
        'localStorage', 'sessionStorage',
        'history.pushState', 'history.replaceState',
    ]
    
    SOURCES = HIGH_RISK_SOURCES + MEDIUM_RISK_SOURCES + LOW_RISK_SOURCES
    
    HIGH_RISK_SINKS = [
        'eval(', 'setTimeout(', 'setInterval(', 'Function(',
        'document.write(', 'document.writeln(',
    ]
    MEDIUM_RISK_SINKS = [
        '.innerHTML', '.outerHTML', 'insertAdjacentHTML(',
        'jQuery.html(', '$.html(', '.html(',
    ]
    NAVIGATION_SINKS = [
        'location.assign(', 'location.replace(',
        'window.open(',
    ]
    
    SINKS = HIGH_RISK_SINKS + MEDIUM_RISK_SINKS
    
    SAFE_PATTERNS = [
        r'location\.(?:href|hash|search|pathname)\s*(?:===|==|!==|!=)',
        r'(?:===|==|!==|!=)\s*location\.(?:href|hash|search|pathname)',
        r'location\.href\s*=\s*["\'][^"\']*["\']',
        r'typeof\s+(?:localStorage|sessionStorage)',
        r'(?:localStorage|sessionStorage)\.(?:getItem|length|key)\s*\(',
        r'(?:ga|gtag|analytics|_paq|fbq)\s*\(',
        r'console\.(?:log|warn|error|info)\s*\(',
    ]
    
    DOM_PAYLOADS = [
        '#<img src=x onerror=alert(document.domain)>',
        '#"><img src=x onerror=alert(1)>',
        '#javascript:alert(1)',
        '?q=<script>alert(document.domain)</script>',
        '#\'-alert(1)-\'',
        '#"><svg/onload=alert(1)>',
        '#<details open ontoggle=alert(1)>',
        '#"><input onfocus=alert(1) autofocus>',
    ]

    PARAM_CONFIRM_PAYLOADS = [
        '"><img src=x onerror=alert(1)>',
        "'><img src=x onerror=alert(1)>",
        '<img src=x onerror=alert(1)>',
        '<svg/onload=alert(1)>',
        '<details open ontoggle=alert(1)>',
    ]
    
    def __init__(self, config, http_client=None):
        self.config = config
        self.http_client = http_client
        self.interrupted = False
        
        self._browser = None
        self._context = None
        self._engine = None          # 'playwright' | 'selenium' | None
        self._pw_instance = None     # playwright instance (needs stop)
        self._driver = None          # selenium driver (legacy)
        self.findings = []
        self._flow_analyzer = DOMFlowAnalyzer()
        self._analyzed_scripts = set()  # Cache to avoid re-analyzing same JS file
    
    def scan(self, url: str, response_text: str = None) -> List[Dict]:
        """
        Scan URL for DOM-based XSS.

        Static analysis runs always (just needs HTTP client or cached HTML).
        Dynamic analysis (headless browser) runs only if dom_xss_enabled.
        """
        findings = []
        
        if self.http_client or response_text:
            static_findings = self._static_analysis(url, html=response_text)
            findings.extend(static_findings)
        
        if self.config.dom_xss_enabled:
            dynamic_findings = self._dynamic_analysis(url)
            findings.extend(dynamic_findings)

        min_confidence = getattr(self.config, 'dom_min_confidence', 60)
        findings = [f for f in findings if f.get('confidence', 0) >= min_confidence]

        seen = set()
        unique = []
        for f in findings:
            key = (f.get('url', ''), f.get('parameter', ''), str(f.get('proof', ''))[:80])
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique
    
    
    def _static_analysis(self, url: str, html: str = None) -> List[Dict]:
        """Analyze page source for DOM XSS patterns (uses cached HTML when available)"""
        findings = []
        
        if html:
            findings = self._static_analyze_html(url, html)
        elif self.http_client:
            try:
                response = self.http_client.get(url, timeout=10)
                if response and response.status_code == 200:
                    content_type = response.headers.get('Content-Type', '').lower()
                    if 'text/html' in content_type or 'application/xhtml' in content_type:
                        findings = self._static_analyze_html(url, response.text)
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
        
        return findings
    
    def _is_same_domain(self, base_url: str, target_url: str) -> bool:
        """Check if target_url is on the same domain as base_url"""
        from urllib.parse import urlparse
        base = urlparse(base_url)
        target = urlparse(target_url)
        base_host = base.netloc.lower().lstrip('www.')
        target_host = target.netloc.lower().lstrip('www.')
        return base_host == target_host or target_host == '' or target_host.endswith('.' + base_host)

    def _fetch_and_analyze_external_scripts(self, url: str, html: str) -> List[Dict]:
        """
        Fetch and analyze external JS files referenced in the page.
        Only analyzes same-domain scripts to stay in scope.
        Uses _analyzed_scripts cache to avoid redundant requests.
        """
        from urllib.parse import urljoin
        try:
            from bs4 import BeautifulSoup, MarkupResemblesLocatorWarning
        except ImportError:
            return []

        findings = []
        try:
            snippet = html[:500_000] if html else ''
            if '<' not in snippet or '>' not in snippet:
                return []
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
                soup = BeautifulSoup(snippet, 'html.parser')
        except Exception:
            return []

        for script_tag in soup.find_all('script', src=True):
            src = script_tag.get('src', '').strip()
            if not src:
                continue

            script_url = urljoin(url, src)

            if script_url in self._analyzed_scripts:
                continue
            if not self._is_same_domain(url, script_url):
                continue
            if not script_url.startswith('http'):
                continue

            self._analyzed_scripts.add(script_url)

            try:
                if not self.http_client:
                    continue
                resp = self.http_client.get(script_url, timeout=8)
                if resp.status_code != 200:
                    continue
                ct = resp.headers.get('Content-Type', '')
                if 'javascript' not in ct and not script_url.endswith('.js'):
                    continue

                js_code = resp.text
                if not js_code.strip():
                    continue

                if self._is_library_code(js_code, url=script_url):
                    continue

                taint_flows = self._flow_analyzer.analyze(js_code)
                if not taint_flows:
                    continue

                for flow in taint_flows[:5]:  # max 5 findings per file
                    confidence = min(flow.confidence, 85)  # external JS capped at 85
                    if confidence < 30:
                        continue

                    findings.append({
                        'url': url,
                        'type': 'dom_xss',
                        'subtype': 'external_js_analysis',
                        'parameter': 'DOM',
                        'sources': [flow.source],
                        'sinks': [flow.sink],
                        'confidence': confidence,
                        'status': 'Potential DOM XSS' if confidence < 70 else 'Likely DOM XSS',
                        'payload': f'Source: {flow.source} -> Sink: {flow.sink}',
                        'proof': (
                            f'External JS taint-flow in {script_url}:\n'
                            f'Chain: {" -> ".join(flow.taint_chain)}\n'
                            f'Line ~{flow.line}: {flow.snippet[:200]}'
                        ),
                        'request': f'GET {script_url} HTTP/1.1\nHost: {__import__("urllib.parse", fromlist=["urlparse"]).urlparse(script_url).netloc}',
                        'response': f'Taint flow detected in external script: {script_url}',
                        'context': {'Location': 'DOM', 'Type': 'External JS'},
                        'bypass_technique': 'None',
                        'validated': False,
                        'taint_chain': flow.taint_chain,
                        'external_script_url': script_url,
                    })

            except Exception:
                continue

        return findings


    _LIBRARY_FILENAME_PATTERNS = [
        'jquery', 'react', 'angular', 'vue', 'backbone', 'ember', 'knockout',
        'lodash', 'underscore', 'moment', 'bootstrap', 'foundation', 'materialize',
        'tinymce', 'ckeditor', 'quill', 'codemirror', 'ace.js', 'monaco',
        'chart.js', 'chartjs', 'd3.js', 'd3.min', 'highcharts', 'echarts',
        'three.js', 'three.min', 'babylon', 'pixi', 'phaser',
        'socket.io', 'sockjs', 'signalr', 'pusher',
        'axios', 'superagent', 'fetch.js', 'whatwg-fetch',
        'polyfill', 'es5-shim', 'es6-shim', 'core-js', 'babel',
        'webpack', 'rollup', 'parcel', 'browserify',
        'normalize.css', 'reset.css', 'animate.css',
        'font-awesome', 'fontawesome', 'material-icons',
        'swiper', 'slick', 'glide', 'owl.carousel',
        'select2', 'chosen', 'chosen.jquery',
        'datatables', 'ag-grid',
        'fullcalendar', 'flatpickr', 'pikaday',
        'pdfjs', 'pdf.min', 'pdf.worker',
        'google-analytics', 'gtag', 'amplitude',
        'stripe.js', 'paypal', 'braintree',
    ]

    def _is_library_code(self, js_code: str, url: str = '') -> bool:
        """
        Heuristic: skip well-known JS libraries to reduce false positives
        and avoid wasting time on minified vendor bundles.

        Checks (in order of speed):
          1. URL filename contains a known library name
          2. File is large (>150KB) AND heavily minified (<100 newlines)
          3. First 2KB contains library header fingerprints
        """
        if url:
            url_lower = url.lower()
            if any(lib in url_lower for lib in self._LIBRARY_FILENAME_PATTERNS):
                return True

        size = len(js_code)
        newlines = js_code.count('\n')
        if size > 150_000 and newlines < 100:
            return True  # Large minified file â€” almost certainly a vendor bundle
        
        if size > 30_000 and newlines > 0 and (size / newlines) > 5_000:
            return True  # Average line > 5KB â€” definitely minified

        header = js_code[:3000].lower()
        library_header_signals = [
            '@license', 'mit license', 'apache license', 'bsd license',
            'copyright (c)', '* copyright', '@copyright',
            'dual licensed', 'triple licensed',
            '/*!', 'minified by', 'uglifyjs', 'webpack', 'terser',
            'jquery v', 'jquery javascript library',
            'react.development', 'react.production',
            'angular:', '@angular/core',
            'vue.js v', 'vue.runtime',
            'lodash v', 'lodash 4',
            'moment.js', 'underscore.js',
            'tinymce', 'tinyMCE',
            'ckeditor', 'ck-editor',
            'bootstrap v', 'bootstrap.js',
            'backbone.js', 'backbone v',
            'ember.js', 'ember debug',
        ]
        return any(sig in header for sig in library_header_signals)

    def _static_analyze_html(self, url: str, html: str) -> List[Dict]:
        """Analyze HTML/JS code for source-to-sink flows with data-flow proximity analysis"""
        findings = []

        external_findings = self._fetch_and_analyze_external_scripts(url, html)
        findings.extend(external_findings)

        scripts = re.findall(r'<script[^>]*>(.*?)</script>', html, re.DOTALL | re.IGNORECASE)
        
        for script in scripts:
            if not script.strip():
                continue
            
            if self._is_inline_library_code(script):
                continue
            
            sources_found = []
            sinks_found = []
            
            for source in self.SOURCES:
                pattern = r'(?<![\w.])' + re.escape(source)
                if re.search(pattern, script):
                    sources_found.append(source)
            
            for sink in self.SINKS:
                pattern = r'(?<![\w])' + re.escape(sink)
                if re.search(pattern, script):
                    sinks_found.append(sink)
            
            if not (sources_found and sinks_found):
                continue
            
            flow_pairs = self._find_data_flows(script, sources_found, sinks_found)
            
            if not flow_pairs:
                continue
            
            taint_flows = self._flow_analyzer.analyze(script)

            confidence = self._calculate_static_confidence(flow_pairs, script)

            best_taint_chain = []
            if taint_flows:
                top = taint_flows[0]
                if top.confidence > confidence:
                    confidence = min(top.confidence, 90)  # static capped at 90 with taint
                best_taint_chain = top.taint_chain
            
            if confidence < 45:
                continue
            
            best_flow = flow_pairs[0]
            flow_sources = list(set(f['source'] for f in flow_pairs))
            flow_sinks = list(set(f['sink'] for f in flow_pairs))
            
            status = 'Potential DOM XSS' if confidence < 70 else 'Likely DOM XSS'

            if best_taint_chain and len(best_taint_chain) > 2:
                chain_str = ' â†’ '.join(best_taint_chain)
                proof = f'Taint-flow analysis: {chain_str}'
            else:
                proof = (
                    f'Static analysis found potential data flow from '
                    f'{best_flow["source"]} to {best_flow["sink"]}'
                    f'{" (within " + str(best_flow["distance"]) + " lines)" if best_flow.get("distance") else ""}'
                )

            findings.append({
                'url': url,
                'type': 'dom_xss',
                'subtype': 'static_analysis',
                'parameter': 'DOM',
                'sources': flow_sources,
                'sinks': flow_sinks,
                'confidence': confidence,
                'status': status,
                'payload': f'Source: {best_flow["source"]} -> Sink: {best_flow["sink"]}',
                'proof': proof,
                'request': f'GET {url} HTTP/1.1',
                'response': (
                    f'JavaScript code contains potential source-to-sink flow:\n'
                    f'Sources: {", ".join(flow_sources)}\n'
                    f'Sinks: {", ".join(flow_sinks)}'
                ),
                'context': {'Location': 'DOM', 'Type': 'DOM'},
                'bypass_technique': 'None',
                'validated': False,
                'taint_chain': best_taint_chain,
                'taint_flows': [f.to_dict() for f in taint_flows[:5]],
            })
        
        return findings
    
    def _is_inline_library_code(self, script: str) -> bool:
        """Detect common JS libraries/frameworks to skip (they handle XSS safely)"""
        lines = script.strip().split('\n')
        if len(lines) <= 3 and len(script) > 5000:
            return True  # Likely minified library
        
        library_signatures = [
            'jQuery v', 'jQuery JavaScript Library',
            'Bootstrap v', 'angular.module',
            'React.createElement', '__REACT_DEVTOOLS',
            'Vue.js v', 'vue.runtime',
            'Lodash', 'underscore.js',
            'Google Analytics', 'GoogleAnalyticsObject',
            'gtag(', '_gaq.push',
            'fbq(', 'Facebook Pixel',
            'hotjar', 'Sentry.init',
        ]
        for sig in library_signatures:
            if sig in script:
                return True
        return False
    
    def _find_data_flows(self, script: str, sources: List[str], sinks: List[str]) -> List[Dict]:
        """
        Attempt to find actual data-flow connections between sources and sinks.
        Uses proximity analysis and pattern matching for assignment/call patterns.
        """
        flows = []
        lines = script.split('\n')
        
        source_lines = {}  # source -> [line_numbers]
        sink_lines = {}    # sink -> [line_numbers]
        
        for i, line in enumerate(lines):
            stripped = line.strip()
            if stripped.startswith('//') or stripped.startswith('*'):
                continue
            
            is_safe = False
            for safe_pat in self.SAFE_PATTERNS:
                if re.search(safe_pat, line):
                    is_safe = True
                    break
            if is_safe:
                continue
            
            for source in sources:
                if source in line:
                    source_lines.setdefault(source, []).append(i)
            for sink in sinks:
                if sink in line:
                    sink_lines.setdefault(sink, []).append(i)
        
        if not source_lines or not sink_lines:
            return self._trace_data_flow(script)
        
        for i, line in enumerate(lines):
            for source in sources:
                for sink in sinks:
                    if source in line and sink in line:
                        flows.append({
                            'source': source,
                            'sink': sink,
                            'distance': 0,
                            'direct': True,
                            'line': i,
                        })
        
        MAX_FLOW_DISTANCE = 15
        for source, s_lines in source_lines.items():
            for sink, k_lines in sink_lines.items():
                for sl in s_lines:
                    for kl in k_lines:
                        dist = abs(sl - kl)
                        if 0 < dist <= MAX_FLOW_DISTANCE:
                            if sl <= kl:
                                flows.append({
                                    'source': source,
                                    'sink': sink,
                                    'distance': dist,
                                    'direct': False,
                                    'line': sl,
                                })

        flows.extend(self._trace_data_flow(script))
        
        seen = set()
        unique_flows = []
        flows.sort(key=lambda f: (not f['direct'], f['distance']))
        for f in flows:
            key = (f['source'], f['sink'])
            if key not in seen:
                seen.add(key)
                unique_flows.append(f)
        
        return unique_flows

    def _trace_data_flow(self, js_content: str) -> List[Dict]:
        """Heuristic source->sink traces used as fallback signal."""
        trace_sources = [
            'location.hash', 'location.search', 'location.href',
            'document.referrer', 'document.URL', 'window.name', 'postMessage',
        ]
        trace_sinks = [
            'innerHTML', 'outerHTML', 'document.write', 'document.writeln',
            'eval', 'setTimeout', 'setInterval', 'Function(', 'insertAdjacentHTML',
        ]
        flows = []
        for source in trace_sources:
            if source not in js_content:
                continue
            for sink in trace_sinks:
                if sink in js_content:
                    flows.append({
                        'source': source,
                        'sink': sink,
                        'distance': 999,
                        'direct': False,
                        'line': 0,
                        'confidence': 0.7,
                    })
        return flows
    
    def _calculate_static_confidence(self, flows: List[Dict], script: str) -> int:
        """
        Calculate confidence score for static analysis findings.
        Returns 0-100.
        """
        if not flows:
            return 0
        
        best_flow = flows[0]
        confidence = 15  # Base confidence for static analysis is low
        
        if best_flow.get('direct'):
            confidence += 35
        
        dist = best_flow.get('distance', 999)
        if dist <= 3:
            confidence += 20
        elif dist <= 8:
            confidence += 10
        elif dist <= 15:
            confidence += 5
        
        if best_flow['source'] in self.HIGH_RISK_SOURCES:
            confidence += 10
        
        if best_flow['sink'] in self.HIGH_RISK_SINKS:
            confidence += 10
        
        if len(flows) >= 3:
            confidence += 5
        
        return min(confidence, 80)  # Static analysis capped at 80
    
    
    def _dynamic_analysis(self, url: str) -> List[Dict]:
        """Dynamic analysis using headless browser (Playwright preferred, Selenium fallback)"""
        findings = []
        
        if not self._init_browser():
            return findings
        
        for payload in self.DOM_PAYLOADS:
            if self.interrupted:
                break
            try:
                if '#' in payload and payload.startswith('#'):
                    test_url = url.split('#')[0] + payload
                elif '?' in payload:
                    parsed = urlparse(url)
                    test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}{payload}"
                else:
                    test_url = url + payload
                
                result = self._test_dom_payload(test_url, payload)
                if result:
                    findings.append(result)
                    if result.get('validated'):
                        break
                    
            except Exception:
                continue
        
        if not self.interrupted:
            param_findings = self._param_dynamic_analysis(url)
            findings.extend(param_findings)
        
        return findings


    def _param_dynamic_analysis(self, url: str) -> List[Dict]:
        """Test URL parameters for DOM XSS via HTML injection.

        Two-phase approach for efficiency:
          1. Canary scan â€” inject unique HTML tags into ALL parameters in
             a single page load to detect which params reflect unescaped.
          2. Confirmation â€” test only the vulnerable params with real XSS
             payloads (event handlers that trigger JS dialogs).
        """
        findings: List[Dict] = []
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)

        if not params:
            return findings

        vulnerable_params = self._canary_scan(url, params, parsed)

        if not vulnerable_params:
            return findings

        for param_name in vulnerable_params:
            if self.interrupted:
                break

            confirmed = False
            for payload in self.PARAM_CONFIRM_PAYLOADS:
                if self.interrupted:
                    break

                test_params = {k: v[0] if v else '' for k, v in params.items()}
                test_params[param_name] = payload
                new_query = urlencode(test_params)
                test_url = urlunparse((
                    parsed.scheme, parsed.netloc, parsed.path,
                    parsed.params, new_query, parsed.fragment,
                ))

                result = self._test_dom_payload(test_url, payload)
                if result:
                    result['parameter'] = param_name
                    findings.append(result)
                    confirmed = True
                    break  # one confirmed payload is enough

            if not confirmed:
                    findings.append({
                    'url': url,
                    'type': 'dom_xss',
                    'subtype': 'dynamic_analysis',
                    'parameter': param_name,
                    'payload': f'HTML injection via parameter: {param_name}',
                        'confidence': 50,
                    'status': 'Potential DOM XSS (HTML Injection)',
                    'context': {'Location': 'DOM', 'Type': 'DOM'},
                    'bypass_technique': 'None',
                    'proof': (
                        f'Parameter "{param_name}" reflects unescaped HTML into the DOM. '
                        f'A custom HTML tag injected via the query string was rendered '
                        f'as a live DOM element.'
                    ),
                    'request': f'GET {url} HTTP/1.1\nHost: {parsed.netloc}\n',
                    'response': f'HTML injection confirmed in parameter: {param_name}',
                    'validated': False,
                })

        if not getattr(self.config, 'aggressive_mode', False):
            findings = [f for f in findings if f.get('validated')]

        return findings

    def _canary_scan(self, url: str, params: dict, parsed) -> List[str]:
        """Dispatch canary scan to the active browser engine."""
        if self._engine == 'playwright':
            return self._canary_scan_playwright(url, params, parsed)
        elif self._engine == 'selenium':
            return self._canary_scan_selenium(url, params, parsed)
        return []

    def _build_canary_url(self, params: dict, parsed) -> tuple:
        """Build a test URL with unique canary tags in every parameter.

        Returns (test_url, canaries_dict) where canaries_dict maps
        tag_name â†’ param_name.
        """
        canaries: Dict[str, str] = {}
        test_params: Dict[str, str] = {}
        for i, (name, _values) in enumerate(params.items()):
            tag = f'akhaxss{i}'
            canaries[tag] = name
            test_params[name] = f'\'"><{tag}>'

        new_query = urlencode(test_params)
        test_url = urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
        return test_url, canaries

    def _canary_scan_playwright(self, url: str, params: dict, parsed) -> List[str]:
        """One page load â€” detect which parameters reflect HTML unescaped."""
        test_url, canaries = self._build_canary_url(params, parsed)
        vulnerable: List[str] = []
        page = None
        try:
            page = self._context.new_page()
            try:
                page.goto(test_url, wait_until='domcontentloaded', timeout=5000)
                page.wait_for_timeout(800)
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)

            for tag, param_name in canaries.items():
                try:
                    exists = page.evaluate(
                        '(tag) => document.querySelector(tag) !== null', tag,
                    )
                    if exists:
                        vulnerable.append(param_name)
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
        return vulnerable

    def _canary_scan_selenium(self, url: str, params: dict, parsed) -> List[str]:
        """Selenium fallback â€” detect which parameters reflect HTML unescaped."""
        test_url, canaries = self._build_canary_url(params, parsed)
        vulnerable: List[str] = []
        try:
            self._driver.get(test_url)
            time.sleep(0.5)
            page_source = self._driver.page_source.lower()

            for tag, param_name in canaries.items():
                if f'<{tag}>' in page_source:
                    vulnerable.append(param_name)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)
        return vulnerable
    
    def _test_dom_payload(self, url: str, payload: str) -> Optional[Dict]:
        """Test a single DOM XSS payload using the active browser engine"""
        if self._engine == 'playwright':
            return self._test_playwright(url, payload)
        elif self._engine == 'selenium':
            return self._test_selenium(url, payload)
        return None
    
    
    def _test_playwright(self, url: str, payload: str) -> Optional[Dict]:
        """Test DOM XSS payload using Playwright"""
        page = None
        try:
            page = self._context.new_page()
            
            alert_texts = []
            
            def _on_dialog(dialog):
                alert_texts.append(dialog.message)
                dialog.accept()
            
            page.on('dialog', _on_dialog)
            
            try:
                page.goto(url, wait_until='domcontentloaded', timeout=5000)
                page.wait_for_timeout(800)
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            
            if alert_texts:
                return {
                    'url': url,
                    'type': 'dom_xss',
                    'subtype': 'dynamic_analysis',
                    'parameter': 'DOM (fragment/hash)',
                    'payload': payload,
                    'confidence': 95,
                    'status': 'Vulnerability Detected',
                    'context': {'Location': 'DOM', 'Type': 'DOM'},
                    'bypass_technique': 'None',
                    'proof': f'DOM XSS confirmed: JavaScript alert triggered with text "{alert_texts[0]}"',
                    'request': f'GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n',
                    'response': f'Alert triggered: {alert_texts[0]}',
                    'validated': True,
                    'validation_proof': f'Browser alert triggered: {alert_texts[0]}',
                }
            
            try:
                content = page.content()
                clean_payload = payload.lstrip('#')
                if clean_payload and self._verify_dom_injection(page, clean_payload):
                    is_js_proto = 'javascript:' in payload
                    conf = 50 if is_js_proto else 55
                    status = 'Manual Verification Required' if conf <= 50 else 'Potential DOM XSS'
                    return {
                        'url': url,
                        'type': 'dom_xss',
                        'subtype': 'dynamic_analysis',
                        'parameter': 'DOM',
                        'payload': payload,
                        'confidence': conf,
                        'status': status,
                        'context': {'Location': 'DOM', 'Type': 'DOM'},
                        'bypass_technique': 'None',
                        'proof': (
                            'DOM payload injected as HTML element â€” alert() did NOT fire.\n'
                            'Manual verification required to confirm executability.\n'
                            'This may be a false positive if the javascript: URI was pre-existing\n'
                            f'or if event handlers require user interaction.\nURL: {url}'
                        ) if is_js_proto else (
                            'Payload rendered as active HTML/JS element in the DOM.\n'
                            'Browser did not fire alert() â€” may require user interaction (e.g. focus/click).\n'
                            f'Manual verification recommended.\nURL: {url}'
                        ),
                        'request': f'GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n',
                        'response': 'DOM element created â€” alert() not triggered',
                        'validated': False,
                    }
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            
        except Exception:
            
            logger.debug("Suppressed exception", exc_info=True)
        finally:
            if page:
                try:
                    page.close()
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    
    def _test_selenium(self, url: str, payload: str) -> Optional[Dict]:
        """Test a single DOM XSS payload using Selenium"""
        try:
            self._driver.get(url)
            time.sleep(0.5)
            
            try:
                from selenium.webdriver.support.ui import WebDriverWait
                from selenium.webdriver.support import expected_conditions as EC
                
                WebDriverWait(self._driver, 2).until(EC.alert_is_present())
                alert = self._driver.switch_to.alert
                alert_text = alert.text
                alert.accept()
                
                return {
                    'url': url,
                    'type': 'dom_xss',
                    'subtype': 'dynamic_analysis',
                    'parameter': 'DOM (fragment/hash)',
                    'payload': payload,
                    'confidence': 95,
                    'status': 'Vulnerability Detected',
                    'context': {'Location': 'DOM', 'Type': 'DOM'},
                    'bypass_technique': 'None',
                    'proof': f'DOM XSS confirmed: JavaScript alert triggered with text "{alert_text}"',
                    'request': f'GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n',
                    'response': f'Alert triggered: {alert_text}',
                    'validated': True,
                    'validation_proof': f'Browser alert triggered: {alert_text}',
                }
            except Exception:
                try:
                    page_source = self._driver.page_source
                    clean_payload = payload.lstrip('#')
                    if clean_payload and self._verify_dom_injection_selenium(page_source, clean_payload):
                        return {
                            'url': url,
                            'type': 'dom_xss',
                            'subtype': 'dynamic_analysis',
                            'parameter': 'DOM',
                            'payload': payload,
                            'confidence': 55,
                            'status': 'Potential DOM XSS',
                            'context': {'Location': 'DOM', 'Type': 'DOM'},
                            'bypass_technique': 'None',
                            'proof': 'Payload rendered as active HTML/JS in DOM after JavaScript processing',
                            'request': f'GET {url} HTTP/1.1\nHost: {urlparse(url).netloc}\n',
                            'response': 'Payload injected as executable DOM element',
                            'validated': False,
                        }
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)
        
        return None
    
    
    def _verify_dom_injection(self, page, payload: str) -> bool:
        """
        Verify that the payload was actually rendered as executable HTML/JS in the DOM.
        Checks for actual DOM element creation, not just string presence.
        This prevents false positives from HTML-encoded or text-node reflections.
        """
        try:
            tag_match = re.search(r'<(\w+)', payload)
            if tag_match:
                injected_tag = tag_match.group(1).lower()
                count = page.evaluate('''
                    (tag) => {
                        const els = document.querySelectorAll(tag);
                        let injected = 0;
                        for (const el of els) {
                            const html = el.outerHTML.toLowerCase();
                            if (html.includes('onerror') || html.includes('onload') || 
                                html.includes('onfocus') || html.includes('ontoggle') ||
                                html.includes('alert') || html.includes('javascript:')) {
                                injected++;
                            }
                        }
                        return injected;
                    }
                ''', injected_tag)
                return count > 0
            
            if 'javascript:' in payload:
                found = page.evaluate('''
                    (p) => {
                        // Check raw page text contains the payload (injected, not pre-existing)
                        return document.documentElement.innerHTML.includes(p.replace('#', ''));
                    }
                ''', payload)
                return found
            
            return False
        except Exception:
            return False
    
    def _verify_dom_injection_selenium(self, page_source: str, payload: str) -> bool:
        """
        Verify DOM injection for Selenium by checking if payload created actual
        executable elements (not just text reflection).
        """
        try:
            tag_match = re.search(r'<(\w+)', payload)
            if tag_match:
                injected_tag = tag_match.group(1).lower()
                tag_pattern = rf'<{re.escape(injected_tag)}[^>]*(?:onerror|onload|onfocus|ontoggle|onclick)\s*='
                if re.search(tag_pattern, page_source, re.IGNORECASE):
                    return True
            
            if 'javascript:' in payload:
                js_pattern = r'(?:href|src|action)\s*=\s*["\']?javascript:'
                if re.search(js_pattern, page_source, re.IGNORECASE):
                    return True
            
            return False
        except Exception:
            return False
    
    
    def _init_browser(self) -> bool:
        """Initialize browser engine: try Playwright first, then Selenium"""
        if self._engine:
            return True
        
        if self._init_playwright():
            return True
        
        if self._init_selenium():
            return True
        
        return False
    
    def _init_playwright(self) -> bool:
        """Initialize Playwright Chromium"""
        try:
            from playwright.sync_api import sync_playwright
            
            self._pw_instance = sync_playwright().start()
            
            self._browser = self._pw_instance.chromium.launch(
                headless=True,
                args=[
                    '--no-sandbox',
                    '--disable-dev-shm-usage',
                    '--disable-gpu',
                    '--disable-web-security',
                    '--disable-features=VizDisplayCompositor',
                ]
            )
            
            self._context = self._browser.new_context(
                user_agent=self.config.user_agent,
                ignore_https_errors=True,
                java_script_enabled=True,
            )
            
            self._engine = 'playwright'
            return True
            
        except Exception as e:
            self._cleanup_playwright()
            if self.config.verbose:
                logger.debug("Playwright not available", exc_info=True)
            return False
    
    def _init_selenium(self) -> bool:
        """Initialize Selenium Chrome (legacy fallback)"""
        try:
            from selenium import webdriver
            from selenium.webdriver.chrome.options import Options
            
            options = Options()
            options.add_argument('--headless')
            options.add_argument('--no-sandbox')
            options.add_argument('--disable-dev-shm-usage')
            options.add_argument('--disable-gpu')
            options.add_argument('--disable-web-security')
            options.add_argument('--disable-features=VizDisplayCompositor')
            options.add_argument(f'--user-agent={self.config.user_agent}')
            
            self._driver = webdriver.Chrome(options=options)
            self._driver.set_page_load_timeout(10)
            self._engine = 'selenium'
            return True
            
        except Exception as e:
            if self.config.verbose:
                logger.debug("Selenium not available", exc_info=True)
            return False
    
    
    def _cleanup_playwright(self):
        """Clean up Playwright resources"""
        try:
            if self._context:
                self._context.close()
        except Exception:
            logger.debug("Failed closing Playwright context", exc_info=True)
        try:
            if self._browser:
                self._browser.close()
        except Exception:
            logger.debug("Failed closing Playwright browser", exc_info=True)
        try:
            if self._pw_instance:
                self._pw_instance.stop()
        except Exception:
            logger.debug("Failed stopping Playwright instance", exc_info=True)
        self._context = None
        self._browser = None
        self._pw_instance = None
    
    def close(self):
        """Close browser engine"""
        if self._engine == 'playwright':
            self._cleanup_playwright()
        elif self._engine == 'selenium' and self._driver:
            try:
                self._driver.quit()
            except Exception:
                logger.debug("Failed quitting Selenium driver", exc_info=True)
            self._driver = None
        self._engine = None
    
    def __del__(self):
        self.close()

