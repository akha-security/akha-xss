"""
Advanced parameter discovery module — Arjun / ParamMiner inspired.

Techniques:
  1. URL query-string extraction
  2. HTML form extraction (with full context: action, method, siblings)
  3. HTML mining: data-* attrs, JS variables, comments, meta tags
  4. JavaScript mining: regex-based param name extraction from JS files
  5. Batch fuzzing with binary-split differential analysis (GET + POST + JSON)
  6. Header injection probing (17 common injectable headers)
  7. Cookie reflection probing
  8. URL path-segment reflection probing
"""

import os
import re
import math
import threading
import warnings
import logging
import uuid
from importlib import resources
from collections import defaultdict
from urllib.parse import urlparse, parse_qs, urlencode, urljoin, urlunparse
from typing import List, Dict, Set, Optional, Tuple
from bs4 import BeautifulSoup

try:
    from bs4 import MarkupResemblesLocatorWarning
except ImportError:
    class MarkupResemblesLocatorWarning(Warning):
        pass



_JS_VAR_RE = re.compile(
    r'''(?:'''
    r'''(?:var|let|const)\s+([a-zA-Z_$][a-zA-Z0-9_$]*)'''  # var/let/const decl
    r'''|([a-zA-Z_$][a-zA-Z0-9_$]*)\s*[:=]\s*'''           # assignment / object key
    r'''|['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"]\s*:'''          # quoted object key
    r'''|\[['"]([a-zA-Z_$][a-zA-Z0-9_$]*)['"]\]'''          # bracket property access
    r''')''',
    re.MULTILINE,
)

_JS_PARAM_CONTEXT_RE = re.compile(
    r'(?:params|query|body|data|args|fields|request)\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)',
    re.IGNORECASE,
)

_PARAM_GETTER_RE = re.compile(
    r'''(?:'''
    r'''(?:get(?:Parameter|Attribute|Header)|'''
    r'''request\.(?:args|form|values|params|query|body|cookies|headers)'''
    r'''(?:\[|\.get\s*\())\s*'''
    r'''[(\[]\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]'''
    r'''|(?:params|args|query|body|data|fields|values|options)'''
    r'''\s*\.\s*([a-zA-Z_][a-zA-Z0-9_]*)'''
    r''')''',
    re.IGNORECASE,
)

_URL_PARAM_RE = re.compile(
    r'''[?&]([a-zA-Z_][a-zA-Z0-9_]{0,50})=''',
)

_DATA_ATTR_RE = re.compile(r'data-([a-z][a-z0-9_-]*)', re.IGNORECASE)

_NAME_ID_RE = re.compile(r'(?:name|id)\s*=\s*["\']([a-zA-Z_][a-zA-Z0-9_.-]*)["\']')

_COMMENT_PARAM_RE = re.compile(r'(?:param|parameter|field|input|arg)\w*\s*[=:]\s*["\']?([a-zA-Z_][a-zA-Z0-9_]*)', re.IGNORECASE)



_JS_NOISE = frozenset({
    'function', 'return', 'var', 'let', 'const', 'this', 'new', 'delete',
    'typeof', 'instanceof', 'void', 'true', 'false', 'null', 'undefined',
    'if', 'else', 'for', 'while', 'do', 'switch', 'case', 'break',
    'continue', 'try', 'catch', 'finally', 'throw', 'with', 'yield',
    'class', 'extends', 'super', 'import', 'export', 'default', 'from',
    'async', 'await', 'static', 'get', 'set', 'of', 'in',
    'prototype', 'constructor', 'length', 'push', 'pop', 'shift',
    'unshift', 'splice', 'slice', 'map', 'filter', 'reduce', 'forEach',
    'indexOf', 'includes', 'join', 'split', 'replace', 'match', 'test',
    'toString', 'valueOf', 'hasOwnProperty', 'keys', 'values', 'entries',
    'document', 'window', 'console', 'navigator', 'location', 'history',
    'Math', 'JSON', 'Date', 'Array', 'Object', 'String', 'Number',
    'Boolean', 'RegExp', 'Error', 'Promise', 'Symbol', 'Map', 'Set',
    'parseInt', 'parseFloat', 'isNaN', 'isFinite', 'encodeURI',
    'decodeURI', 'encodeURIComponent', 'decodeURIComponent',
    'setTimeout', 'setInterval', 'clearTimeout', 'clearInterval',
    'addEventListener', 'removeEventListener', 'querySelector',
    'querySelectorAll', 'getElementById', 'getElementsByClassName',
    'getElementsByTagName', 'createElement', 'appendChild',
    'innerHTML', 'textContent', 'className', 'classList', 'style',
    'getAttribute', 'setAttribute', 'removeAttribute', 'parentNode',
    'childNodes', 'firstChild', 'lastChild', 'nextSibling',
    'previousSibling', 'nodeName', 'nodeType', 'nodeValue',
    'apply', 'call', 'bind', 'then', 'catch', 'resolve', 'reject',
    'log', 'warn', 'error', 'info', 'debug', 'table', 'trace',
    'stringify', 'parse', 'assign', 'freeze', 'defineProperty',
    'getPrototypeOf', 'setPrototypeOf', 'create', 'now',
    'abs', 'ceil', 'floor', 'round', 'random', 'min', 'max',
    'pow', 'sqrt', 'PI', 'E',
})

_MIN_PARAM_LEN = 1
_MAX_PARAM_LEN = 60

_META_NOISE = frozenset({
    'viewport', 'description', 'keywords', 'author', 'robots',
    'theme-color', 'generator', 'rating', 'revisit-after',
    'charset', 'og', 'twitter', 'fb', 'article', 'referrer',
    'format-detection', 'apple', 'msapplication', 'handheldfriendly',
    'googlebot', 'bingbot', 'msvalidate', 'yandex-verification',
})

SESSION_COOKIES = frozenset({
    'session', 'sessionid', 'phpsessid', 'jsessionid', 'asp.net_sessionid',
    'auth', 'auth_token', 'access_token', 'remember_token', 'csrf_token',
    '_session', 'sid', 'user_session',
})

logger = logging.getLogger("akha.param_finder")


def _is_valid_param_name(name: str) -> bool:
    """Return True if *name* looks like a plausible HTTP parameter."""
    if not name:
        return False
    n = len(name)
    if n < _MIN_PARAM_LEN or n > _MAX_PARAM_LEN:
        return False
    if name.lower() in _JS_NOISE:
        return False
    if not (name[0].isalpha() or name[0] in ('_', '$')):
        return False
    if not re.fullmatch(r'[a-zA-Z0-9_$.-]+', name):
        return False
    return True


class ParamFinder:
    """
    Advanced parameter discovery and fuzzing.

    Normal mode:  URL extraction + form extraction + HTML/JS mining
    Deep scan:    + batch differential fuzzing (Arjun-style)
    """

    INJECTABLE_HEADERS = [
        'X-Forwarded-For',
        'X-Forwarded-Host',
        'X-Real-IP',
        'Referer',
        'User-Agent',
        'X-Custom-IP-Authorization',
        'X-Original-URL',
        'X-Rewrite-URL',
        'X-HTTP-Method-Override',
        'X-Requested-With',
        'Accept-Language',
        'Origin',
        'True-Client-IP',
        'CF-Connecting-IP',
        'X-Client-IP',
        'X-Host',
        'X-Forwarded-Server',
    ]

    def __init__(self, http_client, config):
        self.client = http_client
        self.config = config
        self.wordlist = self._load_wordlist()
        self._vector_probe_seen = {
            'header': set(),
            'cookie': set(),
            'path': set(),
        }
        self._vector_probe_lock = threading.Lock()

    @staticmethod
    def _likely_markup(text: str) -> bool:
        if not text:
            return False
        sample = text[:3000].lstrip()
        if not sample:
            return False
        return '<' in sample and '>' in sample

    def _safe_soup(self, html: str, max_len: int = 500_000) -> Optional[BeautifulSoup]:
        if not html:
            return None
        snippet = html[:max_len]
        if not self._likely_markup(snippet):
            return None
        try:
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
                return BeautifulSoup(snippet, 'html.parser')
        except Exception:
            return None

    @staticmethod
    def _make_marker() -> str:
        return f"akha{uuid.uuid4().hex[:8]}"


    def _load_wordlist(self) -> List[str]:
        """Load parameter wordlist from file or use built-in defaults."""
        default_params = [
            'id', 'page', 'pid', 'uid', 'user', 'userid', 'username',
            'query', 'q', 'search', 's', 'keyword', 'key',
            'name', 'title', 'description', 'text', 'content',
            'url', 'link', 'redirect', 'return', 'next', 'goto',
            'file', 'filename', 'path', 'dir', 'folder',
            'cat', 'category', 'type', 'action', 'act',
            'view', 'display', 'show', 'mode', 'method',
            'data', 'value', 'val', 'input', 'msg', 'message',
            'email', 'mail', 'comment', 'feedback',
            'debug', 'test', 'admin', 'token', 'auth', 'api',
            'callback', 'cmd', 'lang', 'format', 'template',
            'include', 'src', 'ref', 'sort', 'order', 'limit',
            'offset', 'filter', 'field', 'column',
        ]

        wordlist_path = getattr(self.config, 'param_wordlist', None)
        if wordlist_path and os.path.exists(wordlist_path):
            try:
                with open(wordlist_path, 'r', encoding='utf-8') as f:
                    file_params = [line.strip() for line in f if line.strip()]
                if file_params:
                    return file_params
            except Exception:
                logger.debug("Failed loading custom parameter wordlist", exc_info=True)

        try:
            resource_path = resources.files('akha').joinpath('data/wordlists/wordlist.txt')
            with resource_path.open('r', encoding='utf-8') as f:
                file_params = [line.strip() for line in f if line.strip()]
            if file_params:
                return file_params
        except Exception:
            logger.debug("Failed loading packaged parameter wordlist", exc_info=True)

        return default_params


    def find_parameters(self, url: str, response_text: str = None) -> List[Dict]:
        """
        Discover parameters for *url* using multiple techniques.

        Normal mode:
          1. URL query string extraction
          2. HTML form extraction
          3. HTML/JS mining (data-* attrs, JS vars, comments)
          4. Lightweight reflection check for mined params

        Deep scan (``--deep-scan``):
          + Arjun-style batch differential fuzzing with the full wordlist
        """
        parameters: List[Dict] = []

        url_params = self._extract_from_url(url)
        parameters.extend(url_params)

        html = response_text
        if html:
            form_params = self._extract_forms_from_html(url, html)
        else:
            form_params = self._extract_from_forms(url)
            try:
                resp = self.client.get(url, timeout=self.config.timeout)
                html = resp.text
            except Exception:
                html = None
        parameters.extend(form_params)

        mined_params = set()
        if html:
            mined_params.update(self._mine_params_from_html(html))
            js_params = self._mine_params_from_js_urls(url, html)
            mined_params.update(js_params)

        profile = getattr(self.config, 'scan_profile', 'balanced').lower()
        include_mined = (
            self.config.deep_scan or self.config.aggressive_mode or profile == 'deep'
        )

        existing_names = {p['name'] for p in parameters}
        if include_mined:
            for pname in mined_params:
                if pname not in existing_names:
                    parameters.append({
                        'name': pname,
                        'value': '',
                        'type': 'mined',
                        'location': 'query',
                        'confidence': 'medium',
                    })
        elif not parameters and mined_params:
            for pname in sorted(mined_params)[:8]:
                if pname not in existing_names:
                    parameters.append({
                        'name': pname,
                        'value': '',
                        'type': 'mined',
                        'location': 'query',
                        'confidence': 'low',
                    })

        if self._should_run_fuzzing(url, parameters):
            fuzzed = self._fuzz_parameters(url, existing_names | mined_params)
            parameters.extend(fuzzed)

        return self._deduplicate(parameters)


    def _extract_from_url(self, url: str) -> List[Dict]:
        """Extract parameters from URL query string."""
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


    def _extract_from_forms(self, url: str) -> List[Dict]:
        """Extract parameters from HTML forms (fetches the page)."""
        try:
            response = self.client.get(url, timeout=self.config.timeout)
            content_type = (response.headers.get('Content-Type', '') or '').lower()
            if content_type and 'html' not in content_type and 'xml' not in content_type:
                return []
            soup = self._safe_soup(response.text, 500_000)
            if soup is None:
                return []
            return self._parse_forms_from_soup(soup, url)
        except Exception as e:
            if self.config.verbose:
                print(f"Error extracting form parameters: {e}")
            return []

    def _extract_forms_from_html(self, url: str, html: str) -> List[Dict]:
        """Extract parameters from pre-fetched HTML."""
        soup = self._safe_soup(html, 500_000)
        if soup is None:
            return []
        return self._parse_forms_from_soup(soup, url)

    def _parse_forms_from_soup(self, soup: BeautifulSoup, url: str) -> List[Dict]:
        """Parse ``<form>`` elements and return parameter dicts with full context."""
        params = []
        for form in soup.find_all('form'):
            method = form.get('method', 'GET').upper()
            form_action = urljoin(url, form.get('action', ''))

            sibling_inputs = {}
            for inp in form.find_all(['input', 'textarea', 'select']):
                name = inp.get('name', '')
                if name:
                    sibling_inputs[name] = inp.get('value', '')

            for input_tag in form.find_all(['input', 'textarea', 'select']):
                param_name = input_tag.get('name', '')
                param_type = input_tag.get('type', 'text').lower()
                param_value = input_tag.get('value', '')

                if param_name and param_type not in ('submit', 'button', 'image'):
                    params.append({
                        'name': param_name,
                        'value': param_value,
                        'type': 'form',
                        'location': method,
                        'input_type': param_type,
                        'form_action': form_action,
                        'form_inputs': sibling_inputs,
                    })
        return params


    def _mine_params_from_html(self, html: str) -> Set[str]:
        """
        Extract potential parameter names from HTML content:
          - ``name=`` / ``id=`` attributes on input-like elements
          - ``data-*`` attributes
          - URL query params embedded in href/src/action
          - HTML comment hints
          - ``<meta>`` name/property attributes
        """
        found: Set[str] = set()
        html_sample = html[:1_000_000]  # limit for performance

        for m in _NAME_ID_RE.finditer(html_sample):
            name = m.group(1)
            if _is_valid_param_name(name):
                found.add(name)

        for m in _DATA_ATTR_RE.finditer(html_sample):
            name = m.group(1).replace('-', '_')
            if _is_valid_param_name(name):
                found.add(name)

        for m in _URL_PARAM_RE.finditer(html_sample):
            name = m.group(1)
            if _is_valid_param_name(name):
                found.add(name)

        for m in _COMMENT_PARAM_RE.finditer(html_sample):
            name = m.group(1)
            if _is_valid_param_name(name):
                found.add(name)

        try:
            soup = self._safe_soup(html_sample, 200_000)
            if soup is None:
                return found
            for meta in soup.find_all('meta'):
                for attr in ('name', 'property'):
                    raw_val = meta.get(attr)
                    val = (raw_val or '').split(':')[0].strip().lower()
                    if val and val not in _META_NOISE and _is_valid_param_name(val):
                        found.add(val)
        except Exception:
            logger.debug("Meta-tag parameter mining failed", exc_info=True)

        return found

    def _mine_params_from_js(self, js_content: str) -> Set[str]:
        """
        Extract potential parameter names from JavaScript code:
          - Variable declarations and assignments
          - Object property accesses
          - Getter calls: getParameter("x"), request.args.get("x")
          - Query params in embedded URLs
        """
        found: Set[str] = set()
        js_sample = js_content[:500_000]

        for m in _JS_VAR_RE.finditer(js_sample):
            for g in m.groups():
                if g and _is_valid_param_name(g):
                    found.add(g)

        for m in _PARAM_GETTER_RE.finditer(js_sample):
            for g in m.groups():
                if g and _is_valid_param_name(g):
                    found.add(g)

        for m in _URL_PARAM_RE.finditer(js_sample):
            name = m.group(1)
            if _is_valid_param_name(name):
                found.add(name)

        for m in _JS_PARAM_CONTEXT_RE.finditer(js_sample):
            name = m.group(1)
            if _is_valid_param_name(name):
                found.add(name)

        return found

    def _mine_params_from_js_urls(self, page_url: str, html: str) -> Set[str]:
        """
        Find <script src="..."> tags, fetch each JS file, and mine
        parameter names from the content.  Limited to first 10 JS files.
        """
        found: Set[str] = set()
        soup = self._safe_soup(html, 500_000)
        if soup is None:
            return found

        js_urls = []
        for script in soup.find_all('script', src=True):
            src = script['src']
            if src:
                full_url = urljoin(page_url, src)
                js_urls.append(full_url)

        js_limit = 10 if self.config.deep_scan else 4
        for js_url in js_urls[:js_limit]:
            try:
                resp = self.client.get(js_url, timeout=min(self.config.timeout, 8))
                if resp.status_code == 200:
                    found.update(self._mine_params_from_js(resp.text))
            except Exception:
                continue

        for script in soup.find_all('script', src=False):
            if script.string:
                found.update(self._mine_params_from_js(script.string))

        return found


    def _fuzz_parameters(self, url: str, already_known: Set[str] = None) -> List[Dict]:
        """
        Arjun-inspired batch fuzzing with binary-split refinement.

        1. Collect stable baselines (3 samples to measure natural variance).
        2. Split the wordlist into chunks (batch_size params per request).
        3. Send one request per chunk with all params.
        4. If response differs significantly → binary-split to find which
           params cause the diff.
        5. Verify each candidate with a solo request to confirm reflection
           or persistent diff.

        Normal mode:  uses smaller batches, tests up to 500 params.
        Deep scan:    full wordlist with larger batches.
        """
        if already_known is None:
            already_known = set()

        candidates = [p for p in self.wordlist if p not in already_known]

        if not candidates:
            return []

        profile = getattr(self.config, 'scan_profile', 'balanced').lower()
        if profile == 'quick' and not self.config.deep_scan and not self.config.aggressive_mode:
            candidates = candidates[:40]
        elif profile == 'balanced' and not self.config.deep_scan and not self.config.aggressive_mode:
            candidates = candidates[:80]
        elif not self.config.deep_scan:
            candidates = candidates[:120]

        baseline_samples = 3 if self.config.deep_scan else 2
        baselines = self._collect_baselines(url, n=baseline_samples)
        if not baselines:
            return []

        baseline_len = baselines[0]['length']
        baseline_code = baselines[0]['status']
        baseline_hash = baselines[0]['body_hash']

        natural_variance = 0
        for bl in baselines[1:]:
            natural_variance = max(natural_variance,
                                   abs(bl['length'] - baseline_len))

        if len(baselines) >= 2:
            variances = [abs(b['length'] - baselines[0]['length']) for b in baselines[1:]]
            avg_variance = sum(variances) / len(variances) if variances else 0
            threshold = max(int(avg_variance * 3), 20)
        else:
            threshold = max(int(baseline_len * 0.03), 20)

        methods = ['GET']
        if self.config.deep_scan or self.config.aggressive_mode or profile == 'deep':
            methods = ['GET', 'POST', 'JSON']

        batch_size = 20 if self.config.deep_scan else 10
        interesting_params: Set[str] = set()

        chunks = [candidates[i:i + batch_size]
                  for i in range(0, len(candidates), batch_size)]

        for chunk in chunks:
            if not chunk:
                continue
            for method in methods:
                try:
                    diff = self._test_param_batch(
                        url,
                        chunk,
                        baseline_len,
                        baseline_code,
                        baseline_hash,
                        threshold,
                        method=method,
                    )
                    if diff:
                        narrowed = self._binary_split(
                            url,
                            chunk,
                            baseline_len,
                            baseline_code,
                            baseline_hash,
                            threshold,
                            method=method,
                        )
                        interesting_params.update(narrowed)
                except Exception:
                    continue

        generic_query_echo = self._is_generic_query_echo(url, baseline_len, baseline_code, threshold)

        confirmed: List[Dict] = []

        for param_name in interesting_params:
            try:
                probe_marker = self._make_marker()
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param_name}={probe_marker}"
                resp = self.client.get(test_url, timeout=min(self.config.timeout, 8))

                reflected = probe_marker in resp.text
                len_diff = abs(len(resp.text) - baseline_len)
                status_diff = resp.status_code != baseline_code

                if reflected:
                    if generic_query_echo and not status_diff and len_diff <= (threshold * 2):
                        continue
                    confidence = 'high' if not generic_query_echo else 'medium'
                elif status_diff and len_diff > threshold and not generic_query_echo:
                    confidence = 'medium'
                elif len_diff > threshold and (self.config.deep_scan or profile == 'deep'):
                    confidence = 'low'
                else:
                    continue  # false positive from batch — skip

                confirmed.append({
                    'name': param_name,
                    'value': '',
                    'type': 'fuzzed',
                    'location': 'query',
                    'confidence': confidence,
                    'reflected': reflected,
                })

                if self.config.verbose:
                    print(f"[fuzz] Discovered: {param_name} "
                          f"(confidence={confidence}, reflected={reflected})")
            except Exception:
                continue

        priority = {'high': 3, 'medium': 2, 'low': 1}
        confirmed.sort(key=lambda p: priority.get(p.get('confidence', ''), 0), reverse=True)

        if profile == 'quick':
            return confirmed[:0]
        if profile == 'balanced' and not self.config.deep_scan and not self.config.aggressive_mode:
            return confirmed[:12]
        return confirmed

    def _collect_baselines(self, url: str, n: int = 3) -> List[Dict]:
        """Collect *n* baseline responses to measure natural variance."""
        baselines = []
        for _ in range(n):
            try:
                resp = self.client.get(url, timeout=min(self.config.timeout, 10))
                baselines.append({
                    'status': resp.status_code,
                    'length': len(resp.text),
                    'body_hash': hash(resp.text),
                    'headers': dict(resp.headers),
                })
            except Exception:
                logger.debug("Baseline collection request failed", exc_info=True)
        return baselines

    def _test_param_batch(self, url: str, param_names: List[str],
                          baseline_len: int, baseline_code: int,
                          baseline_hash: int, threshold: int,
                          method: str = 'GET') -> bool:
        """
        Send one request with all *param_names* and a unique marker.
        Return True if the response differs significantly from baseline.
        """
        marker = self._make_marker()
        params = {name: marker for name in param_names}

        try:
            if method == 'GET':
                separator = '&' if '?' in url else '?'
                qs = urlencode(params)
                test_url = f"{url}{separator}{qs}"
                resp = self.client.get(test_url, timeout=min(self.config.timeout, 10))
            elif method == 'POST':
                resp = self.client.post(url, data=params, timeout=min(self.config.timeout, 10))
            elif method == 'JSON':
                resp = self.client.post_json(url, json_data=params, timeout=min(self.config.timeout, 10))
            else:
                return False
        except Exception:
            return False

        marker_reflected = marker in resp.text
        if resp.status_code != baseline_code:
            if marker_reflected or self.config.deep_scan or self.config.aggressive_mode:
                return True
        if abs(len(resp.text) - baseline_len) > threshold:
            if marker_reflected or self.config.deep_scan or self.config.aggressive_mode:
                return True
        body_hash = hash(resp.text)
        if body_hash != baseline_hash and marker_reflected:
            return True

        return False

    def _is_generic_query_echo(
        self,
        url: str,
        baseline_len: int,
        baseline_code: int,
        threshold: int,
    ) -> bool:
        """Return True when arbitrary query params are reflected regardless of name."""
        try:
            m1 = self._make_marker()
            m2 = self._make_marker()
            p1 = f"akha_ctrl_{uuid.uuid4().hex[:6]}"
            p2 = f"akha_ctrl_{uuid.uuid4().hex[:6]}"

            sep = '&' if '?' in url else '?'
            u1 = f"{url}{sep}{p1}={m1}"
            u2 = f"{url}{sep}{p2}={m2}"

            r1 = self.client.get(u1, timeout=min(self.config.timeout, 8))
            r2 = self.client.get(u2, timeout=min(self.config.timeout, 8))

            if m1 not in r1.text or m2 not in r2.text:
                return False

            if r1.status_code != baseline_code or r2.status_code != baseline_code:
                return False

            d1 = abs(len(r1.text) - baseline_len)
            d2 = abs(len(r2.text) - baseline_len)
            return d1 <= threshold and d2 <= threshold
        except Exception:
            return False

    def _binary_split(self, url: str, param_names: List[str],
                      baseline_len: int, baseline_code: int,
                      baseline_hash: int, threshold: int,
                      depth: int = 0, method: str = 'GET') -> Set[str]:
        """
        Recursively halve the param list until individual interesting
        params are identified (Arjun binary-split algorithm).
        """
        if not param_names:
            return set()

        if len(param_names) == 1:
            return set(param_names)

        if depth > 10:
            return set(param_names)

        mid = len(param_names) // 2
        left = param_names[:mid]
        right = param_names[mid:]

        found: Set[str] = set()

        try:
            if self._test_param_batch(url, left, baseline_len, baseline_code,
                                      baseline_hash, threshold, method=method):
                found.update(self._binary_split(url, left, baseline_len,
                                                baseline_code, baseline_hash,
                                                threshold, depth + 1, method=method))
        except Exception:
            logger.debug("Binary split left branch failed", exc_info=True)

        try:
            if self._test_param_batch(url, right, baseline_len, baseline_code,
                                      baseline_hash, threshold, method=method):
                found.update(self._binary_split(url, right, baseline_len,
                                                baseline_code, baseline_hash,
                                                threshold, depth + 1, method=method))
        except Exception:
            logger.debug("Binary split right branch failed", exc_info=True)

        return found


    def find_header_parameters(self, url: str) -> List[Dict]:
        """
        Test injectable HTTP headers for XSS reflection.
        Sends a harmless probe in each header and checks if it appears in response.
        """
        params = []
        probe_value = self._make_marker()

        if not getattr(self.config, 'test_headers', False):
            return params

        if not self._should_probe_vector(url, 'header'):
            return params

        for header_name in self.INJECTABLE_HEADERS:
            try:
                response = self.client.get(
                    url,
                    timeout=self.config.timeout,
                    headers={header_name: probe_value},
                )
                if probe_value in response.text:
                    params.append({
                        'name': header_name,
                        'value': '',
                        'type': 'header',
                        'location': 'header',
                        'confidence': 'high',
                    })
                    if self.config.verbose:
                        print(f"[header] Reflected: {header_name}")
            except Exception:
                continue

        return params


    def find_cookie_parameters(self, url: str) -> List[Dict]:
        """
        Test existing cookie values for XSS reflection.
        Sends a probe value for each cookie and checks response.
        """
        params = []
        probe_value = self._make_marker()

        if not getattr(self.config, 'test_cookies', False):
            return params

        if not self._should_probe_vector(url, 'cookie'):
            return params

        try:
            response = self.client.get(url, timeout=self.config.timeout)
            cookies = response.cookies
        except Exception:
            return params

        for cookie_name in cookies.keys():
            if cookie_name.lower() in SESSION_COOKIES:
                continue
            try:
                test_cookies = {k: v for k, v in cookies.items()}
                test_cookies[cookie_name] = probe_value

                resp = self.client.get(
                    url,
                    timeout=self.config.timeout,
                    cookies=test_cookies,
                )
                if probe_value in resp.text:
                    params.append({
                        'name': cookie_name,
                        'value': '',
                        'type': 'cookie',
                        'location': 'cookie',
                        'confidence': 'high',
                    })
                    if self.config.verbose:
                        print(f"[cookie] Reflected: {cookie_name}")
            except Exception:
                continue

        return params


    def find_path_parameters(self, url: str) -> List[Dict]:
        """
        Test URL path segments for XSS reflection.
        Replaces numeric/UUID/slug path segments with a probe value.
        """
        params = []
        probe_value = self._make_marker()

        if not self._should_probe_vector(url, 'path'):
            return params

        parsed = urlparse(url)
        path_parts = [p for p in parsed.path.split('/') if p]

        if not path_parts:
            return params

        for i, segment in enumerate(path_parts):
            is_numeric = segment.isdigit()
            is_uuid = bool(re.match(
                r'^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$',
                segment, re.IGNORECASE
            ))
            is_slug = bool(re.match(r'^[a-z0-9][a-z0-9-]{2,50}$', segment))

            if not self.config.deep_scan:
                is_slug = False

            if not (is_numeric or is_uuid or is_slug):
                continue

            test_parts = path_parts.copy()
            test_parts[i] = probe_value
            test_path = '/' + '/'.join(test_parts)
            test_url = urlunparse((
                parsed.scheme, parsed.netloc, test_path,
                parsed.params, parsed.query, parsed.fragment,
            ))

            try:
                resp = self.client.get(test_url, timeout=self.config.timeout)
                if resp.status_code < 400 and probe_value in resp.text:
                    params.append({
                        'name': f'path_segment_{i}',
                        'value': segment,
                        'type': 'path',
                        'location': 'path',
                        'path_index': i,
                        'original_segment': segment,
                        'confidence': 'high',
                    })
                    if self.config.verbose:
                        print(f"[path] Reflected segment {i}: {segment}")
            except Exception:
                continue

        return params


    def analyze_parameter_behavior(self, url: str, param_name: str) -> Dict:
        """
        Analyze parameter behavior using harmless probes.
        """
        analysis = {
            'reflected': False,
            'encoded': False,
            'filtered': False,
            'context': None,
        }

        marker = "AKHA_TEST_12345"

        try:
            separator = '&' if '?' in url else '?'
            test_url = f"{url}{separator}{param_name}={marker}"
            response = self.client.get(test_url, timeout=10)

            if marker in response.text:
                analysis['reflected'] = True
                if re.search(r'&[a-z]+;', response.text):
                    analysis['encoded'] = True
                analysis['context'] = self._detect_context(response.text, marker)

            test_value = f"{marker}<>\"'`"
            test_url2 = f"{url}{separator}{param_name}={test_value}"
            response2 = self.client.get(test_url2, timeout=10)

            if marker in response2.text:
                if '<' not in response2.text.split(marker, 1)[-1][:20]:
                    analysis['filtered'] = True
        except Exception:
            logger.debug("Parameter behavior analysis failed for %s", param_name, exc_info=True)

        return analysis

    def _detect_context(self, html: str, marker: str) -> str:
        """Detect the context where marker appears in response HTML."""
        pos = html.find(marker)
        if pos == -1:
            return "unknown"

        before = html[:pos]

        last_script_open = before.rfind('<script')
        last_script_close = before.rfind('</script')
        if last_script_open > last_script_close and last_script_open != -1:
            return "javascript"

        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open > last_tag_close and last_tag_open != -1:
            tag_content = html[last_tag_open:pos]
            if re.search(r'(href|src|action|formaction)\s*=\s*["\']?\s*$',
                         tag_content, re.I):
                return "url"
            return "attribute"

        return "html"


    def _deduplicate(self, parameters: List[Dict]) -> List[Dict]:
        """Remove duplicate parameters, keeping the highest-confidence entry."""
        seen: Dict[tuple, Dict] = {}
        priority = {'high': 3, 'medium': 2, 'low': 1}

        for param in parameters:
            key = (
                (param.get('name') or '').strip(),
                (param.get('location', '') or '').strip().upper(),
                self._canonical_endpoint_signature(param),
            )
            existing = seen.get(key)
            if existing is None:
                seen[key] = param
            else:
                new_pri = priority.get(param.get('confidence', ''), 0)
                old_pri = priority.get(existing.get('confidence', ''), 0)
                if new_pri > old_pri:
                    seen[key] = param

        return list(seen.values())

    def _canonical_endpoint_signature(self, param: Dict) -> str:
        """Return a stable endpoint signature for dedup across semantically same URLs."""
        target = (param.get('form_action') or param.get('url') or '').strip()
        if not target:
            return ''

        try:
            parsed = urlparse(target)
            path = parsed.path.rstrip('/') if parsed.path not in ('', '/') else '/'
            names = sorted(parse_qs(parsed.query, keep_blank_values=True).keys())
            qsig = '&'.join(names)
            return f"{parsed.scheme.lower()}://{parsed.netloc.lower()}{path}?{qsig}"
        except Exception:
            return target

    def _should_run_fuzzing(self, url: str, params: List[Dict]) -> bool:
        """Decide whether to run expensive differential fuzzing for this URL."""
        profile = getattr(self.config, 'scan_profile', 'balanced')
        if profile == 'quick' and not (self.config.deep_scan or self.config.aggressive_mode):
            return False

        if not (self.config.deep_scan or self.config.aggressive_mode or profile in ('deep', 'balanced')):
            return False

        parsed = urlparse(url)
        if parsed.query:
            return True

        if any(p.get('type') in ('form', 'mined') for p in params):
            return True

        return self.config.deep_scan

    def _should_probe_vector(self, url: str, vector: str) -> bool:
        """Budget expensive vector probes across URLs to avoid discovery stalls."""
        parsed = urlparse(url)
        key = f"{parsed.netloc.lower()}{parsed.path}"

        max_urls = 40 if self.config.deep_scan else 12

        with self._vector_probe_lock:
            seen = self._vector_probe_seen.get(vector, set())
            if key in seen:
                return False
            if len(seen) >= max_urls:
                return False
            seen.add(key)
            self._vector_probe_seen[vector] = seen
            return True

    def analyze_parameter_behavior(self, url: str, param_name: str) -> Dict[str, str]:
        """Analyze per-character filtering behavior for a specific parameter."""
        marker = self._make_marker()
        special_chars = ['<', '>', '"', "'", '`', '(', ')', ';', '/']
        char_status: Dict[str, str] = {}

        for char in special_chars:
            probe = f"{marker}{char}{marker}"
            try:
                separator = '&' if '?' in url else '?'
                test_url = f"{url}{separator}{param_name}={probe}"
                resp = self.client.get(test_url, timeout=self.config.timeout)
                body = resp.text
                if probe in body:
                    char_status[char] = 'raw'
                elif f"&#{ord(char)};" in body or f"&#x{ord(char):x};" in body:
                    char_status[char] = 'encoded'
                else:
                    char_status[char] = 'removed'
            except Exception:
                char_status[char] = 'unknown'

        return char_status
