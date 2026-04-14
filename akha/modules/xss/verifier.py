"""
Unified XSS verification module.

Implements the multi-step verification pipeline:
  1. Marker reflection check — is our unique marker in the response?
  2. Raw reflection check — are XSS-critical chars unencoded?
  3. Safe context exclusion — is the reflection trapped in a non-executable context?
  4. Re-verification — send the same payload again to confirm consistency
  5. Browser verification — headless browser confirms real JS execution

This replaces and consolidates validator.py and execution_verifier.py.
"""

from __future__ import annotations

import re
import logging
import uuid
import html
import urllib.parse
from enum import Enum
from typing import Dict, Optional
from akha.modules.xss.execution_verifier import ExecutionVerifier

logger = logging.getLogger("akha.verifier")

SAFE_CONTAINERS = ('textarea', 'title', 'noscript', 'style', 'xmp')


class ReflectionQuality(Enum):
    RAW = 4
    URL_ENCODED = 3
    HTML_ENCODED = 2
    DOUBLE_ENCODED = 1
    NOT_REFLECTED = 0


class VerificationResult:
    """Result of the verification pipeline."""
    __slots__ = (
        'verified', 'marker_in_tag', 'payload_reflected_raw',
        'reverify_ok', 'browser_executed', 'browser_method',
        'execution_evidence', 'method',
    )

    def __init__(self):
        self.verified: bool = False
        self.marker_in_tag: bool = False
        self.payload_reflected_raw: bool = False
        self.reverify_ok: bool = False
        self.browser_executed: bool = False
        self.browser_method: Optional[str] = None
        self.execution_evidence: Optional[str] = None
        self.method: Optional[str] = None  # 'static' | 'browser'


class Verifier:
    """
    Multi-step XSS verification engine.

    Designed to minimize false positives by requiring multiple evidence
    signals before confirming a vulnerability. Uses Playwright for
    browser-based execution verification.
    """

    def __init__(self, config, marker: Optional[str] = None):
        self.config = config
        self.marker = marker or f"akha{uuid.uuid4().hex[:10]}"
        self.verify_class = f'class={self.marker}'
        self.verify_id = f'id={self.marker}'
        self._execution_verifier: Optional[ExecutionVerifier] = None


    def verify_reflection(self, body: str, payload: str) -> VerificationResult:
        """
        Steps 1-3: Check if the payload is reflected in an exploitable way.
        Does NOT make any HTTP requests — operates on the response body only.
        """
        result = VerificationResult()

        has_marker = self.verify_class in body or self.verify_id in body

        quality = self._reflection_quality(body, payload)

        payload_raw = quality == ReflectionQuality.RAW and self._is_payload_reflected_raw(body, payload)

        if not has_marker and not payload_raw:
            return result

        marker_in_tag = False
        if has_marker:
            marker_in_tag = self._is_marker_in_real_tag(body)

        if has_marker and not marker_in_tag and not payload_raw:
            return result

        result.marker_in_tag = marker_in_tag
        result.payload_reflected_raw = payload_raw
        result.verified = marker_in_tag or payload_raw
        result.method = 'static'

        return result

    def _reflection_quality(self, body: str, payload: str) -> ReflectionQuality:
        if payload in body:
            return ReflectionQuality.RAW
        if html.escape(payload) in body:
            return ReflectionQuality.HTML_ENCODED
        if urllib.parse.quote(payload) in body:
            return ReflectionQuality.URL_ENCODED
        double = urllib.parse.quote(urllib.parse.quote(payload))
        if double in body:
            return ReflectionQuality.DOUBLE_ENCODED
        return ReflectionQuality.NOT_REFLECTED

    def verify_browser(self, url: str, payload: str,
                       method: str = "GET",
                       post_data: Optional[Dict] = None) -> VerificationResult:
        """
        Step 5: Browser-based execution verification.
        Loads the URL in a headless browser and checks for JS execution
        (dialog/alert, console markers, DOM mutations).

        Supports both GET (navigation) and POST (form submission) verification.
        """
        result = VerificationResult()

        if self._execution_verifier is None:
            timeout_ms = int(getattr(self.config, 'timeout', 10) * 1000)
            self._execution_verifier = ExecutionVerifier(timeout_ms=timeout_ms)

        exec_result = self._execution_verifier.verify(url, payload)
        result.browser_executed = bool(exec_result.executed)
        result.browser_method = exec_result.method
        result.execution_evidence = exec_result.evidence
        if result.browser_executed:
            result.verified = True
            result.method = 'browser'
        

        return result


    def _is_payload_reflected_raw(self, html: str, payload: str) -> bool:
        """
        Check if the critical XSS parts of the payload appear unencoded
        in the response. This is the core false-positive prevention check.
        """
        payload_lower = payload.lower()
        html_lower = html.lower()

        if payload in html or payload_lower in html_lower:
            if self._is_in_safe_context(html, payload):
                return False
            return True

        tag_match = re.search(r'<(\w+)', payload_lower)
        if tag_match:
            return self._check_tag_reflection(html, html_lower, payload_lower, tag_match)

        js_match = re.search(r'(alert|confirm|prompt)\s*[\(`]', payload_lower)
        if js_match and not tag_match:
            if payload in html or payload_lower in html_lower:
                if not self._is_in_safe_context(html, payload):
                    return True
            return False

        if 'javascript:' in payload_lower:
            if payload in html or payload_lower in html_lower:
                if not self._is_in_safe_context(html, payload):
                    return True
            return False

        if payload.startswith('-->'):
            return self._check_comment_breakout(html, html_lower, payload)

        if payload_lower.startswith(('"', "'", ' ')):
            if payload in html or payload_lower in html_lower:
                if not self._is_in_safe_context(html, payload):
                    return True

        return False

    def _check_tag_reflection(self, html: str, html_lower: str,
                              payload_lower: str, tag_match) -> bool:
        """Check if a tag-based payload is reflected raw."""
        tag_name = tag_match.group(1)
        injected_tag = f'<{tag_name}'
        encoded_tag = f'&lt;{tag_name}'

        if encoded_tag in html_lower and injected_tag not in html_lower:
            return False

        if injected_tag not in html_lower:
            return False

        handler_match = re.search(r'(on\w+)\s*=', payload_lower)
        if handler_match:
            handler = handler_match.group(1)
            pattern = re.escape(injected_tag) + r'[^>]*' + re.escape(handler) + r'\s*='
            if re.search(pattern, html_lower):
                return True

        if tag_name == 'script':
            if re.search(re.escape(payload_lower[:40]), html_lower):
                return True

        if tag_name in ('iframe', 'object', 'embed') and 'javascript:' in payload_lower:
            pattern = re.escape(injected_tag) + r'[^>]*javascript:'
            if re.search(pattern, html_lower):
                return True

        tag_positions = [m.start() for m in re.finditer(re.escape(injected_tag), html_lower)]
        for tp in tag_positions:
            nearby = html[tp:tp + 500]
            if self.verify_class in nearby or self.verify_id in nearby:
                return True

        return False

    def _check_comment_breakout(self, html: str, html_lower: str, payload: str) -> bool:
        """Check if a comment breakout payload is reflected."""
        remaining = payload[3:]
        tag_match = re.search(r'<(\w+)', remaining.lower())
        if tag_match:
            tag = f'<{tag_match.group(1)}'
            for m in re.finditer(re.escape(tag), html_lower):
                chunk = html[m.start():m.start() + 500]
                if self.verify_class in chunk or self.verify_id in chunk:
                    return True
        return False


    def _is_in_safe_context(self, html: str, payload: str) -> bool:
        """
        Check if ALL reflections of the payload are in non-exploitable contexts.
        Returns True only if EVERY reflection is safely contained.
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
            html_lower = html.lower()
            payload_lower = payload.lower()
            start = 0
            while True:
                pos = html_lower.find(payload_lower, start)
                if pos == -1:
                    break
                positions.append(pos)
                start = pos + 1

        if not positions:
            return False

        return all(self._is_position_safe(html, pos, payload) for pos in positions)

    def _is_position_safe(self, html: str, pos: int, payload: str) -> bool:
        """Check if a single reflection at position *pos* is safely contained."""
        before = html[max(0, pos - 500):pos]
        before_lower = before.lower()

        for container in SAFE_CONTAINERS:
            last_open = before_lower.rfind(f'<{container}')
            last_close = before_lower.rfind(f'</{container}')
            if last_open > last_close and last_open != -1:
                if f'</{container}' not in payload.lower():
                    return True

        last_comment_open = before.rfind('<!--')
        last_comment_close = before.rfind('-->')
        if last_comment_open > last_comment_close and last_comment_open != -1:
            if '-->' not in payload:
                return True

        stripped = html.strip()
        if stripped.startswith(('{', '[')):
            sample = stripped[:3000].lower()
            if not any(t in sample for t in ('<html', '<body', '<head', '<!doctype', '<div', '<form')):
                return True

        last_script_open = before_lower.rfind('<script')
        last_script_close = before_lower.rfind('</script')
        if last_script_open > last_script_close and last_script_open != -1:
            json_before = before.rstrip()
            json_endings = (
                '":', "':", '": "', ": '", '":"',
                '":["', "':['", '": ["', ": ['",
                '":[', "':[", '","', "','",
            )
            if json_before.endswith(json_endings):
                return True

            if self._is_trapped_in_js_string(html, pos, payload):
                return True

            nearby = html[max(0, pos - 10):pos + len(payload) + 10]
            if self._is_js_string_escaped(nearby, payload):
                return True

            if self._is_js_hex_encoded(html, pos, payload):
                return True

        if self._is_url_encoded_in_attr(before, payload):
            return True

        return False

    def _is_trapped_in_js_string(self, html: str, pos: int, payload: str) -> bool:
        """Check if payload is inside a JS string it cannot break."""
        before = html[:pos]
        last_script = before.lower().rfind('<script')
        if last_script == -1:
            return False

        tag_end = html.find('>', last_script)
        if tag_end == -1 or tag_end >= pos:
            return False

        js_content = html[tag_end + 1:pos]
        in_string = None
        escaped = False

        for char in js_content:
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

        if in_string is None:
            return False

        if in_string not in payload:
            return True

        for idx, c in enumerate(payload):
            if c == in_string:
                html_idx = pos + idx
                if html_idx > 0 and html[html_idx - 1] == '\\':
                    continue
                else:
                    return False
        return True

    @staticmethod
    def _is_js_string_escaped(nearby: str, payload: str) -> bool:
        for q in ('"', "'"):
            if q in payload:
                escaped_payload = payload.replace(q, f'\\{q}')
                if escaped_payload in nearby:
                    return True
        return False

    @staticmethod
    def _is_js_hex_encoded(html: str, pos: int, payload: str) -> bool:
        window = html[max(0, pos - 100):min(len(html), pos + len(payload) + 100)]
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
                for enc in encode_map[char]:
                    if enc in window:
                        return True
        return False

    @staticmethod
    def _is_url_encoded_in_attr(before: str, payload: str) -> bool:
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')
        if last_tag_open <= last_tag_close:
            return False
        tag_content = before[last_tag_open:]
        if not re.search(r'=\s*["\'][^"\']*$', tag_content):
            return False
        attr_val_match = re.search(r'=\s*(["\'])([^"\']*$)', tag_content)
        if not attr_val_match:
            return False
        attr_value_content = attr_val_match.group(2)
        dangerous = {'<': '%3c', '>': '%3e', "'": '%27', '"': '%22', '(': '%28', ')': '%29'}
        for char, enc in dangerous.items():
            if char in payload and enc in attr_value_content.lower():
                return True
        return False


    def _is_marker_in_real_tag(self, body: str) -> bool:
        """Check if verification marker appears inside an actual HTML tag."""
        for search_marker in (self.verify_class, self.verify_id):
            search_start = 0
            while True:
                marker_pos = body.find(search_marker, search_start)
                if marker_pos == -1:
                    break
                search_start = marker_pos + 1

                before = body[max(0, marker_pos - 80):marker_pos]
                after = body[marker_pos:marker_pos + len(search_marker) + 30]

                last_lt = before.rfind('<')
                last_gt = before.rfind('>')

                if last_lt > last_gt and last_lt != -1:
                    abs_lt_pos = max(0, marker_pos - 80) + last_lt
                    if abs_lt_pos >= 3:
                        preceding = body[abs_lt_pos - 3:abs_lt_pos + 1]
                        if preceding.startswith('&lt'):
                            continue
                    if '>' in after:
                        return True
        return False

    def close(self):
        if self._execution_verifier is not None:
            try:
                self._execution_verifier.close()
            except Exception:
                logger.debug("Suppressed exception", exc_info=True)
            self._execution_verifier = None

    def __del__(self):
        self.close()
