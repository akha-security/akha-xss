"""
Context analyzer for XSS detection.

Provides HTML-parser-assisted context detection to accurately determine
where user input is reflected in an HTTP response. This is the single
source of truth for injection context — used by both the probe phase
and the verification phase of the XSS engine.

Context types:
  - html        : Between HTML tags (needs tag injection)
  - attribute   : Inside an HTML attribute value
  - javascript  : Inside a <script> block or event handler
  - url         : Inside href/src/action attribute
  - css         : Inside a <style> block or style attribute
  - comment     : Inside an HTML comment
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional, Tuple

from bs4 import BeautifulSoup


class ContextType(str, Enum):
    HTML = "html"
    ATTRIBUTE = "attribute"
    JAVASCRIPT = "javascript"
    URL = "url"
    CSS = "css"
    COMMENT = "comment"


ENCODED_FORMS: Dict[str, List[str]] = {
    '<': ['&lt;', '&#60;', '&#x3c;', '&#x3C;'],
    '>': ['&gt;', '&#62;', '&#x3e;', '&#x3E;'],
    '"': ['&quot;', '&#34;', '&#x22;'],
    "'": ['&#39;', '&#x27;', '&apos;'],
    '`': ['&#96;', '&#x60;'],
    '(': ['&#40;', '&#x28;'],
    ')': ['&#41;', '&#x29;'],
    '/': ['&#47;', '&#x2f;', '&#x2F;'],
}

URL_ATTRIBUTES = frozenset({
    'href', 'src', 'action', 'formaction', 'data', 'codebase',
    'cite', 'poster', 'background', 'dynsrc', 'lowsrc',
})

EVENT_HANDLER_RE = re.compile(r'^on[a-z]+$', re.IGNORECASE)

SAFE_CONTAINERS = frozenset({'textarea', 'title', 'noscript', 'xmp', 'plaintext'})


@dataclass
class CharStatus:
    """Status of special characters after reflection."""
    char: str
    status: str  # 'raw' | 'encoded' | 'removed'


@dataclass
class ReflectionContext:
    """Full context analysis for a single reflection point."""
    context_type: ContextType
    position: int = 0
    quote_type: Optional[str] = None  # " | ' | ` | None
    attr_name: Optional[str] = None
    tag_name: Optional[str] = None
    in_script: bool = False
    in_attribute: bool = False
    in_safe_container: bool = False
    can_break_out: bool = False
    encoding: str = "none"
    chars: Dict[str, str] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            'Location': self.context_type.value.capitalize()
                        if self.context_type != ContextType.URL else 'URL',
            'Type': self.context_type.value,
            'QuoteChar': self.quote_type,
            'AttributeName': self.attr_name,
            'TagName': self.tag_name,
            'InScript': self.in_script,
            'InAttribute': self.in_attribute,
            'InSafeContainer': self.in_safe_container,
            'CanBreakOut': self.can_break_out,
            'Encoding': self.encoding,
        }


@dataclass
class AnalysisResult:
    """Result of analyzing all reflections of a marker in a response."""
    found: bool = False
    contexts: List[ReflectionContext] = field(default_factory=list)
    best: Optional[ReflectionContext] = None

    def to_dict(self) -> dict:
        return {
            'found': self.found,
            'contexts': [c.to_dict() for c in self.contexts],
        }


class ContextAnalyzer:
    """
    Analyzes injection context for XSS detection using HTML parsing.

    Main entry points:
      - analyze(html, marker) → AnalysisResult with all reflections
      - detect_at_position(html, marker, pos) → single ReflectionContext
      - analyze_chars(html, probe_id, special_chars) → char status dict
    """

    def analyze(self, html: str, marker: str) -> AnalysisResult:
        """
        Find all reflections of *marker* in *html* and classify each one.

        Returns an AnalysisResult with:
          - found: whether marker appears at all
          - contexts: list of ReflectionContext for each occurrence
          - best: the most exploitable context (highest priority)

        Backward-compatible: result.to_dict() produces the same shape as
        the old ContextAnalyzer.analyze() return value.
        """
        result = AnalysisResult()

        if marker not in html:
            return result

        result.found = True

        positions = [m.start() for m in re.finditer(re.escape(marker), html)]
        best_score = -1

        for pos in positions:
            ctx = self.detect_at_position(html, marker, pos)
            result.contexts.append(ctx)

            score = self._exploitability_score(ctx)
            if score > best_score:
                best_score = score
                result.best = ctx

        return result

    def detect_at_position(self, html: str, marker: str, pos: int) -> ReflectionContext:
        """Detect the injection context at a specific character position."""
        before = html[:pos]

        safe_container = self._check_safe_container(before)
        if safe_container:
            return ReflectionContext(
                context_type=ContextType.HTML,
                position=pos,
                in_safe_container=True,
                tag_name=safe_container,
                can_break_out=False,
            )

        if self._is_in_comment(before):
            return ReflectionContext(
                context_type=ContextType.COMMENT,
                position=pos,
                can_break_out=True,  # --> can break out
            )

        if self._is_in_script(before):
            quote = self._detect_js_string_context(html, pos)
            return ReflectionContext(
                context_type=ContextType.JAVASCRIPT,
                position=pos,
                quote_type=quote,
                in_script=True,
                in_attribute=False,
                can_break_out=True,
            )

        if self._is_in_style(before):
            return ReflectionContext(
                context_type=ContextType.CSS,
                position=pos,
                can_break_out=True,
            )

        tag_info = self._check_tag_context(html, before, pos)
        if tag_info:
            return tag_info

        return ReflectionContext(
            context_type=ContextType.HTML,
            position=pos,
            can_break_out=True,
        )

    def analyze_chars(
        self, html: str, probe_id: str, special_chars: str = '<>"\'`()/',
        search_window: int = 500,
    ) -> Dict[str, str]:
        """
        Analyze which special characters survive reflection unencoded.

        Sends probe_id + special_chars as input; checks the response
        for each character's status: 'raw', 'encoded', or 'removed'.
        """
        probe_pos = html.find(probe_id)
        if probe_pos == -1:
            return {c: 'removed' for c in special_chars}

        after_probe = html[probe_pos + len(probe_id):
                           probe_pos + len(probe_id) + search_window]
        if not any(c in after_probe for c in special_chars):
            wide = html[probe_pos:probe_pos + 2000]
            if any(c in wide for c in special_chars):
                after_probe = wide

        char_status: Dict[str, str] = {}
        for char in special_chars:
            if char in after_probe:
                char_status[char] = 'raw'
            else:
                found_encoded = False
                for enc in ENCODED_FORMS.get(char, []):
                    if enc in after_probe or enc.lower() in after_probe.lower():
                        char_status[char] = 'encoded'
                        found_encoded = True
                        break
                if not found_encoded:
                    char_status[char] = 'removed'

        return char_status

    def detect_encoding(self, html: str, marker: str) -> str:
        """Detect what encoding was applied to the marker."""
        if marker in html:
            return 'none'

        sample = html[:5000]
        if re.search(r'&(?:lt|gt|quot|amp|apos);', sample):
            return 'html_entity'
        if re.search(r'%[0-9a-fA-F]{2}', sample):
            return 'url_encoded'
        if re.search(r'\\u[0-9a-fA-F]{4}', sample):
            return 'unicode'
        if re.search(r'\\x[0-9a-fA-F]{2}', sample):
            return 'hex'
        return 'unknown'


    def _is_in_script(self, before: str) -> bool:
        """Check if position is inside a <script> block."""
        last_open = before.lower().rfind('<script')
        last_close = before.lower().rfind('</script')
        return last_open > last_close and last_open != -1

    def _is_in_style(self, before: str) -> bool:
        """Check if position is inside a <style> block."""
        last_open = before.lower().rfind('<style')
        last_close = before.lower().rfind('</style')
        return last_open > last_close and last_open != -1

    def _is_in_comment(self, before: str) -> bool:
        """Check if position is inside an HTML comment."""
        last_open = before.rfind('<!--')
        last_close = before.rfind('-->')
        return last_open > last_close and last_open != -1

    def _check_safe_container(self, before: str) -> Optional[str]:
        """Check if inside a safe container tag. Returns tag name or None."""
        before_lower = before.lower()
        for container in SAFE_CONTAINERS:
            last_open = before_lower.rfind(f'<{container}')
            last_close = before_lower.rfind(f'</{container}')
            if last_open > last_close and last_open != -1:
                return container
        return None

    def _check_tag_context(
        self, html: str, before: str, pos: int
    ) -> Optional[ReflectionContext]:
        """Check if position is inside an HTML tag (attribute context)."""
        last_tag_open = before.rfind('<')
        last_tag_close = before.rfind('>')

        if last_tag_open <= last_tag_close or last_tag_open == -1:
            return None

        tag_content = html[last_tag_open:pos]

        tag_match = re.match(r'</?(\w+)', tag_content)
        tag_name = tag_match.group(1).lower() if tag_match else None

        attr_match = re.search(r'(\w+)\s*=\s*["\']?\s*$', tag_content)
        attr_name = attr_match.group(1).lower() if attr_match else None

        quote = None
        if re.search(r'=\s*"[^"]*$', tag_content):
            quote = '"'
        elif re.search(r"=\s*'[^']*$", tag_content):
            quote = "'"

        if attr_name:
            if attr_name in URL_ATTRIBUTES:
                return ReflectionContext(
                    context_type=ContextType.URL,
                    position=pos,
                    quote_type=quote,
                    attr_name=attr_name,
                    tag_name=tag_name,
                    in_attribute=True,
                    can_break_out=quote is not None,
                )

            if EVENT_HANDLER_RE.match(attr_name):
                return ReflectionContext(
                    context_type=ContextType.JAVASCRIPT,
                    position=pos,
                    quote_type=quote,
                    attr_name=attr_name,
                    tag_name=tag_name,
                    in_script=False,
                    in_attribute=True,
                    can_break_out=True,
                )

            if attr_name == 'style':
                return ReflectionContext(
                    context_type=ContextType.CSS,
                    position=pos,
                    quote_type=quote,
                    attr_name=attr_name,
                    tag_name=tag_name,
                    in_attribute=True,
                    can_break_out=quote is not None,
                )

        return ReflectionContext(
            context_type=ContextType.ATTRIBUTE,
            position=pos,
            quote_type=quote,
            attr_name=attr_name,
            tag_name=tag_name,
            in_attribute=True,
            can_break_out=quote is not None or attr_name is None,
        )

    def _detect_js_string_context(self, html: str, pos: int) -> Optional[str]:
        """
        Walk through JS content from <script> tag start to *pos* to determine
        if we're inside a JS string literal and which quote type.
        """
        before = html[:pos]
        last_script = before.lower().rfind('<script')
        if last_script == -1:
            return None

        tag_end = html.find('>', last_script)
        if tag_end == -1 or tag_end >= pos:
            return None

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

        return in_string

    @staticmethod
    def _exploitability_score(ctx: ReflectionContext) -> int:
        """Rank contexts by exploitability for selecting the best one."""
        if ctx.in_safe_container:
            return -1
        scores = {
            ContextType.JAVASCRIPT: 50,
            ContextType.URL: 40,
            ContextType.ATTRIBUTE: 30,
            ContextType.HTML: 20,
            ContextType.CSS: 15,
            ContextType.COMMENT: 10,
        }
        base = scores.get(ctx.context_type, 0)
        if ctx.can_break_out:
            base += 5
        return base
