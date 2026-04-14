"""
HTML Structural Diff Engine — DOM-level comparison for XSS verification.

Compares a *baseline* HTTP response (before injection) against an
*injected* response to identify structural changes that indicate
successful payload reflection or execution.  Every comparison operates
on the parsed DOM tree, **never** on raw strings, which eliminates
false positives caused by whitespace / comment / encoding noise.

Designed for:
  • Large responses  — caps input at 1 MB, early-exits on identical trees.
  • Low false-positive rate — filters benign / dynamic nodes (ads, CSRF
    tokens, timestamps) before reporting.
  • Modularity — each detector (new-node, attribute-diff, script-audit,
    structure-break) is a standalone method; callers can cherry-pick.

Usage::

    from akha.modules.xss.html_diff_engine import HTMLDiffEngine

    engine = HTMLDiffEngine()
    result = engine.diff(baseline_html, injected_html)

    if result.structure_changed:
        for node in result.new_nodes:
            print(node)
"""

from __future__ import annotations

import hashlib
import logging
import re
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

from bs4 import BeautifulSoup, Comment, NavigableString, Tag

try:
    from bs4 import MarkupResemblesLocatorWarning
except ImportError:
    class MarkupResemblesLocatorWarning(Warning):
        pass

logger = logging.getLogger("akha.html_diff_engine")


_MAX_HTML_BYTES = 1_048_576  # 1 MB

_DANGEROUS_TAGS: FrozenSet[str] = frozenset({
    "script", "iframe", "object", "embed", "svg", "math",
    "link", "meta", "base", "form", "style", "video", "audio",
    "applet", "marquee", "details", "frameset", "frame",
})

_EXECUTION_CAPABLE: Dict[str, float] = {
    'script': 1.0,
    'iframe': 0.9,
    'svg': 0.8,
    'img': 0.6,
    'video': 0.5,
    'a': 0.3,
}

_EVENT_ATTR_RE = re.compile(r"^on[a-z]+$", re.IGNORECASE)

_JS_PROTOCOL_RE = re.compile(
    r"^\s*(javascript|vbscript|data\s*:text/html)\s*:", re.IGNORECASE
)

_DYNAMIC_ATTRS: FrozenSet[str] = frozenset({
    "data-csrf", "data-token", "data-nonce", "data-timestamp",
    "csrf_token", "authenticity_token", "_token", "nonce",
})



@dataclass
class NewNode:
    """A node present in the injected DOM but absent from the baseline."""
    tag: str
    attributes: Dict[str, str]
    path: str          # simplified CSS-like path in the tree
    text_content: str  # first 200 chars of inner text
    dangerous: bool    # True if tag ∈ _DANGEROUS_TAGS or has event attrs
    execution_score: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag": self.tag,
            "attributes": self.attributes,
            "path": self.path,
            "text_content": self.text_content,
            "dangerous": self.dangerous,
            "execution_score": self.execution_score,
        }


@dataclass
class ModifiedAttribute:
    """An attribute whose value differs between baseline and injected."""
    tag: str
    path: str
    attribute: str
    baseline_value: Optional[str]
    injected_value: Optional[str]
    suspicious: bool  # True if value looks like JS / event handler

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tag": self.tag,
            "path": self.path,
            "attribute": self.attribute,
            "baseline_value": self.baseline_value,
            "injected_value": self.injected_value,
            "suspicious": self.suspicious,
        }


@dataclass
class SuspiciousInjection:
    """High-confidence XSS injection indicator."""
    kind: str            # "new_script" | "event_handler" | "js_protocol" | "broken_structure" | "dangerous_tag"
    detail: str
    path: str
    severity: str        # "high" | "medium" | "low"
    evidence: str        # raw snippet (≤ 300 chars)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "kind": self.kind,
            "detail": self.detail,
            "path": self.path,
            "severity": self.severity,
            "evidence": self.evidence[:300],
        }


@dataclass
class DiffResult:
    """Top-level diff output."""
    structure_changed: bool = False
    new_nodes: List[NewNode] = field(default_factory=list)
    modified_attributes: List[ModifiedAttribute] = field(default_factory=list)
    suspicious_injection_points: List[SuspiciousInjection] = field(default_factory=list)
    baseline_node_count: int = 0
    injected_node_count: int = 0
    error: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "structure_changed": self.structure_changed,
            "new_nodes": [n.to_dict() for n in self.new_nodes],
            "modified_attributes": [m.to_dict() for m in self.modified_attributes],
            "suspicious_injection_points": [s.to_dict() for s in self.suspicious_injection_points],
            "baseline_node_count": self.baseline_node_count,
            "injected_node_count": self.injected_node_count,
            "error": self.error,
        }

    @property
    def has_suspicious(self) -> bool:
        return len(self.suspicious_injection_points) > 0



def _node_path(tag: Tag, max_depth: int = 8) -> str:
    """Return a simplified CSS-like path for *tag* (e.g. ``html>body>div>p``)."""
    parts: List[str] = []
    current: Optional[Tag] = tag
    while current and isinstance(current, Tag) and len(parts) < max_depth:
        parts.append(current.name)
        current = current.parent
    parts.reverse()
    return ">".join(parts)


def _tag_signature(tag: Tag) -> str:
    """Stable, hashable signature for a tag (name + sorted attributes)."""
    attr_str = ";".join(
        f"{k}={','.join(v) if isinstance(v, list) else v}"
        for k, v in sorted((tag.attrs or {}).items())
    )
    return f"{tag.name}|{attr_str}"


def _text_preview(tag: Tag, limit: int = 200) -> str:
    """First *limit* characters of the tag's visible text."""
    text = tag.get_text(separator=" ", strip=True)
    return text[:limit]


def _is_event_attr(name: str) -> bool:
    return bool(_EVENT_ATTR_RE.match(name))


def _attr_value_str(val: Any) -> str:
    """Normalise an attribute value to a plain string."""
    if val is None:
        return ""
    if isinstance(val, list):
        return " ".join(val)
    return str(val)


def _is_js_protocol(value: str) -> bool:
    return bool(_JS_PROTOCOL_RE.match(value))


def _is_dynamic_attr(name: str) -> bool:
    """Return True if the attribute is known to carry benign dynamic data."""
    return name.lower() in _DYNAMIC_ATTRS



class HTMLDiffEngine:
    """DOM-level structural diff between baseline and injected HTTP responses.

    Parameters
    ----------
    parser : str
        BeautifulSoup parser backend (default ``"html.parser"``; ``"lxml"``
        is faster for very large pages).
    max_html_size : int
        Truncate input HTML beyond this byte count.
    ignore_comments : bool
        Strip HTML comments before comparison (reduces noise).
    ignore_text_changes : bool
        If True, only structural (tag / attribute) changes are reported;
        pure text-content changes are ignored.
    """

    def __init__(
        self,
        parser: str = "html.parser",
        max_html_size: int = _MAX_HTML_BYTES,
        ignore_comments: bool = True,
        ignore_text_changes: bool = True,
    ) -> None:
        self.parser = parser
        self.max_html_size = max_html_size
        self.ignore_comments = ignore_comments
        self.ignore_text_changes = ignore_text_changes


    def diff(
        self,
        baseline_html: str,
        injected_html: str,
        max_size: int = 50_000,
    ) -> DiffResult:
        """Compare *baseline_html* and *injected_html* at the DOM level.

        Args:
            baseline_html: HTML before injection
            injected_html: HTML after injection
            max_size: Truncate both inputs to this byte limit before parsing.
                      Prevents excessive memory/CPU on large pages (default 50KB).

        Returns a ``DiffResult`` describing structural differences and any
        suspicious injection indicators.
        """
        result = DiffResult()

        if len(baseline_html) > max_size:
            baseline_html = baseline_html[:max_size]
        if len(injected_html) > max_size:
            injected_html = injected_html[:max_size]

        try:
            baseline_soup = self._parse(baseline_html)
            injected_soup = self._parse(injected_html)
        except Exception as exc:
            logger.warning("HTML parse error: %s", exc)
            result.error = f"Parse error: {exc}"
            return result

        baseline_tags = list(baseline_soup.find_all(True))
        injected_tags = list(injected_soup.find_all(True))

        result.baseline_node_count = len(baseline_tags)
        result.injected_node_count = len(injected_tags)

        if self._trees_identical(baseline_soup, injected_soup):
            return result  # structure_changed stays False

        result.structure_changed = True

        baseline_sigs = self._build_signature_map(baseline_tags)
        injected_sigs = self._build_signature_map(injected_tags)

        self._detect_new_nodes(baseline_sigs, injected_sigs, result)

        self._detect_modified_attrs(baseline_soup, injected_soup, result)

        self._detect_suspicious_injections(
            baseline_soup, injected_soup, result,
        )

        return result


    def _parse(self, html: str) -> BeautifulSoup:
        """Parse HTML, truncate to size limit, optionally strip comments."""
        if len(html) > self.max_html_size:
            html = html[: self.max_html_size]

        with warnings.catch_warnings():
            warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
            soup = BeautifulSoup(html, self.parser)

        if self.ignore_comments:
            for comment in soup.find_all(string=lambda t: isinstance(t, Comment)):
                comment.extract()

        return soup


    def _trees_identical(
        self, baseline: BeautifulSoup, injected: BeautifulSoup
    ) -> bool:
        """Quick hash-based identity test on the serialised DOM."""
        def _dom_hash(soup: BeautifulSoup) -> str:
            raw = soup.encode_contents(formatter="html5")
            return hashlib.md5(raw).hexdigest()

        return _dom_hash(baseline) == _dom_hash(injected)


    @staticmethod
    def _build_signature_map(
        tags: List[Tag],
    ) -> Dict[str, List[Tag]]:
        """Map tag signatures to their occurrences."""
        sig_map: Dict[str, List[Tag]] = {}
        for tag in tags:
            sig = _tag_signature(tag)
            sig_map.setdefault(sig, []).append(tag)
        return sig_map


    def _detect_new_nodes(
        self,
        baseline_sigs: Dict[str, List[Tag]],
        injected_sigs: Dict[str, List[Tag]],
        result: DiffResult,
    ) -> None:
        """Find tags present in injected but not in baseline."""
        for sig, inj_tags in injected_sigs.items():
            base_count = len(baseline_sigs.get(sig, []))
            new_count = len(inj_tags) - base_count

            if new_count <= 0:
                continue

            for tag in inj_tags[-new_count:]:
                attrs = {
                    k: _attr_value_str(v) for k, v in (tag.attrs or {}).items()
                }
                dangerous = (
                    tag.name in _DANGEROUS_TAGS
                    or any(_is_event_attr(a) for a in attrs)
                    or any(_is_js_protocol(v) for v in attrs.values())
                )
                node = NewNode(
                    tag=tag.name,
                    attributes=attrs,
                    path=_node_path(tag),
                    text_content=_text_preview(tag),
                    dangerous=dangerous,
                    execution_score=self._score_new_node(tag),
                )
                result.new_nodes.append(node)

    def _score_new_node(self, tag: Tag) -> float:
        """Score how likely a new node is to enable JS execution."""
        base = _EXECUTION_CAPABLE.get(tag.name, 0.0)
        has_handler = any(str(attr).lower().startswith('on') for attr in (tag.attrs or {}))
        has_js_scheme = any(
            str(_attr_value_str(v)).strip().lower().startswith('javascript:')
            for v in (tag.attrs or {}).values()
        )
        mult = 1.5 if has_handler or has_js_scheme else 0.5
        return round(base * mult, 3)


    def _detect_modified_attrs(
        self,
        baseline_soup: BeautifulSoup,
        injected_soup: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        """Walk matching nodes and report attribute-value changes.

        Matching heuristic: pair nodes by (tag-name, index-within-parent)
        for the first 3 levels of the tree — deep enough to catch head /
        body-level injections without O(n²) full-tree matching.
        """
        pairs = self._pair_matching_nodes(baseline_soup, injected_soup, max_depth=4)

        for base_tag, inj_tag in pairs:
            base_attrs = base_tag.attrs or {}
            inj_attrs = inj_tag.attrs or {}

            all_keys = set(base_attrs.keys()) | set(inj_attrs.keys())

            for key in all_keys:
                if _is_dynamic_attr(key):
                    continue  # skip CSRF tokens, nonces, etc.

                base_val = _attr_value_str(base_attrs.get(key))
                inj_val = _attr_value_str(inj_attrs.get(key))

                if base_val == inj_val:
                    continue

                suspicious = (
                    _is_event_attr(key)
                    or _is_js_protocol(inj_val)
                    or key.lower() in ("href", "src", "action", "formaction", "data", "srcdoc")
                    and _is_js_protocol(inj_val)
                )

                result.modified_attributes.append(
                    ModifiedAttribute(
                        tag=inj_tag.name,
                        path=_node_path(inj_tag),
                        attribute=key,
                        baseline_value=base_val or None,
                        injected_value=inj_val or None,
                        suspicious=suspicious,
                    )
                )


    def _detect_suspicious_injections(
        self,
        baseline_soup: BeautifulSoup,
        injected_soup: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        """Aggregate high-signal suspicious indicators."""

        self._check_new_scripts(baseline_soup, injected_soup, result)

        self._check_new_event_handlers(baseline_soup, injected_soup, result)

        self._check_js_protocols(baseline_soup, injected_soup, result)

        self._check_structure_break(baseline_soup, injected_soup, result)

        for node in result.new_nodes:
            if node.dangerous and node.tag != "script":  # scripts already covered
                severity = "high" if node.execution_score >= 1.0 else (
                    "medium" if node.execution_score >= 0.5 else "low"
                )
                result.suspicious_injection_points.append(
                    SuspiciousInjection(
                        kind="dangerous_tag",
                        detail=f"Injected <{node.tag}> tag with attrs {node.attributes}",
                        path=node.path,
                        severity=severity,
                        evidence=f"<{node.tag} {' '.join(f'{k}={v!r}' for k,v in node.attributes.items())}>",
                    )
                )


    def _check_new_scripts(
        self,
        baseline: BeautifulSoup,
        injected: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        base_scripts = set()
        for s in baseline.find_all("script"):
            base_scripts.add(_tag_signature(s) + "|" + (s.string or "").strip()[:200])

        for s in injected.find_all("script"):
            sig = _tag_signature(s) + "|" + (s.string or "").strip()[:200]
            if sig not in base_scripts:
                content = (s.string or "").strip()[:300]
                result.suspicious_injection_points.append(
                    SuspiciousInjection(
                        kind="new_script",
                        detail=f"New <script> tag injected (src={s.get('src', 'inline')})",
                        path=_node_path(s),
                        severity="high",
                        evidence=f"<script>{content}</script>" if content else str(s)[:300],
                    )
                )

    def _check_new_event_handlers(
        self,
        baseline: BeautifulSoup,
        injected: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        """Detect attributes like onerror=, onclick=, … added by injection."""
        base_events: Set[Tuple[str, str, str]] = set()
        for tag in baseline.find_all(True):
            for attr_name in (tag.attrs or {}):
                if _is_event_attr(attr_name):
                    base_events.add((_node_path(tag), tag.name, attr_name))

        for tag in injected.find_all(True):
            for attr_name, attr_val in (tag.attrs or {}).items():
                if _is_event_attr(attr_name):
                    key = (_node_path(tag), tag.name, attr_name)
                    if key not in base_events:
                        result.suspicious_injection_points.append(
                            SuspiciousInjection(
                                kind="event_handler",
                                detail=f"New {attr_name}= on <{tag.name}>",
                                path=_node_path(tag),
                                severity="high",
                                evidence=f'<{tag.name} {attr_name}="{_attr_value_str(attr_val)[:200]}">',
                            )
                        )

    def _check_js_protocols(
        self,
        baseline: BeautifulSoup,
        injected: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        """Detect javascript:/data: protocol injected into href, src, action, …"""
        _URL_ATTRS = ("href", "src", "action", "formaction", "data", "srcdoc", "poster", "background")

        base_protos: Set[Tuple[str, str, str]] = set()
        for tag in baseline.find_all(True):
            for attr in _URL_ATTRS:
                val = _attr_value_str(tag.get(attr))
                if val and _is_js_protocol(val):
                    base_protos.add((_node_path(tag), tag.name, attr))

        for tag in injected.find_all(True):
            for attr in _URL_ATTRS:
                val = _attr_value_str(tag.get(attr))
                if val and _is_js_protocol(val):
                    key = (_node_path(tag), tag.name, attr)
                    if key not in base_protos:
                        result.suspicious_injection_points.append(
                            SuspiciousInjection(
                                kind="js_protocol",
                                detail=f'javascript: protocol in {attr}= on <{tag.name}>',
                                path=_node_path(tag),
                                severity="high",
                                evidence=f'<{tag.name} {attr}="{val[:200]}">',
                            )
                        )

    def _check_structure_break(
        self,
        baseline: BeautifulSoup,
        injected: BeautifulSoup,
        result: DiffResult,
    ) -> None:
        """Detect gross structural differences that indicate broken HTML context.

        Heuristics:
          • Significantly different tag counts in <head> or <body>.
          • <script> or <style> as direct child of unexpected parents.
          • Multiple <body> or <html> tags.
        """
        def _child_tag_count(soup: BeautifulSoup, parent: str) -> int:
            p = soup.find(parent)
            if not p:
                return 0
            return len(list(p.children)) if isinstance(p, Tag) else 0

        for section in ("head", "body"):
            base_c = _child_tag_count(baseline, section)
            inj_c = _child_tag_count(injected, section)
            if inj_c > base_c + 3:  # allow small dynamic variance
                result.suspicious_injection_points.append(
                    SuspiciousInjection(
                        kind="broken_structure",
                        detail=f"<{section}> gained {inj_c - base_c} child nodes (baseline={base_c}, injected={inj_c})",
                        path=section,
                        severity="medium",
                        evidence=f"<{section}> children: {base_c} → {inj_c}",
                    )
                )

        for root_tag in ("html", "body"):
            base_n = len(baseline.find_all(root_tag))
            inj_n = len(injected.find_all(root_tag))
            if inj_n > base_n:
                result.suspicious_injection_points.append(
                    SuspiciousInjection(
                        kind="broken_structure",
                        detail=f"Extra <{root_tag}> tag injected ({base_n} → {inj_n})",
                        path=root_tag,
                        severity="high",
                        evidence=f"<{root_tag}> count: {base_n} → {inj_n}",
                    )
                )


    def _pair_matching_nodes(
        self,
        baseline: BeautifulSoup,
        injected: BeautifulSoup,
        max_depth: int = 4,
    ) -> List[Tuple[Tag, Tag]]:
        """Pair baseline/injected nodes by tag-name + position at each depth.

        This is an O(n) heuristic that works well because legitimate pages
        re-render the same structure — only the injected node introduces a
        mismatch.
        """
        pairs: List[Tuple[Tag, Tag]] = []
        base_queue: List[Tuple[Tag, int]] = [(baseline, 0)]  # type: ignore[arg-type]
        inj_queue: List[Tuple[Tag, int]] = [(injected, 0)]  # type: ignore[arg-type]

        while base_queue and inj_queue:
            b_tag, b_depth = base_queue.pop(0)
            i_tag, i_depth = inj_queue.pop(0)

            if b_depth >= max_depth or i_depth >= max_depth:
                continue

            b_children = [c for c in (b_tag.children if isinstance(b_tag, Tag) else []) if isinstance(c, Tag)]
            i_children = [c for c in (i_tag.children if isinstance(i_tag, Tag) else []) if isinstance(c, Tag)]

            b_index: Dict[Tuple[str, int], Tag] = {}
            b_counts: Dict[str, int] = {}
            for child in b_children:
                n = child.name
                idx = b_counts.get(n, 0)
                b_counts[n] = idx + 1
                b_index[(n, idx)] = child

            i_counts: Dict[str, int] = {}
            for child in i_children:
                n = child.name
                idx = i_counts.get(n, 0)
                i_counts[n] = idx + 1
                key = (n, idx)
                if key in b_index:
                    pairs.append((b_index[key], child))
                    base_queue.append((b_index[key], b_depth + 1))
                    inj_queue.append((child, i_depth + 1))

        return pairs
