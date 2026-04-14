"""
DOM Source-to-Sink Flow Analyzer — lightweight taint tracking for DOM XSS.

Goes beyond keyword matching by performing **variable-level taint propagation**
through JavaScript code:

    1. **Lexical extraction** — Split JS into statements, strip comments/strings.
    2. **Source identification** — Detect reads from user-controllable DOM APIs.
    3. **Taint propagation** — Track which variables carry tainted data through
       assignments, concatenation, function parameters, and method chains.
    4. **Sink detection** — Flag when a tainted variable (or a raw source) flows
       into a dangerous sink (innerHTML, eval, document.write, …).
    5. **Confidence scoring** — Direct source→sink = 90; one-hop variable = 80;
       multi-hop = 70; proximity-only = 50.

Usage::

    from akha.modules.xss.dom_flow_analyzer import DOMFlowAnalyzer

    analyzer = DOMFlowAnalyzer()
    flows = analyzer.analyze(js_code)
    for f in flows:
        print(f.to_dict())

The analyzer is **stateless** — each ``analyze()`` call is independent.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("akha.dom_flow_analyzer")


SOURCES: Dict[str, int] = {
    "location.search":       95,
    "location.hash":         95,
    "location.href":         90,
    "document.URL":          90,
    "document.documentURI":  85,
    "document.referrer":     85,
    "window.name":           80,
    "document.cookie":       70,
    "location.pathname":     65,
    "document.baseURI":      60,
    "window.location":       60,
    "location.toString()":   85,
    "event.data":              85,
    "messageEvent.data":       80,
}

SINKS: Dict[str, int] = {
    "eval(":                 100,
    "Function(":             100,
    "setTimeout(":           90,   # only when first arg is string
    "setInterval(":          90,
    ".innerHTML":            95,
    ".outerHTML":            95,
    "document.write(":       95,
    "document.writeln(":     95,
    "insertAdjacentHTML(":   85,
    ".html(":                80,
    "jQuery.html(":          80,
    "$.html(":               80,
    "location.assign(":      70,
    "location.replace(":     70,
    "window.open(":          65,
    ".setAttribute(":        60,
    ".src":                  55,
}

SAFE_SOURCE_SINK_PAIRS: FrozenSet[tuple] = frozenset({
    ("location.href",    ".href"),
    ("location.href",    "location.assign("),
    ("location.href",    "location.replace("),
    ("window.location",  ".href"),
    ("window.location",  "location.assign("),
    ("window.location",  "location.replace("),
    ("location.pathname", ".href"),
    ("location.pathname", "location.assign("),
    ("location.search",  ".href"),
    ("location.hash",    ".href"),
})


_IDENT = r"[A-Za-z_$][A-Za-z0-9_$]*"

_SOURCE_RE = re.compile(
    "|".join(re.escape(s) for s in sorted(SOURCES, key=len, reverse=True))
)

_SINK_PART_RE = re.compile(
    "|".join(re.escape(s) for s in sorted(SINKS, key=len, reverse=True))
)

_COMMENT_LINE_RE = re.compile(r"//[^\n]*")
_COMMENT_BLOCK_RE = re.compile(r"/\*.*?\*/", re.DOTALL)
_STRING_DQ_RE = re.compile(r'"(?:[^"\\]|\\.)*"')
_STRING_SQ_RE = re.compile(r"'(?:[^'\\]|\\.)*'")
_TEMPLATE_LIT_RE = re.compile(r"`(?:[^`\\]|\\.)*`", re.DOTALL)

_ASSIGN_RE = re.compile(
    rf"(?:(?:var|let|const)\s+)?({_IDENT})\s*=\s*(.+)"
)

_CALL_ARG_RE = re.compile(
    rf"({_IDENT}(?:\.{_IDENT})*)\s*\(\s*({_IDENT})\s*[,)]"
)

_PROP_ASSIGN_RE = re.compile(
    rf"({_IDENT}(?:\.{_IDENT})*)\.({_IDENT})\s*=\s*(.+)"
)

_METHOD_CALL_RE = re.compile(
    rf"({_IDENT}(?:\.{_IDENT})*)\s*\(\s*(.+?)\s*\)"
)

_CONCAT_RE = re.compile(rf"\+\s*({_IDENT})|({_IDENT})\s*\+")
_TEMPLATE_VAR_RE = re.compile(rf"\$\{{\s*({_IDENT})\s*\}}")

_TIMER_STRING_RE = re.compile(
    r"(?:setTimeout|setInterval)\s*\(\s*(?:"
    r"['\"]"               # starts with quote → string arg → dangerous
    r"|"
    rf"({_IDENT})\s*[,)]"  # or a variable (may be tainted)
    r")"
)



@dataclass
class FlowResult:
    """One detected source→sink data flow."""
    flow_detected: bool = False
    source: str = ""
    sink: str = ""
    taint_chain: List[str] = field(default_factory=list)  # [source, var1, …, sink]
    confidence: int = 0          # 0-100
    line: int = -1               # approximate line number (0-based)
    snippet: str = ""            # shortened code context

    def to_dict(self) -> Dict[str, Any]:
        return {
            "flow_detected": self.flow_detected,
            "source": self.source,
            "sink": self.sink,
            "taint_chain": self.taint_chain,
            "confidence": self.confidence,
            "line": self.line,
            "snippet": self.snippet[:300],
        }



class DOMFlowAnalyzer:
    """Lightweight static taint analyzer for inline / external JavaScript.

    Parameters
    ----------
    max_js_size : int
        Skip analysis for scripts larger than this (bytes).  Keeps
        runtime bounded.
    max_taint_hops : int
        Maximum variable-to-variable propagation depth.
    """

    def __init__(
        self,
        max_js_size: int = 500_000,
        max_taint_hops: int = 6,
    ) -> None:
        self.max_js_size = max_js_size
        self.max_taint_hops = max_taint_hops


    def analyze(self, js_code: str) -> List[FlowResult]:
        """Analyze *js_code* and return all detected source→sink flows."""
        if not js_code or len(js_code) > self.max_js_size:
            return []

        raw_lines = js_code.split("\n")
        cleaned = self._strip_noise(js_code)
        clean_lines = cleaned.split("\n")

        taint_map: Dict[str, _TaintInfo] = {}   # var_name → TaintInfo
        source_locs: List[Tuple[int, str]] = []  # (line, source_api)

        for idx, line in enumerate(clean_lines):
            for src in SOURCES:
                if src in line:
                    source_locs.append((idx, src))
                    m = _ASSIGN_RE.search(line)
                    if m:
                        var_name = m.group(1)
                        taint_map[var_name] = _TaintInfo(
                            source=src, line=idx, hops=0,
                            var_name=var_name,
                        )

        if not source_locs:
            return []

        postmessage_re = re.compile(
            r"(?:window|self)\s*\.\s*addEventListener\s*\(\s*['\"]message['\"]\s*,\s*(\w+)",
            re.IGNORECASE,
        )
        for idx, line in enumerate(clean_lines):
            m = postmessage_re.search(line)
            if m:
                handler_name = m.group(1)
                for data_alias in ('event.data', 'e.data', 'msg.data', 'data'):
                    if data_alias not in taint_map:
                        taint_map[data_alias] = _TaintInfo(
                            source='event.data',
                            line=idx,
                            hops=0,
                            var_name=data_alias,
                        )
                source_locs.append((idx, 'event.data'))

        self._propagate(clean_lines, taint_map)

        flows: List[FlowResult] = []
        seen: Set[Tuple[str, str, int]] = set()

        for idx, line in enumerate(clean_lines):
            hits = self._check_sinks(line, idx, taint_map, source_locs)
            for h in hits:
                key = (h.source, h.sink, h.line)
                if key not in seen:
                    seen.add(key)
                    h.snippet = raw_lines[idx].strip() if idx < len(raw_lines) else ""
                    flows.append(h)

        flows.sort(key=lambda f: f.confidence, reverse=True)
        return flows

    def analyze_html(self, html: str) -> List[FlowResult]:
        """Extract ``<script>`` blocks from HTML and analyze each."""
        scripts = re.findall(
            r"<script[^>]*>(.*?)</script>", html, re.DOTALL | re.IGNORECASE,
        )
        all_flows: List[FlowResult] = []
        for script in scripts:
            if script.strip():
                all_flows.extend(self.analyze(script))
        return all_flows


    @staticmethod
    def _strip_noise(js: str) -> str:
        """Replace comments and string literals with whitespace (preserving line count)."""
        def _blank(m):
            return re.sub(r"[^\n]", " ", m.group(0))

        js = _COMMENT_BLOCK_RE.sub(_blank, js)
        js = _COMMENT_LINE_RE.sub(_blank, js)
        js = _STRING_DQ_RE.sub(_blank, js)
        js = _STRING_SQ_RE.sub(_blank, js)
        js = _TEMPLATE_LIT_RE.sub(_blank, js)
        return js


    def _propagate(
        self,
        lines: List[str],
        taint_map: Dict[str, _TaintInfo],
    ) -> None:
        """Multi-pass forward propagation of tainted variables.

        Handles:
            x = tainted_var
            x = tainted_var + "something"
            x = `...${tainted_var}...`
            func(tainted_var)   → marks return as tainted if assigned
        """
        changed = True
        passes = 0
        while changed and passes < self.max_taint_hops:
            changed = False
            passes += 1
            for idx, line in enumerate(lines):
                m = _ASSIGN_RE.search(line)
                if m:
                    lhs = m.group(1)
                    rhs = m.group(2)
                    if lhs in taint_map:
                        continue  # already tainted

                    tainted_by = self._rhs_tainted(rhs, taint_map)
                    if tainted_by:
                        taint_map[lhs] = _TaintInfo(
                            source=tainted_by.source,
                            line=idx,
                            hops=tainted_by.hops + 1,
                            via=tainted_by,
                            var_name=lhs,
                        )
                        changed = True
                        continue

                m = _PROP_ASSIGN_RE.search(line)
                if m:
                    obj_chain = m.group(1)
                    rhs = m.group(3)
                    tainted_by = self._rhs_tainted(rhs, taint_map)
                    if tainted_by:
                        full_name = f"{obj_chain}.{m.group(2)}"
                        if full_name not in taint_map:
                            taint_map[full_name] = _TaintInfo(
                                source=tainted_by.source,
                                line=idx,
                                hops=tainted_by.hops + 1,
                                via=tainted_by,
                                var_name=full_name,
                            )
                            changed = True

    def _rhs_tainted(
        self,
        rhs: str,
        taint_map: Dict[str, _TaintInfo],
    ) -> Optional[_TaintInfo]:
        """Check whether any tainted variable appears in *rhs* expression."""
        for var, info in taint_map.items():
            if info.hops >= self.max_taint_hops:
                continue
            if re.search(rf"\b{re.escape(var)}\b", rhs):
                return info

        for m in _TEMPLATE_VAR_RE.finditer(rhs):
            var = m.group(1)
            if var in taint_map and taint_map[var].hops < self.max_taint_hops:
                return taint_map[var]

        for src in SOURCES:
            if src in rhs:
                return _TaintInfo(source=src, line=-1, hops=0)

        return None


    def _check_sinks(
        self,
        line: str,
        line_idx: int,
        taint_map: Dict[str, _TaintInfo],
        source_locs: List[Tuple[int, str]],
    ) -> List[FlowResult]:
        """Check whether *line* uses tainted data in a dangerous sink."""
        results: List[FlowResult] = []

        for sink, sink_risk in SINKS.items():
            if sink not in line:
                continue

            for src in SOURCES:
                if src in line:
                    if (src, sink) in SAFE_SOURCE_SINK_PAIRS:
                        continue
                    results.append(self._build_flow(
                        src, sink, line_idx,
                        chain=[src, sink],
                        hops=0,
                        sink_risk=sink_risk,
                        source_risk=SOURCES[src],
                    ))

            for var, info in taint_map.items():
                if re.search(rf"\b{re.escape(var)}\b", line):
                    if (info.source, sink) in SAFE_SOURCE_SINK_PAIRS:
                        continue
                    chain = self._build_chain(var, info)
                    chain.append(sink)
                    results.append(self._build_flow(
                        info.source, sink, line_idx,
                        chain=chain,
                        hops=info.hops + 1,
                        sink_risk=sink_risk,
                        source_risk=SOURCES.get(info.source, 50),
                    ))

        for m in _TIMER_STRING_RE.finditer(line):
            var_name = m.group(1)
            if var_name and var_name in taint_map:
                info = taint_map[var_name]
                sink = "setTimeout(" if "setTimeout" in line else "setInterval("
                chain = self._build_chain(var_name, info)
                chain.append(sink)
                flow = self._build_flow(
                    info.source, sink, line_idx,
                    chain=chain,
                    hops=info.hops + 1,
                    sink_risk=90,
                    source_risk=SOURCES.get(info.source, 50),
                )
                if flow not in results:
                    results.append(flow)

        return results


    @staticmethod
    def _build_chain(var: str, info: _TaintInfo) -> List[str]:
        """Reconstruct the taint chain from source → var."""
        nodes: List[_TaintInfo] = []
        current: Optional[_TaintInfo] = info
        while current:
            nodes.append(current)
            current = current.via
        nodes.reverse()  # now root-first

        parts: List[str] = []
        for node in nodes:
            if node.via is None:
                parts.append(node.source)
            if node.var_name and (not parts or parts[-1] != node.var_name):
                parts.append(node.var_name)

        if not parts or parts[-1] != var:
            parts.append(var)
        return parts

    @staticmethod
    def _build_flow(
        source: str,
        sink: str,
        line: int,
        *,
        chain: List[str],
        hops: int,
        sink_risk: int,
        source_risk: int,
    ) -> FlowResult:
        """Create a ``FlowResult`` with computed confidence."""
        if hops == 0:
            base = 90   # direct source→sink
        elif hops == 1:
            base = 80   # one variable hop
        elif hops <= 3:
            base = 70   # multi-hop
        else:
            base = 55   # deep taint — less reliable

        risk_avg = (source_risk + sink_risk) / 200  # 0.0 – 1.0
        confidence = int(base * (0.6 + 0.4 * risk_avg))
        confidence = max(10, min(confidence, 98))

        return FlowResult(
            flow_detected=True,
            source=source,
            sink=sink,
            taint_chain=chain,
            confidence=confidence,
            line=line,
        )



@dataclass
class _TaintInfo:
    """Tracks how a variable became tainted."""
    source: str              # original DOM source API
    line: int                # line where taint was introduced
    hops: int = 0            # number of variable hops from source
    via: Optional[_TaintInfo] = None  # previous hop (for chain reconstruction)
    var_name: str = ""       # variable name that holds this taint
