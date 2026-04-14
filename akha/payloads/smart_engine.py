"""Non-breaking smart payload wrapper layer.

This module wraps existing payload generator + mutator logic and adds
lightweight context detection, mutation, and encoded-reflection filters.
"""

from __future__ import annotations

import html
import logging
import urllib.parse
from typing import Dict, List, Optional

from akha.payloads.generator import PayloadGenerator
from akha.payloads.mutator import PayloadMutator


logger = logging.getLogger("akha.smart_payload_engine")


class SmartPayloadEngine:
    """Wrap existing payload components with additional intelligence."""

    def __init__(self, generator: Optional[PayloadGenerator] = None, mutator: Optional[PayloadMutator] = None):
        self.generator = generator or PayloadGenerator()
        self.mutator = mutator or PayloadMutator()

    def detect_context(self, response_text: str, payload: str) -> str:
        """Lightweight context detector used as a fallback signal."""
        if not response_text or not payload:
            return "html"
        if f'"{payload}"' in response_text or f"'{payload}'" in response_text:
            return "attribute"
        if f"<script>{payload}" in response_text or f"<script>{payload};" in response_text:
            return "javascript"
        return "html"

    def is_encoded_reflection(self, response_text: str, payload: str) -> bool:
        """Return True when payload appears reflected only in encoded form."""
        if not response_text or not payload:
            return False

        if payload in response_text:
            return False

        encoded_variants = {
            html.escape(payload),
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload)),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
        }
        return any(v in response_text for v in encoded_variants if v)

    def mutate(self, payload: str) -> List[str]:
        """Apply lightweight generic mutations in addition to mutator output."""
        if not payload:
            return []
        variants = [
            payload,
            payload.upper(),
            payload.replace("<", "%3C"),
            payload.replace("script", "scr<script>ipt"),
        ]
        variants.extend(self.mutator.mutate([payload], max_variants_per_payload=2))

        deduped: List[str] = []
        seen = set()
        for item in variants:
            if item and item not in seen:
                seen.add(item)
                deduped.append(item)
        return deduped

    def generate(
        self,
        *,
        url: str,
        param: str,
        probe_result: Dict,
        marker: str,
        waf_name: Optional[str] = None,
        payload_limit: int = 50,
    ) -> List[str]:
        """Generate payloads with non-breaking wrappers over existing engine."""
        chars = probe_result.get("chars", {})
        context = probe_result.get("context", "html")
        quote_type = probe_result.get("quote_type")

        response = probe_result.get("response")
        body = response.text if response is not None else ""
        probe_id = probe_result.get("probe_id", "")

        if context not in {"html", "attribute", "javascript", "url", "css", "comment"}:
            context = self.detect_context(body, probe_id)

        payloads = self.generator.generate(
            context=context,
            chars=chars,
            quote_type=quote_type,
            in_script=probe_result.get("in_script", False),
            in_attribute=probe_result.get("in_attribute", False),
            attr_name=probe_result.get("attr_name"),
            marker=marker,
            waf_name=waf_name,
        )

        expanded: List[str] = []
        for payload in payloads[:8]:
            expanded.extend(self.mutate(payload))

        merged = payloads + expanded
        deduped: List[str] = []
        seen = set()
        for item in merged:
            if item and item not in seen:
                seen.add(item)
                deduped.append(item)

        logger.debug(
            "Smart payload generation for %s@%s: context=%s base=%d final=%d",
            param,
            url,
            context,
            len(payloads),
            len(deduped),
        )

        return deduped[:max(1, payload_limit)]
