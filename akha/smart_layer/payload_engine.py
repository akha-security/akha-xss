"""Smart payload generation side-car layer.

Wraps existing payload generation and mutation without replacing core logic.
"""

from __future__ import annotations

import logging
from typing import Dict, List, Optional

from akha.payloads.generator import PayloadGenerator
from akha.payloads.mutator import PayloadMutator
from akha.smart_layer.context_detector import SmartContextDetector
from akha.smart_layer.mutator import SmartMutator


logger = logging.getLogger("akha.smart_layer.payload_engine")


class SmartPayloadEngine:
    """Context-aware payload generator wrapper (plug-and-play)."""

    def __init__(
        self,
        payload_generator: Optional[PayloadGenerator] = None,
        mutator: Optional[object] = None,
        context_detector: Optional[SmartContextDetector] = None,
    ):
        self._generator = payload_generator or PayloadGenerator()
        if isinstance(mutator, SmartMutator):
            self._mutator = mutator
        elif isinstance(mutator, PayloadMutator):
            self._mutator = SmartMutator(base_mutator=mutator)
        else:
            self._mutator = SmartMutator()
        self._context_detector = context_detector or SmartContextDetector()

    def generate(
        self,
        *,
        url: str,
        param: str,
        probe_result: Dict,
        marker: str,
        waf_name: Optional[str] = None,
        payload_limit: int = 50,
        minimal_grammar: bool = True,
    ) -> List[str]:
        chars = probe_result.get("chars", {})
        context = probe_result.get("context", "html")
        quote_type = probe_result.get("quote_type")

        response = probe_result.get("response")
        body = response.text if response is not None else ""
        probe_id = probe_result.get("probe_id", "")

        if context not in {"html", "attribute", "javascript", "url", "css", "comment"}:
            context = self._context_detector.detect(body, probe_id)

        base_payloads = self._generator.generate(
            context=context,
            chars=chars,
            quote_type=quote_type,
            in_script=probe_result.get("in_script", False),
            in_attribute=probe_result.get("in_attribute", False),
            attr_name=probe_result.get("attr_name"),
            marker=marker,
            waf_name=waf_name,
            minimal_grammar=minimal_grammar,
        )

        expanded: List[str] = []
        for p in base_payloads[:8]:
            expanded.extend(self._mutator.mutate(p, waf_name=waf_name))

        out: List[str] = []
        seen = set()
        for p in base_payloads + expanded:
            if p and p not in seen:
                seen.add(p)
                out.append(p)

        logger.debug(
            "SmartLayer payload generation for %s@%s context=%s base=%d final=%d",
            param,
            url,
            context,
            len(base_payloads),
            len(out),
        )
        return out[:max(1, payload_limit)]
