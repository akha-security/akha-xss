"""Payload mutation side-car wrapper."""

from __future__ import annotations

from typing import List, Optional

from akha.payloads.mutator import PayloadMutator


class SmartMutator:
    """Combines simple deterministic mutations with existing mutator logic."""

    def __init__(self, base_mutator: Optional[PayloadMutator] = None):
        self._base_mutator = base_mutator or PayloadMutator()

    def mutate(self, payload: str, waf_name: Optional[str] = None) -> List[str]:
        if not payload:
            return []

        variants = [
            payload,
            payload.upper(),
            payload.replace("<", "%3C").replace(">", "%3E"),
            payload.replace("script", "scr<script>ipt"),
        ]

        variants.extend(
            self._base_mutator.mutate([payload], waf_name=waf_name, max_variants_per_payload=2)
        )

        out: List[str] = []
        seen = set()
        for v in variants:
            if v and v not in seen:
                seen.add(v)
                out.append(v)
        return out
