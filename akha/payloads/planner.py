"""Payload planning helpers: canonical dedupe, prioritization, and budgeting."""

from __future__ import annotations

import re
from typing import List


class PayloadPlanner:
    """Normalize and prioritize payload candidates with minimal noise."""

    @staticmethod
    def signature(payload: str) -> str:
        s = (payload or "").strip().lower()
        s = re.sub(r"\s+", "", s)
        s = s.replace("\"", "'")
        s = s.replace("%09", "")
        s = s.replace("<!--x-->", "")
        s = s.replace("window['ale'+'rt']", "alert")
        s = s.replace("self['alert']", "alert")
        s = s.replace("\u0061lert", "alert")
        return s

    def dedupe(self, payloads: List[str]) -> List[str]:
        out: List[str] = []
        seen = set()
        for payload in payloads:
            if not payload:
                continue
            sig = self.signature(payload)
            if sig in seen:
                continue
            seen.add(sig)
            out.append(payload)
        return out

    def prioritize(self, payloads: List[str], learned_payloads: List[str]) -> List[str]:
        if not learned_payloads:
            return payloads
        learned_sigs = {self.signature(p) for p in learned_payloads}
        head = [p for p in payloads if self.signature(p) in learned_sigs]
        tail = [p for p in payloads if self.signature(p) not in learned_sigs]
        return head + tail

    def budget(self, profile: str, deep_scan: bool, aggressive_mode: bool) -> int:
        profile = (profile or "balanced").lower()
        if profile == "quick":
            limit = 8
        elif profile == "deep":
            limit = 24
        else:
            limit = 15

        if deep_scan:
            limit += 8
        if aggressive_mode:
            limit += 15
        return min(limit, 64)
