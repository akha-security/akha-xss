"""False-positive reduction and external validation side-car."""

from __future__ import annotations

import html
import json
import urllib.parse
from typing import Dict, Iterable, List


class SmartValidator:
    """Non-breaking reflection validator helper."""

    def is_encoded(self, response_text: str, payload: str) -> bool:
        if not response_text or not payload:
            return False

        if payload in response_text:
            return False

        enc = {
            html.escape(payload),
            urllib.parse.quote(payload),
            urllib.parse.quote(urllib.parse.quote(payload)),
            payload.replace("<", "&lt;").replace(">", "&gt;"),
        }
        return any(v in response_text for v in enc if v)

    def is_real_xss(self, response_text: str, payload: str, *, trusted_signal: bool = False) -> bool:
        if trusted_signal:
            return True
        if not response_text or not payload:
            return False

        if payload in response_text:
            return True

        return False

    def export_candidates(self, candidates: Iterable[Dict], output_path: str) -> str:
        candidate_list = list(candidates)
        data = {
            "source": "akha-smart-layer",
            "count": len(candidate_list),
            "candidates": candidate_list,
        }
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        return output_path
