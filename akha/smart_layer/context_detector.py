"""Lightweight response-context detection side-car."""

from __future__ import annotations

from typing import Optional


class SmartContextDetector:
    """Fast heuristic detector for HTML/attribute/JS contexts."""

    def detect(self, response_text: str, probe_or_payload: str) -> str:
        if not response_text or not probe_or_payload:
            return "html"

        token = probe_or_payload
        if f'"{token}"' in response_text or f"'{token}'" in response_text:
            return "attribute"
        if f"<script>{token}" in response_text or f"<script>{token};" in response_text:
            return "javascript"
        return "html"
