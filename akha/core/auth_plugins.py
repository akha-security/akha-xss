"""Authentication flow plugins for advanced login/reauth scenarios.

Plugins are optional and fail-open by design so scans continue even when
an auth flow helper cannot extract/refresh tokens.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any, Dict, Optional

from bs4 import BeautifulSoup


@dataclass
class AuthPluginResult:
    """Container for plugin outcome metadata."""

    ok: bool
    reason: str = ""
    details: Optional[Dict[str, Any]] = None


class AuthFlowPlugin:
    """Base class for auth flow plugins."""

    name = "base"

    def __init__(self, options: Optional[Dict[str, Any]] = None):
        self.options = options or {}

    def prepare_login(self, client, auth_url: str, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        """Return optional login request mutations (data/headers/url)."""
        return {}

    def handle_reauth(self, client, response) -> AuthPluginResult:
        """Try plugin-specific reauth before fallback login."""
        return AuthPluginResult(ok=False, reason="not-implemented")


class CSRFPreflightPlugin(AuthFlowPlugin):
    """Fetch login page and merge CSRF hidden field into auth_data."""

    name = "csrf-preflight"

    def prepare_login(self, client, auth_url: str, auth_data: Dict[str, Any]) -> Dict[str, Any]:
        preflight_url = str(self.options.get("preflight_url") or auth_url)
        timeout = int(self.options.get("timeout", getattr(client.config, "timeout", 10)))

        field_candidates = self.options.get("token_fields") or [
            "csrf_token",
            "csrfmiddlewaretoken",
            "_token",
            "authenticity_token",
            "_csrf",
        ]

        try:
            resp = client.session.get(
                preflight_url,
                timeout=timeout,
                verify=getattr(client.config, "verify_ssl", True),
                allow_redirects=True,
            )
            html = resp.text or ""
            soup = BeautifulSoup(html, "html.parser")

            token_name = None
            token_value = None
            for cand in field_candidates:
                node = soup.find("input", attrs={"name": cand})
                if node and node.get("value"):
                    token_name = cand
                    token_value = str(node.get("value"))
                    break

            if token_name and token_value:
                merged = dict(auth_data or {})
                if token_name not in merged:
                    merged[token_name] = token_value
                return {
                    "data": merged,
                    "meta": {
                        "plugin": self.name,
                        "preflight_url": preflight_url,
                        "csrf_field": token_name,
                    },
                }
            return {"meta": {"plugin": self.name, "preflight_url": preflight_url, "csrf_field": None}}
        except Exception as exc:
            return {
                "meta": {
                    "plugin": self.name,
                    "preflight_url": preflight_url,
                    "error": str(exc),
                }
            }


class BearerRefreshPlugin(AuthFlowPlugin):
    """Refresh bearer token from a refresh endpoint on 401/403."""

    name = "bearer-refresh"

    def _extract_token(self, payload: Dict[str, Any]) -> Optional[str]:
        keys = self.options.get("token_keys") or ["access_token", "token", "jwt"]
        for key in keys:
            value = payload.get(key)
            if isinstance(value, str) and value.strip():
                return value.strip()
        return None

    def handle_reauth(self, client, response) -> AuthPluginResult:
        refresh_url = self.options.get("refresh_url")
        if not refresh_url:
            return AuthPluginResult(ok=False, reason="missing-refresh-url")

        payload_json = self.options.get("payload_json")
        payload_form = self.options.get("payload_form")
        timeout = int(self.options.get("timeout", getattr(client.config, "timeout", 10)))

        try:
            r = client.session.post(
                str(refresh_url),
                json=payload_json if isinstance(payload_json, dict) else None,
                data=payload_form if isinstance(payload_form, dict) else None,
                timeout=timeout,
                verify=getattr(client.config, "verify_ssl", True),
                allow_redirects=True,
            )
            if r.status_code >= 400:
                return AuthPluginResult(ok=False, reason=f"refresh-status-{r.status_code}")

            try:
                data = r.json()
            except Exception:
                data = json.loads(r.text or "{}")

            if not isinstance(data, dict):
                return AuthPluginResult(ok=False, reason="invalid-refresh-json")

            token = self._extract_token(data)
            if not token:
                return AuthPluginResult(ok=False, reason="token-not-found")

            header_template = str(self.options.get("header_template") or "Bearer {token}")
            client.session.headers["Authorization"] = header_template.format(token=token)
            client.authenticated = True
            return AuthPluginResult(
                ok=True,
                reason="refresh-success",
                details={"plugin": self.name, "refresh_url": str(refresh_url)},
            )
        except Exception as exc:
            return AuthPluginResult(ok=False, reason=str(exc))


def create_auth_plugin(name: Optional[str], options: Optional[Dict[str, Any]] = None) -> Optional[AuthFlowPlugin]:
    if not name:
        return None

    norm = str(name).strip().lower()
    if norm in ("csrf", "csrf-preflight", "csrf_form"):
        return CSRFPreflightPlugin(options)
    if norm in ("bearer-refresh", "token-refresh", "refresh"):
        return BearerRefreshPlugin(options)
    return None
