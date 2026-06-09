"""
HTTP injection module — abstracts payload delivery across all HTTP vectors.

Handles:
  - GET query parameters
  - POST form-urlencoded
  - POST JSON body
  - HTTP header injection
  - Cookie injection
  - URL path segment injection
  - CSRF token extraction and reuse
  - POST redirect following (302 → GET)
"""

from __future__ import annotations

import copy
import json
import re
import logging
import warnings
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse, urljoin, quote

from bs4 import BeautifulSoup

try:
    from bs4 import MarkupResemblesLocatorWarning
except ImportError:
    class MarkupResemblesLocatorWarning(Warning):
        pass

from .constants import REPORT_START, REPORT_END

logger = logging.getLogger("akha.injector")

MAX_CSRF_CACHE = 200
# Prevent multi‑MB responses from exhausting RAM when building reports / HTML embeds.
CAPTURE_MAX_BODY_CHARS = 400_000


@dataclass
class InjectionResult:
    """Result of injecting a value into a parameter."""
    success: bool
    response: Any = None          # requests.Response
    test_url: str = ""
    method: str = "GET"           # HTTP method used
    post_data: Optional[Dict] = None
    content_type: str = ""
    status_code: int = 0
    body: str = ""
    error: Optional[str] = None

    @property
    def text(self) -> str:
        return self.body


CSRF_FIELD_NAMES = frozenset({
    'csrf_token', 'csrfmiddlewaretoken', '_token', 'authenticity_token',
    'csrf', '__requestverificationtoken', 'antiforgerytoken', '_csrf',
    'xsrf_token', '_xsrf', 'nonce', 'wp_nonce', '_wpnonce',
    'form_token', 'form_build_id', 'token',
})

CSRF_META_NAMES = frozenset({
    'csrf-token', 'csrf-param', '_csrf_token', 'csrf_token',
    'X-CSRF-Token', 'X-CSRF-TOKEN',
})


class Injector:
    """
    Handles HTTP payload injection across all vectors with CSRF support.

    Usage::

        injector = Injector(http_client, config)

        result = injector.inject('http://example.com/search', 'q', '<script>alert(1)</script>')

        result = injector.inject(
            'http://example.com/submit', 'comment', payload,
            location='POST',
            param_context={'form_action': 'http://example.com/submit',
                           'form_inputs': {'name': 'test'}},
        )
    """

    def __init__(self, http_client, config):
        self.client = http_client
        self.config = config
        self._csrf_cache: Dict[str, Dict[str, str]] = {}

    def _store_csrf_cache(self, key: str, value: Dict[str, str]):
        if len(self._csrf_cache) >= MAX_CSRF_CACHE:
            oldest = next(iter(self._csrf_cache))
            del self._csrf_cache[oldest]
        self._csrf_cache[key] = value

    def inject(
        self,
        url: str,
        param_name: str,
        value: str,
        location: str = "query",
        param_context: Optional[Dict] = None,
        follow_redirect: bool = True,
        check_text: Optional[str] = None,
    ) -> InjectionResult:
        """
        Inject *value* into *param_name* at the specified *location*.

        Args:
            url: Target URL
            param_name: Parameter name to inject into
            value: Value to inject (probe string or payload)
            location: Where to inject — 'query' | 'POST' | 'json_body' | 'header' | 'cookie' | 'path'
            param_context: Extra context (form_action, form_inputs, json_body, path_index)
            follow_redirect: Follow POST redirects to find reflected content
            check_text: Text to look for when deciding whether to follow redirects

        Returns:
            InjectionResult with response data
        """
        try:
            if location == 'json_body':
                return self._inject_json(url, param_name, value, param_context,
                                         follow_redirect, check_text)
            elif location == 'POST':
                return self._inject_post(url, param_name, value, param_context,
                                         follow_redirect, check_text)
            elif location == 'header':
                return self._inject_header(url, param_name, value)
            elif location == 'cookie':
                return self._inject_cookie(url, param_name, value)
            elif location == 'path':
                return self._inject_path(url, param_name, value, param_context)
            else:
                return self._inject_get(url, param_name, value, param_context,
                                        follow_redirect, check_text)
        except Exception as e:
            logger.debug("Injection failed: %s", e)
            return InjectionResult(success=False, error=str(e))


    def _inject_get(
        self, url: str, param_name: str, value: str,
        param_context: Optional[Dict] = None,
        follow_redirect: bool = True,
        check_text: Optional[str] = None,
    ) -> InjectionResult:
        effective_url = url
        if param_context and param_context.get('form_action'):
            effective_url = param_context['form_action']

        test_url = self._build_query_url(effective_url, param_name, value)
        response = self.client.get(test_url, allow_redirects=False)

        if follow_redirect:
            response = self._follow_redirects(response, test_url, check_text or value)

        return InjectionResult(
            success=True,
            response=response,
            test_url=test_url,
            method="GET",
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )


    def _inject_post(
        self, url: str, param_name: str, value: str,
        param_context: Optional[Dict] = None,
        follow_redirect: bool = True,
        check_text: Optional[str] = None,
    ) -> InjectionResult:
        form_action = url
        post_data: Dict[str, str] = {}

        if param_context:
            form_action = param_context.get('form_action', url)
            form_inputs = param_context.get('form_inputs', {})
            post_data = dict(form_inputs)

        post_data = self._refresh_csrf_tokens(form_action, post_data)
        post_data[param_name] = value

        response = self.client.post(form_action, data=post_data, allow_redirects=False)

        if follow_redirect:
            response = self._follow_redirects(response, form_action, check_text or value)

        return InjectionResult(
            success=True,
            response=response,
            test_url=form_action,
            method="POST",
            post_data=post_data,
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )


    def _inject_json(
        self, url: str, param_name: str, value: str,
        param_context: Optional[Dict] = None,
        follow_redirect: bool = True,
        check_text: Optional[str] = None,
    ) -> InjectionResult:
        api_url = url
        json_template: Dict = {}

        if param_context:
            api_url = param_context.get('form_action', url)
            json_template = copy.deepcopy(param_context.get('json_body', {}))

        if not self._set_json_path(json_template, param_name, value):
            json_template[param_name] = value
        response = self.client.post_json(api_url, json_data=json_template,
                                         allow_redirects=False)

        if follow_redirect:
            response = self._follow_redirects(response, api_url, check_text or value)

        return InjectionResult(
            success=True,
            response=response,
            test_url=api_url,
            method="POST",
            post_data=json_template,
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )

    def _set_json_path(self, data: Dict[str, Any], path: str, value: Any) -> bool:
        """Set a dotted JSON path on a dict; returns False when unsupported."""
        if not isinstance(data, dict) or not path:
            return False
        parts = [p for p in str(path).split('.') if p]
        if not parts:
            return False
        current = data
        for idx, part in enumerate(parts):
            last = idx == len(parts) - 1
            if not isinstance(current, dict):
                return False
            if last:
                current[part] = value
                return True
            next_val = current.get(part)
            if not isinstance(next_val, dict):
                next_val = {}
                current[part] = next_val
            current = next_val
        return False


    def _inject_header(self, url: str, param_name: str, value: str) -> InjectionResult:
        response = self.client.get(url, headers={param_name: value})
        return InjectionResult(
            success=True,
            response=response,
            test_url=url,
            method="GET",
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )


    def _inject_cookie(self, url: str, param_name: str, value: str) -> InjectionResult:
        response = self.client.get(url, cookies={param_name: value})
        return InjectionResult(
            success=True,
            response=response,
            test_url=url,
            method="GET",
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )


    def _inject_path(
        self, url: str, param_name: str, value: str,
        param_context: Optional[Dict] = None,
    ) -> InjectionResult:
        raw_index = param_context.get('path_index', 0) if param_context else 0
        try:
            path_index = int(raw_index)
        except (TypeError, ValueError):
            path_index = 0
        test_url = self._build_path_url(url, path_index, value)
        response = self.client.get(test_url)
        return InjectionResult(
            success=True,
            response=response,
            test_url=test_url,
            method="GET",
            status_code=response.status_code,
            body=response.text,
            content_type=response.headers.get('Content-Type', ''),
        )


    def _refresh_csrf_tokens(
        self, form_action: str, post_data: Dict[str, str]
    ) -> Dict[str, str]:
        """
        If *post_data* contains a CSRF token field, fetch a fresh token
        from the form page so the submission isn't rejected.
        """
        csrf_fields = [k for k in post_data if k.lower() in CSRF_FIELD_NAMES]
        if not csrf_fields:
            return post_data

        cache_key = form_action
        if cache_key in self._csrf_cache:
            for f in csrf_fields:
                cached_val = self._csrf_cache[cache_key].get(f)
                if cached_val:
                    post_data[f] = cached_val
            return post_data

        try:
            resp = self.client.get(form_action, timeout=10)
            if resp.status_code >= 400:
                return post_data

            fresh_tokens = self._extract_csrf_tokens(resp.text)
            self._store_csrf_cache(cache_key, fresh_tokens)

            for f in csrf_fields:
                if f in fresh_tokens:
                    post_data[f] = fresh_tokens[f]
                elif f.lower() in {k.lower() for k in fresh_tokens}:
                    for tk, tv in fresh_tokens.items():
                        if tk.lower() == f.lower():
                            post_data[f] = tv
                            break
        except Exception as e:
            logger.debug("CSRF refresh failed for %s: %s", form_action, e)

        return post_data

    @staticmethod
    def _extract_csrf_tokens(html: str) -> Dict[str, str]:
        """
        Extract CSRF tokens from HTML forms and meta tags.
        Returns dict of field_name → token_value.
        """
        tokens: Dict[str, str] = {}

        try:
            snippet = html[:200000] if html else ''
            if '<' not in snippet or '>' not in snippet:
                return tokens
            snippet_lower = snippet.lower()
            if ('csrf' not in snippet_lower
                    and 'token' not in snippet_lower
                    and '<input' not in snippet_lower
                    and '<meta' not in snippet_lower):
                return tokens
            with warnings.catch_warnings():
                warnings.simplefilter("ignore", MarkupResemblesLocatorWarning)
                soup = BeautifulSoup(snippet, 'html.parser')

            for inp in soup.find_all('input', attrs={'type': 'hidden'}):
                name = (inp.get('name') or '').strip()
                value = (inp.get('value') or '').strip()
                if name and name.lower() in CSRF_FIELD_NAMES and value:
                    tokens[name] = value

            for meta in soup.find_all('meta'):
                meta_name = (meta.get('name') or meta.get('property') or '').strip()
                content = (meta.get('content') or '').strip()
                if meta_name.lower() in {n.lower() for n in CSRF_META_NAMES} and content:
                    tokens[meta_name] = content

        except Exception:

            logger.debug("Suppressed exception", exc_info=True)

        return tokens


    def _follow_redirects(self, response, base_url: str,
                          check_text: Optional[str] = None,
                          max_hops: int = 5):
        """Follow 3xx redirects, up to *max_hops* hops."""
        current = response
        current_url = base_url
        base_host = urlparse(base_url).netloc.lower()

        for _ in range(max(1, int(max_hops))):
            if current.status_code not in (301, 302, 303, 307, 308):
                break

            if check_text and check_text in current.text:
                break

            redirect_url = current.headers.get('Location', '').strip()
            if not redirect_url:
                break

            redirect_url = urljoin(current_url, redirect_url)
            if not redirect_url.startswith(('http://', 'https://')):
                break

            redirect_host = urlparse(redirect_url).netloc.lower()
            if redirect_host and redirect_host != base_host:
                break

            try:
                current = self.client.get(redirect_url)
                current_url = redirect_url
            except Exception:
                logger.debug(
                    "Failed following redirect from %s to %s",
                    current_url,
                    redirect_url,
                    exc_info=True,
                )
                break

        return current


    @staticmethod
    def _build_query_url(url: str, param_name: str, value: str) -> str:
        """Build a URL with the given query parameter set to *value*."""
        parsed = urlparse(url)
        params = dict(parse_qs(parsed.query, keep_blank_values=True))
        params[param_name] = [value]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))

    @staticmethod
    def _build_path_url(url: str, path_index: int, value: str) -> str:
        """Build a URL replacing a path segment at *path_index*."""
        parsed = urlparse(url)
        parts = [p for p in parsed.path.split('/') if p]
        path_index = max(0, int(path_index))
        encoded = quote(value, safe='')

        if not parts:
            parts = [encoded]
        elif path_index < len(parts):
            parts[path_index] = encoded
        else:
            parts.append(encoded)

        new_path = '/' + '/'.join(parts)
        return urlunparse((
            parsed.scheme, parsed.netloc, new_path,
            parsed.params, parsed.query, parsed.fragment,
        ))


    def capture_request(self, response, url: str, location: str,
                        post_data: Optional[Dict] = None) -> str:
        """Capture full HTTP request like Burp Suite, including POST body."""
        parsed = urlparse(url)
        method = "POST" if location in ('POST', 'json_body') else "GET"
        path = parsed.path or '/'
        query = f"?{parsed.query}" if parsed.query else ''

        body_str = ''
        content_type = 'application/x-www-form-urlencoded'
        if location == 'json_body' and post_data:
            body_str = json.dumps(post_data, indent=2)
            content_type = 'application/json'
        elif location == 'POST' and post_data:
            body_str = urlencode(post_data, doseq=False)

        lines = [
            f"{method} {path}{query} HTTP/1.1",
            f"Host: {parsed.netloc}",
            f"User-Agent: {self.config.user_agent}",
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-US,en;q=0.5",
            "Accept-Encoding: gzip, deflate",
            "Connection: close",
        ]
        if body_str:
            orig_len = len(body_str)
            if orig_len > CAPTURE_MAX_BODY_CHARS:
                body_str = body_str[:CAPTURE_MAX_BODY_CHARS] + (
                    f"\n\n... [{orig_len - CAPTURE_MAX_BODY_CHARS} bytes truncated for capture]\n"
                )
            lines.append(f"Content-Type: {content_type}")
            lines.append(f"Content-Length: {len(body_str)}")
            lines.append("")
            lines.append(body_str)
        else:
            lines.append("")
        return "\n".join(lines)

    @staticmethod
    def capture_response(response, payload: Optional[str] = None) -> str:
        """Capture full HTTP response, marking payload location."""
        lines = [f"HTTP/1.1 {response.status_code} {response.reason}"]
        for header, value in response.headers.items():
            lines.append(f"{header}: {value}")
        lines.append("")

        body = response.text or ""
        orig_len = len(body)
        if orig_len > CAPTURE_MAX_BODY_CHARS:
            body = body[:CAPTURE_MAX_BODY_CHARS] + (
                f"\n\n... [{orig_len - CAPTURE_MAX_BODY_CHARS} bytes truncated for capture]\n"
            )
        if payload and payload in body:
            body = body.replace(payload, f'{REPORT_START}{payload}{REPORT_END}')
        lines.append(body)
        return "\n".join(lines)
