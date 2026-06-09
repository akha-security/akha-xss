"""
WebSocket XSS Scanner

WebSocket connections are often overlooked by XSS scanners.
If server echoes WS messages back to the DOM without sanitization,
XSS can execute via the WebSocket channel.

Attack chain:
  1. Parse page HTML/JS for WebSocket endpoint URLs
  2. Detect WebSocket library (native, Socket.io, SockJS)
  3. Connect to endpoint and send XSS probe
  4. Check if probe appears in HTTP response on next page load
     (static check — avoids full Playwright requirement)
  5. Optional: Use Playwright to connect WS and monitor DOM mutations

Supported WS libraries detected:
  - Native WebSocket (new WebSocket(...))
  - Socket.io (io.connect / io())
  - SockJS (new SockJS(...))
  - Primus
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, urljoin
from akha.core.async_runner import AsyncRunner

logger = logging.getLogger("akha.websocket")

_WS_CTOR_RE = re.compile(
    r'new\s+WebSocket\s*\(\s*["\']?(wss?://[^"\')\s]+)["\']?',
    re.IGNORECASE,
)
_WS_RELATIVE_RE = re.compile(
    r'new\s+WebSocket\s*\(\s*["\']([^"\')\s]+)["\']',
    re.IGNORECASE,
)
_SOCKETIO_RE = re.compile(
    r'(?:io\.connect|io)\s*\(\s*["\']?([^"\')\s]*)["\']?',
    re.IGNORECASE,
)
_SOCKJS_RE = re.compile(
    r'new\s+SockJS\s*\(\s*["\']([^"\')\s]+)["\']',
    re.IGNORECASE,
)
_PRIMUS_RE = re.compile(
    r'new\s+Primus\s*\(\s*["\']([^"\')\s]+)["\']',
    re.IGNORECASE,
)

COMMON_WS_PATHS = [
    '/ws', '/websocket', '/socket', '/socket.io',
    '/sockjs', '/sockjs-node', '/primus',
    '/api/ws', '/api/socket', '/echo',
    '/chat', '/live', '/realtime', '/stream',
]

WS_XSS_PROBE = 'akhaWSprobe9182'
WS_XSS_PAYLOADS = [
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '<script>alert(1)</script>',
    '"><img src=x onerror=alert(1)>',
]


class WebSocketScanner:
    """
    Static + dynamic WebSocket XSS scanner.

    Static mode (default): Detects WS endpoints in page source and
    reports them as potential injection points with context info.

    Dynamic mode (requires websockets lib + Playwright):
    Actually connects to the WebSocket and sends payloads.
    """

    def __init__(self, http_client, config, execution_verifier=None):
        self.client = http_client
        self.config = config
        self.verifier = execution_verifier
        self._stopped = False
        self._ws_available = self._check_ws_lib()

    def stop(self):
        self._stopped = True

    def _check_ws_lib(self) -> bool:
        """Check if websockets library is available for dynamic testing"""
        try:
            import websockets  # noqa: F401
            return True
        except ImportError:
            return False


    def scan(self, url: str, html: str = '') -> List[Dict]:
        """
        Scan for WebSocket XSS.
        Returns findings — static info if no websockets lib,
        or dynamic test results if available.
        """
        findings = []

        ws_endpoints = self.detect_websockets(url, html)

        if not ws_endpoints:
            ws_endpoints = self._probe_common_paths(url)

        if not ws_endpoints:
            return findings

        if self.config.verbose:
            logger.info("Found %d WebSocket endpoints at %s", len(ws_endpoints), url)

        for ws_info in ws_endpoints:
            if self._stopped:
                break

            if self._ws_available:
                dynamic_findings = self._dynamic_test(url, ws_info)
                findings.extend(dynamic_findings)
            else:
                if getattr(self.config, 'aggressive_mode', False):
                    findings.append(self._static_finding(url, ws_info))

        return findings


    def detect_websockets(self, url: str, html: str = '') -> List[Dict]:
        """
        Parse page HTML and JS for WebSocket connection endpoints.
        Returns list of endpoint info dicts.
        """
        endpoints = []
        seen_urls = set()

        if not html:
            try:
                resp = self.client.get(url, timeout=self.config.timeout)
                html = resp.text
            except Exception:
                return endpoints

        parsed_base = urlparse(url)
        base_ws = f"ws{'s' if parsed_base.scheme == 'https' else ''}://{parsed_base.netloc}"

        def add_endpoint(ws_url: str, lib: str):
            if ws_url in seen_urls:
                return
            seen_urls.add(ws_url)
            endpoints.append({
                'url': ws_url,
                'library': lib,
                'source_page': url,
            })

        for m in _WS_CTOR_RE.finditer(html):
            add_endpoint(m.group(1), 'WebSocket')

        for m in _WS_RELATIVE_RE.finditer(html):
            path = m.group(1)
            if path.startswith('ws://') or path.startswith('wss://'):
                add_endpoint(path, 'WebSocket')
            elif path.startswith('/'):
                add_endpoint(base_ws + path, 'WebSocket')

        for m in _SOCKETIO_RE.finditer(html):
            endpoint = m.group(1).strip()
            if endpoint:
                ws_url = base_ws + (endpoint if endpoint.startswith('/') else '/' + endpoint)
            else:
                ws_url = base_ws + '/socket.io'
            add_endpoint(ws_url, 'Socket.io')

        for m in _SOCKJS_RE.finditer(html):
            path = m.group(1)
            ws_url = base_ws + path if path.startswith('/') else base_ws + '/' + path
            add_endpoint(ws_url, 'SockJS')

        for m in _PRIMUS_RE.finditer(html):
            path = m.group(1)
            ws_url = base_ws + path if path.startswith('/') else base_ws + '/' + path
            add_endpoint(ws_url, 'Primus')

        return endpoints


    def _dynamic_test(self, page_url: str, ws_info: Dict) -> List[Dict]:
        """
        Connect to WebSocket and send XSS payloads.
        Requires websockets library.
        """
        import asyncio
        findings = []
        ws_url = ws_info['url']

        async def _test_async():
            try:
                import websockets
                async with websockets.connect(
                    ws_url,
                    ssl=True if ws_url.startswith('wss') else False,
                    open_timeout=5,
                    close_timeout=3,
                ) as ws:
                    await ws.send(WS_XSS_PROBE)
                    try:
                        resp = await asyncio.wait_for(ws.recv(), timeout=3)
                        if WS_XSS_PROBE not in resp:
                            return  # Server doesn't echo back
                    except asyncio.TimeoutError:
                        return

                    for payload in WS_XSS_PAYLOADS:
                        await ws.send(payload)
                        try:
                            msg = await asyncio.wait_for(ws.recv(), timeout=3)
                            if payload in msg and '<' in msg:
                                findings.append({
                                    'url': page_url,
                                    'parameter': f'WebSocket:{ws_url}',
                                    'payload': payload,
                                    'test_url': page_url,
                                    'type': 'websocket_xss',
                                    'subtype': f'WebSocket ({ws_info["library"]})',
                                    'status': 'Potential WebSocket XSS',
                                    'confidence': 70,
                                    'context': {
                                        'Location': 'WebSocket',
                                        'Endpoint': ws_url,
                                        'Library': ws_info['library'],
                                    },
                                    'bypass_technique': 'WebSocket Message Injection',
                                    'proof': (
                                        f'WebSocket endpoint echoed XSS payload unencoded.\n'
                                        f'Endpoint: {ws_url}\n'
                                        f'Library: {ws_info["library"]}\n'
                                        f'Payload: {payload}\n'
                                        f'Response: {msg[:200]}'
                                    ),
                                    'request': f'WebSocket SEND: {payload}',
                                    'response': msg[:500],
                                    'validated': False,
                                    'websocket_url': ws_url,
                                })
                                break
                        except asyncio.TimeoutError:
                            continue
            except Exception as e:
                if self.config.verbose:
                    logger.debug("WebSocket test error for %s: %s", ws_url, e)

        try:
            AsyncRunner().run(_test_async(), timeout=10)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)

        return findings


    def _static_finding(self, page_url: str, ws_info: Dict) -> Dict:
        """
        Create an informational finding when dynamic testing isn't available.
        Confidence is lower since we haven't actually sent a payload.
        """
        return {
            'url': page_url,
            'parameter': f'WebSocket:{ws_info["url"]}',
            'payload': WS_XSS_PAYLOADS[0],
            'test_url': page_url,
            'type': 'websocket_xss',
            'subtype': f'WebSocket endpoint detected ({ws_info["library"]})',
            'status': 'Manual Review Required',
            'confidence': 30,
            'context': {
                'Location': 'WebSocket',
                'Endpoint': ws_info['url'],
                'Library': ws_info['library'],
            },
            'bypass_technique': 'WebSocket Message Injection',
            'proof': (
                f'WebSocket endpoint found — manual testing recommended.\n'
                f'Install "websockets" package for dynamic testing:\n'
                f'  pip install websockets\n'
                f'Endpoint: {ws_info["url"]}\n'
                f'Library: {ws_info["library"]}\n'
                f'Source page: {page_url}'
            ),
            'request': f'WebSocket CONNECT: {ws_info["url"]}',
            'response': 'Static detection only — dynamic test requires websockets package',
            'validated': False,
            'websocket_url': ws_info['url'],
        }


    def _probe_common_paths(self, url: str) -> List[Dict]:
        """
        If no WS endpoints found in source, probe common paths via HTTP
        to see if they return WebSocket upgrade headers.
        """
        parsed = urlparse(url)
        origin = f"{parsed.scheme}://{parsed.netloc}"
        base_ws = f"ws{'s' if parsed.scheme == 'https' else ''}://{parsed.netloc}"
        found = []

        for path in COMMON_WS_PATHS:
            if self._stopped:
                break
            try:
                resp = self.client.get(
                    origin + path,
                    timeout=5,
                    headers={'Upgrade': 'websocket', 'Connection': 'Upgrade'},
                    allow_redirects=False,
                )
                if resp.status_code in (101, 400, 426):
                    found.append({
                        'url': base_ws + path,
                        'library': 'Unknown',
                        'source_page': url,
                    })
            except Exception:
                continue

        return found
