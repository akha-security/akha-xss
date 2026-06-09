"""
Smart HTTP client with retry, rate limiting, authentication,
async batch support (httpx), proxy rotation, and auto-reauth.
"""

import time
import warnings
import random
import threading
import uuid
import requests
import logging
import re
from datetime import datetime, timezone
from urllib3.util.retry import Retry
from requests.adapters import HTTPAdapter
from typing import Optional, Dict, List, Tuple, Any
from urllib.parse import parse_qsl, urlencode, urlparse as _urlparse, urlsplit, urlunsplit
import urllib3
from akha.core.auth_plugins import create_auth_plugin
from akha.utils.json_logger import bind_log_context, get_log_context


logger = logging.getLogger("akha.http_client")


_URL_RE = re.compile(r"https?://\S+", re.IGNORECASE)


def _redact_url_for_log(url: str) -> str:
    """Mask query values before printing URLs in terminal/log output."""
    if not url:
        return ""
    try:
        parts = urlsplit(str(url))
    except Exception:
        return str(url)
    if not parts.query:
        return str(url)
    redacted_query = urlencode(
        [(key, "[redacted]") for key, _value in parse_qsl(parts.query, keep_blank_values=True)],
        doseq=True,
    )
    return urlunsplit((parts.scheme, parts.netloc, parts.path, redacted_query, parts.fragment))


def _redact_urls_in_text(value: object) -> str:
    """Mask URL query values inside arbitrary exception/log text."""
    text = str(value)
    return _URL_RE.sub(lambda match: _redact_url_for_log(match.group(0)), text)


# ---------------------------------------------------------------------------
# Proxy Rotator (Phase 4)
# ---------------------------------------------------------------------------

class ProxyRotator:
    """Round-robin proxy pool with automatic rotation on failures."""

    def __init__(self, proxy_list: Optional[List[str]] = None):
        self._proxies: List[str] = []
        self._index = 0
        self._lock = threading.Lock()
        self._failed: Dict[str, int] = {}  # proxy_url -> consecutive failures
        self._max_failures = 5  # Ban proxy after N consecutive failures
        self._quarantined_until: Dict[str, float] = {}  # proxy_url -> timestamp
        self._cooldown_seconds = 60
        self._stats: Dict[str, Dict[str, Any]] = {}
        self._latency_cap = 200

        if proxy_list:
            for p in proxy_list:
                p = p.strip()
                if p and not p.startswith('#'):
                    self._proxies.append(p)

    @property
    def available(self) -> bool:
        return len(self._proxies) > 0

    def next(self) -> Optional[str]:
        """Get the next working proxy (round-robin with score preference)."""
        if not self._proxies:
            return None
        with self._lock:
            now = time.time()
            n = len(self._proxies)
            start = self._index % n
            # Advance index by 1 so the next call starts from a different position
            self._index = (start + 1) % n

            best_proxy = None
            best_score = None
            for i in range(n):
                proxy = self._proxies[(start + i) % n]
                quarantine_until = self._quarantined_until.get(proxy, 0)
                if quarantine_until and quarantine_until > now:
                    continue
                if self._failed.get(proxy, 0) >= self._max_failures:
                    continue

                score = self._score(proxy)
                if best_score is None or score > best_score:
                    best_score = score
                    best_proxy = proxy
            if best_proxy:
                return best_proxy
            # All proxies unavailable: release the least-quarantined as last resort.
            if self._quarantined_until:
                candidate = min(self._quarantined_until.items(), key=lambda kv: kv[1])[0]
                self._quarantined_until.pop(candidate, None)
                self._failed[candidate] = max(0, self._max_failures - 1)
                return candidate
            # All proxies are exhausted; don't blindly clear and return.
            # This prevents indefinite retries with failed proxies.
            logger.warning("All proxies exhausted and quarantined; no working proxy available")
            return None

    def report_success(self, proxy: str):
        """Mark a proxy as healthy."""
        self.report_result(proxy, success=True)

    def report_failure(self, proxy: str):
        """Increment failure counter for a proxy."""
        self.report_result(proxy, success=False)

    def report_result(
        self,
        proxy: str,
        *,
        success: bool,
        latency_ms: Optional[float] = None,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        timeout: bool = False,
    ):
        if not proxy:
            return
        with self._lock:
            stats = self._stats.setdefault(proxy, {
                'success': 0,
                'fail': 0,
                'timeouts': 0,
                'latency_ms': [],
                'last_status': None,
                'last_error': None,
            })
            if success:
                stats['success'] += 1
                current = self._failed.get(proxy, 0)
                if current <= 1:
                    self._failed.pop(proxy, None)
                else:
                    self._failed[proxy] = current - 1
                self._quarantined_until.pop(proxy, None)
            else:
                stats['fail'] += 1
                self._failed[proxy] = self._failed.get(proxy, 0) + 1
                count = self._failed[proxy]
                if count >= self._max_failures:
                    self._quarantined_until[proxy] = time.time() + self._cooldown_seconds
                    logger.info("Proxy %s banned after %d failures", proxy, count)

            if timeout:
                stats['timeouts'] += 1
            if latency_ms is not None:
                stats['latency_ms'].append(float(latency_ms))
                if len(stats['latency_ms']) > self._latency_cap:
                    stats['latency_ms'] = stats['latency_ms'][-self._latency_cap:]
            if status_code is not None:
                stats['last_status'] = int(status_code)
            if error_type:
                stats['last_error'] = str(error_type)

    def _score(self, proxy: str) -> float:
        stats = self._stats.get(proxy) or {}
        success = int(stats.get('success', 0))
        fail = int(stats.get('fail', 0))
        total = success + fail
        success_ratio = (success / total) if total else 0.5
        timeouts = int(stats.get('timeouts', 0))
        timeout_ratio = (timeouts / total) if total else 0.0
        lat = stats.get('latency_ms') or []
        avg_lat = (sum(lat) / len(lat)) if lat else 0.0
        latency_penalty = min(avg_lat / 2000.0, 0.5)
        timeout_penalty = min(timeout_ratio, 0.5)
        return success_ratio - latency_penalty - timeout_penalty

    def snapshot(self) -> Dict[str, Any]:
        """Return a report-safe proxy pool health snapshot."""
        with self._lock:
            now = time.time()
            proxies = []
            for proxy in self._proxies:
                stats = dict(self._stats.get(proxy) or {})
                lat = list(stats.get('latency_ms') or [])
                success = int(stats.get('success', 0))
                fail = int(stats.get('fail', 0))
                total = success + fail
                quarantine_until = float(self._quarantined_until.get(proxy, 0) or 0)
                proxies.append({
                    'proxy': proxy,
                    'success': success,
                    'fail': fail,
                    'timeouts': int(stats.get('timeouts', 0) or 0),
                    'success_ratio': round((success / total) if total else 0.0, 4),
                    'avg_latency_ms': round((sum(lat) / len(lat)) if lat else 0.0, 2),
                    'last_status': stats.get('last_status'),
                    'last_error': stats.get('last_error'),
                    'consecutive_failures': int(self._failed.get(proxy, 0) or 0),
                    'quarantined': quarantine_until > now,
                    'quarantine_remaining_seconds': max(0, int(quarantine_until - now)),
                    'score': round(float(self._score(proxy)), 4),
                })
            return {
                'enabled': bool(self._proxies),
                'total': len(self._proxies),
                'available': sum(1 for p in proxies if not p['quarantined']),
                'proxies': proxies,
            }

    @classmethod
    def from_file(cls, filepath: str) -> 'ProxyRotator':
        """Load proxy list from a text file (one proxy per line)."""
        proxies: List[str] = []
        try:
            with open(filepath, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        proxies.append(line)
        except Exception as e:
            logger.warning("Failed to load proxy list from %s: %s", filepath, e)
        return cls(proxies)


class HTTPClient:
    """Smart HTTP client wrapper with authentication, proxy rotation, and async support"""
    
    def __init__(self, config):
        self.config = config
        self.session = self._create_session()
        self.last_request_time = 0
        self._rate_lock = threading.Lock()
        self._request_count = 0
        self.authenticated = False
        
        self._current_rate = config.rate_limit  # Current effective rate (req/s)
        self._base_rate = config.rate_limit      # Original configured rate
        self._consecutive_errors = 0             # Consecutive 429/503 errors
        self._rate_backoff_until = 0             # Timestamp until which we're in backoff
        self._host_last_request: Dict[str, float] = {}
        self._path_last_request: Dict[str, float] = {}
        self._host_backoff_until: Dict[str, float] = {}
        self._path_backoff_until: Dict[str, float] = {}
        self._target_penalty: Dict[str, float] = {}
        self._latency_samples_ms: List[float] = []
        self._latency_cap = 2000
        self._status_buckets: Dict[str, int] = {
            '2xx': 0,
            '3xx': 0,
            '4xx': 0,
            '5xx': 0,
            'error': 0,
        }
        self._inflight_requests = 0
        self._peak_inflight_requests = 0

        # --- Phase 3: Auto-reauth support ---
        self._reauth_lock = threading.Lock()
        self._reauth_401_streak = 0
        self._max_401_streak = 3  # Re-login after N consecutive 401/403
        self._reauth_count = 0
        self._auth_failures = 0
        self._last_auth_event: Dict[str, Any] = {}
        self._auth_plugin = create_auth_plugin(
            getattr(config, 'auth_plugin', None),
            getattr(config, 'auth_plugin_options', None),
        )

        # --- Phase 4: Proxy rotation ---
        self._proxy_rotator: Optional[ProxyRotator] = None
        proxy_list_path = getattr(config, 'proxy_list', None)
        if proxy_list_path:
            self._proxy_rotator = ProxyRotator.from_file(proxy_list_path)
            if self._proxy_rotator.available:
                try:
                    self._proxy_rotator._cooldown_seconds = max(
                        10, int(getattr(config, 'proxy_cooldown_seconds', 60) or 60)
                    )
                except Exception:
                    self._proxy_rotator._cooldown_seconds = 60
                logger.info(
                    "Proxy pool loaded: %d proxies",
                    len(self._proxy_rotator._proxies),
                )
        
        self._apply_auth()
        
    def _create_session(self) -> requests.Session:
        """Create HTTP session with connection pooling, keep-alive, and retry logic"""
        session = requests.Session()
        
        retry = Retry(
            total=2,
            backoff_factor=0.3,
            status_forcelist=[502, 503, 504],
            allowed_methods=['GET', 'POST', 'PUT', 'HEAD', 'OPTIONS'],
        )
        
        pool_size = max(self.config.threads * 2, 20)
        adapter = HTTPAdapter(
            max_retries=retry,
            pool_connections=pool_size,
            pool_maxsize=pool_size,
            pool_block=False,
        )
        session.mount('http://', adapter)
        session.mount('https://', adapter)
        
        session.headers.update({
            'User-Agent': self.config.user_agent,
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
        })

        self._bind_request_context()  # Ensure request context is bound
        if self.config.proxy:
            proxy_url = self.config.proxy
            # When explicit proxy is set from CLI/config, ignore ambient
            # HTTP(S)_PROXY/NO_PROXY environment variables to avoid
            # accidental bypass during crawling.
            session.trust_env = False
            session.proxies = {
                'http': proxy_url,
                'https': proxy_url,
            }
            parsed_proxy = _urlparse(proxy_url)
            if parsed_proxy.username and parsed_proxy.password:
                from requests.auth import HTTPProxyAuth
                session.auth = HTTPProxyAuth(parsed_proxy.username, parsed_proxy.password)
                logger.debug("Proxy authentication configured for %s", parsed_proxy.hostname)
        
        return session

    def _bind_request_context(
        self,
        *,
        request_id: Optional[str] = None,
        proxy_id: Optional[str] = None,
    ) -> None:
        """Bind HTTP request fields into the structured logging context."""
        updates: Dict[str, str] = {}
        if request_id is not None:
            updates["request_id"] = request_id
        if proxy_id is not None:
            updates["proxy_id"] = proxy_id
        if updates:
            bind_log_context(**updates)
            return

        # Preserve an existing scanner-level context and ensure the expected
        # context variables are initialized for standalone HTTPClient usage.
        ctx = get_log_context()
        bind_log_context(
            scan_id=ctx.get("scan_id", ""),
            target_id=ctx.get("target_id", ""),
            worker_id=ctx.get("worker_id", ""),
            request_id=ctx.get("request_id", ""),
            payload_id=ctx.get("payload_id", ""),
            correlation_id=ctx.get("correlation_id", ""),
            proxy_id=ctx.get("proxy_id", ""),
        )

    def _create_direct_session(self) -> requests.Session:
        """Create a one-off session that ignores any configured proxy settings."""
        direct_session = requests.Session()
        direct_session.headers.update(self.session.headers)
        direct_session.cookies.update(self.session.cookies)
        direct_session.auth = self.session.auth
        direct_session.verify = self.session.verify
        direct_session.trust_env = False
        return direct_session
    
    def _apply_auth(self):
        """Apply authentication settings to session"""
        if self.config.custom_headers:
            self.session.headers.update(self.config.custom_headers)
        
        if self.config.bearer_token:
            self.session.headers['Authorization'] = f'Bearer {self.config.bearer_token}'
            self.authenticated = True
        
        if self.config.cookies:
            self._parse_and_set_cookies(self.config.cookies)
            self.authenticated = True
        
        if self.config.auth_url and self.config.auth_data:
            self._perform_login()
    
    def _parse_and_set_cookies(self, cookie_string: str):
        """Parse cookie string and set on session"""
        scope_domain = None
        for source_url in (getattr(self.config, 'target_url', None), getattr(self.config, 'auth_url', None)):
            if source_url:
                try:
                    scope_domain = _urlparse(source_url).netloc or None
                except Exception:
                    scope_domain = None
                if scope_domain:
                    break
        if scope_domain:
            if scope_domain.startswith('www.'):
                scope_domain = scope_domain[4:]

        for cookie_pair in cookie_string.split(';'):
            cookie_pair = cookie_pair.strip()
            if '=' in cookie_pair:
                name, value = cookie_pair.split('=', 1)
                self.session.cookies.set(
                    name.strip(),
                    value.strip(),
                    domain=scope_domain,
                    path="/",
                )
    
    def _perform_login(self):
        """Perform form-based login"""
        try:
            login_url = self.config.auth_url
            login_data = dict(self.config.auth_data or {})
            login_headers = {}

            if self._auth_plugin:
                try:
                    plugin_patch = self._auth_plugin.prepare_login(self, login_url, login_data) or {}
                except Exception as exc:
                    plugin_patch = {"meta": {"plugin": self._auth_plugin.name, "error": str(exc)}}

                if isinstance(plugin_patch.get('url'), str) and plugin_patch.get('url').strip():
                    login_url = plugin_patch['url'].strip()
                if isinstance(plugin_patch.get('data'), dict):
                    login_data = dict(plugin_patch['data'])
                if isinstance(plugin_patch.get('headers'), dict):
                    login_headers.update(plugin_patch['headers'])
                if isinstance(plugin_patch.get('meta'), dict):
                    self._last_auth_event = dict(plugin_patch['meta'])

            response = self.session.post(
                login_url,
                data=login_data,
                headers=login_headers or None,
                timeout=self.config.timeout,
                verify=self.config.verify_ssl,
                allow_redirects=True,
            )

            session_cookie_names = {
                'session', 'sessionid', 'phpsessid', 'jsessionid',
                'auth_token', 'access_token', 'remember_token',
            }
            has_session_cookie = any(
                c.lower() in session_cookie_names
                for c in self.session.cookies.keys()
            )
            landed_on_auth_page = any(
                kw in response.url.lower()
                for kw in ('/dashboard', '/home', '/account', '/profile', '/panel')
            )

            if has_session_cookie or landed_on_auth_page:
                self.authenticated = True
                self._last_auth_event = {
                    'event': 'login-success',
                    'status_code': int(response.status_code),
                    'plugin': getattr(self._auth_plugin, 'name', None),
                }
                if self.config.verbose:
                    print(f"Login successful: {self.config.auth_url} (Status: {response.status_code})")
            elif response.status_code < 400:
                self.authenticated = True
                self._last_auth_event = {
                    'event': 'login-heuristic-success',
                    'status_code': int(response.status_code),
                    'plugin': getattr(self._auth_plugin, 'name', None),
                }
                logger.warning(
                    "Login heuristic: status %d but no session cookie detected.",
                    response.status_code,
                )
            else:
                self.authenticated = False
                self._auth_failures += 1
                self._last_auth_event = {
                    'event': 'login-failed-status',
                    'status_code': int(response.status_code),
                    'plugin': getattr(self._auth_plugin, 'name', None),
                }
                if self.config.verbose:
                    print(f"Login may have failed: Status {response.status_code}")
                    
        except Exception as e:
            self.authenticated = False
            self._auth_failures += 1
            self._last_auth_event = {
                'event': 'login-exception',
                'error': str(e),
                'plugin': getattr(self._auth_plugin, 'name', None),
            }
            logger.debug("Login failed: %s", e)

    # -----------------------------------------------------------------
    # Phase 3: Auto-reauth interceptor
    # -----------------------------------------------------------------

    def _check_reauth(self, response: requests.Response, url: str,
                      method: str = 'GET', **replay_kwargs) -> requests.Response:
        """If response is 401/403 and auth_url is configured, re-login and retry once."""
        if response.status_code not in (401, 403):
            with self._reauth_lock:
                self._reauth_401_streak = 0
            return response

        if not (self.config.auth_url and self.config.auth_data):
            return response

        if not getattr(self.config, 'auto_reauth', True):
            return response

        with self._reauth_lock:
            self._reauth_401_streak += 1
            if self._reauth_401_streak < self._max_401_streak:
                return response

            # Streak threshold reached → re-login
            logger.info("Auth expired (streak=%d). Re-authenticating...", self._reauth_401_streak)
            if self.config.verbose:
                print(f"[Auth] Session expired — re-logging in to {self.config.auth_url}")

            plugin_recovered = False

            if self._auth_plugin:
                plugin_result = self._auth_plugin.handle_reauth(self, response)
                if plugin_result.ok:
                    plugin_recovered = True
                    self._reauth_401_streak = 0
                    self._reauth_count += 1
                    self._last_auth_event = {
                        'event': 'reauth-plugin-success',
                        'plugin': getattr(self._auth_plugin, 'name', None),
                        'reason': plugin_result.reason,
                        'details': plugin_result.details or {},
                    }
                else:
                    self._last_auth_event = {
                        'event': 'reauth-plugin-fallback',
                        'plugin': getattr(self._auth_plugin, 'name', None),
                        'reason': plugin_result.reason,
                    }

            if not plugin_recovered:
                self._perform_login()
                if self.authenticated:
                    self._reauth_count += 1
            self._reauth_401_streak = 0

        # Retry the original request once
        try:
            if method.upper() == 'POST':
                return self.session.post(url, timeout=self.config.timeout,
                                         verify=self.config.verify_ssl, **replay_kwargs)
            return self.session.get(url, timeout=self.config.timeout,
                                    verify=self.config.verify_ssl, **replay_kwargs)
        except Exception:
            return response

    # -----------------------------------------------------------------
    # Phase 4: Proxy rotation helpers
    # -----------------------------------------------------------------

    def _get_proxies_dict(self) -> Optional[Dict[str, str]]:
        """Get proxy dict for the next rotation, or None if not using rotation."""
        if not self._proxy_rotator or not self._proxy_rotator.available:
            return None
        proxy_url = self._proxy_rotator.next()
        if proxy_url:
            self._bind_request_context(proxy_id=proxy_url)
            return {'http': proxy_url, 'https': proxy_url}
        return None

    def _apply_rotation_result(
        self,
        proxy_url: Optional[str],
        success: bool,
        *,
        latency_ms: Optional[float] = None,
        status_code: Optional[int] = None,
        error_type: Optional[str] = None,
        timeout: bool = False,
    ):
        """Report proxy health back to rotator."""
        if proxy_url and self._proxy_rotator:
            self._proxy_rotator.report_result(
                proxy_url,
                success=success,
                latency_ms=latency_ms,
                status_code=status_code,
                error_type=error_type,
                timeout=timeout,
            )

    # -----------------------------------------------------------------
    # Rate-limiting (unchanged from original)
    # -----------------------------------------------------------------
    
    def _rate_limit(self):
        """Apply adaptive rate limiting (thread-safe).
        
        Automatically slows down when receiving 429/503 responses,
        and gradually recovers to the base rate when requests succeed.
        """
        with self._rate_lock:
            now = time.time()
            backoff_remaining = self._rate_backoff_until - now
            min_interval = 1.0 / max(float(self._current_rate), 0.1)
            wait = min_interval - (now - self.last_request_time)

        if backoff_remaining > 0:
            time.sleep(backoff_remaining)
        elif wait > 0:
            time.sleep(wait)

        with self._rate_lock:
            self.last_request_time = time.time()

    def _target_rate_limit(self, url: str):
        """Apply additional host/path-aware throttling on top of global limiter."""
        parsed = _urlparse(url or '')
        host_key = (parsed.netloc or '').lower()
        path_key = f"{host_key}{parsed.path or '/'}"
        now = time.time()

        host_wait = 0.0
        path_wait = 0.0

        with self._rate_lock:
            host_backoff_remaining = max(0.0, self._host_backoff_until.get(host_key, 0.0) - now)
            path_backoff_remaining = max(0.0, self._path_backoff_until.get(path_key, 0.0) - now)

            if bool(getattr(self.config, 'per_host_rate_limit', True)) and host_key:
                host_penalty = max(1.0, float(self._target_penalty.get(host_key, 1.0)))
                host_min_interval = 1.0 / max(float(self._current_rate) / host_penalty, 0.1)
                host_wait = host_min_interval - (now - self._host_last_request.get(host_key, 0.0))
                host_wait = max(host_wait, host_backoff_remaining)

            if bool(getattr(self.config, 'per_path_rate_limit', True)) and path_key:
                multiplier = float(getattr(self.config, 'path_rate_multiplier', 0.75) or 0.75)
                path_penalty = max(1.0, float(self._target_penalty.get(path_key, 1.0)))
                path_rate = max(
                    (float(self._current_rate) * max(min(multiplier, 1.0), 0.1)) / path_penalty,
                    0.1,
                )
                path_min_interval = 1.0 / path_rate
                path_wait = path_min_interval - (now - self._path_last_request.get(path_key, 0.0))
                path_wait = max(path_wait, path_backoff_remaining)

        wait_for = max(host_wait, path_wait, 0.0)
        if wait_for > 0:
            time.sleep(wait_for)

        with self._rate_lock:
            stamp = time.time()
            if host_key:
                self._host_last_request[host_key] = stamp
            if path_key:
                self._path_last_request[path_key] = stamp

    def _is_challenge_response(self, response: requests.Response) -> bool:
        """Detect anti-bot/WAF challenge responses beyond plain 429/503."""
        try:
            status = int(getattr(response, 'status_code', 0) or 0)
            if status not in (403, 429, 503):
                return False

            headers = {k.lower(): str(v).lower() for k, v in getattr(response, 'headers', {}).items()}
            body = (getattr(response, 'text', '') or '')[:10000].lower()

            if any(h in headers for h in ('cf-ray', 'x-akamai-request-id', 'x-sucuri-id', 'x-amzn-waf-action')):
                return True

            markers = (
                'captcha', 'attention required', 'just a moment', 'verify you are human',
                'bot challenge', 'access denied', 'request blocked', 'cloudflare', 'akamai',
            )
            return any(m in body for m in markers)
        except Exception:
            return False

    def _endpoint_backoff_profile(self, url: str, method: str = 'GET') -> Dict[str, Any]:
        """Classify endpoint and return adaptive backoff weights."""
        parsed = _urlparse(url or '')
        path = (parsed.path or '/').lower()
        method_u = (method or 'GET').upper()

        profile_name = 'default'
        if any(t in path for t in ('/login', '/auth', '/signin', '/session', '/token')):
            profile_name = 'auth'
        elif method_u in ('POST', 'PUT', 'PATCH', 'DELETE') and '/api/' in path:
            profile_name = 'api_write'
        elif '/api/' in path or '/graphql' in path:
            profile_name = 'api_read'

        weights = {
            'default': {'penalty_mult': 1.2, 'path_penalty_mult': 1.3, 'backoff_extra': 0},
            'api_read': {'penalty_mult': 1.35, 'path_penalty_mult': 1.5, 'backoff_extra': 1},
            'api_write': {'penalty_mult': 1.6, 'path_penalty_mult': 1.8, 'backoff_extra': 2},
            'auth': {'penalty_mult': 1.8, 'path_penalty_mult': 2.0, 'backoff_extra': 3},
        }

        # Optional runtime/YAML overrides (profile-scoped).
        overrides = getattr(self.config, 'endpoint_backoff_profile_overrides', None)
        if isinstance(overrides, dict):
            for p_name, patch in overrides.items():
                if p_name not in weights or not isinstance(patch, dict):
                    continue

                if 'penalty_mult' in patch:
                    try:
                        weights[p_name]['penalty_mult'] = max(1.0, min(float(patch['penalty_mult']), 3.0))
                    except Exception:
                        logger.debug("Invalid penalty_mult override for profile %s", p_name, exc_info=True)

                if 'path_penalty_mult' in patch:
                    try:
                        weights[p_name]['path_penalty_mult'] = max(1.0, min(float(patch['path_penalty_mult']), 4.0))
                    except Exception:
                        logger.debug("Invalid path_penalty_mult override for profile %s", p_name, exc_info=True)

                if 'backoff_extra' in patch:
                    try:
                        weights[p_name]['backoff_extra'] = max(0, min(int(patch['backoff_extra']), 20))
                    except Exception:
                        logger.debug("Invalid backoff_extra override for profile %s", p_name, exc_info=True)

        out = {'profile': profile_name}
        out.update(weights.get(profile_name, weights['default']))
        return out

    def _adapt_target_rate(self, url: str, response: requests.Response, method: str = 'GET'):
        """Apply host/path penalties and backoff windows based on challenge signals."""
        parsed = _urlparse(url or '')
        host_key = (parsed.netloc or '').lower()
        path_key = f"{host_key}{parsed.path or '/'}"
        is_rate_limited = response.status_code in (429, 503)
        is_challenge = self._is_challenge_response(response)
        profile = self._endpoint_backoff_profile(url, method)

        if not bool(getattr(self.config, 'endpoint_backoff_profiles', True)):
            profile = {'profile': 'default', 'penalty_mult': 1.0, 'path_penalty_mult': 1.0, 'backoff_extra': 0}

        with self._rate_lock:
            if is_rate_limited or is_challenge:
                host_penalty = min(
                    float(self._target_penalty.get(host_key, 1.0)) * float(profile['penalty_mult']),
                    8.0,
                )
                path_penalty = min(
                    float(self._target_penalty.get(path_key, 1.0)) * float(profile['path_penalty_mult']),
                    10.0,
                )
                self._target_penalty[host_key] = host_penalty
                self._target_penalty[path_key] = path_penalty

                retry_after = self._retry_after_seconds(response.headers.get('Retry-After'), 2)
                base = max(retry_after, 2)
                extra = int(profile.get('backoff_extra', 0)) + (2 if is_challenge else 0)
                now = time.time()
                self._host_backoff_until[host_key] = max(self._host_backoff_until.get(host_key, 0.0), now + base + extra)
                self._path_backoff_until[path_key] = max(self._path_backoff_until.get(path_key, 0.0), now + base + extra + 1)
            elif response.status_code < 400:
                if host_key:
                    self._target_penalty[host_key] = max(1.0, float(self._target_penalty.get(host_key, 1.0)) * 0.9)
                if path_key:
                    self._target_penalty[path_key] = max(1.0, float(self._target_penalty.get(path_key, 1.0)) * 0.85)
    
    def _adapt_rate(self, response: requests.Response):
        """Adapt rate limiting based on response status.
        
        - 429 (Too Many Requests) / 503 (Service Unavailable): slow down aggressively
        - 200-399: gradually recover towards base rate
        """
        with self._rate_lock:
            if response.status_code in (429, 503):
                self._consecutive_errors += 1
                old_rate = self._current_rate
                self._current_rate = max(self._current_rate / 2, 1)
                retry_after = response.headers.get('Retry-After')
                if retry_after:
                    try:
                        backoff_secs = int(retry_after)
                    except ValueError:
                        backoff_secs = 5 * self._consecutive_errors
                else:
                    base_backoff = min(3 * self._consecutive_errors, 30)
                    jitter = random.uniform(0, base_backoff * 0.3)
                    backoff_secs = base_backoff + jitter
                self._rate_backoff_until = time.time() + backoff_secs
                logger.info(
                    "Rate limit hit (%d). Slowing %.1f → %.1f req/s, backoff %.1fs",
                    response.status_code, old_rate, self._current_rate, backoff_secs,
                )
                if self.config.verbose:
                    print(f"[Rate Limit] {response.status_code} → {self._current_rate:.1f} req/s, backoff {backoff_secs:.0f}s")

                # Phase 4: rotate proxy on rate-limit
                if self._proxy_rotator and self._proxy_rotator.available:
                    current_proxy = (self.session.proxies or {}).get('http')
                    self._apply_rotation_result(current_proxy, False)
                    new_proxies = self._get_proxies_dict()
                    if new_proxies:
                        self.session.proxies = new_proxies
                        if self.config.verbose:
                            print(f"[Proxy] Rotated to {new_proxies.get('http', '?')}")

            elif response.status_code < 400:
                if self._consecutive_errors > 0:
                    self._consecutive_errors = 0
                if self._current_rate < self._base_rate:
                    old_rate = self._current_rate
                    self._current_rate = min(self._current_rate * 1.1, self._base_rate)
                    if old_rate != self._current_rate:
                        logger.debug(
                            "Rate recovering: %.1f → %.1f req/s (base: %.1f)",
                            old_rate, self._current_rate, self._base_rate,
                        )

    def _retry_after_seconds(self, retry_after: Optional[str], default_seconds: int) -> int:
        """Parse Retry-After header as seconds or HTTP date."""
        if not retry_after:
            return default_seconds
        value = retry_after.strip()
        if not value:
            return default_seconds
        try:
            return max(int(value), 0)
        except ValueError:
            pass
        try:
            parsed = datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)
            delta = int((parsed - datetime.now(timezone.utc)).total_seconds())
            return max(delta, 0)
        except ValueError:
            return default_seconds

    def _sleep_before_retry(self, response: requests.Response, fallback_seconds: int = 2):
        """Sleep before retrying 429/503 responses."""
        wait_seconds = self._retry_after_seconds(response.headers.get('Retry-After'), fallback_seconds)
        if wait_seconds > 0:
            time.sleep(wait_seconds)
    
    @property
    def request_count(self) -> int:
        """Total HTTP requests made (thread-safe)"""
        with self._rate_lock:
            return self._request_count

    def _begin_request(self):
        self._bind_request_context(request_id=uuid.uuid4().hex)
        with self._rate_lock:
            self._request_count += 1
            self._inflight_requests += 1
            if self._inflight_requests > self._peak_inflight_requests:
                self._peak_inflight_requests = self._inflight_requests

    def _end_request(self, *, started_at: float, status_code: Optional[int] = None, error: bool = False):
        elapsed_ms = max((time.time() - started_at) * 1000.0, 0.0)
        with self._rate_lock:
            self._inflight_requests = max(0, self._inflight_requests - 1)
            self._latency_samples_ms.append(elapsed_ms)
            if len(self._latency_samples_ms) > self._latency_cap:
                self._latency_samples_ms = self._latency_samples_ms[-self._latency_cap:]

            if error:
                self._status_buckets['error'] += 1
            elif status_code is not None:
                if 200 <= status_code < 300:
                    self._status_buckets['2xx'] += 1
                elif 300 <= status_code < 400:
                    self._status_buckets['3xx'] += 1
                elif 400 <= status_code < 500:
                    self._status_buckets['4xx'] += 1
                elif 500 <= status_code < 600:
                    self._status_buckets['5xx'] += 1

    def get_telemetry_snapshot(self) -> Dict[str, Any]:
        """Return transport telemetry for reports and diagnostics."""
        with self._rate_lock:
            lat = list(self._latency_samples_ms)
            status = dict(self._status_buckets)
            req = int(self._request_count)
            peak = int(self._peak_inflight_requests)

        if lat:
            ordered = sorted(lat)
            n = len(ordered)
            p50 = ordered[int(0.50 * (n - 1))]
            p95 = ordered[int(0.95 * (n - 1))]
            avg = sum(ordered) / n
            max_v = ordered[-1]
        else:
            p50 = p95 = avg = max_v = 0.0

        pool_max = max(int(getattr(self.config, 'threads', 10)) * 2, 20)
        util = (peak / pool_max) if pool_max > 0 else 0.0

        proxy_snapshot = (
            self._proxy_rotator.snapshot()
            if self._proxy_rotator is not None
            else {'enabled': False, 'total': 0, 'available': 0, 'proxies': []}
        )

        return {
            'request_count': req,
            'latency_ms': {
                'p50': round(float(p50), 2),
                'p95': round(float(p95), 2),
                'avg': round(float(avg), 2),
                'max': round(float(max_v), 2),
                'samples': len(lat),
            },
            'status_buckets': status,
            'connection_pool': {
                'configured_max': pool_max,
                'peak_inflight': peak,
                'utilization_ratio': round(util, 4),
            },
            'proxy_pool': proxy_snapshot,
        }

    def get_auth_snapshot(self) -> Dict[str, Any]:
        """Return auth lifecycle snapshot for reporting and diagnostics."""
        return {
            'authenticated': bool(self.authenticated),
            'auto_reauth': bool(getattr(self.config, 'auto_reauth', True)),
            'plugin': getattr(self._auth_plugin, 'name', None),
            'reauth_count': int(self._reauth_count),
            'auth_failures': int(self._auth_failures),
            'last_event': dict(self._last_auth_event or {}),
        }
    
    # -----------------------------------------------------------------
    # Core HTTP Methods (with reauth + proxy rotation)
    # -----------------------------------------------------------------

    def _request(self, method: str, url: str, timeout: Optional[int] = None, allow_redirects: Optional[bool] = None, **kwargs) -> requests.Response:
        self._rate_limit()
        self._target_rate_limit(url)
        started_at = time.time()
        self._begin_request()
        
        timeout = timeout or self.config.timeout
        if allow_redirects is None:
            allow_redirects = self.config.follow_redirects

        explicit_proxy_applied = False
        if self._proxy_rotator and self._proxy_rotator.available and 'proxies' not in kwargs:
            rot_proxies = self._get_proxies_dict()
            if rot_proxies:
                kwargs['proxies'] = rot_proxies
        elif self.config.proxy and 'proxies' not in kwargs:
            session_proxies = getattr(self.session, 'proxies', None) or {
                'http': self.config.proxy,
                'https': self.config.proxy,
            }
            if session_proxies:
                kwargs['proxies'] = dict(session_proxies)
                explicit_proxy_applied = True
                self._bind_request_context(proxy_id=kwargs['proxies'].get('http', ''))
        
        req_kwargs = dict(kwargs)
        req_kwargs['timeout'] = timeout
        req_kwargs['verify'] = self.config.verify_ssl
        req_kwargs['allow_redirects'] = allow_redirects

        try:
            response = self._send_with_session(self.session, method, url, **req_kwargs)
            self._adapt_rate(response)
            self._adapt_target_rate(url, response, method=method)
            
            if response.status_code in (429, 503):
                self._sleep_before_retry(response)
                response = self._send_with_session(self.session, method, url, **req_kwargs)
                self._adapt_rate(response)
                self._adapt_target_rate(url, response, method=method)

            response = self._check_reauth(response, url, method=method, allow_redirects=allow_redirects, **kwargs)

            used_proxy = (kwargs.get('proxies') or {}).get('http')
            latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
            self._apply_rotation_result(
                used_proxy,
                response.status_code < 500,
                latency_ms=latency_ms,
                status_code=response.status_code,
            )
            self._end_request(started_at=started_at, status_code=response.status_code)
            return response
            
        except requests.exceptions.SSLError:
            logger.warning("SSL verification failed for %s. Traffic may be intercepted.", _redact_url_for_log(url))
            if self.config.verify_ssl and not getattr(self.config, 'allow_ssl_fallback', False):
                raise
            if getattr(self.config, 'allow_ssl_fallback', False):
                with warnings.catch_warnings():
                    warnings.simplefilter("ignore", urllib3.exceptions.InsecureRequestWarning)
                    fallback_kwargs = dict(req_kwargs)
                    fallback_kwargs['verify'] = False
                    response = self._send_with_session(self.session, method, url, **fallback_kwargs)
                    
                used_proxy = (kwargs.get('proxies') or {}).get('http')
                latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
                self._apply_rotation_result(
                    used_proxy,
                    response.status_code < 500,
                    latency_ms=latency_ms,
                    status_code=response.status_code,
                )
                self._end_request(started_at=started_at, status_code=response.status_code)
                return response
            self._end_request(started_at=started_at, error=True)
            raise Exception(f"{method} request failed due to TLS certificate validation")
            
        except requests.exceptions.Timeout:
            used_proxy = (kwargs.get('proxies') or {}).get('http')
            latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
            self._apply_rotation_result(
                used_proxy, False, latency_ms=latency_ms, error_type="Timeout", timeout=True
            )
            self._end_request(started_at=started_at, error=True)
            raise Exception(f"Request timeout after {timeout} seconds")
            
        except requests.exceptions.TooManyRedirects:
            self._end_request(started_at=started_at, error=True)
            raise Exception("Too many redirects")
            
        except requests.exceptions.RequestException as e:
            used_proxy = (kwargs.get('proxies') or {}).get('http')
            latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
            self._apply_rotation_result(used_proxy, False, latency_ms=latency_ms, error_type=type(e).__name__)

            if self.config.proxy and explicit_proxy_applied and method == 'GET':
                is_proxy_error = isinstance(e, (requests.exceptions.ProxyError, requests.exceptions.ConnectionError))
                if is_proxy_error:
                    logger.warning(
                        "Proxy request failed for %s; retrying once without proxy: %s",
                        _redact_url_for_log(url),
                        _redact_urls_in_text(e),
                    )
                    direct_kwargs = dict(req_kwargs)
                    direct_kwargs.pop('proxies', None)
                    try:
                        direct_session = self._create_direct_session()
                        response = self._send_with_session(direct_session, method, url, **direct_kwargs)
                        self._adapt_rate(response)
                        self._adapt_target_rate(url, response, method=method)
                        response = self._check_reauth(response, url, method=method, allow_redirects=allow_redirects, **kwargs)
                        latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
                        self._apply_rotation_result(None, response.status_code < 500, latency_ms=latency_ms, status_code=response.status_code)
                        self._end_request(started_at=started_at, status_code=response.status_code)
                        return response
                    except requests.exceptions.RequestException:
                        pass
                        
            self._end_request(started_at=started_at, error=True)
            raise Exception(f"{method} request failed: {_redact_urls_in_text(e)}")

    @staticmethod
    def _send_with_session(session, method: str, url: str, **kwargs) -> requests.Response:
        """Send through requests.Session or a lightweight test/custom session."""
        request_fn = getattr(session, 'request', None)
        if callable(request_fn):
            return request_fn(method, url, **kwargs)

        method_fn = getattr(session, method.lower(), None)
        if callable(method_fn):
            return method_fn(url, **kwargs)

        raise AttributeError(f"Session object does not support {method} requests")

    def get(self, url: str, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        """Send GET request with improved error handling"""
        return self._request('GET', url, timeout=timeout, **kwargs)

    def post(self, url: str, data: Optional[Dict] = None, timeout: Optional[int] = None, allow_redirects: Optional[bool] = None, **kwargs) -> requests.Response:
        """Send POST request (form-urlencoded)"""
        return self._request('POST', url, data=data, timeout=timeout, allow_redirects=allow_redirects, **kwargs)

    def post_json(self, url: str, json_data: Optional[Dict] = None, timeout: Optional[int] = None, allow_redirects: Optional[bool] = None, **kwargs) -> requests.Response:
        """Send POST request with JSON body (application/json)"""
        return self._request('POST', url, json=json_data, timeout=timeout, allow_redirects=allow_redirects, **kwargs)

    def put_json(self, url: str, json_data: Optional[Dict] = None, timeout: Optional[int] = None, **kwargs) -> requests.Response:
        """Send PUT request with JSON body"""
        return self._request('PUT', url, json=json_data, timeout=timeout, **kwargs)

    # -----------------------------------------------------------------
    # Phase 2: Async batch requests via httpx
    # -----------------------------------------------------------------

    def async_batch_get(self, urls: List[str], timeout: Optional[int] = None,
                        concurrency: int = 20) -> List[Tuple[str, Any]]:
        """Fetch multiple URLs concurrently using httpx async client.

        Returns a list of (url, response_or_none) tuples.
        Falls back to synchronous requests if httpx is not installed.
        """
        if not urls:
            return []

        concurrency = max(1, int(concurrency))
        timeout = timeout or self.config.timeout
        try:
            from akha.core.async_runner import AsyncRunner
            runner = AsyncRunner()
            return runner.run(
                self._async_batch_get_impl(urls, timeout, concurrency),
                timeout=max(timeout * len(urls) / concurrency, 60),
            )
        except ImportError:
            logger.warning("httpx not available, falling back to sync batch")
            return self._sync_batch_get(urls, timeout)

    async def _async_batch_get_impl(self, urls: List[str], timeout: int,
                                     concurrency: int) -> List[Tuple[str, Any]]:
        """Internal async implementation using httpx."""
        try:
            import httpx
        except ImportError:
            logger.warning("httpx not installed — async batch unavailable")
            return self._sync_batch_get(urls, timeout)

        import asyncio

        results: List[Tuple[str, Any]] = []
        semaphore = asyncio.Semaphore(concurrency)

        base_params = {
            "timeout": httpx.Timeout(timeout),
            "verify": self.config.verify_ssl,
            "follow_redirects": self.config.follow_redirects,
            "http2": True,
            "headers": dict(self.session.headers),
            "cookies": {
                c.name: c.value
                for c in getattr(self.session, "cookies", [])
            },
            "limits": httpx.Limits(
                max_connections=concurrency,
                max_keepalive_connections=concurrency,
            ),
        }

        proxy_clients: Dict[str, httpx.AsyncClient] = {}
        proxy_lock = asyncio.Lock()

        async with httpx.AsyncClient(**base_params) as client:
            async def _client_for_proxy(proxy_url: Optional[str]) -> httpx.AsyncClient:
                if not proxy_url:
                    return client
                async with proxy_lock:
                    if proxy_url in proxy_clients:
                        return proxy_clients[proxy_url]
                    proxy_client = httpx.AsyncClient(**base_params, proxy=proxy_url)
                    proxy_clients[proxy_url] = proxy_client
                    return proxy_client

            async def _fetch(url: str):
                async with semaphore:
                    # Respect rate limit
                    interval = 1.0 / max(float(self._current_rate), 0.1)
                    await asyncio.sleep(interval)
                    started_at = time.time()
                    self._begin_request()
                    proxy_url = None
                    if self._proxy_rotator and self._proxy_rotator.available:
                        proxy_url = self._proxy_rotator.next()
                    elif self.config.proxy:
                        proxy_url = self.config.proxy
                    try:
                        self._bind_request_context(proxy_id=proxy_url)
                        active_client = await _client_for_proxy(proxy_url)
                        resp = await active_client.get(url)
                        latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
                        self._end_request(started_at=started_at, status_code=getattr(resp, 'status_code', None))
                        self._apply_rotation_result(
                            proxy_url,
                            resp.status_code < 500,
                            latency_ms=latency_ms,
                            status_code=getattr(resp, 'status_code', None),
                        )
                        return (url, resp)
                    except Exception as e:
                        logger.debug(
                            "Async fetch failed for %s: %s",
                            _redact_url_for_log(url),
                            _redact_urls_in_text(e),
                        )
                        latency_ms = max((time.time() - started_at) * 1000.0, 0.0)
                        self._end_request(started_at=started_at, error=True)
                        self._apply_rotation_result(
                            proxy_url,
                            False,
                            latency_ms=latency_ms,
                            error_type=type(e).__name__,
                        )
                        return (url, None)

            tasks = [_fetch(u) for u in urls]
            results = await asyncio.gather(*tasks)

            for pc in proxy_clients.values():
                try:
                    await pc.aclose()
                except Exception:
                    logger.debug("Suppressed exception", exc_info=True)

        return list(results)

    def _sync_batch_get(self, urls: List[str], timeout: int) -> List[Tuple[str, Any]]:
        """Fallback synchronous batch using ThreadPoolExecutor."""
        from concurrent.futures import ThreadPoolExecutor, as_completed

        if not urls:
            return []

        results = []
        with ThreadPoolExecutor(max_workers=min(20, len(urls))) as executor:
            future_to_url = {executor.submit(self.get, url, timeout): url for url in urls}
            for future in as_completed(future_to_url):
                url = future_to_url[future]
                try:
                    resp = future.result()
                    results.append((url, resp))
                except Exception:
                    results.append((url, None))
        return results

    def close(self):
        """Close session"""
        self.session.close()
