"""
Execution Verifier — Real JavaScript execution detection via Playwright.

Unlike simple reflection checks, this module launches headless Chromium and
instruments the page with three independent detection hooks to verify that
injected XSS payloads actually *execute* in the browser context:

    1. **JS variable hook** — Rewrites alert/confirm/prompt calls in the
       payload to set ``window.__akha_executed = true``, then checks the
       variable after navigation.
    2. **Console hook** — Intercepts ``console.log`` messages for a unique
       marker that the rewritten payload emits.
    3. **DOM mutation hook** — Injects a ``MutationObserver`` via
       ``page.add_init_script`` before navigation to catch any DOM nodes
       created by the payload (e.g. ``<img>``, ``<iframe>``, event-handler
       attributes).

A verification succeeds if *any* of the three hooks fires.

Designed for production use inside AKHA-XSS — async-first, reusable browser
context, timeout-safe (8 s hard cap), infinite-loop protection, and clean
shutdown.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import re
import time
import traceback
from concurrent.futures import TimeoutError as FutureTimeoutError
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from akha.core.async_runner import AsyncRunner
try:
    from akha.utils.json_logger import bind_log_context, get_log_context
except Exception:
    def bind_log_context(**kwargs):
        return None
    def get_log_context():
        return {}

logger = logging.getLogger("akha.execution_verifier")


_MARKER_PREFIX = "__akha_"
_JS_VAR = f"window.{_MARKER_PREFIX}executed"
_CONSOLE_MARKER = f"{_MARKER_PREFIX}xss_"

_HOOK_TARGETS = ("alert", "confirm", "prompt")


def _rewrite_hook_calls(payload: str) -> str:
    """Normalize direct dialog calls to window-scoped calls.

    This keeps verification deterministic across contexts where unqualified
    dialog names may be shadowed.
    """
    rewritten = payload
    for target in _HOOK_TARGETS:
        pattern = rf"(?<![\w$.]){target}\s*\("
        rewritten = re.sub(pattern, f"window.{target}(", rewritten)
    return rewritten


def _apply_payload_transform(url: str, payload: str, enabled: bool) -> tuple[str, str]:
    """Return possibly transformed URL and payload for runtime verification."""
    if not enabled or not payload:
        return url, payload

    transformed_payload = _rewrite_hook_calls(payload)
    if transformed_payload == payload:
        return url, payload

    if payload in url:
        return url.replace(payload, transformed_payload, 1), transformed_payload
    return url, transformed_payload



@dataclass
class BrowserIsolationPolicy:
    """Isolation settings applied to each verification browser context."""

    service_workers: str = "block"
    accept_downloads: bool = False
    bypass_csp: bool = False
    permissions: List[str] = field(default_factory=list)
    max_runs_before_restart: int = 40
    renderer_memory_mb: int = 128
    nav_timeout_ceiling_ms: int = 8000
    post_navigation_wait_ms: int = 2000

    def normalized(self) -> "BrowserIsolationPolicy":
        return BrowserIsolationPolicy(
            service_workers=self.service_workers if self.service_workers in {"allow", "block"} else "block",
            accept_downloads=bool(self.accept_downloads),
            bypass_csp=bool(self.bypass_csp),
            permissions=list(self.permissions or []),
            max_runs_before_restart=max(5, min(int(self.max_runs_before_restart), 200)),
            renderer_memory_mb=max(64, min(int(self.renderer_memory_mb), 512)),
            nav_timeout_ceiling_ms=max(2000, min(int(self.nav_timeout_ceiling_ms), 30000)),
            post_navigation_wait_ms=max(250, min(int(self.post_navigation_wait_ms), 5000)),
        )


@dataclass
class VerificationResult:
    """Structured result returned by the verifier."""

    executed: bool = False
    method: Optional[str] = None  # "js_variable" | "console_hook" | "dom_mutation"
    evidence: Optional[str] = None
    payload: str = ""
    url: str = ""
    elapsed_ms: int = 0
    error: Optional[str] = None
    browser_engine: str = "chromium"
    sink_traces: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "executed": self.executed,
            "method": self.method,
            "evidence": self.evidence,
            "payload": self.payload,
            "url": self.url,
            "elapsed_ms": self.elapsed_ms,
            "error": self.error,
            "browser_engine": self.browser_engine,
            "sink_traces": list(self.sink_traces),
        }


@dataclass
class _DetectionState:
    """Mutable state shared between the detection hooks for a single run."""

    js_variable: bool = False
    console_hook: bool = False
    dom_mutation: bool = False
    console_evidence: Optional[str] = None
    dom_evidence: Optional[str] = None
    marker: str = ""



def _build_init_script(marker: str) -> str:
    """Return JS executed in every frame *before* page scripts.

    Installs:
      • ``window.__akha_executed`` variable (initially false).
      • ``MutationObserver`` that watches for injected elements / attributes
        and sets both the variable and emits a console marker.
      • Override of ``alert / confirm / prompt`` so that calling any of them
        also sets the variable + emits the marker.
      • Infinite-loop protection via a 7-second ``setTimeout`` that calls
        ``window.stop()`` to kill runaway scripts.
    """
    return f"""
    (function() {{
        // ── JS variable hook ────────────────────────────────────────
        window.{_MARKER_PREFIX}executed = false;

        function _markExecuted(method, detail) {{
            window.{_MARKER_PREFIX}executed = true;
            window.{_MARKER_PREFIX}method   = method;
            window.{_MARKER_PREFIX}evidence = detail;
            window.{_MARKER_PREFIX}nonce = "{marker}";
            try {{ console.log("{_CONSOLE_MARKER}{marker}:" + method + ":" + detail); }} catch(e) {{}}
        }}

        window.{_MARKER_PREFIX}sinks = [];
        function _markSink(name, detail) {{
            try {{
                var item = name + ":" + String(detail).slice(0, 120);
                window.{_MARKER_PREFIX}sinks.push(item);
                if (window.{_MARKER_PREFIX}sinks.length > 20) {{
                    window.{_MARKER_PREFIX}sinks.shift();
                }}
                console.log("{_CONSOLE_MARKER}{marker}:sink_trace:" + item);
            }} catch(e) {{}}
        }}

        // ── Override alert / confirm / prompt ───────────────────────
        try {{
            var _origEval = window.eval;
            window.eval = function(code) {{
                _markSink("eval", code);
                return _origEval.call(window, code);
            }};
            var _OrigFunction = window.Function;
            window.Function = function() {{
                _markSink("Function", Array.prototype.join.call(arguments, ","));
                return _OrigFunction.apply(this, arguments);
            }};
            var _origSetTimeout = window.setTimeout;
            window.setTimeout = function(handler, delay) {{
                if (typeof handler === "string") _markSink("setTimeout", handler);
                return _origSetTimeout.apply(window, arguments);
            }};
            var _origSetInterval = window.setInterval;
            window.setInterval = function(handler, delay) {{
                if (typeof handler === "string") _markSink("setInterval", handler);
                return _origSetInterval.apply(window, arguments);
            }};
        }} catch(e) {{}}

        var _origAlert   = window.alert;
        var _origConfirm = window.confirm;
        var _origPrompt  = window.prompt;

        window.alert = function(m) {{
            _markExecuted("js_variable", "alert(" + m + ")");
            // Do NOT call original — prevents blocking dialogs
        }};
        window.confirm = function(m) {{
            _markExecuted("js_variable", "confirm(" + m + ")");
            return true;
        }};
        window.prompt = function(m) {{
            _markExecuted("js_variable", "prompt(" + m + ")");
            return "";
        }};

        // NOTE: eval is NOT overridden — too many legitimate uses cause
        // false positives.  XSS payloads using eval() will be caught by
        // the alert/confirm/prompt hooks they ultimately call.

        // ── DOM Mutation hook ───────────────────────────────────────
        // Only fire for elements that look like XSS injections:
        // - Elements with our AKHA marker class
        // - Elements with event handler attributes containing suspicious JS
        // - SCRIPT tags with inline content (no src)
        // Normal page elements (<img>, <body>, <input> etc.) are NOT flagged.
        var _eventAttrs = /^on[a-z]+$/i;
        var _suspiciousHandlerValue = /\\balert\\s*\\(|\\bconfirm\\s*\\(|\\bprompt\\s*\\(|document\\.cookie|document\\.domain|window\\.location|\\beval\\s*\\(/i;

        function _checkNode(node) {{
            if (node.nodeType !== 1) return;

            // 1. Check for AKHA marker — strongest signal of our payload
            var cls = node.getAttribute && node.getAttribute("class");
            if (cls && /\\bakha\\b/.test(cls)) {{
                _markExecuted("dom_mutation",
                    "akha_marker on <" + node.tagName.toLowerCase() + ">");
                return;
            }}

            // 2. SCRIPT tags with inline content (no src) — likely injected
            if (node.tagName === "SCRIPT" && !node.src && node.textContent && node.textContent.trim()) {{
                // Only flag if the script content looks like an XSS payload
                var scriptText = node.textContent;
                if (_suspiciousHandlerValue.test(scriptText)) {{
                    _markExecuted("dom_mutation", "injected_script");
                    return;
                }}
            }}

            // 3. Event handler attributes with suspicious values
            if (node.attributes) {{
                for (var i = 0; i < node.attributes.length; i++) {{
                    var attrName = node.attributes[i].name;
                    var attrVal  = node.attributes[i].value || "";
                    if (_eventAttrs.test(attrName) && _suspiciousHandlerValue.test(attrVal)) {{
                        _markExecuted("dom_mutation",
                            "attr:" + attrName + " on <" + node.tagName.toLowerCase() + ">");
                        return;
                    }}
                    // Check for javascript: protocol in src/href
                    if ((attrName === "src" || attrName === "href") &&
                        /^javascript:/i.test(attrVal)) {{
                        _markExecuted("dom_mutation",
                            "javascript_proto on <" + node.tagName.toLowerCase() + ">");
                        return;
                    }}
                }}
            }}
        }}

        try {{
            var _observer = new MutationObserver(function(mutations) {{
                for (var i = 0; i < mutations.length; i++) {{
                    var m = mutations[i];
                    if (m.type === "childList") {{
                        for (var j = 0; j < m.addedNodes.length; j++) {{
                            _checkNode(m.addedNodes[j]);
                        }}
                    }} else if (m.type === "attributes") {{
                        if (_eventAttrs.test(m.attributeName)) {{
                            var val = m.target.getAttribute(m.attributeName) || "";
                            if (_suspiciousHandlerValue.test(val)) {{
                                _markExecuted("dom_mutation",
                                    "attr:" + m.attributeName + " on <" + m.target.tagName.toLowerCase() + ">");
                            }}
                        }}
                    }}
                }}
            }});
            _observer.observe(document.documentElement || document, {{
                childList: true,
                subtree: true,
                attributes: true,
                attributeFilter: undefined,
            }});
        }} catch(e) {{}}

        // ── Infinite-loop protection ────────────────────────────────
        setTimeout(function() {{
            try {{ window.stop(); }} catch(e) {{}}
        }}, 7000);
    }})();
    """



class ExecutionVerifier:
    """Headless-Chromium verifier for real XSS execution.

    Usage::

        verifier = ExecutionVerifier()
        result = verifier.verify(url_with_payload, raw_payload)
        print(result.to_dict())
        verifier.close()          # or use as context manager

    The verifier is **reusable** — a single browser instance is kept alive
    across calls and recycled until ``close()`` / ``__del__``.

    Parameters
    ----------
    timeout_ms : int
        Hard per-page timeout in milliseconds (default 8000).
    headless : bool
        Run Chromium in headless mode (default True).
    browser_args : list[str] | None
        Extra Chromium flags.
    user_agent : str | None
        Override User-Agent.
    """

    _DEFAULT_ARGS: List[str] = [
        "--disable-dev-shm-usage",
        "--disable-gpu",
        "--disable-background-networking",
        "--disable-default-apps",
        "--disable-extensions",
        "--disable-sync",
        "--metrics-recording-only",
        "--mute-audio",
        "--no-first-run",
        "--js-flags=--max_old_space_size=128",
    ]

    def __init__(
        self,
        timeout_ms: int = 8000,
        headless: bool = True,
        browser_args: Optional[List[str]] = None,
        user_agent: Optional[str] = None,
        max_concurrency: int = 3,
        browser_engine: str = "chromium",
        ignore_https_errors: bool = False,
        max_runs_before_restart: int = 40,
        isolation_policy: Optional[BrowserIsolationPolicy] = None,
    ) -> None:
        self.isolation_policy = (
            isolation_policy or BrowserIsolationPolicy(max_runs_before_restart=max_runs_before_restart)
        ).normalized()
        self.timeout_ms = max(timeout_ms, 2000)  # floor at 2s
        self.headless = headless
        base_args = browser_args or self._DEFAULT_ARGS.copy()
        self.browser_args = self._with_memory_arg(base_args, self.isolation_policy.renderer_memory_mb)
        self.user_agent = user_agent
        self.max_concurrency = max(1, int(max_concurrency))
        self.browser_engine = (browser_engine or "chromium").lower()
        self.ignore_https_errors = bool(ignore_https_errors)
        self._max_runs_before_restart = self.isolation_policy.max_runs_before_restart

        self._pw: Any = None           # playwright context manager
        self._browser: Any = None      # Browser instance
        self._playwright: Any = None   # Playwright API handle

        self._runner = AsyncRunner()
        self._loop: asyncio.AbstractEventLoop = self._runner.get_loop()

        self._lock = asyncio.Lock()    # guards browser init
        self._verify_sem = asyncio.Semaphore(self.max_concurrency)
        self._restart_lock = asyncio.Lock()
        self._runs_since_restart = 0
        self._restart_requested = False
        self._inflight = 0

    @staticmethod
    def _with_memory_arg(args: List[str], memory_mb: int) -> List[str]:
        filtered = [a for a in args if not a.startswith("--js-flags=--max_old_space_size=")]
        filtered.append(f"--js-flags=--max_old_space_size={int(memory_mb)}")
        return filtered

    @staticmethod
    def runtime_status() -> Dict[str, Any]:
        """Return dependency readiness without launching a browser."""
        try:
            import playwright  # noqa: F401
            return {"playwright": True, "error": None}
        except Exception as exc:
            return {"playwright": False, "error": str(exc)}


    async def _ensure_browser(self) -> None:
        """Launch browser lazily on first call (guarded by asyncio.Lock)."""
        if self._browser is not None:
            try:
                if self._browser.is_connected():
                    return
            except Exception:
                pass
            await self._close_async()
        async with self._lock:
            if self._browser is not None:
                try:
                    if self._browser.is_connected():
                        return
                except Exception:
                    pass
                await self._close_async()
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                raise RuntimeError(
                    "Playwright is required for ExecutionVerifier.  "
                    "Install it with:  pip install playwright && playwright install chromium"
                ) from exc

            self._pw = async_playwright()
            self._playwright = await self._pw.__aenter__()

            browser_factory = getattr(self._playwright, self.browser_engine, None)
            if browser_factory is None:
                browser_factory = self._playwright.chromium
                self.browser_engine = "chromium"

            self._browser = await browser_factory.launch(
                headless=self.headless,
                args=self.browser_args,
            )
            logger.debug("ExecutionVerifier: %s launched", self.browser_engine)

    async def _close_async(self) -> None:
        """Shut down browser and Playwright."""
        if self._browser:
            try:
                await self._browser.close()
            except Exception:
                logger.debug("ExecutionVerifier browser close failed", exc_info=True)
            self._browser = None
        if self._pw:
            try:
                await self._pw.__aexit__(None, None, None)
            except Exception:
                logger.debug("ExecutionVerifier playwright context exit failed", exc_info=True)
            self._pw = None
            self._playwright = None


    async def verify_async(
        self,
        url: str,
        payload: str,
        *,
        transform_payload: bool = True,
    ) -> VerificationResult:
        """Verify whether *payload* actually executes JS at *url*.

        Parameters
        ----------
        url : str
            Full URL with the payload already injected (query string / path / fragment).
        payload : str
            The raw payload string (used for evidence reporting and optional
            transform).
        transform_payload : bool
            If True the verifier **also** rewrites ``alert/confirm/prompt`` in
            the URL to hook variants.  Disable if you've already done this.

        Returns
        -------
        VerificationResult
        """
        async with self._verify_sem:
            ctx = get_log_context()
            if ctx.get("correlation_id"):
                bind_log_context(correlation_id=ctx.get("correlation_id"))
            self._inflight += 1
            try:
                return await asyncio.wait_for(
                    self._verify_once(url, payload, transform_payload=transform_payload),
                    timeout=(self.timeout_ms / 1000 + 5),
                )
            except asyncio.TimeoutError:
                return VerificationResult(error="Verification timed out")
            finally:
                self._runs_since_restart += 1
                if self._runs_since_restart >= self._max_runs_before_restart:
                    self._restart_requested = True
                self._inflight = max(0, self._inflight - 1)
                if self._restart_requested and self._inflight == 0:
                    await self._restart_browser()

    async def _restart_browser(self) -> None:
        async with self._restart_lock:
            if not self._restart_requested or self._inflight != 0:
                return
            await self._close_async()
            self._runs_since_restart = 0
            self._restart_requested = False

    async def _verify_once(
        self,
        url: str,
        payload: str,
        *,
        transform_payload: bool = True,
    ) -> VerificationResult:
        url, payload = _apply_payload_transform(url, payload, transform_payload)

        t0 = time.monotonic()
        result = VerificationResult(payload=payload, url=url)
        result.browser_engine = self.browser_engine

        marker = hashlib.md5(f"{url}{payload}{time.time()}".encode()).hexdigest()[:12]
        state = _DetectionState(marker=marker)

        try:
            await self._ensure_browser()
        except RuntimeError as exc:
            result.error = str(exc)
            result.elapsed_ms = int((time.monotonic() - t0) * 1000)
            return result

        context = None
        page = None
        try:
            ctx_opts: Dict[str, Any] = {
                "ignore_https_errors": self.ignore_https_errors,
                "java_script_enabled": True,
                "service_workers": self.isolation_policy.service_workers,
                "accept_downloads": self.isolation_policy.accept_downloads,
                "bypass_csp": self.isolation_policy.bypass_csp,
            }
            if self.user_agent:
                ctx_opts["user_agent"] = self.user_agent

            context = await self._browser.new_context(**ctx_opts)
            if self.isolation_policy.permissions:
                await context.grant_permissions(self.isolation_policy.permissions)

            await context.add_init_script(_build_init_script(marker))

            page = await context.new_page()

            def _on_console(msg):
                text = msg.text
                expected_prefix = f"{_CONSOLE_MARKER}{marker}:"
                if expected_prefix in text:
                    state.console_hook = True
                    state.console_evidence = text

            page.on("console", _on_console)

            async def _on_dialog(dialog):
                try:
                    await dialog.accept()
                except Exception:
                    logger.debug("Dialog auto-accept failed", exc_info=True)

            page.on("dialog", _on_dialog)

            nav_timeout = min(self.timeout_ms, self.isolation_policy.nav_timeout_ceiling_ms)
            try:
                await page.goto(url, timeout=nav_timeout, wait_until="domcontentloaded")
            except Exception as nav_err:
                logger.debug("Navigation error (expected): %s", nav_err)

            post_wait = min(
                self.isolation_policy.post_navigation_wait_ms,
                max(500, self.timeout_ms - 3000),
            )
            await page.wait_for_timeout(post_wait)

            try:
                js_check = await page.evaluate(
                    f"() => ({{ executed: !!window.{_MARKER_PREFIX}executed, "
                    f"method: window.{_MARKER_PREFIX}method || null, "
                    f"evidence: window.{_MARKER_PREFIX}evidence || null, "
                    f"nonce: window.{_MARKER_PREFIX}nonce || null, "
                    f"sinks: window.{_MARKER_PREFIX}sinks || [] }})"
                )
                if js_check and js_check.get("sinks"):
                    result.sink_traces = list(js_check.get("sinks") or [])
                if js_check and js_check.get("executed"):
                    nonce_ok = js_check.get("nonce") == marker
                    if not nonce_ok:
                        raise RuntimeError("execution nonce mismatch")
                    hook_method = js_check.get("method")
                    if hook_method == "dom_mutation":
                        state.dom_mutation = True
                        state.dom_evidence = js_check.get("evidence") or "DOM mutation observed"
                    else:
                        state.js_variable = True
            except Exception:
                logger.debug("Primary JS execution probe failed", exc_info=True)

            try:
                dom_check = await page.evaluate("""() => {
                    const dangerous = ['SCRIPT','IMG','IFRAME','OBJECT','EMBED','SVG'];
                    const found = [];
                    document.querySelectorAll(dangerous.join(',')).forEach(el => {
                        for (const attr of el.attributes) {
                            if (/^on/i.test(attr.name) || /^javascript:/i.test(attr.value)) {
                                found.push(el.tagName.toLowerCase() + '[' + attr.name + ']');
                            }
                        }
                    });
                    return found.length > 0 ? found.join(', ') : null;
                }""")
                if dom_check:
                    state.dom_mutation = True
                    state.dom_evidence = state.dom_evidence or dom_check
            except Exception:
                logger.debug("Secondary DOM probe failed", exc_info=True)

            if state.js_variable:
                result.executed = True
                result.method = "js_variable"
                evidence = ""
                if js_check and js_check.get("evidence"):
                    evidence = js_check["evidence"]
                result.evidence = evidence or "window.__akha_executed set to true"
            elif state.console_hook:
                result.executed = True
                result.method = "console_hook"
                result.evidence = state.console_evidence or "Console marker detected"
            elif state.dom_mutation:
                result.executed = True
                result.method = "dom_mutation"
                result.evidence = state.dom_evidence or "Dangerous DOM mutation observed"

        except asyncio.CancelledError:
            result.error = "Verification cancelled"
        except Exception as exc:
            logger.debug("Verification error: %s\n%s", exc, traceback.format_exc())
            result.error = str(exc)
            self._restart_requested = True
        finally:
            if page:
                try:
                    await page.close()
                except Exception:
                    logger.debug("Page close failed", exc_info=True)
            if context:
                try:
                    await context.close()
                except Exception:
                    logger.debug("Browser context close failed", exc_info=True)

        result.elapsed_ms = int((time.monotonic() - t0) * 1000)
        return result


    def verify(
        self,
        url: str,
        payload: str,
        *,
        transform_payload: bool = True,
    ) -> VerificationResult:
        """Synchronous façade for ``verify_async``.

        Dispatches work to the persistent background event loop so that
        Playwright subprocess transports always have a live loop.
        """
        if self._loop.is_closed():
            return VerificationResult(error="Event loop closed")

        try:
            return self._runner.run_limited_with_retry(
                name="execution_verifier",
                limit=self.max_concurrency,
                coro_factory=lambda: self.verify_async(url, payload, transform_payload=transform_payload),
                retries=2,
                delay_seconds=0.15,
                timeout=self.timeout_ms / 1000 + 5,
            )
        except Exception as exc:
            return VerificationResult(error=str(exc))


    async def verify_batch_async(
        self,
        items: List[Dict[str, str]],
        *,
        concurrency: int = 3,
    ) -> List[VerificationResult]:
        """Verify multiple URL/payload pairs concurrently.

        Parameters
        ----------
        items : list[dict]
            Each dict must have ``"url"`` and ``"payload"`` keys.
        concurrency : int
            Max parallel browser contexts (default 3).

        Returns
        -------
        list[VerificationResult]
        """
        if not items:
            return []

        concurrency = max(1, int(concurrency))
        semaphore = asyncio.Semaphore(concurrency)

        async def _limited(item: Dict[str, str]) -> VerificationResult:
            async with semaphore:
                return await self.verify_async(
                    url=item["url"],
                    payload=item["payload"],
                )

        return await asyncio.gather(*[_limited(i) for i in items])

    def verify_batch(
        self,
        items: List[Dict[str, str]],
        *,
        concurrency: int = 3,
    ) -> List[VerificationResult]:
        """Synchronous façade for ``verify_batch_async``."""
        if not items:
            return []

        if self._loop.is_closed():
            return [VerificationResult(error="Event loop closed") for _ in items]

        concurrency = max(1, int(concurrency))
        coro = self.verify_batch_async(items, concurrency=concurrency)
        try:
            return self._runner.run(
                coro,
                timeout=(self.timeout_ms / 1000 + 5) * max(len(items), 1),
            )
        except FutureTimeoutError:
            return [VerificationResult(error="Batch timed out") for _ in items]
        except TimeoutError:
            return [VerificationResult(error="Batch timed out") for _ in items]
        except Exception as exc:
            return [VerificationResult(error=f"Batch failed: {exc}") for _ in items]


    def close(self) -> None:
        """Shut down browser resources on the shared background event loop."""
        if self._loop.is_closed():
            return

        try:
            future = asyncio.run_coroutine_threadsafe(
                self._close_async(), self._loop,
            )
            future.result(timeout=10)
        except Exception:
            logger.debug("Suppressed exception", exc_info=True)


    async def __aenter__(self):
        await self._ensure_browser()
        return self

    async def __aexit__(self, *exc):
        await self._close_async()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()

    def __del__(self):
        self._browser = None
        self._playwright = None
        self._pw = None
