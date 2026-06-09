"""Regression tests for second-round logic hardening fixes."""

import asyncio
import unittest

from akha.core.config import Config
from akha.modules.xss.dom_scanner import DOMScanner
from akha.modules.xss.execution_verifier import (
    BrowserIsolationPolicy,
    ExecutionVerifier,
    VerificationResult,
    _apply_payload_transform,
)
from akha.modules.xss.injector import Injector
from akha.modules.xss.xss_engine import XSSEngine


class _DummyHttp:
    def get(self, *_args, **_kwargs):
        class _Resp:
            status_code = 200
            text = ""
            headers = {"Content-Type": "text/html"}
            reason = "OK"

        return _Resp()

    def post(self, *args, **kwargs):
        return self.get(*args, **kwargs)

    def post_json(self, *args, **kwargs):
        return self.get(*args, **kwargs)


class _DummyPayloadManager:
    pass


class _DummyLearning:
    pass


class TestLogicHardeningRound2(unittest.TestCase):
    def test_apply_payload_transform_replaces_only_first_occurrence(self):
        url = "https://example.com/?a=alert(1)&b=alert(1)"
        transformed_url, transformed_payload = _apply_payload_transform(url, "alert(1)", True)

        self.assertEqual(transformed_payload, "window.alert(1)")
        self.assertEqual(transformed_url, "https://example.com/?a=window.alert(1)&b=alert(1)")

    def test_execution_verifier_verify_batch_reports_non_timeout_errors(self):
        verifier = ExecutionVerifier(timeout_ms=2000)
        original_run = verifier._runner.run

        def _fake_run(coro, timeout):
            coro.close()
            raise RuntimeError("boom")

        try:
            verifier._runner.run = _fake_run
            out = verifier.verify_batch([{"url": "https://example.com", "payload": "x"}], concurrency=1)
            self.assertEqual(out[0].error, "Batch failed: boom")
        finally:
            verifier._runner.run = original_run

    def test_execution_verifier_batch_async_clamps_zero_concurrency(self):
        verifier = ExecutionVerifier(timeout_ms=2000)

        async def _fake_verify_async(url, payload):
            return VerificationResult(executed=False, url=url, payload=payload)

        verifier.verify_async = _fake_verify_async
        out = asyncio.run(
            verifier.verify_batch_async(
                [{"url": "https://example.com", "payload": "x"}],
                concurrency=0,
            )
        )
        self.assertEqual(len(out), 1)
        self.assertEqual(out[0].url, "https://example.com")

    def test_execution_verifier_normalizes_isolation_policy(self):
        policy = BrowserIsolationPolicy(
            service_workers="invalid",
            max_runs_before_restart=1,
            renderer_memory_mb=999,
            nav_timeout_ceiling_ms=100,
            post_navigation_wait_ms=99999,
        )
        verifier = ExecutionVerifier(timeout_ms=2000, isolation_policy=policy)

        self.assertEqual(verifier.isolation_policy.service_workers, "block")
        self.assertEqual(verifier.isolation_policy.max_runs_before_restart, 5)
        self.assertEqual(verifier.isolation_policy.renderer_memory_mb, 512)
        self.assertIn("--js-flags=--max_old_space_size=512", verifier.browser_args)

    def test_execution_verifier_runtime_status_is_structured(self):
        status = ExecutionVerifier.runtime_status()

        self.assertIn("playwright", status)
        self.assertIn("error", status)

    def test_injector_build_path_url_handles_root_and_negative_index(self):
        self.assertEqual(
            Injector._build_path_url("https://example.com/", 0, "PAYLOAD"),
            "https://example.com/PAYLOAD",
        )
        self.assertEqual(
            Injector._build_path_url("https://example.com/a/b", -1, "PAYLOAD"),
            "https://example.com/PAYLOAD/b",
        )

    def test_injector_build_path_url_appends_when_index_out_of_range(self):
        self.assertEqual(
            Injector._build_path_url("https://example.com/a/b", 99, "PAYLOAD"),
            "https://example.com/a/b/PAYLOAD",
        )

    def test_dom_scanner_uses_configurable_timeouts(self):
        cfg = Config.default()
        cfg.timeout = 7
        scanner = DOMScanner(cfg, http_client=None)

        self.assertEqual(scanner._nav_timeout_ms, 7000)
        self.assertEqual(scanner._post_nav_wait_ms, 1050)

    def test_xss_engine_safe_context_delegates_to_verifier(self):
        cfg = Config.default()
        engine = XSSEngine(_DummyHttp(), _DummyPayloadManager(), _DummyLearning(), cfg)

        called = {}

        class _StubVerifier:
            @staticmethod
            def _is_in_safe_context(html, payload):
                called["html"] = html
                called["payload"] = payload
                return True

        engine.verifier = _StubVerifier()
        result = engine._is_reflection_in_safe_context("<html>abc</html>", "abc")

        self.assertTrue(result)
        self.assertEqual(called["payload"], "abc")

    def test_xss_engine_browser_skip_reasons_are_explicit(self):
        cfg = Config.default()
        engine = XSSEngine(_DummyHttp(), _DummyPayloadManager(), _DummyLearning(), cfg)

        self.assertEqual(
            engine._browser_verification_skip_reason(
                location="query",
                stage_score=4,
                verification_url="https://example.com/?q=x",
            ),
            "skipped_browser_verify_disabled",
        )
        cfg.browser_execution_verify = True
        self.assertEqual(
            engine._browser_verification_skip_reason(
                location="POST",
                stage_score=4,
                verification_url="https://example.com/",
            ),
            "skipped_post_body_no_headless_replay",
        )
        self.assertEqual(
            engine._browser_verification_skip_reason(
                location="query",
                stage_score=0,
                verification_url="https://example.com/?q=x",
            ),
            "skipped_stage_score_below_threshold",
        )


if __name__ == "__main__":
    unittest.main()
