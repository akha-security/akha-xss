"""Unit tests for execution verifier payload transform behavior."""

import unittest

from akha.modules.xss.execution_verifier import (
    VerificationResult,
    _apply_payload_transform,
    _build_init_script,
    _rewrite_hook_calls,
)


class TestExecutionVerifierTransform(unittest.TestCase):
    def test_rewrite_hook_calls_prefixes_window_scope(self):
        payload = "<script>alert(1);confirm(2);prompt(3)</script>"
        out = _rewrite_hook_calls(payload)

        self.assertIn("window.alert(", out)
        self.assertIn("window.confirm(", out)
        self.assertIn("window.prompt(", out)

    def test_apply_payload_transform_updates_url_when_payload_present(self):
        payload = "alert(1)"
        url = "https://example.com/?q=alert(1)"

        transformed_url, transformed_payload = _apply_payload_transform(url, payload, enabled=True)

        self.assertEqual(transformed_payload, "window.alert(1)")
        self.assertIn("window.alert(1)", transformed_url)

    def test_apply_payload_transform_noop_when_disabled(self):
        payload = "alert(1)"
        url = "https://example.com/?q=alert(1)"

        transformed_url, transformed_payload = _apply_payload_transform(url, payload, enabled=False)

        self.assertEqual(transformed_payload, payload)
        self.assertEqual(transformed_url, url)

    def test_init_script_traces_dangerous_sinks_without_execution_claim(self):
        script = _build_init_script("abc123")

        self.assertIn("window.eval = function", script)
        self.assertIn("_markSink(\"Function\"", script)
        self.assertIn("sink_trace", script)

    def test_verification_result_serializes_sink_traces(self):
        result = VerificationResult(sink_traces=["eval:alert(1)"])

        self.assertEqual(result.to_dict()["sink_traces"], ["eval:alert(1)"])


if __name__ == "__main__":
    unittest.main()
