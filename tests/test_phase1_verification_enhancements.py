import unittest

from akha.core.config import Config
from akha.modules.xss.scoring import ConfidenceScorer
from akha.modules.xss.xss_engine import XSSEngine


class _DummyResp:
    def __init__(self, text: str):
        self.text = text
        self.status_code = 200
        self.headers = {"Content-Type": "text/html"}
        self.reason = "OK"


class _DummyHttp:
    def __init__(self, html: str):
        self._resp = _DummyResp(html)

    def get(self, url, **kwargs):
        return self._resp

    def post(self, *args, **kwargs):
        return self._resp

    def post_json(self, *args, **kwargs):
        return self._resp


class _DummyPayloadManager:
    pass


class _DummyLearning:
    pass


class _StubExecVerifier:
    def __init__(self, executed=False, method=None, error=None, evidence=None):
        self._executed = executed
        self._method = method
        self._error = error
        self._evidence = evidence

    class _Result:
        def __init__(self, executed, method, error, evidence):
            self.executed = executed
            self.method = method
            self.error = error
            self.evidence = evidence

    def verify(self, url, payload):
        return self._Result(
            executed=self._executed,
            method=self._method,
            error=self._error,
            evidence=self._evidence,
        )


class TestPhase1VerificationEnhancements(unittest.TestCase):
    def test_scorer_uses_reproducibility_and_structural_dom_signal(self):
        scorer = ConfidenceScorer()
        strong = scorer.score(
            marker_in_tag=True,
            payload_reflected_raw=True,
            reverify_ok=True,
            structural_dom_evidence=True,
            reproducibility_ratio=1.0,
            context_executable=True,
        )
        weak = scorer.score(
            marker_in_tag=True,
            payload_reflected_raw=True,
            reverify_ok=False,
            structural_dom_evidence=False,
            reproducibility_ratio=0.33,
            context_executable=True,
        )

        self.assertGreater(strong.score, weak.score)
        self.assertLessEqual(strong.exploitability_score, 70)

    def test_verify_result_contains_browser_matrix_and_exploitability(self):
        cfg = Config.default()
        cfg.verbose = False
        cfg.execution_verify_firefox = False

        payload = '<img class=akha src=x onerror=alert(1)>'
        html = f'<html><body>{payload}</body></html>'
        engine = XSSEngine(_DummyHttp(html), _DummyPayloadManager(), _DummyLearning(), cfg)
        engine.execution_verifier = _StubExecVerifier(executed=False)

        result = engine._verify_xss(
            url='https://example.com/search',
            param_name='q',
            payload=payload,
            location='query',
            baseline_html='<html><body>baseline</body></html>',
        )

        self.assertIsNotNone(result)
        self.assertIn('browser_matrix', result)
        self.assertIn('chromium', result['browser_matrix'])
        self.assertIn('exploitability_score', result)


if __name__ == '__main__':
    unittest.main()
