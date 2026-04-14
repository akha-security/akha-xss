"""Regression tests for GraphQL and mXSS scanner hardening."""

import json
import unittest

from akha.core.config import Config
from akha.modules.xss.graphql_scanner import GraphQLScanner
from akha.modules.xss.mxss_engine import MXSSEngine


class _Resp:
    def __init__(self, text: str, status_code: int = 200):
        self.text = text
        self.status_code = status_code

    def json(self):
        return json.loads(self.text)


class _GraphQLHttpStub:
    def __init__(self):
        self.last_data = None

    def post(self, url, data=None, headers=None, timeout=None):
        self.last_data = data
        # Successful data response for query build assertion
        return _Resp('{"data": {"search": "ok"}}')


class _GraphQLErrorOnlyHttpStub:
    def post(self, url, data=None, headers=None, timeout=None):
        # Payload reflected inside error string only: should be ignored
        return _Resp('{"errors": [{"message": "invalid <script>alert(1)</script>"}]}', 200)


class _MxssHttpStub:
    def get(self, url, timeout=None):
        return _Resp('<html><body><script>alert(1)</script></body></html>', 200)


class TestGraphQLMxssHardening(unittest.TestCase):
    def test_graphql_test_field_uses_inline_value_and_object_selection(self):
        cfg = Config.default()
        http = _GraphQLHttpStub()
        scanner = GraphQLScanner(http, cfg)

        field_info = {
            'field_name': 'search',
            'arg_name': 'q',
            'operation': 'query',
            'return_kind': 'OBJECT',
        }
        result = scanner._test_field('https://example.com/graphql', field_info, '<img src=x onerror=1>')

        self.assertIsNotNone(result)
        sent = json.loads(http.last_data)
        q = sent['query']
        self.assertIn('query AkhaTest', q)
        self.assertIn('search(q: "<img src=x onerror=1>")', q)
        self.assertIn('{ __typename }', q)
        self.assertNotIn('$val', q)

    def test_graphql_test_field_ignores_error_only_response(self):
        cfg = Config.default()
        http = _GraphQLErrorOnlyHttpStub()
        scanner = GraphQLScanner(http, cfg)

        field_info = {
            'field_name': 'search',
            'arg_name': 'q',
            'operation': 'query',
            'return_kind': 'SCALAR',
        }
        result = scanner._test_field('https://example.com/graphql', field_info, '<script>alert(1)</script>')
        self.assertIsNone(result)

    def test_mxss_static_check_requires_payload_linked_evidence(self):
        cfg = Config.default()
        engine = MXSSEngine(_MxssHttpStub(), cfg)

        body = '<html><body><script>alert(1)</script></body></html>'
        payload = '<math><annotation-xml encoding="text/html"><svg onload=alert(1)></svg></annotation-xml></math>'

        self.assertFalse(engine._static_check(body, payload))

    def test_mxss_skips_plain_reflected_payloads(self):
        class _ReflectHttp:
            def get(self, url, timeout=None):
                from urllib.parse import urlparse, parse_qs

                parsed = urlparse(url)
                q = parse_qs(parsed.query)
                val = q.get("q", [""])[0]

                class _Resp:
                    def __init__(self, v):
                        self.text = f"<html><body>{v}</body></html>"

                return _Resp(val)

        cfg = Config.default()
        mx = MXSSEngine(_ReflectHttp(), cfg, execution_verifier=None)
        mx.ALL_PAYLOADS = ['<img src=x onerror=alert(1)>']

        findings = mx.scan(
            "https://example.com/search?q=test",
            [{"name": "q", "location": "query"}],
        )

        self.assertEqual(findings, [])


if __name__ == '__main__':
    unittest.main()

