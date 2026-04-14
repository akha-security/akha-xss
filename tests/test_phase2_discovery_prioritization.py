from types import SimpleNamespace
from collections import deque

from akha.core.scanner import Scanner
from akha.modules.crawler import Crawler
from akha.modules.param_finder import ParamFinder


class _DummyClient:
    def get(self, *args, **kwargs):
        raise RuntimeError("not used in this unit test")


class _DummyAuthClient:
    def __init__(self, authenticated):
        self.authenticated = authenticated


def _cfg_for_paramfinder():
    return SimpleNamespace(
        timeout=10,
        param_wordlist=None,
        deep_scan=False,
        aggressive_mode=False,
        scan_profile="balanced",
        verbose=False,
    )


def test_paramfinder_deduplicate_uses_canonical_form_action_signature():
    finder = ParamFinder(_DummyClient(), _cfg_for_paramfinder())

    params = [
        {
            "name": "q",
            "location": "GET",
            "form_action": "https://example.com/search/?b=2&a=1",
            "confidence": "medium",
        },
        {
            "name": "q",
            "location": "GET",
            "form_action": "https://example.com/search?a=1&b=2",
            "confidence": "high",
        },
    ]

    deduped = finder._deduplicate(params)

    assert len(deduped) == 1
    assert deduped[0]["confidence"] == "high"


def test_scanner_prioritizes_high_risk_urls_first():
    scanner = object.__new__(Scanner)
    scanner.config = SimpleNamespace(risk_prioritization=True, risk_priority_top_k=0)

    crawled = [
        {"url": "https://example.com/static/about", "depth": 1, "forms": [], "parameters": []},
        {
            "url": "https://example.com/search?q=test",
            "depth": 1,
            "forms": [{"action": "/search"}],
            "parameters": [{"name": "q"}],
        },
        {"url": "https://example.com/api/profile/update", "depth": 2, "forms": [], "parameters": [{"name": "name"}]},
    ]

    prioritized = scanner._prioritize_crawled_urls(crawled)

    assert prioritized[0]["url"] == "https://example.com/search?q=test"


def test_scanner_prioritization_can_be_capped():
    scanner = object.__new__(Scanner)
    scanner.config = SimpleNamespace(risk_prioritization=True, risk_priority_top_k=2)

    crawled = [
        {"url": "https://example.com/a", "depth": 1, "forms": [], "parameters": []},
        {"url": "https://example.com/search?q=1", "depth": 1, "forms": [{"action": "/search"}], "parameters": [{"name": "q"}]},
        {"url": "https://example.com/graphql", "depth": 2, "forms": [], "parameters": [{"name": "query"}]},
    ]

    prioritized = scanner._prioritize_crawled_urls(crawled)

    assert len(prioritized) == 2


def test_crawler_pop_priority_batch_prefers_high_value_urls():
    crawler = object.__new__(Crawler)
    crawler.config = SimpleNamespace(risk_prioritization=True)

    q = deque([
        ("https://example.com/static/about", 1),
        ("https://example.com/search?q=test", 1),
        ("https://example.com/graphql", 2),
    ])

    batch = crawler._pop_priority_batch(q, 2)

    picked_urls = {u for u, _ in batch}
    assert "https://example.com/search?q=test" in picked_urls
    assert len(batch) == 2


def test_crawler_resolves_discovery_profile_from_auth_state():
    crawler = object.__new__(Crawler)
    crawler.config = SimpleNamespace(discovery_profile="auto")
    crawler.client = _DummyAuthClient(authenticated=True)
    assert crawler._resolve_discovery_profile() == "authenticated"

    crawler.client = _DummyAuthClient(authenticated=False)
    assert crawler._resolve_discovery_profile() == "anonymous"


def test_state_fingerprint_is_stable_for_same_route_and_html():
    fp1 = Crawler._state_fingerprint("https://example.com/app?page=1", "<html><body>A</body></html>")
    fp2 = Crawler._state_fingerprint("https://example.com/app?page=1", "<html><body>A</body></html>")
    fp3 = Crawler._state_fingerprint("https://example.com/app?page=2", "<html><body>A</body></html>")

    assert fp1 == fp2
    assert fp1 != fp3
