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


def test_crawler_normalization_collapses_numeric_ids_and_pagination():
    crawler = object.__new__(Crawler)

    first = crawler._normalize_url("https://example.com/user/18281/profile?page=1&utm_source=x")
    second = crawler._normalize_url("https://example.com/user/19281/profile?page=2&utm_source=y")

    assert first == second
    assert first == "https://example.com/user/{id}/profile?page={page}"


def test_waf_cautious_crawler_keeps_limited_passive_discovery_but_skips_browser():
    class _Resp:
        url = "https://example.com/"
        status_code = 200
        headers = {"Content-Type": "text/html"}
        text = "<html><a href='/next'>next</a></html>"

    class _Client:
        def get(self, *_args, **_kwargs):
            return _Resp()

    crawler = Crawler(
        _Client(),
        SimpleNamespace(
            waf_cautious_applied=True,
            timeout=3,
            max_pages=1,
            max_depth=1,
            threads=1,
            deep_scan=False,
            dynamic_crawling=True,
            parse_js=True,
            probe_sensitive=False,
            crawler_aggressiveness="balanced",
            discovery_profile="auto",
            risk_prioritization=True,
            include_patterns=[],
            exclude_patterns=[],
        ),
    )
    called = {"passive": False, "browser": False}

    def _passive(*_args, **_kwargs):
        called["passive"] = True
        return set()

    def _browser(*_args, **_kwargs):
        called["browser"] = True
        return set(), ""

    crawler._passive_discovery = _passive
    crawler._browser_render_discovery = _browser

    crawler.crawl("https://example.com/")

    assert called["passive"] is True
    assert called["browser"] is False


def test_waf_cautious_common_path_probe_keeps_small_budget():
    class _Resp:
        status_code = 404
        url = "https://example.com/miss"

    class _Client:
        def __init__(self):
            self.calls = []

        def get(self, url, **_kwargs):
            self.calls.append(url)
            return _Resp()

    client = _Client()
    crawler = Crawler(
        client,
        SimpleNamespace(
            waf_cautious_applied=True,
            timeout=3,
            max_pages=350,
            max_depth=2,
            threads=8,
            deep_scan=False,
            dynamic_crawling=False,
            parse_js=False,
            probe_sensitive=False,
            crawler_aggressiveness="balanced",
            discovery_profile="auto",
            risk_prioritization=True,
            include_patterns=[],
            exclude_patterns=[],
        ),
    )

    crawler._probe_common_paths("https://example.com", "example.com")

    assert len(client.calls) <= 25
