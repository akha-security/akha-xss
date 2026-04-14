from types import SimpleNamespace

from akha.modules.param_finder import ParamFinder


class _Resp:
    def __init__(self, text, headers=None):
        self.text = text
        self.headers = headers or {}


class _Client:
    def __init__(self, html, content_type):
        self._html = html
        self._content_type = content_type

    def get(self, url, timeout=10, **kwargs):
        return _Resp(self._html, headers={"Content-Type": self._content_type})


def _cfg(scan_profile="balanced", deep_scan=False, aggressive_mode=False):
    return SimpleNamespace(
        timeout=10,
        param_wordlist=None,
        deep_scan=deep_scan,
        aggressive_mode=aggressive_mode,
        scan_profile=scan_profile,
        verbose=False,
    )


def test_form_extraction_is_content_type_case_insensitive():
    html = """
    <html><body>
      <form action='/search' method='GET'>
        <input name='q' value='x'>
      </form>
    </body></html>
    """
    finder = ParamFinder(_Client(html, "Text/HTML; Charset=UTF-8"), _cfg())
    params = finder.find_parameters("https://example.com/")
    names = {p["name"] for p in params}
    assert "q" in names


def test_mined_fallback_prevents_zero_params_in_balanced_mode():
    html = """
    <html><body>
      <script>
        const params = {query:'', token:''};
      </script>
    </body></html>
    """
    finder = ParamFinder(_Client(html, "text/html"), _cfg(scan_profile="balanced"))
    params = finder.find_parameters("https://example.com/")
    assert len(params) > 0
    assert any(p.get("type") == "mined" for p in params)
