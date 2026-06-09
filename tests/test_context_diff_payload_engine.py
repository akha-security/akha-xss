from akha.modules.xss.context_analyzer import ContextAnalyzer, ContextType
from akha.modules.xss.html_diff_engine import HTMLDiffEngine
from akha.payloads.generator import PayloadGenerator


def test_context_analyzer_detects_attribute_context():
    analyzer = ContextAnalyzer()
    marker = "AKHA_MARKER"
    html = f'<input value="{marker}">'

    result = analyzer.analyze(html, marker)

    assert result.found is True
    assert result.best is not None
    assert result.best.context_type == ContextType.ATTRIBUTE
    assert result.best.in_attribute is True


def test_html_diff_engine_flags_injected_script_node():
    engine = HTMLDiffEngine()
    baseline = "<html><body><div>safe</div></body></html>"
    injected = "<html><body><div>safe</div><script>alert(1)</script></body></html>"

    result = engine.diff(baseline, injected)

    assert result.structure_changed is True
    assert result.has_suspicious is True
    assert any(point.kind in {"new_script", "dangerous_tag"} for point in result.suspicious_injection_points)


def test_payload_generator_returns_context_payloads_with_marker():
    generator = PayloadGenerator()
    chars = {
        "<": "raw",
        ">": "raw",
        '"': "raw",
        "'": "raw",
        "(": "raw",
        ")": "raw",
        "`": "raw",
        "/": "raw",
    }

    payloads = generator.generate(context="html", chars=chars, marker="class=akha")

    assert payloads
    assert any("class=akha" in payload for payload in payloads)
    assert any("svg" in payload.lower() or "script" in payload.lower() for payload in payloads)
