"""Regression tests for shared typed pipeline models."""

from akha.core.models import (
    BrowserExecutionResult,
    PayloadCandidate,
    ScanResult,
    VerificationResult,
)


def test_verification_result_to_dict_preserves_nested_execution():
    execution = BrowserExecutionResult(
        executed=True,
        method="dialog",
        evidence="alert(1)",
        browser_engine="chromium",
    )
    result = VerificationResult(
        url="https://example.com/?q=x",
        payload="alert(1)",
        validated=True,
        confidence=95,
        severity_level="confirmed",
        context={"type": "html"},
        execution=execution,
    )

    out = result.to_dict()

    assert out["execution"]["executed"] is True
    assert out["execution"]["browser_engine"] == "chromium"


def test_payload_candidate_and_scan_result_to_dict_are_report_safe():
    candidate = PayloadCandidate(
        url="https://example.com",
        parameter="q",
        payload="<img src=x onerror=alert(1)>",
        context={"type": "attribute"},
        location="query",
    )
    scan = ScanResult(
        target="https://example.com",
        scan_mode="url",
        vulnerabilities=[candidate.to_dict()],
        statistics={"total": 1},
    )

    out = scan.to_dict()

    assert out["vulnerabilities"][0]["parameter"] == "q"
    assert out["statistics"]["total"] == 1
