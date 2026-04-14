"""External Playwright validation for exported XSS candidates.

Usage:
  python tools/validate_candidates_playwright.py --input candidates.json --output validated.json
"""

from __future__ import annotations

import argparse
import json
from typing import Dict, List

from akha.modules.xss.execution_verifier import ExecutionVerifier


def validate_candidates(candidates: List[Dict], timeout_ms: int = 8000) -> List[Dict]:
    verifier = ExecutionVerifier(timeout_ms=timeout_ms)
    out: List[Dict] = []
    try:
        for item in candidates:
            url = item.get("test_url") or item.get("url")
            payload = item.get("payload", "")
            if not url or not payload:
                continue
            result = verifier.verify(url, payload)
            enriched = dict(item)
            enriched["external_validated"] = bool(result.executed)
            enriched["external_validation_method"] = result.method
            enriched["external_validation_evidence"] = result.evidence
            out.append(enriched)
    finally:
        verifier.close()
    return out


def main() -> int:
    parser = argparse.ArgumentParser(description="Validate XSS candidates via external Playwright runner")
    parser.add_argument("--input", required=True, help="Input JSON file containing candidates")
    parser.add_argument("--output", required=True, help="Output JSON file for validated results")
    parser.add_argument("--timeout-ms", type=int, default=8000)
    args = parser.parse_args()

    with open(args.input, "r", encoding="utf-8") as f:
        data = json.load(f)

    candidates = data.get("candidates", data if isinstance(data, list) else [])
    validated = validate_candidates(candidates, timeout_ms=args.timeout_ms)

    with open(args.output, "w", encoding="utf-8") as f:
        json.dump({"count": len(validated), "results": validated}, f, indent=2, default=str)

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
