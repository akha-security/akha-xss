"""Quality gate evaluator for AKHA scan reports.

Compares a current JSON report against a baseline and exits non-zero on
regressions beyond configured thresholds.
"""

from __future__ import annotations

import argparse
import json
import sys
from typing import Dict, Tuple


def _load(path: str) -> Dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def evaluate_quality_gate(current: Dict, baseline: Dict, *,
                          max_duration_regression_pct: float = 20.0,
                          max_request_regression_pct: float = 25.0,
                          min_confirmed_ratio_pct: float = 0.0,
                          max_p95_latency_regression_pct: float = 30.0,
                          max_confirmed_ratio_drop_pct: float = 20.0) -> Tuple[bool, Dict]:
    c_dur = float(current.get("duration", 0.0) or 0.0)
    b_dur = float(baseline.get("duration", 0.0) or 0.0)

    c_req = float((current.get("statistics", {}) or {}).get("requests_sent", 0) or 0)
    b_req = float((baseline.get("statistics", {}) or {}).get("requests_sent", 0) or 0)

    c_vulns = current.get("vulnerabilities", []) or []
    confirmed = sum(1 for v in c_vulns if str(v.get("severity_level", "")).lower() == "confirmed")
    confirmed_ratio_pct = (100.0 * confirmed / max(1, len(c_vulns))) if c_vulns else 0.0

    b_vulns = baseline.get("vulnerabilities", []) or []
    b_confirmed = sum(1 for v in b_vulns if str(v.get("severity_level", "")).lower() == "confirmed")
    baseline_confirmed_ratio_pct = (100.0 * b_confirmed / max(1, len(b_vulns))) if b_vulns else 0.0

    c_p95 = float((((current.get("telemetry", {}) or {}).get("latency_ms", {}) or {}).get("p95", 0.0) or 0.0))
    b_p95 = float((((baseline.get("telemetry", {}) or {}).get("latency_ms", {}) or {}).get("p95", 0.0) or 0.0))

    dur_reg = ((c_dur - b_dur) / b_dur * 100.0) if b_dur > 0 else 0.0
    req_reg = ((c_req - b_req) / b_req * 100.0) if b_req > 0 else 0.0
    p95_reg = ((c_p95 - b_p95) / b_p95 * 100.0) if b_p95 > 0 else 0.0
    confirmed_ratio_drop = max(0.0, baseline_confirmed_ratio_pct - confirmed_ratio_pct)

    reasons = []
    if dur_reg > max_duration_regression_pct:
        reasons.append(f"duration regression {dur_reg:.2f}% > {max_duration_regression_pct:.2f}%")
    if req_reg > max_request_regression_pct:
        reasons.append(f"request regression {req_reg:.2f}% > {max_request_regression_pct:.2f}%")
    if confirmed_ratio_pct < min_confirmed_ratio_pct:
        reasons.append(f"confirmed ratio {confirmed_ratio_pct:.2f}% < {min_confirmed_ratio_pct:.2f}%")
    if p95_reg > max_p95_latency_regression_pct:
        reasons.append(f"p95 latency regression {p95_reg:.2f}% > {max_p95_latency_regression_pct:.2f}%")
    if confirmed_ratio_drop > max_confirmed_ratio_drop_pct:
        reasons.append(f"confirmed ratio drop {confirmed_ratio_drop:.2f}% > {max_confirmed_ratio_drop_pct:.2f}%")

    return (len(reasons) == 0), {
        "duration_regression_pct": round(dur_reg, 2),
        "request_regression_pct": round(req_reg, 2),
        "p95_latency_regression_pct": round(p95_reg, 2),
        "confirmed_ratio_pct": round(confirmed_ratio_pct, 2),
        "baseline_confirmed_ratio_pct": round(baseline_confirmed_ratio_pct, 2),
        "confirmed_ratio_drop_pct": round(confirmed_ratio_drop, 2),
        "passed": len(reasons) == 0,
        "reasons": reasons,
    }


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="AKHA quality gate evaluator")
    p.add_argument("--current", required=True, help="Current scan JSON report path")
    p.add_argument("--baseline", required=True, help="Baseline scan JSON report path")
    p.add_argument("--max-duration-regression", type=float, default=20.0)
    p.add_argument("--max-request-regression", type=float, default=25.0)
    p.add_argument("--min-confirmed-ratio", type=float, default=0.0)
    p.add_argument("--max-p95-latency-regression", type=float, default=30.0)
    p.add_argument("--max-confirmed-ratio-drop", type=float, default=20.0)
    args = p.parse_args(argv)

    current = _load(args.current)
    baseline = _load(args.baseline)

    passed, summary = evaluate_quality_gate(
        current,
        baseline,
        max_duration_regression_pct=args.max_duration_regression,
        max_request_regression_pct=args.max_request_regression,
        min_confirmed_ratio_pct=args.min_confirmed_ratio,
        max_p95_latency_regression_pct=args.max_p95_latency_regression,
        max_confirmed_ratio_drop_pct=args.max_confirmed_ratio_drop,
    )

    print(json.dumps(summary, indent=2))
    return 0 if passed else 2


if __name__ == "__main__":
    sys.exit(main())
