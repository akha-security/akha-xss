"""Benchmark Section-4 quality signals and scan overhead.

Usage:
  python tools/benchmark_section4_signals.py --target https://example.com

This benchmark runs AKHA multiple times and summarizes:
- elapsed time
- finding counts
- validated finding counts
- findings with consistency_ratio
- findings with html_diff suspicious signals
- findings with browser execution evidence
"""

from __future__ import annotations

import argparse
import json
import statistics
import subprocess
import sys
import time
from pathlib import Path
from typing import Any


def run_command(cmd: list[str]) -> tuple[int, float, str]:
    start = time.time()
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed = time.time() - start
    return proc.returncode, elapsed, (proc.stdout or "") + "\n" + (proc.stderr or "")


def load_findings(json_path: Path) -> list[dict[str, Any]]:
    if not json_path.exists():
        return []
    try:
        data = json.loads(json_path.read_text(encoding="utf-8"))
    except Exception:
        return []

    results = data.get("results") or []
    findings: list[dict[str, Any]] = []
    for result in results:
        vulns = result.get("vulnerabilities") or []
        findings.extend(vulns)
    return findings


def summarize_findings(findings: list[dict[str, Any]]) -> dict[str, int]:
    html_diff_signal_count = 0
    consistency_signal_count = 0
    execution_signal_count = 0
    validated_count = 0

    for f in findings:
        if f.get("validated"):
            validated_count += 1

        if f.get("consistency_ratio") is not None:
            consistency_signal_count += 1

        html_diff = f.get("html_diff") or {}
        suspicious = html_diff.get("suspicious_injection_points") or []
        if suspicious:
            html_diff_signal_count += 1

        if f.get("execution_evidence"):
            execution_signal_count += 1

    return {
        "total_findings": len(findings),
        "validated_findings": validated_count,
        "with_consistency_ratio": consistency_signal_count,
        "with_html_diff_signal": html_diff_signal_count,
        "with_execution_evidence": execution_signal_count,
    }


def percentile(values: list[float], p: float) -> float:
    if not values:
        return 0.0
    if len(values) == 1:
        return values[0]
    idx = (len(values) - 1) * p
    lo = int(idx)
    hi = min(lo + 1, len(values) - 1)
    frac = idx - lo
    return values[lo] * (1 - frac) + values[hi] * frac


def main() -> int:
    parser = argparse.ArgumentParser(description="Benchmark AKHA Section-4 signals")
    parser.add_argument("--target", required=True, help="Target URL")
    parser.add_argument("--runs", type=int, default=3, help="Number of repeated runs (default: 3)")
    parser.add_argument("--profile", choices=["quick", "balanced", "deep"], default="balanced")
    parser.add_argument("--output", default="benchmark_section4_signals.json", help="Output JSON file")
    parser.add_argument("--timeout", type=int, default=15, help="HTTP timeout per request in seconds")
    args = parser.parse_args()

    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    run_summaries: list[dict[str, Any]] = []
    elapsed_values: list[float] = []

    for run_idx in range(1, args.runs + 1):
        json_path = output_path.parent / f"section4_run_{run_idx}.json"

        cmd = [
            sys.executable,
            "-m",
            "akha",
            "scan",
            "--url",
            args.target,
            "--mode",
            "url",
            "--profile",
            args.profile,
            "--timeout",
            str(args.timeout),
            "--json-output",
            str(json_path),
            "--quiet",
        ]

        code, elapsed, log_text = run_command(cmd)
        elapsed_values.append(elapsed)

        findings = load_findings(json_path)
        signal_summary = summarize_findings(findings)

        run_summaries.append(
            {
                "run": run_idx,
                "exit_code": code,
                "elapsed_seconds": round(elapsed, 3),
                "signals": signal_summary,
                "log_excerpt": log_text[-1600:],
                "json_output": str(json_path),
            }
        )

    elapsed_sorted = sorted(elapsed_values)
    aggregate = {
        "runs": args.runs,
        "profile": args.profile,
        "avg_elapsed_seconds": round(statistics.mean(elapsed_values), 3) if elapsed_values else 0.0,
        "min_elapsed_seconds": round(min(elapsed_values), 3) if elapsed_values else 0.0,
        "max_elapsed_seconds": round(max(elapsed_values), 3) if elapsed_values else 0.0,
        "p50_elapsed_seconds": round(percentile(elapsed_sorted, 0.50), 3),
        "p95_elapsed_seconds": round(percentile(elapsed_sorted, 0.95), 3),
        "successful_runs": sum(1 for r in run_summaries if r["exit_code"] == 0),
    }

    payload = {
        "target": args.target,
        "aggregate": aggregate,
        "runs": run_summaries,
    }

    output_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    print(f"Section-4 benchmark complete: {output_path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
